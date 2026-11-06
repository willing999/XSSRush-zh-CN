import argparse
import asyncio
from pathlib import Path
import re
import sys
from typing import Optional, Set, List, Dict, Tuple

from constants import VERSION
from models import ScanConfig
from parsers.url import parse_postfields_string
from utils.logger import Logger
from utils.helpers import is_valid_url
from scanner.engine import ScannerEngine
from reporters.console import Reporter
from payloads import get_all_payloads
from config import GENERAL_PARAMS, REDIRECT_PARAMS, XSS_HEADERS
from detection.context import normalize_context_name

def strip_ansi(text: str) -> str:
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_regex.sub('', text)

def resolve_output_path(user_path: str, base_dir: Path) -> Path:
    raw = user_path.strip()
    is_rooted = (
        raw.startswith(("/", "\\"))
        or bool(re.match(r"^[a-zA-Z]:[/\\]", raw))
        or Path(raw).is_absolute()
    )
    if is_rooted:
        target = Path(raw)
    else:
        target = base_dir / "output" / raw

    target.parent.mkdir(parents=True, exist_ok=True)
    return target

def resolve_wordlist_path(user_path: str, base_dir: Path) -> Path:
    raw = user_path.strip()
    p = Path(raw)
    if p.is_file():
        return p
    alt = base_dir / raw
    if alt.is_file():
        return alt
    return p

def load_wordlist(file_path: Path) -> List[str]:
    if not file_path.is_file():
        return []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return list(dict.fromkeys(lines))

def parse_scan_modules(scan_str: Optional[str]) -> Set[str]:
    if not scan_str:
        return {"get", "post"}

    raw_tokens = [t.strip().lower() for t in scan_str.split(",") if t.strip()]
    if "all" in raw_tokens:
        return {"get", "post", "path", "fragment", "header"}

    valid_mods = {"get", "post", "path", "fragment", "header"}
    selected = set()
    for tok in raw_tokens:
        if tok in valid_mods:
            selected.add(tok)
        elif tok == "dom":
            selected.add("get")
        elif tok in ("paths", "link", "links"):
            selected.add("path")
        elif tok in ("fragments", "hash"):
            selected.add("fragment")
        elif tok in ("headers", "head"):
            selected.add("header")

    return selected if selected else {"get", "post"}

def parse_target_params(param_arg) -> Tuple[List[str], Dict[str, str]]:
    if not param_arg:
        return [], {}
    params = []
    contexts = {}
    if isinstance(param_arg, str):
        param_arg = [param_arg]
    for item in param_arg:
        for piece in item.split(","):
            piece = piece.strip()
            if not piece:
                continue
            if ":" in piece:
                name, raw_ctx = piece.split(":", 1)
                name = name.strip()
                raw_ctx = raw_ctx.strip()
                norm_ctx = normalize_context_name(raw_ctx)
                if name:
                    if name.lower() not in [x.lower() for x in params]:
                        params.append(name)
                    if norm_ctx:
                        contexts[name.lower()] = norm_ctx
            else:
                if piece.lower() not in [x.lower() for x in params]:
                    params.append(piece)
    return params, contexts

def parse_exclude_params(exclude_arg) -> List[str]:
    if not exclude_arg:
        return []
    res = []
    if isinstance(exclude_arg, str):
        exclude_arg = [exclude_arg]
    for item in exclude_arg:
        for p in item.split(","):
            cleaned = p.strip()
            if cleaned and cleaned.lower() not in res:
                res.append(cleaned.lower())
    return res

def parse_header_list(header_arg) -> List[str]:
    if not header_arg:
        return []
    res = []
    if isinstance(header_arg, str):
        header_arg = [header_arg]
    for item in header_arg:
        for h in item.split(","):
            cleaned = h.strip()
            if cleaned and cleaned not in res:
                res.append(cleaned)
    return res

class XSSRHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=34, width=100)

class XSSRArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        formatter = self._get_formatter()
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_text(action_group.description)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()
        return formatter.format_help()

    def print_help(self, file=None):
        logger = Logger()
        logger.print_banner()
        raw_help = self.format_help()
        clean = strip_ansi(raw_help)
        print(f"\033[97m{clean.strip()}\033[0m\n")

    def error(self, message):
        print(f"\033[97mxssr: 错误: {message}\033[0m", file=sys.stderr)
        print("\033[90m(使用 'xssr -h' 或 'xssr --help' 查看所有可用选项)\033[0m\n", file=sys.stderr)
        sys.exit(2)

def build_parser() -> argparse.ArgumentParser:
    parser = XSSRArgumentParser(
        prog="xssr",
        add_help=False,
        formatter_class=XSSRHelpFormatter,
    )

    target_group = parser.add_argument_group("目标选项")
    target_group.add_argument(
        "-u", "--url",
        dest="url",
        type=str,
        default=None,
        help="要扫描的目标 URL（例如 https://example.com/search?q=test）",
    )

    browser_group = parser.add_argument_group("浏览器与引擎选项")
    browser_group.add_argument(
        "-b", "--browser",
        dest="browser",
        type=str,
        choices=["firefox", "chromium", "webkit"],
        default="firefox",
        help="要使用的浏览器引擎（默认：firefox）",
    )
    browser_group.add_argument(
        "--headless",
        dest="headless",
        type=str.lower,
        choices=["true", "false"],
        default="true",
        metavar="",
        help="以无头模式运行浏览器（可选：true, false，默认：true）",
    )
    browser_group.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=15000,
        help="页面导航超时（毫秒，默认：15000）",
    )
    browser_group.add_argument(
        "--delay-min",
        dest="delay_min",
        type=int,
        default=3000,
        help="最小请求延迟（毫秒，默认：3000）",
    )
    browser_group.add_argument(
        "--delay-max",
        dest="delay_max",
        type=int,
        default=5000,
        help="最大请求延迟（毫秒，默认：5000）",
    )

    scope_group = parser.add_argument_group("扫描范围选项")
    scope_group.add_argument(
        "--scan",
        dest="scan",
        type=str,
        default="get,post",
        metavar="MODULES",
        help="要测试的模块：get, post, path, fragment, header 或 all（默认：get,post）",
    )
    scope_group.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        type=str,
        default=None,
        metavar="FILE",
        help="要探测的自定义参数字典文件（例如 'wordlists/common.txt'）",
    )
    scope_group.add_argument(
        "-m", "--mining",
        dest="mining",
        action="store_true",
        default=False,
        help="仅执行参数挖掘与反射分析（不进行 XSS 测试）",
    )
    scope_group.add_argument(
        "-p", "--param",
        dest="param",
        action="append",
        default=None,
        metavar="PARAMS",
        help="要测试的参数（例如 'p:js,q:html' 或 'name'）",
    )
    scope_group.add_argument(
        "-e", "--exclude",
        dest="exclude",
        action="append",
        default=None,
        metavar="PARAMS",
        help="测试期间要跳过的参数（逗号分隔，例如 'name,location'）",
    )
    scope_group.add_argument(
        "-d", "--data",
        dest="data",
        type=str,
        default=None,
        metavar="POSTFIELDS",
        help="自定义 POST 数据字段（例如 'username=admin&search=keyword'）",
    )
    scope_group.add_argument(
        "--context",
        dest="context",
        type=str,
        default=None,
        metavar="CONTEXT",
        help="默认注入上下文（可选：js, html, attr, url, dom）",
    )
    scope_group.add_argument(
        "--include-header",
        dest="include_headers",
        action="append",
        default=None,
        metavar="HEADERS",
        help="要添加到 header 扫描的自定义 HTTP 头（逗号分隔，例如 'X-User-Agent,X-Referer'）",
    )
    scope_group.add_argument(
        "--exclude-header",
        dest="exclude_headers",
        action="append",
        default=None,
        metavar="HEADERS",
        help="header 扫描期间要跳过的 HTTP 头（逗号分隔，例如 'User-Agent,Referer'）",
    )

    parser.add_argument(
        "--parameter-mining",
        dest="mining",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--mine",
        dest="mining",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--params",
        dest="param",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--postfields",
        dest="data",
        type=str,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--include-headers",
        dest="include_headers",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--exclude-headers",
        dest="exclude_headers",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--show-parameters",
        dest="show_params",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    info_group = parser.add_argument_group("信息选项")
    info_group.add_argument(
        "--show-payloads",
        dest="show_payloads",
        action="store_true",
        help="显示所有内置 XSS payload 并退出",
    )
    info_group.add_argument(
        "--show-params",
        dest="show_params",
        action="store_true",
        help="显示所有内置已知参数并退出",
    )
    info_group.add_argument(
        "--show-headers",
        dest="show_headers",
        action="store_true",
        help="显示所有内置目标 HTTP 头并退出",
    )

    output_group = parser.add_argument_group("输出与报告选项")
    output_group.add_argument(
        "-o", "--output",
        dest="output",
        type=str,
        default=None,
        metavar="FILE",
        help="保存报告 JSON（除非给定绝对路径，否则保存到 output/ 文件夹）",
    )
    output_group.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="启用详细调试输出",
    )
    output_group.add_argument(
        "-h", "--help",
        action="help",
        help="显示此帮助信息并退出",
    )
    output_group.add_argument(
        "--version",
        action="version",
        version="XSSR/XSSRush 2.0.0",
        help="显示程序版本号并退出",
    )

    return parser

async def main_async(args):
    logger = Logger(verbose=args.verbose)
    logger.print_banner()

    target_url = args.url.strip()
    if not is_valid_url(target_url):
        logger.error(f"无效的目标 URL：'{target_url}'（必须以 http:// 或 https:// 开头）")
        sys.exit(1)

    raw_data = getattr(args, "data", None)
    custom_postfields = parse_postfields_string(raw_data) if raw_data else None
    is_headless = str(args.headless).strip().lower() in ("true", "1", "yes")
    scan_modules = parse_scan_modules(args.scan)
    target_params, target_param_contexts = parse_target_params(getattr(args, "param", None))
    default_context = normalize_context_name(getattr(args, "context", None))
    exclude_params = parse_exclude_params(args.exclude)
    include_headers = parse_header_list(args.include_headers)
    exclude_headers = parse_header_list(args.exclude_headers)

    base_dir = Path(__file__).resolve().parent

    resolved_output = None
    if args.output:
        resolved_output = str(resolve_output_path(args.output, base_dir))

    resolved_wordlist = None
    wordlist_params = []
    if getattr(args, "wordlist", None):
        wl_path = resolve_wordlist_path(args.wordlist, base_dir)
        if not wl_path.is_file():
            logger.error(f"未找到字典文件：'{args.wordlist}'")
            sys.exit(1)
        wordlist_params = load_wordlist(wl_path)
        resolved_wordlist = str(wl_path)
        logger.info(f"从字典加载了 {len(wordlist_params)} 个参数：'{args.wordlist}'")

    config = ScanConfig(
        target_url=target_url,
        postfields=custom_postfields,
        browser_type=args.browser,
        headless=is_headless,
        timeout_ms=args.timeout,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        verbose=args.verbose,
        output_file=resolved_output,
        scan_modules=scan_modules,
        target_params=target_params,
        target_param_contexts=target_param_contexts,
        default_context=default_context,
        exclude_params=exclude_params,
        include_headers=include_headers,
        exclude_headers=exclude_headers,
        wordlist_path=resolved_wordlist,
        wordlist_params=wordlist_params,
        mining_only=getattr(args, "mining", False),
    )

    engine = ScannerEngine(config=config, logger=logger)
    findings, parameters = await engine.run()

    reporter = Reporter(findings=findings, parameters=parameters, logger=logger, mining_only=config.mining_only)
    reporter.render_console()

    if config.output_file:
        reporter.export_json(config.output_file)

def handle_show_options(args) -> bool:
    has_show = False
    if getattr(args, "show_payloads", False):
        has_show = True
        for p in get_all_payloads():
            print(p.payload)
    if getattr(args, "show_headers", False):
        has_show = True
        for h in XSS_HEADERS.keys():
            print(h)
    if getattr(args, "show_params", False):
        has_show = True
        all_params = list(dict.fromkeys(GENERAL_PARAMS + REDIRECT_PARAMS))
        print(", ".join(all_params))
    return has_show

def main():
    parser = build_parser()
    args = parser.parse_args()

    if handle_show_options(args):
        sys.exit(0)

    if not args.url:
        parser.error("缺少必需的参数：-u/--url")

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n\033[1m\033[31m[!]\033[0m 扫描已被用户中断。")
        sys.exit(130)

if __name__ == "__main__":
    main()
