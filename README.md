<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://xssr.n45ht.or.id/assets/img/xssr-banner-light-34px.png">
    <source media="(prefers-color-scheme: light)" srcset="https://xssr.n45ht.or.id/assets/img/xssr-banner-dark-34px.png">
    <img alt="XSSR / XSSRush Logo" src="https://xssr.n45ht.or.id/assets/img/xssr-banner-light-34px.png" height="42">
  </picture>
</p>

<p align="center">
  <b>简体中文</b> · <a href="README.en.md">English</a>
</p>

<h3 align="center">自动化多向量跨站脚本（XSS）扫描器与审计器</h3>

<p align="center">
  <b>基于 Playwright 无头浏览器自动化 &bull; 零后端 &bull; 独立 Python CLI</b>
</p>

<p align="center">
  <a href="https://github.com/willing999/XSSRush-zh-CN/releases"><img src="https://img.shields.io/badge/version-v2.0.0-crimson.svg?style=flat-square" alt="Version"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="https://playwright.dev/"><img src="https://img.shields.io/badge/Engine-Playwright-2EAD33.svg?style=flat-square&logo=playwright&logoColor=white" alt="Playwright"></a>
  <a href="https://github.com/willing999/XSSRush-zh-CN/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/willing999/XSSRush-zh-CN"><img src="https://img.shields.io/badge/GitHub-willing999/XSSRush--zh--CN-1f6feb.svg?style=flat-square" alt="GitHub"></a>
  <a href="https://github.com/willing999/XSSRush-zh-CN/stargazers"><img src="https://img.shields.io/github/stars/willing999/XSSRush-zh-CN?style=flat-square&color=yellow" alt="GitHub Stars"></a>
</p>

---

<p align="center">
  <img src="https://xssr.n45ht.or.id/assets/img/xssr-cli-terminal.png" alt="XSSR CLI Execution Preview" width="880">
</p>

**XSSR（XSSRush）** 是基于 **Playwright** 的自动化跨站脚本（XSS）漏洞扫描器与安全审计器。

通过 **Playwright** 驱动真实的浏览器实例，XSSR 挂接进浏览器事件循环，拦截真实的 JavaScript 执行（`alert`、`confirm`、`prompt`）。它通过在 DOM 内部确认 payload 的执行，消除了静态正则扫描器常见的误报。

---

## 审计流水线

XSSR 执行一个结构化的 7 阶段审计序列：

```text
[Step 0: 参数挖掘]  ──>  [Step 1: 金丝雀探测]  ──>  [Step 2: GET & DOM XSS]
                                                               │
[Step 5: Fragment] <──  [Step 4: 路径 XSS]  <──  [Step 3: POST 表单 XSS]
        │
        └───> [Step 6: Header XSS]  ───> [验证与报告]
```

| 步骤 | 模块 | 攻击向量与说明 |
|:---:|---|---|
| **0** | `modules/parameter_mining.py` | **参数挖掘**：提取查询参数、表单控件、全局 `window` JS 变量，并用字典探测隐藏参数。 |
| **1** | `modules/reflection.py` | **反射分析**：注入唯一的金丝雀探测 token，发现反射点并映射语法上下文（`html`、`attribute`、`javascript`、`url`）。 |
| **2** | `modules/get_dom.py` | **反射 GET & DOM XSS**：向查询/DOM 参数测试上下文调优的 payload，并拦截浏览器对话框。 |
| **3** | `modules/forms.py` | **POST 表单 XSS**：自动化 DOM 表单提交（`requestSubmit()`），并生成 base64 HTML 复现 PoC。 |
| **4** | `modules/links.py` | **路径型 XSS**：向 URL 路径段和目录重写注入 payload。 |
| **5** | `modules/dom.py` | **Fragment 型 XSS**：针对客户端 SPA 路由器和 DOM sink 测试 URL hash 片段（`#payload`）。 |
| **6** | `modules/headers.py` | **Header 型 XSS**：向 HTTP 请求头（`User-Agent`、`Referer`、`Origin`、`Cookie`、`X-Forwarded-*`）注入 payload。 |

---

## 安装

### 前置要求
* Python **3.10** 或更高版本
* `pip` 包管理器

```bash
# 1. 克隆仓库
git clone https://github.com/willing999/XSSRush-zh-CN.git
cd XSSRush-zh-CN

# 2. 安装依赖
pip install -r requirements.txt

# 3. 安装 Playwright 浏览器引擎（默认 Firefox）
playwright install firefox
```

*（可选）如果你计划使用 Chromium 或 WebKit 引擎进行测试：*
```bash
playwright install chromium webkit
```

---

## 使用示例

### 1. 基础单目标扫描（GET & POST）
```bash
python xssr.py -u "https://target.com/page?id=12"
```

### 2. 测试自定义 POST 数据字段
```bash
python xssr.py -u "https://target.com/login" --scan post -d "username=admin&search=keyword"
```

### 3. 完整多向量审计
测试所有向量（GET、POST、Path、Fragment、Header）并导出报告：
```bash
python xssr.py -u "https://target.com/app" --scan all -o scan_report.json
```

### 4. 选择浏览器引擎
切换到 Chromium 或 WebKit：
```bash
python xssr.py -u "https://target.com/app" -b chromium --scan all
```

### 5. 可见 GUI 浏览器模式（调试）
关闭无头模式，可视化监控浏览器交互：
```bash
python xssr.py -u "https://target.com/search?q=test" --headless false -v
```

### 6. 微调请求延迟
调整延迟范围（毫秒）以规避 WAF 速率限制：
```bash
python xssr.py -u "https://target.com" --scan all --delay-min 1500 --delay-max 3000
```

### 7. 自定义字典参数挖掘
使用自定义字典探测隐藏参数：
```bash
python xssr.py -u "https://target.com/view" -w "wordlists/common.txt" --scan get,post
```

### 8. 自定义 HTTP 头注入
在默认目标之外审计特定的 HTTP 头：
```bash
python xssr.py -u "https://target.com" --scan header --include-header "X-Client-IP,X-Custom-Auth"
```

### 9. 查看内置知识库
查看 payload、已知参数列表或目标头，然后退出：
```bash
python xssr.py --show-payloads
python xssr.py --show-params
python xssr.py --show-headers
```

---

## 命令行选项

```text
目标选项：
  -u, --url URL                   要扫描的目标 URL（例如 https://example.com/search?q=test）

浏览器与引擎选项：
  -b, --browser {firefox,chromium,webkit}
                                  浏览器引擎（默认：firefox）
  --headless                      以无头模式运行浏览器（可选：true, false，默认：true）
  --timeout TIMEOUT               页面导航超时（毫秒，默认：15000）
  --delay-min DELAY_MIN           最小请求延迟（毫秒，默认：3000）
  --delay-max DELAY_MAX           最大请求延迟（毫秒，默认：5000）

扫描范围选项：
  --scan MODULES                  要测试的模块：get, post, path, fragment, header 或 all
                                  （默认：get,post）
  -w, --wordlist FILE             要探测的自定义参数字典文件（例如
                                  'wordlists/common.txt'）
  -p, --param PARAMS              要测试的参数（逗号分隔，例如 'firstname,lastname'）
  -e, --exclude PARAMS            测试期间要跳过的参数（逗号分隔，例如
                                  'name,location'）
  -d, --data POSTFIELDS           自定义 POST 数据字段（例如 'username=admin&search=keyword'）
  --include-header HEADERS        添加到 header 扫描的自定义 HTTP 头（逗号分隔，例如
                                  'X-User-Agent,X-Referer'）
  --exclude-header HEADERS        header 扫描期间要跳过的 HTTP 头（逗号分隔，例如
                                  'User-Agent,Referer'）

信息选项：
  --show-payloads                 显示所有内置 XSS payload 并退出
  --show-params                   显示所有内置已知参数并退出
  --show-headers                  显示所有内置目标 HTTP 头并退出

输出与报告选项：
  -o, --output FILE               保存报告 JSON（除非给定绝对路径，否则保存到 output/ 文件夹）
  -v, --verbose                   启用详细调试输出
  -h, --help                      显示此帮助信息并退出
  --version                       显示程序版本号并退出
```

---

## 法律免责声明

> **仅限负责任的安全研究：**
> **XSSR（XSSRush）** 是严格为授权的渗透测试、安全审计、教育目的和负责任漏洞研究而开发的。
>
> 在大多数司法管辖区，未经事先双方书面同意测试目标属于违法行为。开发者不承担任何责任，对由本软件造成的任何滥用、损害或法律后果概不负责。请负责任地使用。

---

## 支持与捐赠

如果你觉得这个项目有用并希望支持其持续开发：

<p align="center">
  <a href="https://github.com/willing999/XSSRush-zh-CN" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/Star-On%20GitHub-2ea44f?style=for-the-badge&logo=github&logoColor=white" alt="Star On GitHub">
  </a>
</p>

---

## 作者与许可

* **作者：** **[willing999](https://github.com/willing999)**
* **GitHub：** [https://github.com/willing999/XSSRush-zh-CN](https://github.com/willing999/XSSRush-zh-CN)
* **许可：** 以 [MIT 许可证](LICENSE) 发布。
