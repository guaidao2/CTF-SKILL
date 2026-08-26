# Web 方向总览

Web 是 CTF 中题量最大、技术点最广的方向。本目录按漏洞类型拆分，每个文件自包含完整攻击链。

## 子路由表（症状 → 文件）

| 题目症状 | 漏洞类型 | 文件 |
|---------|---------|------|
| 参数拼进 SQL 查询、有数据库报错、`?id=1` 类 URL | SQL 注入 | `sqli.md` |
| 用户输入回显到 HTML、有 `<script>` 过滤、CSP 头 | XSS | `xss.md` |
| 模板渲染用户输入（Jinja2/Twig/Freemarker/Velocity） | 模板注入 SSTI | `ssti.md` |
| 后端会请求 URL、有 URL 参数、`url=`、`fetch` | SSRF | `ssrf.md` |
| 接收 XML、`Content-Type: application/xml` | XXE | `xxe.md` |
| 表单提交、状态变更操作、`SameSite` Cookie | CSRF | `csrf.md` |
| 文件上传功能、`multipart/form-data` | 文件上传 | `file-upload.md` |
| `include`/`require`、`?file=`、`?page=` | 文件包含 | `file-inclusion.md` |
| `unserialize`/`ObjectInputStream`/`pickle.loads` | 反序列化 | `deserialization.md` |
| `system`/`exec`/`popen`/`Runtime.exec`、命令拼接 | 命令注入 | `command-injection.md` |
| Node.js、`merge`/`extend`/`defaultsDeep`、`__proto__` | 原型链污染 | `prototype-pollution.md` |
| JWT Token、`Authorization: Bearer`、`alg` 字段 | JWT 攻击 | `jwt-attacks.md` |
| 前后端架构、CDN、反向代理、HTTP/2 | 请求走私 | `request-smuggling.md` |
| `/graphql` 端点、`query` 参数、Introspection | GraphQL 攻击 | `graphql-attacks.md` |
| 并发请求、余额/库存/优惠券、`FOR UPDATE` | 竞态条件 | `race-conditions.md` |
| 越权、密码找回逻辑、支付逻辑、验证码 | 逻辑漏洞 | `logic-vulnerabilities.md` |

## Web 通用解题流程

### 1. 信息收集

```bash
# 端口与服务
nmap -sV -sC -p- target.com
whatweb target.com

# 目录扫描
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js -t 50
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,401,403

# 子域名
subfinder -d target.com -all -recursive
amass enum -d target.com

# 指纹识别
wappalyzer-cli --url https://target.com
curl -sI https://target.com  # 看 Server、X-Powered-By、Set-Cookie
```

### 2. 漏洞探测

- **手动测试**：每个参数都试 `'`、`"`、`<`、`{{7*7}}`、`${7*7}`、`%0a`、`..%2f..%2f`、`file:///etc/passwd`
- **自动化扫描**：`sqlmap -u URL --batch --random-agent`、`nuclei -u URL -t cves/`
- **源码审计**：如果给了源码，重点搜 `eval`、`system`、`exec`、`unserialize`、`include`、`render`、`template`、`merge`

### 3. 漏洞利用

定位到具体漏洞后，读对应文件获取 payload 模板和绕过技巧。

## Web 通用工具清单

| 工具 | 用途 |
|------|------|
| Burp Suite | 抓包、改包、Repeater、Intruder、插件（Autorize、Logger++、Hackvertizer） |
| sqlmap | SQL 注入自动化 |
| ffuf / dirsearch | 目录/参数 fuzz |
| nuclei | CVE 模板扫描 |
| XSStrike / Dalfox | XSS 自动化 |
| tplmap | SSTI 自动化 |
| jwt_tool | JWT 攻击 |
| gobuster | 目录/子域名爆破 |
| httpx | 批量 HTTP 探测 |
| CyberChef | 编码解码瑞士军刀（Web 版） |

## Web 框架指纹速查

| 指纹信号 | 框架 |
|---------|------|
| `Set-Cookie: PHPSESSID` | PHP |
| `Set-Cookie: JSESSIONID` | Java Servlet |
| `Set-Cookie: ASP.NET_SessionId` | .NET |
| `Set-Cookie: connect.sid` | Express (Node.js) |
| `Set-Cookie: session` + Flask 签名 | Flask |
| `Set-Cookie: csrftoken` | Django |
| `Set-Cookie: rack.session` | Ruby on Rails |
| `Set-Cookie: laravel_session` | Laravel |
| `X-Powered-By: Express` | Express |
| `Server: nginx` + 静态 | Nginx |
| `Server: Apache` | Apache |
| `X-AspNet-Version` | .NET |
| Cookie 含 `csrf_token` + Python 风格 URL | Django/Flask |

## 2024-2026 Web 新趋势

- **HTTP/2 与 HTTP/3 请求走私**：传统 CL.TE/TE.CL 在 HTTP/2 下有新变种
- **WebAssembly (WASM) 漏洞**：越来越多前端用 WASM，需要逆向 WASM 模块
- **GraphQL 批量查询攻击**：通过 batch query 绕过限流
- **JWT 算法混淆**：PS256/ES256 算法混淆攻击
- **原型链污染新 gadget**：不断有新的 prototype pollution gadget 被发现
- **Server-Side Prototype Pollution**：服务端原型链污染
- **Log4Shell 衍生**：JNDI 注入仍是 Java 应用常见入口
- **Spring4Shell (CVE-2022-22965)**：Spring 框架 RCE
- **PHP 8.x 新特性利用**：`#[Attribute]`、Fiber、命名参数带来的新攻击面
- **Next.js / React Server Components**：SSR 框架的 SSRF/XSS 新场景
- **OAuth/OIDC 配置错误**：redirect_uri 验证不严、PKCE 缺失
- **WebSocket 攻击**：CSWSH、WebSocket 注入
- **WebRTC 信息泄露**：内网 IP 泄露
- **Service Worker 持久化 XSS**：通过 SW 实现持久化攻击

具体技术细节见各漏洞文件末尾的"2024-2026 新技术点"小节。
