# 流量分析 (Traffic Analysis)

## 原理

分析 pcap 文件中的网络流量，提取敏感信息、还原通信内容、识别攻击行为。

## 攻击链

### 1. 基础分析

```bash
# Wireshark
wireshark ./capture.pcap

# tshark
tshark -r ./capture.pcap
tshark -r ./capture.pcap -Y "http"  # 过滤 HTTP
tshark -r ./capture.pcap -Y "tcp.port == 80"
tshark -r ./capture.pcap -Y "dns"
tshark -r ./capture.pcap -Y "tls"

# 统计
tshark -r ./capture.pcap -z conv,tcp
tshark -r ./capture.pcap -z io,stat,1
tshark -r ./capture.pcap -z endpoints,ip
tshark -r ./capture.pcap -z protocol,colinfo
```

### 2. HTTP 分析

```bash
# 提取 HTTP 请求
tshark -r ./capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# 提取 HTTP 响应
tshark -r ./capture.pcap -Y "http.response" -T fields -e http.response.code

# 提取 HTTP 内容
tshark -r ./capture.pcap -Y "http" -T fields -e http.file_data

# 提取 User-Agent
tshark -r ./capture.pcap -Y "http.user_agent" -T fields -e http.user_agent

# 提取 Cookie
tshark -r ./capture.pcap -Y "http.cookie" -T fields -e http.cookie

# 导出 HTTP 对象
tshark -r ./capture.pcap --export-objects http,output/
```

### 3. DNS 分析

```bash
# DNS 查询
tshark -r ./capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name

# DNS 响应
tshark -r ./capture.pcap -Y "dns.resp.name" -T fields -e dns.resp.name -e dns.a

# DNS 隧道检测
# 查看异常长的域名
tshark -r ./capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | awk '{print length, $0}' | sort -rn | head
```

### 4. TLS/SSL 分析

```bash
# TLS 握手
tshark -r ./capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# 提取证书
tshark -r ./capture.pcap -Y "tls.handshake.certificate" -T fields -e tls.handshake.certificate

# 解密 TLS
# 需要私钥或 session key
# 编辑 -> 首选项 -> Protocols -> TLS -> (Pre)-Master-Secret log filename
```

### 5. 文件提取

```bash
# Wireshark
# 文件 -> 导出对象 -> HTTP

# tshark
tshark -r ./capture.pcap --export-objects http,output/
tshark -r ./capture.pcap --export-objects smb,output/
tshark -r ./capture.pcap --export-objects ftp,output/

# tcpflow
tcpflow -r ./capture.pcap

# foremost
foremost -i ./capture.pcap -o output/
```

### 6. 凭证提取

```bash
# HTTP Basic Auth
tshark -r ./capture.pcap -Y "http.authorization" -T fields -e http.authorization

# FTP
tshark -r ./capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.arg

# SMTP
tshark -r ./capture.pcap -Y "smtp" -T fields -e smtp.req.username -e smtp.req.password

# Telnet
tshark -r ./capture.pcap -Y "telnet" -T fields -e telnet.data
```

### 7. 攻击识别

```bash
# SQL 注入
tshark -r ./capture.pcap -Y "http.request.uri contains \"union\" || http.request.uri contains \"select\""

# XSS
tshark -r ./capture.pcap -Y "http.request.uri contains \"script\" || http.request.uri contains \"onerror\""

# 目录扫描
tshark -r ./capture.pcap -Y "http.response.code == 404" | wc -l

# 暴力破解
tshark -r ./capture.pcap -Y "http.response.code == 401" | wc -l

# 端口扫描
tshark -r ./capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.src | sort | uniq -c
```

### 8. 协议分析

#### TCP 流

```bash
# 跟踪 TCP 流
tshark -r ./capture.pcap -z follow,tcp,ascii,0

# Wireshark
# 右键 -> Follow -> TCP Stream
```

#### UDP 流

```bash
# 跟踪 UDP 流
tshark -r ./capture.pcap -z follow,udp,ascii,0
```

#### WebSocket

```bash
# WebSocket 流量
tshark -r ./capture.pcap -Y "websocket"
```

### 9. 无线流量

```bash
# 802.11
tshark -r ./capture.pcap -Y "wlan"

# 提取 SSID
tshark -r ./capture.pcap -Y "wlan.fc.type_subtype == 8" -T fields -e wlan.ssid

# 提取握手包
tshark -r ./capture.pcap -Y "eapol"

# 破解 WPA
# aircrack-ng
aircrack-ng -w wordlist.txt ./capture.pcap
```

### 10. 蓝牙流量

```bash
# 蓝牙
tshark -r ./capture.pcap -Y "bthci_acl"
```

## 2024-2026 新技术点

### 1. HTTP/3 (QUIC) 分析

```bash
# HTTP/3 基于 QUIC
tshark -r ./capture.pcap -Y "quic"
tshark -r ./capture.pcap -Y "http3"

# 新的分析方法
```

### 2. gRPC 分析

```bash
# gRPC 基于 HTTP/2
tshark -r ./capture.pcap -Y "grpc"
tshark -r ./capture.pcap -Y "http2"
```

### 3. WebSocket 分析

```bash
# WebSocket
tshark -r ./capture.pcap -Y "websocket"
```

### 4. GraphQL 流量

```bash
# GraphQL
# 在 HTTP 中查找 GraphQL 查询
tshark -r ./capture.pcap -Y "http.request.uri contains \"graphql\""
```

### 5. 容器流量

```bash
# Docker 网络
# Kubernetes 网络
# Service Mesh (Istio, Linkerd)
```

### 6. 云流量

```bash
# AWS API
# GCP API
# Azure API
# 云服务流量分析
```

### 7. IoT 流量

```bash
# MQTT
# CoAP
# AMQP
# IoT 协议分析
```

### 8. 5G 流量

```bash
# 5G 协议
# 新的协议分析
```

### 9. 量子流量

```bash
# 量子密钥分发
# 量子信道
# 新的分析方法
```

### 10. AI 辅助分析

```python
# ML 辅助
# 自动识别攻击
# 异常检测
# 模式识别
```

## 工具推荐

- **Wireshark** — GUI 流量分析
- **tshark** — 命令行流量分析
- **tcpflow** — TCP 流提取
- **foremost** — 文件恢复
- **NetworkMiner** — 文件提取
- **Brim** — 大流量分析
- **Zeek (Bro)** — 网络安全监控
- **Suricata** — IDS/IPS
- **aircrack-ng** — 无线破解

## 参考链接

- [Wireshark](https://www.wireshark.org/)
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [ctf-wiki traffic](https://ctf-wiki.org/misc/traffic/)
- [PCAP Analysis](https://github.com/ctfs/write-ups-2014)
