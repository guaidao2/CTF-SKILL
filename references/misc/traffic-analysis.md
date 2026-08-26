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

### 1. HTTP/3 (QUIC) 流量分析

```bash
# QUIC 协议分析 (tshark 需要 3.6+)
# QUIC 使用 UDP 443 端口

# 过滤 QUIC 流量
tshark -r ./capture.pcap -Y "quic" 2>/dev/null || \
tshark -r ./capture.pcap -Y "udp.port == 443"

# 提取 QUIC 连接信息
tshark -r ./capture.pcap -Y "quic" -T fields \
  -e ip.src -e ip.dst -e udp.srcport -e udp.dstport \
  -e quic.connection.number -e quic.connection.close_reason

# QUIC 版本检测
tshark -r ./capture.pcap -Y "quic" -T fields \
  -e quic.version 2>/dev/null

# 解析 QUIC 加密流量（需要 SSLKEYLOGFILE）
# 1. 从浏览器导出 SSL keys
# 2. 配置 tshark 解密
tshark -r ./capture.pcap -o "tls.keylog_file:sslkeys.log" \
  -Y "quic" -T fields -e http2.headers.method -e http2.headers.path

# 使用 Wireshark GUI
# Edit → Preferences → Protocols → QUIC → (Pre)-Master-Secret log filename
```

### 2. gRPC/HTTP2 流量深度分析

```bash
# gRPC 基于 HTTP/2，分析 HTTP/2 帧
tshark -r ./capture.pcap -Y "http2" -T fields \
  -e http2.headers.method -e http2.headers.path \
  -e http2.headers.authority -e http2.headers.status

# 提取 gRPC 方法调用
tshark -r ./capture.pcap -Y "grpc" -T fields \
  -e grpc.method -e grpc.service

# WebSocket 流量分析
tshark -r ./capture.pcap -Y "websocket" -T fields \
  -e websocket.opcode -e websocket.fin -e websocket.payload

# 跟踪 WebSocket 流
tshark -r ./capture.pcap -Y "websocket" -z follow,websocket,ascii,0

# 提取 WebSocket 消息内容
tshark -r ./capture.pcap -Y "websocket" -T fields \
  -e websocket.payload 2>/dev/null | \
  python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if line:
        try:
            data = bytes.fromhex(line.replace(':', ''))
            print(data.decode('utf-8', errors='replace'))
        except:
            print(line)
"
```

### 3. IoT 协议分析 (MQTT/CoAP)

```bash
# MQTT 流量分析（端口 1883/8883）
tshark -r ./capture.pcap -Y "mqtt" -T fields \
  -e mqtt.topic -e mqtt.msg -e mqtt.clientid -e mqtt.username

# MQTT 订阅/发布消息提取
tshark -r ./capture.pcap -Y "mqtt" -T fields \
  -e mqtt.topic -e mqtt.qos -e mqtt.msg | \
  sort | uniq -c | sort -rn

# CoAP 流量分析（端口 5683/5684）
tshark -r ./capture.pcap -Y "coap" -T fields \
  -e coap.code -e coap.uri_path -e coap.content_format

# MQTT 隧道中的 DNS 查询
tshark -r ./capture.pcap -Y "mqtt.topic contains \"dns\"" -T fields \
  -e mqtt.topic -e mqtt.msg

# 解码 MQTT 有效载荷
python3 << 'PYEOF'
import struct

def decode_mqtt_publish(payload):
    """解码 MQTT PUBLISH 消息"""
    # 变长头部
    pos = 0
    topic_len = struct.unpack('>H', payload[pos:pos+2])[0]
    pos += 2
    topic = payload[pos:pos+topic_len].decode()
    pos += topic_len
    
    # 消息 ID (QoS > 0 时存在)
    if len(payload) > pos + 2:
        msg_id = struct.unpack('>H', payload[pos:pos+2])[0]
        pos += 2
    
    # 有效载荷
    message = payload[pos:]
    try:
        return topic, message.decode()
    except:
        return topic, message.hex()

# 使用示例
# payload = bytes.fromhex("000b6d792f746f7069630048656c6c6f")
# topic, msg = decode_mqtt_publish(payload)
# print(f"Topic: {topic}, Message: {msg}")
PYEOF
```

### 4. DNS 隧道检测与分析

```bash
# DNS 隧道检测自动化脚本
python3 << 'PYEOF'
import subprocess
import re
from collections import Counter

def analyze_dns_tunnel(pcap_file):
    """分析 DNS 隧道"""
    
    # 提取 DNS 查询
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'dns.qry.name',
         '-T', 'fields', '-e', 'dns.qry.name'],
        capture_output=True, text=True
    )
    
    queries = result.stdout.strip().split('\n')
    print(f"[*] 总 DNS 查询: {len(queries)}")
    
    # 分析查询特征
    long_queries = [q for q in queries if len(q) > 50]
    print(f"[*] 长查询 (>50 chars): {len(long_queries)}")
    
    # 检测 Base64 编码的子域名
    b64_pattern = re.compile(r'^[A-Za-z0-9+/=]{20,}\.')
    b64_queries = [q for q in queries if b64_pattern.match(q)]
    if b64_queries:
        print(f"[!] 可能的 Base64 DNS 隧道: {len(b64_queries)}")
        for q in b64_queries[:5]:
            print(f"    {q[:80]}...")
    
    # 检测 hex 编码
    hex_pattern = re.compile(r'^[0-9a-f]{40,}\.')
    hex_queries = [q for q in queries if hex_pattern.match(q)]
    if hex_queries:
        print(f"[!] 可能的 Hex DNS 隧道: {len(hex_queries)}")
    
    # DNS 请求频率分析
    domains = [q.split('.')[-2] if '.' in q else q for q in queries]
    domain_freq = Counter(domains).most_common(10)
    print("\n[*] 高频域名:")
    for domain, count in domain_freq:
        print(f"    {domain}: {count}")
    
    # TXT 记录分析（常用于 DNS 隧道返回数据）
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'dns.txt',
         '-T', 'fields', '-e', 'dns.txt'],
        capture_output=True, text=True
    )
    txt_records = result.stdout.strip().split('\n')
    if txt_records and txt_records[0]:
        print(f"\n[!] DNS TXT 记录: {len(txt_records)}")
        # 尝试 Base64 解码
        import base64
        for txt in txt_records[:5]:
            try:
                decoded = base64.b64decode(txt + '==')
                print(f"    Base64 解码: {decoded[:100]}")
            except:
                pass

analyze_dns_tunnel("capture.pcap")
PYEOF

# 常见 DNS 隧道工具特征
# - iodine: 使用 NULL/TXT/CNAME 记录
# - dns2tcp: 使用 KEY/TXT 记录
# - dnscat2: 使用 CNAME/TXT/MX 记录
# - Cobalt Strike DNS beacon: 特定域名模式
```

### 5. TLS 证书透明度分析

```bash
# 提取 TLS 证书信息
tshark -r ./capture.pcap -Y "tls.handshake.type == 11" -T fields \
  -e x509sat.utf8String -e x509ce.dNSName

# 提取 Server Name Indication (SNI)
tshark -r ./capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn

# 提取 TLS JA3 指纹
tshark -r ./capture.pcap -Y "tls.handshake.type == 1" -T fields \
  -e tls.handshake.ja3_full 2>/dev/null

# 证书固定绕过检测
python3 << 'PYEOF'
import subprocess
import json

def analyze_tls(pcap_file):
    """分析 TLS 流量"""
    
    # 提取 TLS SNI
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'tls.handshake.extensions_server_name',
         '-T', 'fields', '-e', 'ip.dst', '-e', 'tls.handshake.extensions_server_name'],
        capture_output=True, text=True
    )
    
    sni_map = {}
    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) == 2:
            ip, sni = parts
            sni_map.setdefault(ip, set()).add(sni)
    
    # 检测异常
    for ip, snis in sni_map.items():
        if len(snis) > 5:
            print(f"[!] {ip} 有 {len(snis)} 个不同 SNI: {snis}")
    
    return sni_map

analyze_tls("capture.pcap")
PYEOF
```

### 6. 攻击流量特征识别

```bash
# 自动化攻击流量检测
python3 << 'PYEOF'
import subprocess
import re

def detect_attacks(pcap_file):
    """自动检测网络攻击"""
    
    attacks = []
    
    # SQL 注入检测
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y',
         'http.request.uri contains "union" || http.request.uri contains "select" || '
         'http.request.uri contains "or%201" || http.request.uri contains "="',
         '-T', 'fields', '-e', 'http.request.uri', '-e', 'ip.src'],
        capture_output=True, text=True
    )
    sqli = result.stdout.strip().split('\n')
    if sqli and sqli[0]:
        attacks.append(('SQL 注入', len(sqli)))
    
    # XSS 检测
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y',
         'http.request.uri contains "script" || http.request.uri contains "alert" || '
         'http.request.uri contains "onerror" || http.request.uri contains "javascript"',
         '-T', 'fields', '-e', 'http.request.uri'],
        capture_output=True, text=True
    )
    xss = result.stdout.strip().split('\n')
    if xss and xss[0]:
        attacks.append(('XSS', len(xss)))
    
    # 目录遍历
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y',
         'http.request.uri contains "../" || http.request.uri contains "%2e%2e"',
         '-T', 'fields', '-e', 'http.request.uri'],
        capture_output=True, text=True
    )
    traversal = result.stdout.strip().split('\n')
    if traversal and traversal[0]:
        attacks.append(('目录遍历', len(traversal)))
    
    # 暴力破解
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y',
         'http.request.method == "POST" && (http.request.uri contains "login" || '
         'http.request.uri contains "auth")',
         '-T', 'fields', '-e', 'ip.src', '-e', 'http.response.code'],
        capture_output=True, text=True
    )
    
    # 端口扫描检测
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y',
         'tcp.flags.syn == 1 && tcp.flags.ack == 0',
         '-T', 'fields', '-e', 'ip.src'],
        capture_output=True, text=True
    )
    
    # 统计每个源 IP 的 SYN 包数
    syn_sources = result.stdout.strip().split('\n')
    from collections import Counter
    syn_count = Counter(syn_sources)
    scanner_ips = {ip: count for ip, count in syn_count.items() if count > 100}
    if scanner_ips:
        attacks.append(('端口扫描', f"{len(scanner_ips)} 个 IP"))
        for ip, count in scanner_ips.items():
            print(f"    扫描器: {ip} ({count} SYN)")
    
    # 输出结果
    print("[*] 攻击检测结果:")
    for attack_type, count in attacks:
        print(f"    {attack_type}: {count} 次")
    
    return attacks

detect_attacks("capture.pcap")
PYEOF

# Suricata 自动化 IDS
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l output/
cat output/eve.json | jq 'select(.event_type=="alert") | {src: .src_ip, dest: .dest_ip, alert: .alert.signature}'
```

### 7. 恶意流量沙箱分析

```bash
# 恶意软件流量分析工作流
python3 << 'PYEOF'
import subprocess
import os
import json

def malware_traffic_analysis(pcap_file):
    """恶意软件流量分析"""
    
    output_dir = f"malware_analysis_{os.path.basename(pcap_file)}"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. 基本统计
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-z', 'conv,ip', '-q'],
        capture_output=True, text=True
    )
    with open(f"{output_dir}/conversations.txt", 'w') as f:
        f.write(result.stdout)
    
    # 2. 提取 HTTP 请求
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'http.request',
         '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst',
         '-e', 'http.request.method', '-e', 'http.request.uri',
         '-e', 'http.host'],
        capture_output=True, text=True
    )
    with open(f"{output_dir}/http_requests.txt", 'w') as f:
        f.write(result.stdout)
    
    # 3. 提取 DNS 查询（C2 域名检测）
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-Y', 'dns.qry.name',
         '-T', 'fields', '-e', 'dns.qry.name'],
        capture_output=True, text=True
    )
    
    # 检测 DGA 域名
    domains = result.stdout.strip().split('\n')
    dga_candidates = []
    for domain in domains:
        if '.' in domain:
            main_domain = domain.split('.')[-2]
            # DGA 特征：高熵值
            if len(main_domain) > 15 and main_domain.isalpha():
                entropy = len(set(main_domain)) / len(main_domain)
                if entropy > 0.8:
                    dga_candidates.append(domain)
    
    if dga_candidates:
        print(f"[!] 可能的 DGA 域名: {len(dga_candidates)}")
        for d in dga_candidates[:10]:
            print(f"    {d}")
    
    # 4. 导出文件
    subprocess.run([
        'tshark', '-r', pcap_file,
        '--export-objects', f'http,{output_dir}/exported/'
    ])
    
    exported = os.listdir(f"{output_dir}/exported/") if os.path.exists(f"{output_dir}/exported/") else []
    print(f"[*] 导出文件: {len(exported)}")
    
    # 5. 检查异常协议
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-z', 'proto,colinfo,frame.protocols'],
        capture_output=True, text=True
    )
    
    return output_dir

malware_traffic_analysis("capture.pcap")
PYEOF
```

### 8. 大规模 PCAP 分析

```bash
# 大文件 PCAP 分析优化
# 1. 使用 editcap 过滤
editcap -r -F tcp capture.pcap tcp_only.pcap  # 只保留 TCP
editcap -r -F udp capture.pcap udp_only.pcap  # 只保留 UDP
editcap -A '2024-01-01 00:00:00' -B '2024-01-02 00:00:00' \
  capture.pcap time_filtered.pcap  # 按时间过滤

# 2. 使用 mergecap 合并多个 PCAP
mergecap -w combined.pcap *.pcap

# 3. tshark 流量统计
tshark -r capture.pcap -z io,stat,60  # 每分钟统计
tshark -r capture.pcap -z conv,tcp    # TCP 会话
tshark -r capture.pcap -z endpoint,ip # IP 端点

# 4. 使用 Zeek 进行高级分析
zeek -r capture.pcap
# 生成的文件：
# conn.log — 连接日志
# dns.log — DNS 日志
# http.log — HTTP 日志
# ssl.log — TLS 日志
# files.log — 文件日志

# 分析 Zeek 日志
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | sort | uniq -c | sort -rn
```

### 9. Wireshark 显示过滤器速查

```bash
# 常用过滤器
# HTTP
http.request.method == "POST"
http.response.code >= 400
http.host contains "target.com"

# DNS
dns.qry.name contains "suspicious.com"
dns.qry.type == 16  # TXT 记录

# TLS
tls.handshake.extensions_server_name == "target.com"
tls.handshake.type == 1  # Client Hello

# TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN 扫描
tcp.analysis.retransmission  # 重传
tcp.analysis.zero_window    # 零窗口

# IO Graph
# Statistics → I/O Graphs
# 添加表达式：http && tcp.port == 80
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
