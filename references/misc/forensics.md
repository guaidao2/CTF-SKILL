# 数字取证 (Forensics)

## 原理

分析内存 dump、磁盘镜像、日志等，恢复删除文件、提取证据、还原事件。

## 攻击链

### 1. 内存取证

#### Volatility 3

```bash
# 安装
pip install volatility3

# 基础命令
vol -f memory.raw windows.info
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.netscan
vol -f memory.raw windows.filescan
vol -f memory.raw windows.dumpfiles --virtaddr 0x1234
vol -f memory.raw windows.hivelist
vol -f memory.raw windows.hashdump
vol -f memory.raw windows.malfind
vol -f memory.raw windows.dlllist
vol -f memory.raw windows.handles --pid 1234
vol -f memory.raw windows.envars
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

#### Volatility 2

```bash
# 识别 profile
vol.py -f memory.raw imageinfo

# 进程
vol.py -f memory.raw --profile=Win7SP1x64 pslist
vol.py -f memory.raw --profile=Win7SP1x64 pstree
vol.py -f memory.raw --profile=Win7SP1x64 cmdline

# 网络
vol.py -f memory.raw --profile=Win7SP1x64 netscan
vol.py -f memory.raw --profile=Win7SP1x64 connections
vol.py -f memory.raw --profile=Win7SP1x64 sockets

# 文件
vol.py -f memory.raw --profile=Win7SP1x64 filescan
vol.py -f memory.raw --profile=Win7SP1x64 dumpfiles -D output/ --pid 1234

# 注册表
vol.py -f memory.raw --profile=Win7SP1x64 hivelist
vol.py -f memory.raw --profile=Win7SP1x64 hashdump
vol.py -f memory.raw --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"

# 恶意代码
vol.py -f memory.raw --profile=Win7SP1x64 malfind
vol.py -f memory.raw --profile=Win7SP1x64 yarascan -y rules.yar
```

### 2. 磁盘取证

#### Autopsy

```bash
# GUI 工具
autopsy &
# 创建 case
# 添加数据源
# 分析
```

#### FTK Imager

```bash
# Windows 工具
# 挂载磁盘镜像
# 提取文件
```

#### The Sleuth Kit (TSK)

```bash
# 镜像信息
mmls ./disk.img
fsstat ./disk.img

# 文件列表
fls ./disk.img
fls -r ./disk.img  # 递归

# 文件提取
icat ./disk.img 1234 > file.txt

# 删除文件恢复
fls -d ./disk.img  # 删除文件
icat -r ./disk.img 1234 > recovered.txt

# 时间线
fls -r -m / ./disk.img > body.txt
mactime -b body.txt > timeline.txt
```

### 3. 日志分析

#### Linux 日志

```bash
# /var/log/auth.log
# /var/log/syslog
# /var/log/messages
# /var/log/secure
# /var/log/apache2/access.log
# /var/log/nginx/access.log

# 分析
grep "Failed password" /var/log/auth.log
grep "Accepted password" /var/log/auth.log
grep "session opened" /var/log/auth.log

# 提取 IP
grep "Failed password" /var/log/auth.log | grep -oP "from \K[0-9.]+"
```

#### Windows 事件日志

```bash
# 安全日志
# System 事件 ID 4624（登录成功）
# System 事件 ID 4625（登录失败）
# System 事件 ID 4688（进程创建）

# 工具
# Event Viewer
# EvtxECmd
# python-evtx
python-evtx dump ./Security.evtx > security.txt
```

#### Web 日志

```bash
# Apache/Nginx
grep "POST" /var/log/apache2/access.log
grep "404" /var/log/apache2/access.log
grep "500" /var/log/apache2/access.log

# 提取 URL
cat /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn

# 提取 IP
cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

### 4. 注册表分析

```bash
# Windows 注册表
# SAM - 用户密码
# SYSTEM - 系统配置
# SOFTWARE - 软件配置
# SECURITY - 安全策略

# 工具
# regripper
regripper -r ./SAM -f sam
regripper -r ./SYSTEM -f system
regripper -r ./SOFTWARE -f software

# impacket
secretsdump.py -sam ./SAM -system ./SYSTEM local
```

### 5. 文件恢复

```bash
# TestDisk
testdisk ./disk.img
# 恢复删除分区

# PhotoRec
photorec ./disk.img
# 恢复删除文件

# Foremost
foremost -t all -i ./disk.img -o output/
foremost -t pdf -i ./disk.img -o output/

# Scalpel
scalpel ./scalpel.conf -c ./disk.img -o output/
```

### 6. 时间线分析

```bash
# 创建时间线
fls -r -m / ./disk.img > body.txt
mactime -b body.txt > timeline.txt

# 分析时间线
# 查找异常时间
# 查找大量活动
# 查找特定时间范围
```

## 2024-2026 新技术点

### 1. 云取证自动化脚本

```bash
# AWS CloudTrail 日志分析
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time $(date -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date +%Y-%m-%dT%H:%M:%SZ) | \
  jq '.Events[] | {Time:.EventTime, User:.Username, Source:.EventSource, Detail:.CloudTrailEvent}'

# 导出全部 CloudTrail 日志
aws cloudtrail lookup-events --max-results 1000 | \
  jq -r '.Events[] | "\(.EventTime) \(.Username) \(.EventName) \(.EventSource)"' | \
  sort | uniq -c | sort -rn > cloudtrail_summary.txt

# VPC Flow Logs 分析
aws ec2 describe-flow-logs --query 'FlowLogs[*].{ID:FlowLogId,Name:LogGroupName}'
aws logs get-log-events \
  --log-group-name <log-group> \
  --log-stream-name <log-stream> | \
  jq -r '.events[].message' | \
  awk '{print $4, $5, $6, $14}' | \
  sort | uniq -c | sort -rn

# GCP Audit Log 分析
gcloud logging read 'resource.type=gce_instance AND protoPayload.methodName="compute.instances.start"' \
  --limit=100 --format=json

# Azure Activity Log
az monitor activity-log list --query "[].{Event:eventTimestamp,Resource:resourceGroupName,Action:operationName.value}"
```

### 2. 容器取证自动化

```bash
# Docker 容器取证
python3 << 'PYEOF'
import subprocess
import json
import os

class ContainerForensics:
    """容器取证自动化"""
    
    @staticmethod
    def acquire_container(container_id):
        """获取容器快照"""
        # 容器配置
        config = subprocess.run(
            ['docker', 'inspect', container_id],
            capture_output=True, text=True
        )
        with open(f'forensics/{container_id}_config.json', 'w') as f:
            f.write(config.stdout)
        
        # 容器文件系统差异
        diff = subprocess.run(
            ['docker', 'diff', container_id],
            capture_output=True, text=True
        )
        with open(f'forensics/{container_id}_diff.txt', 'w') as f:
            f.write(diff.stdout)
        
        # 容器日志
        logs = subprocess.run(
            ['docker', 'logs', '--tail=10000', container_id],
            capture_output=True, text=True
        )
        with open(f'forensics/{container_id}_logs.txt', 'w') as f:
            f.write(logs.stdout)
            f.write(logs.stderr)
        
        # 导出容器文件系统
        subprocess.run([
            'docker', 'export', container_id, '-o',
            f'forensics/{container_id}_fs.tar'
        ])
        
        # 提取进程列表
        ps = subprocess.run(
            ['docker', 'top', container_id, '-eo', 'pid,ppid,user,%cpu,%mem,comm'],
            capture_output=True, text=True
        )
        with open(f'forensics/{container_id}_ps.txt', 'w') as f:
            f.write(ps.stdout)
    
    @staticmethod
    def analyze_docker_images(image_name):
        """分析 Docker 镜像层"""
        history = subprocess.run(
            ['docker', 'history', '--no-trunc', image_name],
            capture_output=True, text=True
        )
        with open(f'forensics/{image_name}_layers.txt', 'w') as f:
            f.write(history.stdout)
        
        # 提取可能的敏感信息
        for line in history.stdout.split('\n'):
            lower = line.lower()
            if any(kw in lower for kw in ['password', 'secret', 'key', 'token', 'env']):
                print(f"[!] 可疑层: {line[:100]}")

# 使用示例
forensics = ContainerForensics()
forensics.acquire_container("suspicious_container")
forensics.analyze_docker_images("suspicious_image:latest")
PYEOF

# Kubernetes Pod 取证
kubectl debug -it <pod> --image=busybox --target=<container> -- /bin/sh
# 在调试容器中检查原始容器的文件系统
ls /proc/1/root/tmp/
cat /proc/1/root/etc/shadow
```

### 3. 内存取证 Volatility 3 自动化

```bash
# Volatility 3 批量分析脚本
python3 << 'PYEOF'
import subprocess
import json
import os

class MemoryForensics:
    """内存取证自动化"""
    
    def __init__(self, memory_file):
        self.memory_file = memory_file
        self.output_dir = f"memforensics_{os.path.basename(memory_file)}"
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_plugin(self, plugin, extra_args=""):
        """运行 Volatility 插件"""
        cmd = f"vol -f {self.memory_file} {plugin} {extra_args}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
        outfile = f"{self.output_dir}/{plugin.replace('.', '_')}.txt"
        with open(outfile, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n--- STDERR ---\n{result.stderr}")
        return result.stdout
    
    def full_analysis(self):
        """完整内存分析"""
        plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
            "windows.filescan",
            "windows.hivelist",
            "windows.hashdump",
            "windows.malfind",
            "windows.dlllist",
            "windows.envars",
            "windows.handles",
            "windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
        ]
        
        for plugin in plugins:
            print(f"[*] 运行: {plugin}")
            try:
                output = self.run_plugin(plugin)
                lines = output.strip().split('\n')
                print(f"    结果: {len(lines)} 行")
            except Exception as e:
                print(f"[-] 失败: {e}")
    
    def extract_malware(self):
        """提取可疑进程"""
        # 使用 malfind 检测
        output = self.run_plugin("windows.malfind")
        pids = []
        for line in output.split('\n')[2:]:  # 跳过表头
            parts = line.split()
            if parts:
                pids.append(parts[1])
        
        for pid in pids:
            print(f"[*] 转储 PID {pid}")
            self.run_plugin(
                "windows.dumpfiles",
                f"--pid {pid} --dump-dir {self.output_dir}/dumped"
            )

# 使用
forensics = MemoryForensics("memory.raw")
forensics.full_analysis()
forensics.extract_malware()
PYEOF

# 使用 Volatility 3 API 编程
python3 << 'PYEOF'
from volatility3.framework import contexts, interfaces
from volatility3.framework.layers.physical import BufferedTranslatableLayer
import volatility3.plugins.windows as windows_plugins

# 高级分析：使用 yara 规则扫描内存
vol -f memory.raw windows.vadyarascan --yara-file malware.yar
vol -f memory.raw windows.malfind --dump
vol -f memory.raw windows.pslist --pid 1234 --dump
PYEOF
```

### 4. 磁盘取证自动化恢复

```bash
# 自动化磁盘取证恢复脚本
python3 << 'PYEOF'
import subprocess
import os
import struct

class DiskForensics:
    """磁盘取证自动化"""
    
    def __init__(self, image_path):
        self.image = image_path
        self.output = f"diskforensics_{os.path.basename(image_path)}"
        os.makedirs(self.output, exist_ok=True)
    
    def partition_info(self):
        """获取分区信息"""
        result = subprocess.run(
            ['mmls', self.image],
            capture_output=True, text=True
        )
        print(result.stdout)
        return result.stdout
    
    def file_listing(self, recursive=True):
        """列出所有文件"""
        flag = '-r' if recursive else ''
        result = subprocess.run(
            f'fls {flag} {self.image}'.split(),
            capture_output=True, text=True
        )
        # 解析 inode 和文件名
        files = []
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    inode = parts[0]
                    name = ' '.join(parts[2:]) if len(parts) > 2 else parts[1]
                    files.append((inode, name))
        
        with open(f"{self.output}/file_listing.txt", 'w') as f:
            for inode, name in files:
                f.write(f"{inode} {name}\n")
        
        return files
    
    def extract_deleted_files(self):
        """恢复已删除文件"""
        # 列出已删除文件
        result = subprocess.run(
            f'fls -d {self.image}'.split(),
            capture_output=True, text=True
        )
        
        for line in result.stdout.split('\n'):
            if '*  *' in line or 'd/d' in line:
                parts = line.split()
                inode = parts[1]
                # 提取文件
                output_file = f"{self.output}/recovered_{inode}"
                subprocess.run(
                    f'icat {self.image} {inode}'.split(),
                    stdout=open(output_file, 'wb'),
                    stderr=subprocess.DEVNULL
                )
                size = os.path.getsize(output_file)
                if size > 0:
                    print(f"[+] 恢复: inode={inode} size={size}")
    
    def create_timeline(self):
        """创建时间线"""
        # 生成 body 格式时间线
        subprocess.run(
            f'fls -r -m / {self.image}'.split(),
            stdout=open(f"{self.output}/body.txt", 'w'),
            stderr=subprocess.DEVNULL
        )
        
        # 使用 mactime 生成时间线
        result = subprocess.run(
            f'mactime -b {self.output}/body.txt -d'.split(),
            capture_output=True, text=True
        )
        with open(f"{self.output}/timeline.csv", 'w') as f:
            f.write(result.stdout)
    
    def recover_by_type(self, file_type):
        """按文件类型恢复"""
        subprocess.run([
            'foremost', '-t', file_type,
            '-i', self.image,
            '-o', f"{self.output}/foremost_{file_type}/"
        ])
    
    def string_search(self, pattern):
        """字符串搜索"""
        result = subprocess.run(
            f'strings {self.image}'.split(),
            capture_output=True, text=True
        )
        matches = [line for line in result.stdout.split('\n') if pattern in line]
        with open(f"{self.output}/string_search.txt", 'w') as f:
            for match in matches:
                f.write(f"{match}\n")
        print(f"[*] 找到 {len(matches)} 个匹配")

# 使用
forensics = DiskForensics("disk.img")
forensics.partition_info()
forensics.extract_deleted_files()
forensics.recover_by_type("pdf")
forensics.recover_by_type("zip")
forensics.create_timeline()
PYEOF
```

### 5. 日志分析自动化

```bash
# Windows 事件日志批量分析
python3 << 'PYEOF'
import subprocess
import json
import csv
from datetime import datetime

class LogAnalysis:
    """日志分析自动化"""
    
    @staticmethod
    def parse_evtx(event_file, output_format="json"):
        """使用 EvtxECmd 解析 Windows 事件日志"""
        cmd = f"EvtxECmd -f {event_file} --json {output_format}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout
    
    @staticmethod
    def analyze_auth_log(log_path):
        """分析 Linux 认证日志"""
        with open(log_path, 'r') as f:
            lines = f.readlines()
        
        stats = {
            'failed_logins': [],
            'successful_logins': [],
            'sudo_usage': [],
            'ssh_connections': [],
            'brute_force_ips': {},
        }
        
        for line in lines:
            if 'Failed password' in line:
                # 提取 IP
                import re
                ip = re.search(r'from ([\d.]+)', line)
                if ip:
                    stats['brute_force_ips'][ip.group(1)] = \
                        stats['brute_force_ips'].get(ip.group(1), 0) + 1
                stats['failed_logins'].append(line.strip())
            
            elif 'Accepted' in line:
                stats['successful_logins'].append(line.strip())
            
            elif 'sudo' in line:
                stats['sudo_usage'].append(line.strip())
        
        # 输出结果
        print(f"[*] 失败登录: {len(stats['failed_logins'])} 次")
        print(f"[*] 成功登录: {len(stats['successful_logins'])} 次")
        
        # 暴力破解 IP
        if stats['brute_force_ips']:
            print("\n[!] 疑似暴力破解 IP:")
            for ip, count in sorted(
                stats['brute_force_ips'].items(),
                key=lambda x: x[1], reverse=True
            )[:10]:
                print(f"    {ip}: {count} 次")
        
        return stats
    
    @staticmethod
    def analyze_web_log(log_path):
        """分析 Web 日志"""
        stats = {
            'total_requests': 0,
            'status_codes': {},
            'top_ips': {},
            'top_urls': {},
            'suspicious_patterns': [],
        }
        
        suspicious_keywords = [
            '../', '..', 'union', 'select', 'script',
            'eval', 'exec', 'cmd', '/etc/passwd',
            'SELECT', 'FROM', 'WHERE', '<script>',
            'alert(', 'onerror=', 'javascript:'
        ]
        
        with open(log_path, 'r') as f:
            for line in f:
                stats['total_requests'] += 1
                
                parts = line.split()
                if len(parts) >= 7:
                    ip = parts[0]
                    url = parts[6]
                    stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
                    stats['top_urls'][url] = stats['top_urls'].get(url, 0) + 1
                
                # 检测可疑模式
                for keyword in suspicious_keywords:
                    if keyword in line.lower():
                        stats['suspicious_patterns'].append({
                            'line': line.strip()[:200],
                            'pattern': keyword
                        })
                        break
        
        print(f"[*] 总请求: {stats['total_requests']}")
        print(f"[!] 可疑请求: {len(stats['suspicious_patterns'])}")
        
        for item in stats['suspicious_patterns'][:10]:
            print(f"    模式: {item['pattern']}")
            print(f"    内容: {item['line'][:100]}")
        
        return stats

# 使用
analyzer = LogAnalysis()
analyzer.analyze_auth_log("/var/log/auth.log")
analyzer.analyze_web_log("/var/log/apache2/access.log")
PYEOF
```

### 6. Volatility 3 插件链自动化

```bash
# 高级 Volatility 3 用法
# 自动化插件链分析

vol -f memory.raw windows.pslist --pid 0 > system.txt
vol -f memory.raw windows.netscan > netscan.txt
vol -f memory.raw windows.malfind --dump -D dumped_malware/
vol -f memory.raw windows.hashdump > hashes.txt
vol -f memory.raw windows.registry.hivelist > hivelist.txt

# 导出特定进程的所有句柄
vol -f memory.raw windows.handles --pid 1234

# Yara 规则扫描
cat > malware.yar << 'YARA'
rule detect_cobalt_strike {
    strings:
        $s1 = "beacon.dll"
        $s2 = { 68 00 00 00 00 68 00 00 00 00 }
        $s3 = "InternetOpenA"
    condition:
        any of them
}
YARA
vol -f memory.raw windows.vadyarascan --yara-file malware.yar

# 提取浏览器数据
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Internet Explorer\TypedURLs"
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

## 工具推荐

- **Volatility** — 内存取证
- **Autopsy** — 磁盘取证
- **The Sleuth Kit** — 磁盘取证
- **FTK Imager** — 磁盘镜像
- **TestDisk** — 分区恢复
- **PhotoRec** — 文件恢复
- **Foremost** — 文件恢复
- **RegRipper** — 注册表分析
- **EvtxECmd** — 事件日志
- **CyberChef** — 数据处理

## 参考链接

- [Volatility](https://www.volatilityfoundation.org/)
- [Autopsy](https://www.autopsy.com/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [DFIR](https://digitalforensics.com/)
