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

### 1. 云取证

```bash
# AWS
# CloudTrail 日志
# VPC Flow Logs
# S3 访问日志

# GCP
# Cloud Audit Logs
# VPC Flow Logs

# Azure
# Activity Log
# Diagnostic Settings
```

### 2. 容器取证

```bash
# Docker
docker inspect <container>
docker logs <container>
docker diff <container>

# Kubernetes
kubectl logs <pod>
kubectl describe <pod>

# 工具
# docker-explorer
# k8sforensics
```

### 3. 移动取证

```bash
# Android
# adb backup
# TWRP backup
# 工具：ALEAPP, Autopsy

# iOS
# iTunes backup
# 工具：iLEAPP, Autopsy
```

### 4. IoT 取证

```bash
# 固件提取
binwalk ./firmware.bin
binwalk -e ./firmware.bin

# 文件系统分析
# squashfs
# jffs2
# ubifs
```

### 5. AI 取证

```python
# ML 模型提取
# 提取模型权重
# 提取训练数据

# 工具
# model-extraction-attack
# MIST
```

### 6. 区块链取证

```bash
# 链上分析
# 交易追踪
# 地址聚类

# 工具
# Chainalysis
# Elliptic
# Etherscan
```

### 7. 量子取证

```python
# 量子信道分析
# 量子密钥分发
# 新的取证方法
```

### 8. 新型内存取证

```python
# Volatility 3 新插件
# ARM64 支持
# RISC-V 支持
# 新的操作系统支持
```

### 9. 新型磁盘取证

```bash
# NVMe SSD
# 加密磁盘
# 新的文件系统
```

### 10. AI 辅助取证

```python
# ML 辅助
# 自动分析
# 异常检测
# 模式识别
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
