# OSINT (Open Source Intelligence)

## 原理

通过公开来源收集信息，分析目标身份、位置、关系等。CTF 中常需要通过图片、用户名、邮箱等线索找到 flag。

## 攻击链

### 1. 图片 OSINT

#### EXIF 分析

```bash
# exiftool
exiftool ./photo.jpg

# 查看 GPS 坐标
exiftool -n -gpslatitude -gpslongitude ./photo.jpg

# 转换坐标
# 42°21'29" N 71°03'49" W → 42.3581, -71.0636
```

#### 反向图片搜索

```bash
# Google Images
# https://images.google.com/

# TinEye
# https://tineye.com/

# Yandex
# https://yandex.com/images/

# Bing
# https://www.bing.com/images

# Baidu
# https://image.baidu.com/
```

#### 地理定位

```bash
# Google Maps
# https://maps.google.com/

# Google Earth
# https://earth.google.com/

# OpenStreetMap
# https://www.openstreetmap.org/

# 地标识别
# 建筑物
# 路标
# 语言
# 植被
# 气候
```

### 2. 用户名 OSINT

```bash
# Namechk
# https://namechk.com/

# WhatsMyName
# https://whatsmyname.app/

# Sherlock (Python)
sherlock username

# Maigret (Python)
maigret username
```

### 3. 邮箱 OSINT

```bash
# Have I Been Pwned
# https://haveibeenpwned.com/

# Hunter.io
# https://hunter.io/

# EmailRep
# https://emailrep.io/

# Holehe
holehe email@example.com
```

### 4. 社交媒体 OSINT

#### Twitter/X

```bash
# 高级搜索
# https://twitter.com/search-advanced

# 搜索运算符
# from:user
# to:user
# since:2024-01-01
# until:2024-12-31
# filter:images
# filter:videos
```

#### Instagram

```bash
# 位置搜索
# 标签搜索
# 用户搜索
```

#### Facebook

```bash
# Graph Search
# 朋友
# 照片
# 位置
```

#### LinkedIn

```bash
# 公司信息
# 员工信息
# 职位信息
```

#### GitHub

```bash
# 代码搜索
# https://github.com/search

# 搜索敏感信息
# password
# secret
# api_key
# token

# GitDorker
python3 GitDorker.py -s -d dorks.txt
```

### 5. 域名 OSINT

```bash
# WHOIS
whois example.com

# DNS
dig example.com ANY
dig example.com MX
dig example.com TXT

# 子域名
subfinder -d example.com
amass enum -d example.com

# 历史记录
# Wayback Machine
# https://web.archive.org/

# Certificate Transparency
# https://crt.sh/
# https://censys.io/

# Shodan
# https://www.shodan.io/
shodan search "apache"
shodan host 1.2.3.4

# Censys
# https://censys.io/

# ZoomEye
# https://www.zoomeye.org/

# FOFA
# https://fofa.so/
```

### 6. 电话 OSINT

```bash
# Truecaller
# https://www.truecaller.com/

# Google 搜索
# "phone number"

# 电话归属地
```

### 7. IP OSINT

```bash
# IP 地理位置
# https://www.iplocation.net/

# IP 历史
# https://viewdns.info/

# IP 关联域名
# https://viewdns.info/reverseip/
```

### 8. 时间线分析

```bash
# 建立时间线
# 1. 收集所有信息
# 2. 按时间排序
# 3. 分析关联
```

### 9. 关系分析

```bash
# Maltego
# https://www.maltego.com/

# SpiderFoot
# https://www.spiderfoot.net/

# Recon-ng
recon-ng
```

### 10. 元数据分析

```bash
# 文档元数据
exiftool ./document.pdf
exiftool ./document.docx

# 图片元数据
exiftool ./photo.jpg

# 视频元数据
exiftool ./video.mp4
```

## 2024-2026 新技术点

### 1. AI 辅助 OSINT

```python
# LLM 辅助
# - 自动分析
# - 模式识别
# - 关系推断

# ML 模型
# - 人脸识别
# - 物体识别
# - 场景识别
```

### 2. 卫星图像

```python
# Google Earth
# Sentinel Hub
# Planet Labs
# 各卫星图像服务
```

### 3. 社交媒体新平台

```python
# TikTok
# Discord
# Telegram
# Mastodon
# Bluesky
# Threads
# 各新平台
```

### 4. 区块链 OSINT

```python
# 链上分析
# 交易追踪
# 地址聚类

# 工具
# Chainalysis
# Elliptic
# Etherscan
```

### 5. 暗网 OSINT

```python
# Tor
# I2P
# 暗网监控
```

### 6. 物联网 OSINT

```python
# Shodan
# Censys
# IoT 设备搜索
```

### 7. 云 OSINT

```python
# AWS S3
# GCP Buckets
# Azure Blobs
# 云存储搜索
```

### 8. 容器 OSINT

```python
# Docker Hub
# GitHub Container Registry
# 容器镜像搜索
```

### 9. AI 生成内容识别

```python
# 检测 AI 生成图片
# 检测 AI 生成文本
# 检测 Deepfake
```

### 10. 隐私保护

```python
# 差分隐私
# 联邦学习
# 隐私保护 OSINT
```

## 工具推荐

- **Maltego** — 关系分析
- **SpiderFoot** — 自动化 OSINT
- **Recon-ng** — Web 侦察
- **Sherlock** — 用户名搜索
- **Maigret** — 用户名搜索
- **Holehe** — 邮箱检查
- **theHarvester** — 邮箱/子域名收集
- **Shodan** — IoT 搜索
- **Censys** — 设备搜索
- **Wayback Machine** — 历史网页

## 参考链接

- [OSINT Framework](https://osintframework.com/)
- [ctf-wiki OSINT](https://ctf-wiki.org/misc/osint/)
- [Sherlock](https://github.com/sherlock-project/sherlock)
- [SpiderFoot](https://www.spiderfoot.net/)
