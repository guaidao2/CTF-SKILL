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

### 1. AI 辅助 OSINT 自动化

```python
# 使用 LLM/ML 自动化 OSINT 收集和分析
import requests
import json
import subprocess

class AIOSINT:
    """AI 辅助 OSINT 工具"""
    
    @staticmethod
    def auto_recon(target):
        """自动化侦察"""
        results = {}
        
        # 1. Sherlock — 用户名搜索
        try:
            output = subprocess.run(
                ['sherlock', target, '--timeout', '10', '--print-found'],
                capture_output=True, text=True, timeout=120
            )
            results['sherlock'] = output.stdout
        except:
            pass
        
        # 2. Maigret — 增强版用户名搜索
        try:
            output = subprocess.run(
                ['maigret', target, '--json'],
                capture_output=True, text=True, timeout=120
            )
            results['maigret'] = output.stdout
        except:
            pass
        
        # 3. Holehe — 邮箱注册检测
        if '@' in target:
            try:
                output = subprocess.run(
                    ['holehe', target],
                    capture_output=True, text=True, timeout=120
                )
                results['holehe'] = output.stdout
            except:
                pass
        
        return results
    
    @staticmethod
    def face_search(image_path):
        """人脸识别搜索（使用 Python）"""
        # 使用 PimEyes 或其他面部搜索 API
        # 或使用 face_recognition 库
        try:
            import face_recognition
            image = face_recognition.load_image_file(image_path)
            encodings = face_recognition.face_encodings(image)
            if encodings:
                print(f"[+] 检测到 {len(encodings)} 张人脸")
                return encodings
        except ImportError:
            print("[-] 需要安装 face_recognition: pip install face-recognition")
        
        return None
    
    @staticmethod
    def image_exif_auto(image_path):
        """自动提取并分析 EXIF 数据"""
        try:
            output = subprocess.run(
                ['exiftool', '-json', image_path],
                capture_output=True, text=True
            )
            metadata = json.loads(output.stdout)
            
            findings = []
            for item in metadata:
                # GPS 数据
                if 'GPSLatitude' in item:
                    findings.append(f"GPS: {item.get('GPSLatitude')}, {item.get('GPSLongitude')}")
                    findings.append(f"位置: https://maps.google.com/?q={item['GPSLatitude']},{item['GPSLongitude']}")
                
                # 相机信息
                if 'Make' in item:
                    findings.append(f"相机: {item.get('Make')} {item.get('Model', '')}")
                
                # 软件
                if 'Software' in item:
                    findings.append(f"软件: {item.get('Software')}")
                
                # 日期
                if 'DateTimeOriginal' in item:
                    findings.append(f"拍摄时间: {item.get('DateTimeOriginal')}")
                
                # 作者
                if 'Artist' in item:
                    findings.append(f"作者: {item.get('Artist')}")
                
                # 版权
                if 'Copyright' in item:
                    findings.append(f"版权: {item.get('Copyright')}")
            
            return findings
        
        except Exception as e:
            return [f"分析失败: {e}"]
```

### 2. 卫星图像地理定位

```python
# 使用卫星图像服务进行地理定位
import requests

class SatelliteOSINT:
    """卫星图像 OSINT"""
    
    def __init__(self):
        self.services = {
            'sentinel': 'https://scihub.copernicus.eu/dhus',
            'planet': 'https://api.planet.com/basemaps/v1/mosaics',
            'zoom_earth': 'https://zoom.earth/api/v1',
        }
    
    def get_satellite_view(self, lat, lon, zoom=15):
        """获取卫星视图 URL"""
        # Sentinel Hub WMS
        wms_url = (
            f"https://services.sentinel-hub.com/ogc/wms/instance?"
            f"SERVICE=WMS&REQUEST=GetMap&LAYERS=1_TRUE_COLOR"
            f"&BBOX={lon-0.01},{lat-0.01},{lon+0.01},{lat+0.01}"
            f"&WIDTH=512&HEIGHT=512&CRS=EPSG:4326"
            f"&FORMAT=image/png"
        )
        return wms_url
    
    def search_by_location(self, lat, lon):
        """根据坐标搜索相关图像"""
        # 使用 Overpass API 搜索 OpenStreetMap 数据
        query = f"""
        [out:json];
        (
          node(around:1000,{lat},{lon});
          way(around:1000,{lat},{lon});
        );
        out body;
        """
        try:
            r = requests.post(
                "https://overpass-api.de/api/interpreter",
                data={'data': query}
            )
            return r.json().get('elements', [])
        except:
            return []

# CTF 中常见的卫星图像定位线索：
# 1. 建筑物形状 → Google Earth Pro 3D 视图
# 2. 路牌/文字 → 语言判断国家
# 3. 驾驶方向 → 左/右行判断
# 4. 太阳角度 → 半球判断
# 5. 植被类型 → 气候带判断
# 6. 电力线/电杆 → 国家特定样式
```

### 3. 区块链 OSINT

```python
# 链上分析工具
import requests
import hashlib

class BlockchainOSINT:
    """区块链 OSINT"""
    
    def __init__(self):
        self.etherscan_api = "https://api.etherscan.io/api"
    
    def trace_ethereum(self, address):
        """追踪以太坊地址"""
        # 获取余额
        r = requests.get(self.etherscan_api, params={
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest',
            'apikey': 'YourApiKeyToken'
        })
        balance = int(r.json().get('result', '0')) / 10**18
        print(f"[*] 余额: {balance} ETH")
        
        # 获取交易
        r = requests.get(self.etherscan_api, params={
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': 1,
            'offset': 10,
            'sort': 'desc'
        })
        
        txs = r.json().get('result', [])
        for tx in txs[:5]:
            value = int(tx.get('value', '0')) / 10**18
            print(f"  {'→' if tx['to'] == address else '←'} "
                  f"区块#{tx['blockNumber']} "
                  f"值:{value:.4f} ETH "
                  f"从:{tx['from'][:10]}... → 到:{tx['to'][:10]}...")
    
    def check_btc_address(self, address):
        """检查比特币地址"""
        try:
            r = requests.get(f"https://blockchain.info/rawaddr/{address}")
            data = r.json()
            balance = data.get('final_balance', 0) / 10**8
            print(f"[*] BTC 余额: {balance}")
            print(f"[*] 总交易: {data.get('n_tx', 0)}")
            return data
        except:
            return None

# 工具推荐
# - Chainalysis Reactor: 商业链上分析
# - Elliptic Lens: 地址风险评分
# - Etherscan: 以太坊浏览器
# - Blockchain.com: 比特币浏览器
# - Wallet Explorer: 钱包聚类分析
```

### 4. 暗网 OSINT

```python
# Tor 暗网情报收集
import subprocess
import re

class DarkWebOSINT:
    """暗网 OSINT"""
    
    @staticmethod
    def search_onion(domain_keywords):
        """搜索 .onion 域名"""
        # 使用 Ahmia 搜索引擎 API
        for keyword in domain_keywords:
            try:
                r = requests.get(
                    f"https://ahmia.fi/api/v1/search/?q={keyword}"
                )
                results = r.json()
                for item in results.get('data', []):
                    print(f"[*] {item.get('title', 'N/A')}")
                    print(f"    .onion: {item.get('domain', 'N/A')}")
                    print(f"    描述: {item.get('description', 'N/A')[:100]}")
            except Exception as e:
                print(f"[-] 搜索失败: {e}")
    
    @staticmethod
    def check_leaked_data(email):
        """检查泄露数据"""
        # DeHashed API
        # IntelX API
        # 调查搜索引擎
        sources = {
            'leakcheck': f'https://leakcheck.io/api/public?check={email}',
            'dehashed': 'https://api.dehashed.com/search',
        }
        return sources

# 暗网监控工具
# - Tor Browser + DuckDuckGo
# - Ahmia (ahmia.fi) — .onion 搜索引擎
# - OnionLand Search — .onion 搜索
# - DarkSearch API
# - onion.live — 暗网网站列表
```

### 5. 社交媒体批量 OSINT

```python
# 批量社交媒体信息收集
import subprocess
import json

class SocialMediaOSINT:
    """社交媒体批量 OSINT"""
    
    @staticmethod
    def bulk_username_check(usernames):
        """批量用户名检查"""
        results = {}
        for username in usernames:
            print(f"[*] 检查: {username}")
            
            # Sherlock
            try:
                output = subprocess.run(
                    ['sherlock', username, '--timeout', '5', '--print-found', '-o', f'/tmp/sherlock_{username}.txt'],
                    capture_output=True, text=True, timeout=60
                )
                with open(f'/tmp/sherlock_{username}.txt') as f:
                    found = [line.strip() for line in f if '[+]' in line]
                    results[username] = found
                    print(f"    找到 {len(found)} 个匹配")
            except:
                results[username] = []
        
        return results
    
    @staticmethod
    def github_user_recon(username):
        """GitHub 用户深度侦察"""
        r = requests.get(f"https://api.github.com/users/{username}")
        user = r.json()
        
        info = {
            'name': user.get('name'),
            'bio': user.get('bio'),
            'company': user.get('company'),
            'location': user.get('location'),
            'email': user.get('email'),
            'blog': user.get('blog'),
            'repos': user.get('public_repos'),
            'followers': user.get('followers'),
            'created': user.get('created_at'),
        }
        
        # 搜索敏感文件
        r = requests.get(
            f"https://api.github.com/search/code?q=user:{username}+password+OR+secret+OR+key+OR+token",
            headers={'Accept': 'application/vnd.github.v3+json'}
        )
        
        sensitive = r.json().get('items', [])
        info['sensitive_files'] = len(sensitive)
        
        for item in sensitive[:5]:
            print(f"    [!] 敏感文件: {item['repository']['name']}/{item['path']}")
        
        return info
    
    @staticmethod
    def telegram_osint(phone_or_username):
        """Telegram OSINT"""
        # Telegram 公开信息
        # - 用户 profile 图片
        # - 在线状态
        # - 最后上线时间
        # - bio
        # - 公开群组
        
        results = {}
        
        # 使用 Telepathy 或其他工具
        # 常见命令
        commands = [
            f"t.me/{phone_or_username}",
            f"https://t.me/s/{phone_or_username}",
        ]
        
        return results

# 使用
osint = SocialMediaOSINT()
osint.bulk_username_check(['target_user1', 'target_user2'])
info = osint.github_user_recon('target_user')
print(json.dumps(info, indent=2, ensure_ascii=False))
```

### 6. 云存储 Bucket OSINT

```python
# S3/GCS/Azure Blob 匿名访问检测
import requests
import boto3
import json

class CloudStorageOSINT:
    """云存储 OSINT"""
    
    @staticmethod
    def scan_s3_buckets(wordlist_path):
        """扫描 S3 bucket"""
        with open(wordlist_path) as f:
            words = [line.strip() for line in f]
        
        s3 = boto3.client('s3', region_name='us-east-1')
        found = []
        
        for word in words:
            try:
                s3.head_bucket(Bucket=word)
                print(f"[+] Bucket 发现: s3://{word}")
                
                # 尝试列出内容
                try:
                    objects = s3.list_objects_v2(Bucket=word, MaxKeys=5)
                    for obj in objects.get('Contents', []):
                        print(f"    文件: {obj['Key']} ({obj['Size']} bytes)")
                except:
                    print("    (无法列出内容)")
                
                found.append(word)
            except:
                pass
        
        return found
    
    @staticmethod
    def scan_gcs_buckets(wordlist_path):
        """扫描 GCS bucket"""
        with open(wordlist_path) as f:
            words = [line.strip() for line in f]
        
        found = []
        for word in words:
            try:
                r = requests.get(f"https://storage.googleapis.com/{word}/?maxResults=5", timeout=3)
                if r.status_code == 200:
                    print(f"[+] GCS Bucket: gs://{word}")
                    found.append(word)
            except:
                pass
        
        return found

# 资产发现
# - S3 Bucket 名称爆破: censys s3 / 简单词表
# - GitHub dorks: "password" "secret" "api_key"
# - Shodan: 查找暴露的云服务
# - Censys: 查找暴露的数据库/存储
```

### 7. 图片 AI 内容检测

```python
# 检测 AI 生成内容 (Deepfake/AI 图片)
import subprocess
import json

class AIDetection:
    """AI 内容检测"""
    
    @staticmethod
    def detect_ai_image(image_path):
        """检测 AI 生成图片"""
        # 方法 1: 检查 EXIF 元数据
        result = subprocess.run(
            ['exiftool', '-json', image_path],
            capture_output=True, text=True
        )
        metadata = json.loads(result.stdout)
        
        ai_indicators = []
        for item in metadata:
            # AI 工具通常添加特定元数据
            software = item.get('Software', '').lower()
            if any(tool in software for tool in ['stable diffusion', 'midjourney', 'dall-e', 'gpt', 'ai']):
                ai_indicators.append(f"检测到 AI 工具: {item.get('Software')}")
            
            # 缺少相机数据
            if 'Make' not in item and 'Model' not in item:
                ai_indicators.append("缺少相机元数据（可能是 AI 生成）")
            
            # 生成时间
            if 'DateTimeOriginal' not in item:
                ai_indicators.append("缺少拍摄时间")
        
        # 方法 2: 检查频率域特征
        # AI 图片在频域中可能有异常模式
        
        # 方法 3: 检查统计异常
        result = subprocess.run(
            ['identify', '-verbose', image_path],
            capture_output=True, text=True
        )
        
        return {
            'ai_indicators': ai_indicators,
            'metadata': str(metadata)[:500]
        }
    
    @staticmethod
    def detect_deepfake(video_path):
        """检测 Deepfake 视频"""
        # 提取帧
        subprocess.run([
            'ffmpeg', '-i', video_path,
            '-vf', 'fps=1',
            '/tmp/frames/%04d.png'
        ])
        
        # 使用 FaceForensics++ 或其他工具
        # 或使用 Python 深度学习模型
        return "需要安装深度学习检测模型"

# 工具
# - Illuminarty: AI 图片检测 API
# - AI or Not: 在线检测
# - Hive Moderation: 内容审核
# - Sensity AI: Deepfake 检测
```

### 8. 隐私保护 OSINT 防御

```python
# 隐私保护技术（用于防御 OSINT）
class PrivacyDefense:
    """隐私保护"""
    
    @staticmethod
    def scrub_exif(image_path, output_path):
        """清除图片 EXIF"""
        subprocess.run([
            'exiftool', '-all=', '-overwrite_original', image_path
        ])
        print(f"[*] 已清除 {image_path} 的 EXIF 数据")
    
    @staticmethod
    def anonymize_metadata(directory):
        """批量清除元数据"""
        for root, dirs, files in os.walk(directory):
            for f in files:
                if f.lower().endswith(('.jpg', '.jpeg', '.png', '.mp4')):
                    path = os.path.join(root, f)
                    PrivacyDefense.scrub_exif(path, path)
    
    @staticmethod
    def check_exposure(target):
        """检查目标暴露面"""
        checks = {
            'email_breach': f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
            'dns': f"dig {target} ANY",
            'shodan': f"https://api.shodan.io/dns/domain/{target}",
        }
        return checks
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
