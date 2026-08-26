# 隐写术 (Steganography)

## 原理

将秘密信息隐藏在图片、音频、视频等载体中，不引起注意。CTF 中常需要提取隐藏的 flag。

## 攻击链

### 1. 图片隐写

#### 文件头修复

```bash
# 检查文件头
xxd ./image.png | head
# PNG: 89 50 4E 47 0D 0A 1A 0A
# JPG: FF D8 FF
# GIF: 47 49 46 38
# BMP: 42 4D

# 修复文件头
# 使用 010 Editor 或 hexedit
```

#### 文件分离

```bash
# binwalk
binwalk ./image.png
binwalk -e ./image.png

# foremost
foremost ./image.png -o output/

# dd 提取
dd if=./image.png of=./hidden.zip bs=1 skip=1234
```

#### EXIF 信息

```bash
# exiftool
exiftool ./image.jpg
exiftool -all ./image.jpg

# 查看 EXIF 中的隐藏信息
exiftool -Comment ./image.jpg
exiftool -UserComment ./image.jpg
```

#### LSB 隐写

```bash
# zsteg (PNG/BMP)
zsteg ./image.png
zsteg -a ./image.png
zsteg -e 'b1,rgb,lsb,xy' ./image.png

# stegsolve
# GUI 工具
# 查看 Red/Green/Blue 各通道
# 查看 LSB

# Python
from PIL import Image

img = Image.open('./image.png')
pixels = img.load()
width, height = img.size

# 提取 LSB
bits = ''
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y][:3]
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)

# 转字节
bytes_data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
```

#### steghide

```bash
# 提取
steghide extract -sf ./image.jpg -p password
steghide extract -sf ./image.jpg -p ""

# 信息
steghide info ./image.jpg
```

#### F5 算法

```bash
# F5 是 JPEG 隐写算法
# 工具：F5-steganography
java Extract ./image.jpg
```

#### jsteg

```bash
# jsteg 是 JPEG 隐写工具
jsteg reveal ./image.jpg output.txt
```

#### PNG IDAT 隐写

```bash
# 检查 PNG IDAT 块
pngcheck -v ./image.png

# 提取 IDAT 数据
python3 -c "
import zlib
with open('./image.png', 'rb') as f:
    data = f.read()
# 查找 IDAT 块
# 解压
"
```

#### 宽高修改

```bash
# 修改 PNG 宽高
# CRC 校验
python3 -c "
import struct
import zlib

with open('./image.png', 'rb') as f:
    data = f.read()

# 修改宽高
width = 0x1234
height = 0x5678
# 修改 IHDR 块
# 重新计算 CRC
"
```

### 2. 音频隐写

#### Audacity

```bash
# 打开音频
audacity ./audio.wav

# 查看
# 1. 频谱图（可能隐藏图片）
# 2. 波形（可能隐藏信息）
# 3. 末尾的隐藏数据
# 4. 反转音轨
```

#### LSB 音频隐写

```python
# Python
import wave

audio = wave.open('./audio.wav', 'rb')
frames = audio.readframes(audio.getnframes())

# 提取 LSB
bits = ''
for byte in frames:
    bits += str(byte & 1)

# 转字节
bytes_data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
```

#### 频谱图

```bash
# sox
sox ./audio.wav -n spectrogram -o spectrogram.png

# 查看 spectrogram.png
# 可能隐藏图片或文字
```

#### DeepSound

```bash
# DeepSound 是音频隐写工具
# Windows 工具
# 需要密码
```

#### SilentEye

```bash
# SilentEye 是音频/图片隐写工具
# GUI 工具
```

### 3. 视频隐写

```bash
# ffprobe
ffprobe ./video.mp4

# 提取帧
ffmpeg -i ./video.mp4 -r 1 frames/%04d.png

# 提取音频
ffmpeg -i ./video.mp4 -vn audio.wav

# 提取字幕
ffmpeg -i ./video.mp4 -map 0:s:0 subtitles.srt
```

### 4. 文档隐写

#### Word 文档

```bash
# .docx 本质是 ZIP
unzip ./document.docx -d doc/

# 查看
# 1. 隐藏文字
# 2. 元数据
# 3. 隐藏图片
# 4. 隐藏宏
```

#### PDF

```bash
# pdftotext
pdftotext ./document.pdf output.txt

# 查看
# 1. 隐藏文字（白色字体）
# 2. 元数据
# 3. 隐藏图片
# 4. JavaScript
# 5. 附件

# pdfinfo
pdfinfo ./document.pdf

# pdfdetach
pdfdetach -list ./document.pdf
pdfdetach -saveall ./document.pdf
```

### 5. 压缩包隐写

```bash
# 伪加密
# 修改压缩包标志位
# 7z 可以打开伪加密的 ZIP

# 暴力破解
fcrackzip -u -D -p wordlist.txt ./archive.zip
fcrackzip -u -l 1-6 ./archive.zip

# 已知明文攻击
# pkcrack
```

### 6. 磁盘隐写

```bash
# NTFS 交换数据流（ADS）
# 文件:hidden.txt
dir /r

# 提取
more < file:hidden.txt
```

### 7. 网络隐写

```bash
# 在网络协议中隐藏信息
# 1. ICMP 数据
# 2. DNS 查询
# 3. HTTP 头
# 4. TCP 序列号
```

## 2024-2026 新技术点

### 1. AI 生成图片隐写分析

```python
# Stable Diffusion/DALL-E 生成图片中的隐写分析
import struct
import zlib
from PIL import Image
import numpy as np

class AIImageStegAnalysis:
    """AI 生成图片隐写分析"""
    
    @staticmethod
    def analyze_image(image_path):
        """分析图片隐写特征"""
        img = Image.open(image_path)
        pixels = np.array(img)
        
        results = {
            'dimensions': img.size,
            'mode': img.mode,
            'format': img.format,
            'metadata': dict(img.info),
        }
        
        # 检查 LSB 异常
        lsb_r = pixels[:,:,0] & 1
        lsb_g = pixels[:,:,1] & 1
        lsb_b = pixels[:,:,2] & 1
        
        # 正常图片 LSB 应该近似随机
        # 隐写图片 LSB 可能有非随机模式
        results['lsb_randomness'] = {
            'r_mean': float(np.mean(lsb_r)),
            'g_mean': float(np.mean(lsb_g)),
            'b_mean': float(np.mean(lsb_b)),
        }
        
        # Chi-squared 检测
        from collections import Counter
        r_hist = Counter(pixels[:,:,0].flatten().tolist())
        g_hist = Counter(pixels[:,:,1].flatten().tolist())
        b_hist = Counter(pixels[:,:,2].flatten().tolist())
        
        def chi_squared(histogram):
            total = sum(histogram.values())
            expected = total / 256
            chi2 = sum((v - expected) ** 2 / expected for v in histogram.values())
            return chi2
        
        results['chi_squared'] = {
            'r': chi_squared(r_hist),
            'g': chi_squared(g_hist),
            'b': chi_squared(b_hist),
        }
        
        return results
    
    @staticmethod
    def extract_lsb(image_path, num_bits=None):
        """提取 LSB 数据"""
        img = Image.open(image_path)
        pixels = np.array(img)
        
        bits = ''
        for y in range(img.height):
            for x in range(img.width):
                r, g, b = pixels[y, x, :3]
                bits += str(r & 1)
                bits += str(g & 1)
                bits += str(b & 1)
                
                if num_bits and len(bits) >= num_bits:
                    break
            if num_bits and len(bits) >= num_bits:
                break
        
        # 转换为字节
        data = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = int(bits[i:i+8], 2)
            if byte == 0:
                break  # null terminator
            data.append(byte)
        
        return bytes(data)

# 使用
analyzer = AIImageStegAnalysis()
results = analyzer.analyze_image("suspicious_image.png")
print(f"LSB 均值: {results['lsb_randomness']}")
print(f"Chi-squared: {results['chi_squared']}")
hidden = analyzer.extract_lsb("suspicious_image.png")
print(f"隐藏数据: {hidden[:200]}")
```

### 2. 深度学习隐写分析

```python
# 使用神经网络进行隐写分析
# 参考工具: StegExpose, zsteg-ng

import numpy as np
from PIL import Image
import subprocess
import json

class DLStegAnalysis:
    """深度学习隐写分析"""
    
    @staticmethod
    def stegdetect(image_path):
        """使用 stegdetect 检测"""
        result = subprocess.run(
            ['stegdetect', '-s', '10.0', image_path],
            capture_output=True, text=True
        )
        return result.stdout
    
    @staticmethod
    def zsteg_analysis(image_path):
        """使用 zsteg 分析"""
        result = subprocess.run(
            ['zsteg', '-a', image_path],
            capture_output=True, text=True
        )
        return result.stdout
    
    @staticmethod
    def compare_histograms(img1_path, img2_path):
        """比较两张图片的直方图差异"""
        img1 = np.array(Image.open(img1_path))
        img2 = np.array(Image.open(img2_path))
        
        # 确保大小相同
        min_h = min(img1.shape[0], img2.shape[0])
        min_w = min(img1.shape[1], img2.shape[1])
        img1 = img1[:min_h, :min_w]
        img2 = img2[:min_h, :min_w]
        
        # 计算每个通道的直方图差异
        diffs = {}
        for channel in range(3):
            hist1, _ = np.histogram(img1[:,:,channel], bins=256, range=(0,255))
            hist2, _ = np.histogram(img2[:,:,channel], bins=256, range=(0,255))
            # 归一化
            hist1 = hist1 / hist1.sum()
            hist2 = hist2 / hist2.sum()
            # 相对熵
            kl = np.sum(hist1 * np.log((hist1 + 1e-10) / (hist2 + 1e-10)))
            diffs[f'channel_{channel}'] = float(kl)
        
        return diffs

# 工具
# - StegExpose: 隐写自动检测
# - zsteg-ng: 增强版 zsteg
# - OpenStego: 开源隐写工具
# - StegSpy: JPEG 隐写检测
```

### 3. WebP/AVIF 新格式隐写

```python
# WebP 文件隐写分析
import struct
import io

class WebPStegAnalysis:
    """WebP 隐写分析"""
    
    @staticmethod
    def parse_webp_chunks(file_path):
        """解析 WebP 文件块"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
            print("[-] 不是有效的 WebP 文件")
            return
        
        chunks = []
        offset = 12
        while offset < len(data):
            chunk_id = data[offset:offset+4]
            chunk_size = struct.unpack('<I', data[offset+4:offset+8])[0]
            chunk_data = data[offset+8:offset+8+chunk_size]
            
            chunks.append({
                'id': chunk_id.decode('ascii', errors='replace'),
                'size': chunk_size,
                'data_preview': chunk_data[:50].hex()
            })
            
            # 检查是否有异常块
            if chunk_id not in [b'VP8 ', b'VP8L', b'VP8X', b'EXIF', b'XMP ',
                                b'ICCP', b'ANIM', b'ANMF', b'ALPH', b'FRND']:
                print(f"[!] 未知块: {chunk_id} ({chunk_size} bytes)")
            
            offset += 8 + chunk_size
            if chunk_size % 2 != 0:
                offset += 1  # padding
        
        return chunks

# 检查 EXIF/XMP 隐藏数据
python3 -c "
import sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()
    # 搜索 EXIF 数据
    exif_start = data.find(b'Exif')
    if exif_start >= 0:
        print(f'[*] EXIF 块在偏移 {exif_start}')
    # 搜索 XMP 数据
    xmp_start = data.find(b'<x:xmpmeta')
    if xmp_start >= 0:
        xmp_end = data.find(b'</x:xmpmeta>') + len(b'</x:xmpmeta>')
        xmp = data[xmp_start:xmp_end].decode('utf-8', errors='replace')
        print(f'[*] XMP 数据: {xmp[:500]}')
" image.webp
```

### 4. 区块链隐写

```python
# 在区块链交易中隐藏信息
import hashlib
import struct

class BlockchainSteg:
    """区块链隐写"""
    
    @staticmethod
    def bitcoin_op_return(message, encoding='utf-8'):
        """创建 OP_RETURN 输出"""
        # OP_RETURN 最多 80 字节
        if len(message) > 80:
            print("[-] 消息超过 80 字节限制")
            return None
        
        # Bitcoin script: OP_RETURN <data>
        data = message.encode(encoding)
        script = b'\x6a' + bytes([len(data)]) + data  # 0x6a = OP_RETURN
        
        return script.hex()
    
    @staticmethod
    def ethereum_calldata(message):
        """在以太坊 calldata 中隐藏信息"""
        # 普通交易的 calldata 可以包含任意数据
        data = message.encode('utf-8')
        
        # 编码为 calldata (简单的 abi.encode)
        padded = data.ljust((len(data) + 31) // 32 * 32, b'\x00')
        
        return padded.hex()
    
    @staticmethod
    def decode_op_return(tx_hex):
        """解码 OP_RETURN 数据"""
        # 查找 OP_RETURN (0x6a)
        if isinstance(tx_hex, str):
            tx_hex = bytes.fromhex(tx_hex)
        
        idx = tx_hex.find(b'\x6a')
        if idx < 0:
            return None
        
        data_len = tx_hex[idx + 1]
        data = tx_hex[idx + 2:idx + 2 + data_len]
        
        try:
            return data.decode('utf-8')
        except:
            return data.hex()

# 示例
steg = BlockchainSteg()
encoded = steg.bitcoin_op_return("CTF{hidden_in_blockchain}")
print(f"OP_RETURN script: {encoded}")
```

### 5. 容器镜像隐写

```python
# 在 Docker 镜像层中隐藏信息
import hashlib
import tarfile
import io

class ContainerSteg:
    """容器镜像隐写"""
    
    @staticmethod
    def hide_in_layer(image_path, secret_data, layer_index=-1):
        """在镜像层中隐藏数据"""
        # 读取现有层
        with tarfile.open(image_path, 'r') as tar:
            layers = [m for m in tar.getmembers() if 'layer' in m.name]
        
        # 创建隐藏层
        hidden_layer = io.BytesIO()
        with tarfile.open(fileobj=hidden_layer, mode='w') as tar:
            # 将秘密数据作为隐藏文件
            data_bytes = secret_data.encode() if isinstance(secret_data, str) else secret_data
            info = tarfile.TarInfo(name='./.hidden_data')
            info.size = len(data_bytes)
            tar.addfile(info, io.BytesIO(data_bytes))
        
        return hidden_layer.getvalue()
    
    @staticmethod
    def analyze_layers(image_path):
        """分析镜像层中的可疑文件"""
        with tarfile.open(image_path, 'r') as tar:
            suspicious = []
            for member in tar.getmembers():
                name = member.name.lower()
                # 检测可疑文件
                if any(pat in name for pat in [
                    '.hidden', '.secret', '.backdoor',
                    'id_rsa', '.bash_history', 'password',
                    '.env', 'credentials', 'token'
                ]):
                    suspicious.append(member.name)
                    print(f"[!] 可疑文件: {member.name} ({member.size} bytes)")
            
            return suspicious

# 使用 Docker 镜像分析
# docker history <image> --no-trunc
# docker inspect <image>
# dive <image>  # 交互式镜像分析工具
```

### 6. 新型音频隐写 (FLAC/Opus)

```python
# FLAC/Opus 音频隐写分析
import struct
import subprocess

class AudioStegAnalysis:
    """音频隐写分析"""
    
    @staticmethod
    def analyze_flac(file_path):
        """分析 FLAC 文件"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if data[:4] != b'fLaC':
            print("[-] 不是有效的 FLAC 文件")
            return
        
        offset = 4
        while offset < len(data) - 4:
            header = struct.unpack('>I', data[offset:offset+4])[0]
            is_last = (header >> 24) & 0x80
            block_type = (header >> 24) & 0x7F
            block_size = header & 0x1FFFFFF
            
            types = {
                0: 'STREAMINFO', 1: 'PADDING', 2: 'APPLICATION',
                3: 'SEEKTABLE', 4: 'VORBIS_COMMENT', 5: 'CUESHEET',
                6: 'PICTURE',
            }
            type_name = types.get(block_type, f'UNKNOWN({block_type})')
            
            print(f"[*] Block: {type_name}, Size: {block_size}")
            
            # 检查异常大小块
            if block_type == 2:  # APPLICATION
                app_id = data[offset+4:offset+8]
                print(f"    Application ID: {app_id}")
                if block_size > 1000:
                    print(f"    [!] 异常大的 APPLICATION 块")
            
            offset += 4 + block_size
            if is_last:
                break
        
        return True
    
    @staticmethod
    def sox_spectrogram(audio_path, output_path):
        """生成频谱图"""
        subprocess.run([
            'sox', audio_path, '-n', 'spectrogram',
            '-o', output_path
        ])
        print(f"[*] 频谱图已保存: {output_path}")
    
    @staticmethod
    def analyze_spectrogram(image_path):
        """分析频谱图中的隐藏信息"""
        from PIL import Image
        img = Image.open(image_path)
        
        # 检查频谱图中的异常区域
        pixels = np.array(img)
        
        # 检查底部/顶部是否有异常（隐藏文字/图片）
        top_region = pixels[:10, :, :]
        bottom_region = pixels[-10:, :, :]
        
        # 计算每个区域的对比度
        top_std = np.std(top_region)
        bottom_std = np.std(bottom_region)
        
        return {
            'top_contrast': float(top_std),
            'bottom_contrast': float(bottom_std),
            'dimensions': img.size,
        }

# 工具
# - Audacity: 频谱图分析
# - Sonic Visualiser: 高级音频分析
# - DeepSound: 音频隐写
# - sox: 命令行音频处理
```

### 7. 多层嵌套隐写自动检测

```python
# 自动检测多层嵌套隐写
import subprocess
import os

class MultiLayerSteg:
    """多层嵌套隐写检测"""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = []
    
    def auto_detect(self):
        """自动检测所有可能的隐写"""
        print(f"[*] 分析: {self.file_path}")
        
        # 1. binwalk 检测嵌入文件
        result = subprocess.run(
            ['binwalk', self.file_path],
            capture_output=True, text=True
        )
        self.results.append(('binwalk', result.stdout))
        print("[*] binwalk 结果:")
        print(result.stdout)
        
        # 2. foremost 分割
        output_dir = f"output_{os.path.basename(self.file_path)}"
        subprocess.run([
            'foremost', '-i', self.file_path,
            '-o', output_dir, '-T'
        ])
        
        if os.path.exists(f"{output_dir}/carved"):
            carved = os.listdir(f"{output_dir}/carved")
            if carved:
                print(f"[+] foremost 分割出 {len(carved)} 个文件")
                for f in carved:
                    print(f"    {f}")
        
        # 3. strings 搜索
        result = subprocess.run(
            ['strings', '-n', '8', self.file_path],
            capture_output=True, text=True
        )
        self.results.append(('strings', result.stdout))
        
        # 查找 flag 模式
        import re
        flags = re.findall(r'flag\{[^}]+\}|CTF\{[^}]+\}', result.stdout, re.IGNORECASE)
        if flags:
            print(f"[+] 找到 flag: {flags}")
        
        # 4. exiftool 元数据
        result = subprocess.run(
            ['exiftool', self.file_path],
            capture_output=True, text=True
        )
        self.results.append(('exiftool', result.stdout))
        
        return self.results
    
    def chain_decode(self):
        """链式解码"""
        # 尝试各种编码解码
        with open(self.file_path, 'r', errors='ignore') as f:
            data = f.read()
        
        decoders = [
            ('base64', lambda x: __import__('base64').b64decode(x).decode('utf-8', errors='replace')),
            ('hex', lambda x: bytes.fromhex(x.replace(' ', '')).decode('utf-8', errors='replace')),
            ('rot13', lambda x: __import__('codecs').decode(x, 'rot_13')),
        ]
        
        for name, decoder in decoders:
            try:
                decoded = decoder(data.strip())
                if decoded and any(c.isalpha() for c in decoded):
                    print(f"[*] {name} 解码成功:")
                    print(f"    {decoded[:200]}")
            except:
                pass

# 使用
analyzer = MultiLayerSteg("challenge.png")
analyzer.auto_detect()
analyzer.chain_decode()
```

### 8. 压缩包伪加密与已知明文攻击

```bash
# ZIP 伪加密检测与利用
python3 << 'PYEOF'
import struct
import os
import zipfile
import subprocess

class ZipStegAnalysis:
    """ZIP 隐写分析"""
    
    @staticmethod
    def detect_pseudo_encrypt(zip_path):
        """检测 ZIP 伪加密"""
        with open(zip_path, 'rb') as f:
            data = f.read()
        
        # 查找本地文件头
        offset = 0
        while offset < len(data) - 30:
            if data[offset:offset+4] == b'PK\x03\x04':
                # 读取通用位标记
                flags = struct.unpack('<H', data[offset+6:offset+8])[0]
                if flags & 0x01:  # 加密位
                    # 检查是否是伪加密
                    # 伪加密：文件头标记为加密，但中央目录标记为未加密
                    print(f"[*] 文件偏移 {offset}: 加密标记 set")
                    
                    # 尝试用 7z 打开（7z 忽略伪加密）
                    try:
                        result = subprocess.run(
                            ['7z', 't', zip_path],
                            capture_output=True, text=True, timeout=10
                        )
                        if 'Everything is Ok' in result.stdout:
                            print(f"[+] 7z 可以打开 — 可能是伪加密")
                            return True
                    except:
                        pass
            
            offset += 1
        
        return False
    
    @staticmethod
    def known_plaintext_attack(zip_path, known_file, known_content):
        """已知明文攻击 (pkcrack)"""
        # 需要已知压缩后文件的前 N 字节
        cmd = [
            'pkcrack',
            '-C', zip_path,       # 密文 ZIP
            '-c', known_file,      # ZIP 内的文件名
            '-P', 'known_plain.zip',  # 已知明文 ZIP
            '-C', known_file,
            '-d', 'decrypted.zip'
        ]
        
        # 创建已知明文 ZIP
        with zipfile.ZipFile('known_plain.zip', 'w') as zf:
            zf.writestr(known_file, known_content)
        
        subprocess.run(cmd)

# 使用示例
analyzer = ZipStegAnalysis()
analyzer.detect_pseudo_encrypt("challenge.zip")

# 暴力破解 ZIP 密码
# fcrackzip -u -D -p rockyou.txt challenge.zip
# john --wordlist=rockyou.txt zip_hash.txt
# hashcat -m 17200 zip_hash.txt rockyou.txt
PYEOF
```

## 工具推荐

- **binwalk** — 文件分析
- **foremost** — 文件恢复
- **exiftool** — 元数据
- **steghide** — 图片隐写
- **zsteg** — PNG/BMP 隐写
- **stegsolve** — 图片分析
- **Audacity** — 音频分析
- **sox** — 音频处理
- **ffmpeg** — 视频处理
- **010 Editor** — 十六进制编辑
- **CyberChef** — 数据处理

## 参考链接

- [ctf-wiki steganography](https://ctf-wiki.org/misc/picture/)
- [Steganography](https://github.com/ctfs/write-ups-2014/tree/master/plaidctf-2014)
- [Stegsolve](https://github.com/eugenekolo/sec-tools/tree/master/stegsolve)
