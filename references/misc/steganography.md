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

### 1. AI 生成图片隐写

```python
# Stable Diffusion
# DALL-E
# Midjourney
# AI 生成图片中的隐写
```

### 2. 深度学习隐写

```python
# 基于神经网络的隐写
# 更难检测
# 新的分析方法
```

### 3. 量子隐写

```python
# 量子信道隐写
# 新的隐写方法
```

### 4. 区块链隐写

```python
# 在区块链中隐藏信息
# 比特币 OP_RETURN
# 以太坊 calldata
```

### 5. DNA 隐写

```python
# 在 DNA 序列中隐藏信息
# 新的隐写方法
```

### 6. 新型图片格式

```python
# WebP
# AVIF
# HEIC
# 新格式的隐写
```

### 7. 新型音频格式

```python
# FLAC
# Opus
# 新格式的隐写
```

### 8. 容器隐写

```python
# 在容器镜像中隐藏信息
# 新的隐写方法
```

### 9. 云隐写

```python
# 在云服务中隐藏信息
# 元数据
# 标签
```

### 10. AI 辅助检测

```python
# ML 辅助
# 自动检测隐写
# 模式识别
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
