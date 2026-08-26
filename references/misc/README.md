# Misc 方向总览

Misc（杂项）是 CTF 中包罗万象的方向，包括取证、隐写、流量分析、OSINT、编码等。本目录按技术点拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 技术点 | 文件 |
|---------|-------|------|
| 内存 dump、磁盘镜像、日志 | 数字取证 | `forensics.md` |
| 图片中藏 flag、LSB、音频隐写 | 隐写术 | `steganography.md` |
| pcap 文件、网络流量 | 流量分析 | `traffic-analysis.md` |
| 社工、信息搜集、地理位置 | OSINT | `osint.md` |
| Base64/32/58、摩斯密码、二维码 | 编码与解码 | `encoding.md` |

## Misc 通用解题流程

### 1. 文件识别

```bash
# 文件类型
file ./misc
binwalk ./misc
foremost ./misc
DIE ./misc

# 字符串
strings ./misc | grep -E "flag|ctf|{"
strings -el ./misc  # Unicode

# 十六进制查看
xxd ./misc | head
hexdump -C ./misc | head
```

### 2. 文件提取

```bash
# binwalk 提取
binwalk -e ./misc

# foremost 提取
foremost ./misc -o output/

# 7z 解压
7z x ./misc

# 提取隐藏数据
steghide extract -sf ./image.jpg
zsteg ./image.png
```

### 3. 分析

```bash
# 图片分析
exiftool ./image.jpg
identify -verbose ./image.png

# 音频分析
audacity ./audio.wav
soxi ./audio.wav

# 视频分析
ffprobe ./video.mp4

# 文档分析
pdfinfo ./document.pdf
```

## 工具清单

| 工具 | 用途 |
|------|------|
| binwalk | 文件分析/提取 |
| foremost | 文件恢复 |
| exiftool | 元数据查看 |
| steghide | 图片隐写 |
| zsteg | PNG/BMP 隐写 |
| stegsolve | 图片分析 |
| Audacity | 音频分析 |
| Wireshark | 流量分析 |
| Volatility | 内存取证 |
| Autopsy | 磁盘取证 |
| CyberChef | 编码解码 |
| 010 Editor | 十六进制编辑 |
| HxD | 十六进制编辑 |

## 2024-2026 Misc 新趋势

- **云取证**：AWS/GCP/Azure 日志分析
- **容器取证**：Docker/K8s 取证
- **移动取证**：Android/iOS 取证
- **IoT 取证**：固件分析
- **AI 取证**：模型权重提取
- **新型隐写**：AI 生成图片隐写、深度学习隐写
- **区块链取证**：链上数据分析
- **量子隐写**：量子信道隐写
- **OSINT 新工具**：AI 辅助 OSINT
- **新型编码**：量子编码、DNA 编码

具体技术细节见各文件末尾的"2024-2026 新技术点"小节。
