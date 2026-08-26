# Reverse 方向总览

Reverse（逆向工程）是 CTF 中分析二进制程序逻辑、还原算法、找出 flag 的方向。本目录按技术点拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 技术点 | 文件 |
|---------|-------|------|
| 给可执行文件，需分析逻辑 | 静态分析 | `static-analysis.md` |
| 需要动态运行、调试 | 动态分析 | `dynamic-analysis.md` |
| 程序检测调试器、虚拟机 | 反调试 | `anti-debugging.md` |
| 加密算法识别（RC4/AES/TEA 等） | 常见算法 | `common-algorithms.md` |
| 代码混淆、虚拟机保护、加壳 | 混淆与脱壳 | `obfuscation.md` |
| APK 文件、Android 应用 | Android 逆向 | `android-reverse.md` |
| WASM 文件、WebAssembly | WASM 逆向 | `wasm-reverse.md` |

## Reverse 通用解题流程

### 1. 信息收集

```bash
# 文件信息
file ./reverse
checksec ./reverse
readelf -h ./reverse

# 字符串
strings ./reverse | grep -E "flag|correct|wrong|input"
strings -el ./reverse  # Unicode

# 依赖库
ldd ./reverse

# 文件类型
binwalk ./reverse
foremost ./reverse
```

### 2. 反编译分析

```bash
# Ghidra
ghidra ./reverse

# IDA Pro
ida ./reverse

# radare2
r2 -A ./reverse
> afl          # 函数列表
> pdf @main    # 反汇编 main
> s main       # 跳转
> VV           # 图形化

# Binary Ninja
binaryninja ./reverse

# Cutter
cutter ./reverse

# dnSpy (.NET)
dnspy ./reverse.exe

# JD-GUI (Java)
jd-gui ./reverse.jar

# apktool (Android)
apktool d ./reverse.apk
```

### 3. 动态调试

```bash
# gdb
gdb ./reverse
> break main
> run
> step
> next
> continue
> info registers
> x/10x $rsp

# strace
strace ./reverse
strace -f ./reverse  # 跟踪子进程

# ltrace
ltrace ./reverse

# x64dbg (Windows)
# OllyDbg (Windows)
# WinDbg (Windows)
```

### 4. 算法识别

```bash
# 常见加密算法特征
# RC4: S 盒初始化 0-255
# AES: S 盒、轮密钥
# TEA/XTEA/XXTEA: delta = 0x9e3779b9
# MD5: 常量 0x67452301
# SHA1: 常量 0x67452301
# CRC32: 表 0xedb88320

# 工具
# FindCrypt (IDA 插件)
# Signsrch
# PEiD
# Detect It Easy (DIE)
```

### 5. 还原算法

```python
# 1. 识别算法
# 2. 提取密钥/参数
# 3. 编写解密脚本
# 4. 验证结果

# 常见操作
# - 异或
# - 移位
# - 加减乘
# - 查表
# - 自定义变换
```

## 工具清单

| 工具 | 用途 |
|------|------|
| Ghidra | 反编译（免费） |
| IDA Pro | 反编译（商业） |
| Binary Ninja | 反编译（商业） |
| radare2 | 反编译/调试（免费） |
| Cutter | radare2 GUI |
| x64dbg | Windows 调试 |
| dnSpy | .NET 逆向 |
| JD-GUI | Java 反编译 |
| apktool | Android 反编译 |
| jadx | Android 反编译 |
| Frida | 动态插桩 |
| Unicorn | CPU 模拟 |
| angr | 符号执行 |
| z3 | SMT 求解 |
| Detect It Easy | 文件类型识别 |
| PEiD | PE 文件识别 |
| Signsrch | 算法识别 |

## 2024-2026 Reverse 新趋势

- **WASM 逆向**：越来越多 Web 应用使用 WASM
- **AI 辅助逆向**：LLM 辅助反编译、算法识别
- **新混淆技术**：OLLVM、VMP、Tigress 等持续演进
- **ARM64/RISC-V 逆向**：非 x86 架构增多
- **eBPF 逆向**：内核 eBPF 程序
- **智能合约逆向**：Solidity/Vyper 反编译
- **ML 模型逆向**：提取模型权重、参数
- **Rust/Go 逆向**：新语言编译的二进制
- **Flutter 逆向**：Dart 编译的二进制
- **硬件逆向**：FPGA、固件

具体技术细节见各文件末尾的"2024-2026 新技术点"小节。
