# 静态分析 (Static Analysis)

## 原理

不运行程序，通过反汇编、反编译分析程序逻辑，还原算法，找出 flag。

## 攻击链

### 1. 文件类型识别

```bash
# 文件信息
file ./reverse
readelf -h ./reverse
objdump -f ./reverse

# 文件类型
binwalk ./reverse
foremost ./reverse
DIE ./reverse  # Detect It Easy
PEiD ./reverse.exe  # Windows PE
```

### 2. 字符串分析

```bash
# ASCII 字符串
strings ./reverse | grep -E "flag|correct|wrong|input|password"
strings ./reverse | grep -E "http|ftp|file"

# Unicode 字符串
strings -el ./reverse  # UTF-16LE
strings -eb ./reverse  # UTF-16BE

# Base64 字符串
strings ./reverse | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$"

# 提取所有可打印字符串
strings -n 4 ./reverse
```

### 3. 反汇编/反编译

```bash
# Ghidra
ghidra ./reverse
# 使用 CodeBrowser
# F5 反编译

# IDA Pro
ida ./reverse
# F5 反编译（Hex-Rays）

# radare2
r2 -A ./reverse
> afl          # 函数列表
> pdf @main    # 反汇编 main
> s main       # 跳转
> VV           # 图形化
> pdc @main    # 伪代码

# Binary Ninja
binaryninja ./reverse

# objdump
objdump -d ./reverse | grep -A 20 "main"
```

### 4. 控制流分析

```bash
# 函数调用图
# Ghidra: 函数调用图
# IDA: View -> Graphs -> Flow chart

# 识别关键函数
# 1. main
# 2. 字符串比较函数
# 3. 加密函数
# 4. 输入处理函数
```

### 5. 数据流分析

```bash
# 交叉引用
# Ghidra: Ctrl+Shift+F
# IDA: X键

# 查找字符串引用
# Ghidra: Search -> For Strings
# IDA: Shift+F12
```

### 6. 算法识别

```bash
# FindCrypt (IDA 插件)
# 识别加密算法常量

# Signsrch
signsrch ./reverse

# 常见算法特征
# RC4: S 盒初始化 0-255
# AES: S 盒、轮密钥
# TEA/XTEA/XXTEA: delta = 0x9e3779b9
# MD5: 常量 0x67452301
# SHA1: 常量 0x67452301
# CRC32: 表 0xedb88320
```

### 7. 还原算法

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

# 示例：异或解密
def xor_decrypt(data, key):
    return bytes([d ^ key for d in data])

# 示例：TEA 解密
def tea_decrypt(v, k):
    delta = 0x9e3779b9
    v0, v1 = v
    sum_ = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - ((v0 << 4) + k[2] ^ (v0 + sum_) ^ (v0 >> 5) + k[3])) & 0xffffffff
        v0 = (v0 - ((v1 << 4) + k[0] ^ (v1 + sum_) ^ (v1 >> 5) + k[1])) & 0xffffffff
        sum_ = (sum_ - delta) & 0xffffffff
    return [v0, v1]
```

### 8. 符号执行

```python
# angr
import angr

proj = angr.Project('./reverse', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: b"correct" in s.posix.dumps(1),
              avoid=lambda s: b"wrong" in s.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

### 9. SMT 求解

```python
# z3
from z3 import *

# 示例：求解方程
s = Solver()
x = BitVec('x', 32)
y = BitVec('y', 32)
s.add(x + y == 10)
s.add(x * y == 24)
if s.check() == sat:
    m = s.model()
    print(m[x], m[y])
```

## 各语言逆向

### 1. C/C++

```bash
# 标准 ELF/PE 文件
# Ghidra/IDA 反编译
# 注意 STL 模板、虚函数表
```

### 2. Rust

```bash
# Rust 编译的二进制
# 特征：
# - 大量字符串处理
# - panic 信息
# - std 库符号
# 工具：rust-reversing-helper
```

### 3. Go

```bash
# Go 编译的二进制
# 特征：
# - runtime 函数
# - goroutine
# - 字符串拼接
# 工具：
# - IDA Go 插件
# - GoReSym
# - GoLite
```

### 4. .NET

```bash
# C# / VB.NET
# 工具：
# - dnSpy
# - ILSpy
# - dotPeek
# - .NET Reflector
```

### 5. Java

```bash
# JAR 文件
# 工具：
# - JD-GUI
# - CFR
# - Procyon
# - jadx
```

### 6. Python

```bash
# PyInstaller
# pyinstxtractor.py
# uncompyle6 / decompyle3

# Cython
# 需要反编译 .pyx

# Nuitka
# 编译为 C，需要逆向 C
```

### 7. Electron

```bash
# JavaScript + Node.js
# 解包 asar
# asar extract app.asar
```

## 2024-2026 新技术点

### 1. AI 辅助逆向

```python
# LLM 辅助反编译
# - 解释代码逻辑
# - 识别算法
# - 生成解密脚本
# - 重命名变量
```

### 2. 新语言逆向

```python
# Rust
# Go
# Zig
# Crystal
# V
# 各新语言的逆向
```

### 3. WASM 逆向

```python
# WebAssembly
# wasm2wat
# wasm-decompile
# Ghidra WASM 插件
```

### 4. ARM64/RISC-V

```python
# 非 x86 架构
# 移动设备
# IoT 设备
```

### 5. eBPF 逆向

```python
# 内核 eBPF 程序
# llvm-objdump -d
# eBPF 指令集
```

### 6. 智能合约逆向

```python
# Solidity
# Vyper
# 工具：
# - panoramix
# - ethervm.io
# - dedaub
```

### 7. ML 模型逆向

```python
# 提取模型权重
# 提取模型参数
# 工具：
# - model-extraction-attack
```

### 8. Flutter 逆向

```python
# Dart 编译的二进制
# 工具：
# - reFlutter
# - Doldrums
```

### 9. 硬件逆向

```python
# FPGA
# 固件
# 工具：
# - Ghidra
# - binwalk
```

### 10. 新型混淆

```python
# OLLVM
# VMP
# Tigress
# 持续演进
```

## 工具推荐

- **Ghidra** — 反编译（免费）
- **IDA Pro** — 反编译（商业）
- **Binary Ninja** — 反编译（商业）
- **radare2** — 反编译/调试（免费）
- **Cutter** — radare2 GUI
- **angr** — 符号执行
- **z3** — SMT 求解
- **Unicorn** — CPU 模拟
- **DIE** — 文件类型识别
- **PEiD** — PE 文件识别
- **Signsrch** — 算法识别

## 参考链接

- [ctf-wiki reverse](https://ctf-wiki.org/reverse/introduction/)
- [Ghidra](https://ghidra-sre.org/)
- [radare2](https://www.radare.org/)
- [angr](https://angr.io/)
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow)
