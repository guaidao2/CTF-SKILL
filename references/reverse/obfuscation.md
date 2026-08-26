# 混淆与脱壳 (Obfuscation & Unpacking)

## 原理

程序通过代码混淆、虚拟机保护、加壳等技术增加逆向难度。本文件介绍常见混淆/加壳技术及脱壳/反混淆方法。

## 常见混淆技术

### 1. OLLVM (Obfuscator-LLVM)

```c
// 原始代码
int add(int a, int b) {
    return a + b;
}

// OLLVM 混淆后
int add(int a, int b) {
    int result = 0;
    int state = 0x12345678;
    while (1) {
        switch (state) {
            case 0x12345678:
                result = a;
                state = 0x87654321;
                break;
            case 0x87654321:
                result += b;
                state = 0xdeadbeef;
                break;
            case 0xdeadbeef:
                return result;
        }
    }
}
```

#### OLLVM 特征

- 控制流平坦化（Control Flow Flattening）
- 虚假控制流（Bogus Control Flow）
- 指令替换（Instruction Substitution）

#### 反混淆方法

```python
# 1. 静态分析
# - 识别分发器
# - 还原控制流

# 2. 动态分析
# - Unicorn 模拟执行
# - 记录执行路径

# 3. 符号执行
# - angr
# - manticore

# 4. ML 辅助
# - 使用 LLM 识别模式
```

### 2. 虚拟机保护 (VMP)

```c
// 将代码编译为自定义字节码
// 运行时由虚拟机解释执行

// 特征：
// - 自定义指令集
// - 字节码解释器
// - 难以静态分析
```

#### 常见 VMP

- VMProtect
- Themida
- Code Virtualizer
- Enigma Protector

#### 反 VMP 方法

```python
# 1. 识别虚拟机结构
# - 分发器
# - handler 表
# - 上下文结构

# 2. 还原指令集
# - 分析每个 handler
# - 建立指令映射

# 3. 动态分析
# - 记录执行的 handler
# - 还原执行流程

# 4. 工具
# - VMPAttack
# - Triton
# - 各 VMP 分析工具
```

### 3. 代码加密

```c
// 运行时解密代码
// 执行后重新加密

// 特征：
// - 自修改代码
// - 运行时解密
```

#### 反加密方法

```python
# 1. 内存 dump
# - 等代码解密后 dump
# - 重建 PE/ELF

# 2. 动态分析
# - 在解密后下断点
# - 跟踪执行

# 3. 工具
# - Scylla
# - ImpRec
```

### 4. 反汇编混淆

```asm
// 花指令
jmp label
db 0xe8  ; 假的 call 指令
label:
; 实际代码

// 跳转混淆
jmp label1
label1:
jmp label2
label2:
; 实际代码
```

#### 反混淆方法

```python
# 1. 识别花指令
# - 模式匹配
# - 动态执行

# 2. 修复反汇编
# - 移除花指令
# - 重新反汇编

# 3. 工具
# - IDA Pro
# - Ghidra
# - r2
```

## 常见壳

### 1. UPX

```bash
# 脱壳
upx -d ./packed

# 特征
# - UPX! 标识
# - 简单的压缩算法
```

### 2. ASPack

```bash
# 脱壳
# 1. 内存 dump
# 2. 修复 IAT

# 特征
# - aPLib 压缩
```

### 3. PECompact

```bash
# 脱壳
# 1. 内存 dump
# 2. 修复 IAT
```

### 4. Themida

```bash
# 脱壳
# 1. 反 VM
# 2. 内存 dump
# 3. 修复 IAT

# 特征
# - VM 保护
# - 反调试
```

### 5. VMProtect

```bash
# 脱壳
# 1. 反 VM
# 2. 内存 dump
# 3. 修复 IAT

# 特征
# - VM 保护
# - 反调试
```

## 脱壳方法

### 1. 内存 dump

```bash
# 1. 运行程序
# 2. 等待解密完成
# 3. dump 内存
# 4. 修复 PE/ELF

# 工具
# - Scylla (Windows)
# - ImpRec (Windows)
# - LordPE (Windows)
# - gdb (Linux)
```

### 2. 修复 IAT

```bash
# 1. 找到原始 IAT
# 2. 重建 IAT
# 3. 修复导入表

# 工具
# - Scylla
# - ImpRec
```

### 3. 修复重定位

```bash
# 1. 找到重定位表
# 2. 修复重定位
```

## 反混淆工具

### 1. IDA Pro 插件

```bash
# - Hex-Rays Decompiler
# - FindCrypt
# - Signsrch
# - HexRaysPyTools
# - Microcode 插件
```

### 2. Ghidra 插件

```bash
# - Ghidraa
# - 各反混淆插件
```

### 3. 自动化工具

```python
# angr
# - 符号执行
# - 控制流恢复

# Triton
# - 动态符号执行
# - 反混淆

# miasm
# - 符号执行
# - 反汇编

# Unicorn
# - 模拟执行
# - 代码跟踪
```

## 2024-2026 新技术点

### 1. 新型混淆

```python
# Tigress
# - 多种混淆技术
# - C 代码混淆

# OLLVM 变种
# - Hikari
# - Arkari
# - 各 OLLVM 改进版

# 自定义 VM
# - 越来越复杂
```

### 2. AI 反混淆

```python
# LLM 辅助
# - 识别混淆模式
# - 还原代码逻辑
# - 重命名变量

# ML 模型
# - 模式识别
# - 自动反混淆
```

### 3. 硬件辅助

```python
# Intel PT
# - 处理器跟踪
# - 执行流记录

# Intel LBR
# - 最后分支记录
```

### 4. 新型 VM

```python
# WebAssembly VM
# - WASM 字节码
# - 新的混淆

# eBPF VM
# - 内核 eBPF
# - 新的混淆
```

### 5. 容器化混淆

```python
# Docker 容器
# - 多层镜像
# - 运行时解密
```

### 6. 分布式混淆

```python
# 多进程
# 多机器
# 分布式执行
```

### 7. 量子混淆

```python
# 量子算法
# 量子密钥
# 新型混淆
```

### 8. ML 混淆

```python
# 基于 ML 的混淆
# 神经网络混淆
# 新型混淆
```

### 9. 新型壳

```python
# 持续有新的壳出现
# 关注最新研究
```

### 10. 反 AI 逆向

```python
# 检测 AI 辅助逆向
# 阻止 LLM 分析
# 新型反逆向
```

## 工具推荐

- **UPX** — UPX 脱壳
- **Scylla** — IAT 修复
- **ImpRec** — IAT 修复
- **LordPE** — PE 编辑
- **IDA Pro** — 反汇编/反编译
- **Ghidra** — 反汇编/反编译
- **angr** — 符号执行
- **Triton** — 动态符号执行
- **Unicorn** — 模拟执行
- **DIE** — 文件类型识别
- **PEiD** — PE 文件识别

## 参考链接

- [ctf-wiki obfuscation](https://ctf-wiki.org/reverse/obfuscation/)
- [OLLVM](https://github.com/obfuscator-llvm/obfuscator)
- [Tigress](https://tigress.wtf/)
- [angr](https://angr.io/)
- [Triton](https://triton-library.github.io/)
