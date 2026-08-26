# Pwn 方向总览

Pwn 是 CTF 中技术门槛最高的方向之一，涉及二进制漏洞利用。本目录按漏洞类型和利用技术拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 漏洞类型 | 文件 |
|---------|---------|------|
| 栈溢出、`gets`/`scanf`/`read`、`system`/`/bin/sh` | 栈溢出 | `stack-overflow.md` |
| `printf` 用户输入、格式化字符串 | 格式化字符串 | `format-string.md` |
| `malloc`/`free`、堆块操作、UAF/Double Free | 堆利用基础 | `heap-basics.md` |
| 释放后使用、悬垂指针 | UAF | `uaf.md` |
| glibc 2.26+、tcache 机制 | tcache 攻击 | `tcache-attacks.md` |
| glibc 2.23-2.25、fastbin 机制 | fastbin 攻击 | `fastbin-attacks.md` |
| unsorted bin、`main_arena` | unsorted bin 攻击 | `unsorted-bin-attacks.md` |
| House of Spirit/Einherjar/Lore/Apple | House 系列 | `house-of-series.md` |
| `_IO_FILE`、`stdout`/`stdin` 结构体 | IO_FILE 攻击 | `io-file-attacks.md` |
| NX/ASLR/PIE/Canary/RELRO | 现代保护机制 | `modern-protections.md` |
| 内核模块、`/dev/`、`ioctl` | kernel pwn | `kernel-pwn.md` |

## Pwn 通用解题流程

### 1. 信息收集

```bash
# 文件信息
file ./pwn
checksec ./pwn
readelf -h ./pwn
readelf -l ./pwn

# 依赖库
ldd ./pwn

# 字符串
strings ./pwn | grep -E "flag|sh|system|/bin"

# 符号表
nm ./pwn
objdump -T ./pwn
```

### 2. 反编译分析

```bash
# Ghidra
ghidra ./pwn

# IDA Pro
ida ./pwn

# radare2
r2 -A ./pwn
> afl          # 函数列表
> pdf @main    # 反汇编 main
> s main       # 跳转到 main
> VV           # 图形化

# Binary Ninja
binaryninja ./pwn
```

### 3. 动态调试

```bash
# gdb + pwndbg/gef/peda
gdb ./pwn
> checksec
> vmmap
> heap
> bins
> telescope
> ropper --file ./pwn --search "pop rdi"

# 调试子进程
set follow-fork-mode child

# 调试库
set environment LD_PRELOAD ./libc.so.6
```

### 4. 漏洞利用

```bash
# pwntools
python3 exploit.py

# one_gadget
one_gadget ./libc.so.6

# ROPgadget
ROPgadget --binary ./pwn --ropchain

# ropper
ropper --file ./pwn --search "pop rdi"
```

## 工具清单

| 工具 | 用途 |
|------|------|
| pwntools | Python 利用框架 |
| gdb + pwndbg | 动态调试 |
| gdb + gef | 动态调试 |
| gdb + peda | 动态调试 |
| Ghidra | 反编译 |
| IDA Pro | 反编译 |
| radare2 | 反编译/调试 |
| ROPgadget | ROP gadget 查找 |
| ropper | ROP gadget 查找 |
| one_gadget | libc one_gadget 查找 |
| LibcSearcher | libc 版本识别 |
| libc-database | libc 版本识别 |
| seccomp-tools | seccomp 规则查看 |
| patchelf | 修改 ELF |
| strace | 系统调用追踪 |
| ltrace | 库函数追踪 |

## glibc 版本速查

| glibc 版本 | 重要变化 |
|-----------|---------|
| 2.23 | 经典版本，无 tcache |
| 2.26 | 引入 tcache |
| 2.27 | tcache double free 检测（弱） |
| 2.29 | tcache 加 key 字段 |
| 2.31 | tcache key 加强 |
| 2.32 | hook 移除（`__malloc_hook` 等） |
| 2.34 | 完全移除 hooks，引入新机制 |
| 2.35+ | 进一步加固 |
| 2.36+ | tcache 检测加强 |
| 2.37+ | safe-linking |
| 2.38+ | 进一步加固 |
| 2.39+ | 最新版本 |

## 2024-2026 Pwn 新趋势

- **glibc 2.34+ 无 hooks**：传统 `__malloc_hook`/`__free_hook` 利用失效，需用 IO_FILE、`exit_funcs`、`_environ` 等
- **House of Apple 系列**：针对 glibc 2.34+ 的新利用链
- **safe-linking**：tcache/fastbin 指针加密
- **TLS 利用**：通过 `_environ`、`__stack_chk_guard` 等 TLS 变量
- **exit_funcs 利用**：通过 `__exit_funcs` 实现 RCE
- **per-thread cache 加固**：tcache key 检测加强
- **kernel pwn 新攻击面**：eBPF、io_uring、userfaultfd
- **ARM64/RISC-V pwn**：非 x86 架构题目增多
- **WASM pwn**：WebAssembly 二进制利用
- **SGX/TEE pwn**：可信执行环境漏洞

具体技术细节见各漏洞文件末尾的"2024-2026 新技术点"小节。
