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

# fake IO_FILE 构造
fake_file = b''
fake_file += p64(0)  # _flags
# ... 填充字段
fake_file += p64(0)  # _chain
# ... 填充字段
fake_file += p64(fake_vtable_addr)  # vtable
# vtable 中的 _IO_wfile_overflow 指向 _IO_wfile_overflow
# vtable 中的 _IO_wdoallocbuf 指向 system 或 one_gadget
```

### 6. House of Apple 3

```python
# glibc 2.34+
# 类似 Apple 2，但利用不同的 IO 函数
# 利用 _IO_wfile_underflow 等
```

### 7. House of Cat

```python
# 2024 年新利用链
# glibc 2.35+
# 1. largebin attack 修改 _IO_list_all
# 2. 构造 fake IO_FILE
# 3. 触发 IO 操作
# 4. 执行任意函数
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

### 1. glibc 2.34+ 无 hooks

```python
# IO_FILE 攻击成为主流
# House of Apple/Banana/Cat
```

### 2. vtable 检查加强

```python
# glibc 2.24+ vtable 检查
# glibc 2.34+ 进一步加强
# 需要新绕过方法
```

### 3. House of Apple 新变种

```python
# 持续有新的 Apple 变种被发现
# Apple 4, Apple 5 等
```

### 4. House of Cat

```python
# 2024 年新利用链
# 支持 ORW
# 支持 seccomp 沙箱
```

### 5. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# MTE (Memory Tagging Extension)
# 影响 IO_FILE 利用
```

### 6. 沙箱环境

```python
# seccomp 限制
# 通过 ORW (open/read/write) 绕过
# House of Cat 支持 ORW
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
