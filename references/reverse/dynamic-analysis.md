# 动态分析 (Dynamic Analysis)

## 原理

通过运行程序、调试、插桩等方式分析程序行为，观察内存、寄存器、系统调用等，辅助逆向。

## 攻击链

### 1. 基础调试

```bash
# gdb
gdb ./reverse
> break main
> run
> step          # 步入
> next          # 步过
> continue
> info registers
> x/10x $rsp
> x/s $rdi
> set $rax = 0x1234
> disas

# gdb + pwndbg/gef/peda
# 更好的可视化
```

### 2. 系统调用追踪

```bash
# strace
strace ./reverse
strace -f ./reverse  # 跟踪子进程
strace -e trace=open,read,write ./reverse  # 过滤
strace -e trace=network ./reverse  # 网络调用

# ltrace
ltrace ./reverse
ltrace -f ./reverse
ltrace -e malloc+free ./reverse

# dtrace (macOS)
# bpftrace (Linux)
```

### 3. 内存分析

```bash
# gdb
> info proc mappings  # 内存映射
> vmmap
> heap
> bins
> telescope $rsp 20

# 内存 dump
> dump memory dump.bin 0x0 0x10000

# 搜索内存
> search -t string "flag"
> search -t hex 41 42 43
```

### 4. 断点技巧

```bash
# 条件断点
> break main if $rdi == 0x1234

# 硬件断点
> hbreak *0x401234

# 监视点
> watch *0x601234
> rwatch *0x601234  # 读监视
> awatch *0x601234  # 读写监视

# 临时断点
> tbreak main

# 跟踪断点
> trace *0x401234
```

### 5. Frida 动态插桩

```javascript
// hook 函数
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter: function(args) {
        console.log('open:', args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log('returned:', retval);
    }
});

// 替换函数
Interceptor.replace(Module.getExportByName(null, 'strcmp'), new NativeCallback(function(a, b) {
    return 0;  // 总是返回相等
}, 'int', ['pointer', 'pointer']));

// 调用函数
var func = new NativeFunction(Module.getExportByName(null, 'system'), 'int', ['pointer']);
func(Memory.allocUtf8String('id'));
```

### 6. Unicorn 模拟

```python
from unicorn import *
from unicorn.x86_const import *

# 初始化
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# 映射内存
mu.mem_map(0x400000, 0x10000)  # 代码
mu.mem_map(0x600000, 0x10000)  # 数据
mu.mem_map(0x7fff0000, 0x10000)  # 栈

# 写入代码
mu.mem_write(0x400000, code)

# 设置寄存器
mu.reg_write(UC_X86_REG_RSP, 0x7fffffff)

# 设置钩子
def hook_code(mu, address, size, user_data):
    print(f'Executing: {hex(address)}')

mu.hook_add(UC_HOOK_CODE, hook_code)

# 开始执行
mu.emu_start(0x400000, 0x400100)
```

### 7. angr 符号执行

```python
import angr

proj = angr.Project('./reverse', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# 探索
simgr.explore(find=lambda s: b"correct" in s.posix.dumps(1),
              avoid=lambda s: b"wrong" in s.posix.dumps(1))

if simgr.found:
    print(simgr.found[0].posix.dumps(0))  # 输入
```

### 8. 脚本化调试

```python
# pwntools gdb
from pwn import *

p = gdb.debug('./reverse', '''
    break main
    continue
''')

# 或
p = process('./reverse')
gdb.attach(p, '''
    break *0x401234
    continue
''')
```

## 各平台调试

### 1. Linux

```bash
# gdb
gdb ./reverse

# gdb + pwndbg
# https://github.com/pwndbg/pwndbg

# gdb + gef
# https://github.com/hugsy/gef

# gdb + peda
# https://github.com/longld/peda
```

### 2. Windows

```bash
# x64dbg
# https://x64dbg.com/

# OllyDbg
# http://www.ollydbg.de/

# WinDbg
# https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/

# IDA Pro Debugger
```

### 3. macOS

```bash
# lldb
lldb ./reverse
> breakpoint set --name main
> run
> step
> next
> continue
> register read
> memory read $rsp

# Hopper
# https://www.hopperapp.com/
```

### 4. Android

```bash
# gdbserver
adb push gdbserver /data/local/tmp/
adb shell /data/local/tmp/gdbserver :1234 ./reverse

# Frida
frida -U -l hook.js ./reverse

# IDA Pro 远程调试
```

### 5. iOS

```bash
# lldb
# Frida
# Cycript
```

## 2024-2026 新技术点

### 1. AI 辅助动态分析

```python
# LLM 辅助
# - 自动生成 hook 脚本
# - 解释程序行为
# - 识别算法
```

### 2. 新型插桩

```python
# Frida 新功能
# - Stalker（代码跟踪）
# - Interceptor（函数 hook）
# - Memory（内存操作）

# DynamoRIO
# Pin
# 各插桩框架
```

### 3. 模拟执行

```python
# Unicorn
# QEMU
# 各模拟器
```

### 4. 符号执行

```python
# angr
# KLEE
# manticore
# 各符号执行框架
```

### 5. 模糊测试

```python
# AFL
# libFuzzer
# Honggfuzz
# 用于发现程序路径
```

### 6. WASM 调试

```python
# WASM 调试器
# Chrome DevTools
# Firefox DevTools
```

### 7. ARM64/RISC-V 调试

```python
# 非 x86 架构调试
# QEMU 模拟
# 各架构调试器
```

### 8. eBPF 调试

```python
# eBPF 程序调试
# bpftool
# bpftrace
```

### 9. 智能合约调试

```python
# Solidity 调试
# Remix
# Truffle
# Hardhat
```

### 10. ML 模型调试

```python
# ML 模型分析
# TensorBoard
# 各 ML 工具
```

## 工具推荐

- **gdb + pwndbg/gef/peda** — Linux 调试
- **x64dbg** — Windows 调试
- **lldb** — macOS 调试
- **Frida** — 动态插桩
- **Unicorn** — CPU 模拟
- **angr** — 符号执行
- **strace/ltrace** — 系统调用追踪
- **IDA Pro Debugger** — 集成调试

## 参考链接

- [ctf-wiki dynamic analysis](https://ctf-wiki.org/reverse/introduction/)
- [Frida](https://frida.re/)
- [Unicorn](https://www.unicorn-engine.org/)
- [angr](https://angr.io/)
- [GDB Cheat Sheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)
