# 反调试 (Anti-Debugging)

## 原理

程序检测自身是否被调试，如果检测到调试器则改变行为（退出、输出错误信息、自毁等）。逆向时需要识别并绕过这些检测。

## 常见反调试技术

### 1. Linux 反调试

#### ptrace 检测

```c
// 程序自己 ptrace 自己
// 如果已被调试，ptrace 会失败
#include <sys/ptrace.h>

if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    printf("Debugger detected!\n");
    exit(1);
}
```

```bash
# 绕过方法
# 1. patch 掉 ptrace 调用
# 2. LD_PRELOAD hook ptrace
# 3. 修改 ptrace 返回值
```

#### /proc/self/status 检测

```c
// 检查 TracerPid
FILE *f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, 256, f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) {
            printf("Debugger detected!\n");
            exit(1);
        }
    }
}
```

#### /proc/self/stat 检测

```c
// 检查第 19 个字段（开始时间）
// 调试器会改变时间
```

#### 时间检测

```c
// 检测执行时间
#include <time.h>

clock_t start = clock();
// ... 关键代码
clock_t end = clock();
if ((end - start) > 1000) {
    printf("Debugger detected!\n");
    exit(1);
}
```

#### 信号检测

```c
// SIGTRAP 检测
#include <signal.h>

void handler(int sig) {
    printf("No debugger\n");
}
signal(SIGTRAP, handler);
__asm__("int3");  // 触发 SIGTRAP
// 如果被调试，调试器会处理 SIGTRAP
```

#### int3 检测

```c
// 在代码中插入 int3
// 如果被调试，调试器会停在 int3
// 如果未被调试，int3 触发 SIGTRAP
```

### 2. Windows 反调试

#### IsDebuggerPresent

```c
// Windows API
if (IsDebuggerPresent()) {
    printf("Debugger detected!\n");
    ExitProcess(1);
}
```

#### CheckRemoteDebuggerPresent

```c
BOOL isDebuggerPresent = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
if (isDebuggerPresent) {
    ExitProcess(1);
}
```

#### NtQueryInformationProcess

```c
// 检查 ProcessDebugPort
DWORD debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) {
    ExitProcess(1);
}
```

#### PEB 检测

```c
// PEB (Process Environment Block)
// PEB.BeingDebugged
// PEB.NtGlobalFlag
```

#### 时间检测

```c
// QueryPerformanceCounter
// GetTickCount
// __rdtsc
```

#### 硬件断点检测

```c
// 检查 DR0-DR7 寄存器
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
    ExitProcess(1);
}
```

#### 异常处理检测

```c
// 利用异常处理
// 如果被调试，调试器会处理异常
// 如果未被调试，程序自己处理
```

### 3. 通用反调试

#### 虚拟机检测

```c
// 检测 VMware/VirtualBox/QEMU
// 1. CPUID
// 2. MAC 地址
// 3. 注册表
// 4. 文件系统
// 5. 进程列表
```

#### 沙箱检测

```c
// 检测沙箱环境
// 1. 检查内存大小
// 2. 检查 CPU 核心数
// 3. 检查睡眠时间
// 4. 检查用户交互
```

#### 反 IDA/Ghidra

```c
// 检测反编译器
// 1. 检查进程列表
// 2. 检查窗口标题
// 3. 检查文件路径
```

## 绕过方法

### 1. Patch

```bash
# 直接修改二进制
# 1. 找到反调试代码
# 2. 修改跳转指令
# 3. NOP 掉检测代码

# 工具
# - IDA Pro
# - Ghidra
# - x64dbg
# - r2
```

```bash
# r2 修改
r2 -w ./reverse
> s 0x401234
> wx 9090  # NOP
> q
```

### 2. LD_PRELOAD

```c
// hook.c
#include <sys/ptrace.h>

long ptrace(int request, ...) {
    return 0;  // 总是返回成功
}
```

```bash
gcc -shared -o hook.so hook.c
LD_PRELOAD=./hook.so ./reverse
```

### 3. Frida hook

```javascript
// hook ptrace
Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
    onLeave: function(retval) {
        retval.replace(0);  // 返回 0
    }
});

// hook IsDebuggerPresent
Interceptor.attach(Module.getExportByName(null, 'IsDebuggerPresent'), {
    onLeave: function(retval) {
        retval.replace(0);  // 返回 0
    }
});

// hook fopen (检测 /proc/self/status)
Interceptor.attach(Module.getExportByName(null, 'fopen'), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path.includes('/proc/self/status')) {
            this.fake = true;
        }
    },
    onLeave: function(retval) {
        if (this.fake) {
            // 返回伪造的文件
        }
    }
});
```

### 4. gdb 脚本

```bash
# gdb 脚本
# hook ptrace
catch syscall ptrace
commands
    set $rax = 0
    continue
end
```

### 5. 内核模块

```c
// 编写内核模块 hook 系统调用
// 更底层，更难被检测
```

### 6. 模拟执行

```python
# Unicorn 模拟执行
# 完全绕过反调试
# 但需要处理系统调用
```

## 2024-2026 新技术点

### 1. 新型反调试

```python
# 1. 基于 eBPF 的反调试
# 2. 基于硬件特性的反调试
# 3. 基于时序的反调试
# 4. 基于侧信道的反调试
```

### 2. 容器检测

```python
# 检测容器环境
# 1. /proc/1/cgroup
# 2. /.dockerenv
# 3. /proc/self/mountinfo
```

### 3. 云环境检测

```python
# 检测云环境
# 1. AWS/GCP/Azure 元数据
# 2. 云特定文件
# 3. 云特定进程
```

### 4. AI 检测

```python
# 检测 AI 辅助逆向
# 1. 检测 LLM API 调用
# 2. 检测自动化工具
# 3. 检测异常行为
```

### 5. 硬件级反调试

```python
# Intel CET
# ARM PAC/BTI
# ARM MTE
# 利用硬件特性反调试
```

### 6. 新型混淆

```python
# OLLVM
# VMP
# Tigress
# 混淆 + 反调试
```

### 7. 反 Frida

```python
# 检测 Frida
# 1. 检测 frida-server
# 2. 检测 frida-gadget
# 3. 检测内存中的 Frida
# 4. 检测 Frida 线程
```

### 8. 反模拟器

```python
# 检测模拟器
# 1. Unicorn
# 2. QEMU
# 3. 各模拟器特征
```

### 9. 反符号执行

```python
# 检测符号执行
# 1. 路径爆炸
# 2. 复杂约束
# 3. 环境依赖
```

### 10. 反模糊测试

```python
# 检测模糊测试
# 1. 检测异常输入
# 2. 检测覆盖率
# 3. 检测崩溃
```

## 工具推荐

- **IDA Pro** — patch
- **Ghidra** — patch
- **x64dbg** — Windows 调试 + patch
- **Frida** — 动态 hook
- **ScyllaHide** — Windows 反反调试
- **Unicorn** — 模拟执行
- **r2** — patch

## 参考链接

- [Anti-Debugging Techniques](https://anti-debug.checkpoint.com/)
- [ctf-wiki anti-debugging](https://ctf-wiki.org/reverse/anti-debugging/)
- [Frida](https://frida.re/)
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide)
