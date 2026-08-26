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

### 1. Frida 高级反调试绕过

```javascript
// Frida 完整反调试绕过脚本
// 使用方法: frida -U -l anti_debug_bypass.js -f target_binary

// 1. 绕过 ptrace (Linux)
Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
        console.log('[*] ptrace(' + this.request + ')');
    },
    onLeave: function(retval) {
        // PTRACE_TRACEME = 0, 总是返回成功
        if (this.request === 0) {
            retval.replace(ptr(0));
        }
    }
});

// 2. 绕过 IsDebuggerPresent (Windows)
if (Process.platform === 'windows') {
    const kernel32 = Module.getExportByName('kernel32.dll', 'IsDebuggerPresent');
    Interceptor.attach(kernel32, {
        onLeave: function(retval) {
            retval.replace(ptr(0));
        }
    });
    
    // 3. 绕过 CheckRemoteDebuggerPresent
    Interceptor.attach(Module.getExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent'), {
        onEnter: function(args) {
            this.pIsDebuggerPresent = args[1];
        },
        onLeave: function(retval) {
            this.pIsDebuggerPresent.writeU32(0);
        }
    });
    
    // 4. 绕过 NtQueryInformationProcess
    const ntdll = Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess');
    Interceptor.attach(ntdll, {
        onEnter: function(args) {
            // ProcessDebugPort = 7
            this.infoClass = args[1].toInt32();
        },
        onLeave: function(retval) {
            if (this.infoClass === 7) {
                // 返回 0 (未调试)
                retval.replace(ptr(0));
            }
        }
    });
    
    // 5. 绕过 PEB.BeingDebugged
    Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess'), {
        onEnter: function(args) {
            this.handle = args[0];
            this.infoClass = args[1].toInt32();
            this.buffer = args[2];
        },
        onLeave: function(retval) {
            // ProcessDebugPort
            if (this.infoClass === 7) {
                this.buffer.writeU64(ptr(0));
            }
            // ProcessDebugObjectHandle
            if (this.infoClass === 0x1e) {
                retval.replace(ptr(0xc0000353));  // STATUS_PORT_NOT_SET
            }
        }
    });
}

// 6. 绕过时间检测
Interceptor.attach(Module.getExportByName(null, 'clock'), {
    onLeave: function(retval) {
        // 返回较小值
        retval.replace(ptr(100));
    }
});

Interceptor.attach(Module.getExportByName(null, 'gettimeofday'), {
    onEnter: function(args) {
        this.tv = args[0];
    },
    onLeave: function(retval) {
        if (this.tv) {
            this.tv.readU32();  // 不修改，避免循环
        }
    }
});

// 7. 绕过 /proc/self/status 检测
Interceptor.attach(Module.getExportByName(null, 'fopen'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.includes('/proc/self/status')) {
            // 返回伪造的 FILE*
            // 实际实现需要创建伪造文件
            console.log('[*] 拦截 /proc/self/status 访问');
        }
    }
});

// 8. 绕过信号检测
Interceptor.attach(Module.getExportByName(null, 'signal'), {
    onEnter: function(args) {
        var sig = args[0].toInt32();
        console.log('[*] signal(' + sig + ', ...)');
        // SIGTRAP = 5
        if (sig === 5) {
            args[1] = new NativeCallback(function(sig) {
                // 忽略 SIGTRAP
            }, 'void', ['int']);
        }
    }
});

console.log('[*] 反调试绕过已加载');
```

### 2. Ghidra 反混淆脚本

```python
# Ghidra 脚本：自动识别并简化反调试检查
# 在 Ghidra Script Manager 中运行

from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def find_anti_debug_patterns():
    """查找反调试代码模式"""
    listing = currentProgram.getListing()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    
    anti_debug_funcs = [
        'IsDebuggerPresent',
        'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess',
        'GetTickCount',
        'QueryPerformanceCounter',
        'ptrace',
    ]
    
    # 查找反调试 API 调用
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True):
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            calling_func = getFunctionContaining(ref.getFromAddress())
            if calling_func:
                result = decomp.decompileFunction(calling_func, 30, monitor)
                if result and result.getDecompiledFunction():
                    proto = result.getDecompiledFunction().getC()
                    if any(adb in proto for adb in anti_debug_funcs):
                        print(f"[!] 反调试函数调用:")
                        print(f"    调用者: {calling_func.getName()} @ {calling_func.getEntryPoint()}")
                        print(f"    目标: {func.getName()}")
                        print(f"    位置: {ref.getFromAddress()}")
    
    return True

def nop_anti_debug():
    """NOP 掉反调试代码"""
    # 通过反编译结果定位反调试检查
    # 并用 NOP 替换
    func_manager = currentProgram.getFunctionManager()
    memory = currentProgram.getMemory()
    
    for func in func_manager.getFunctions(True):
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            if func.getName() in ['IsDebuggerPresent', 'ptrace']:
                # 找到调用者的条件判断
                # 这需要更复杂的分析
                print(f"[*] 需要手动 patch: {ref.getFromAddress()}")

# 执行
find_anti_debug_patterns()
```

### 3. eBPF 反调试检测与绕过

```python
# 检测基于 eBPF 的反调试
# 一些程序使用 eBPF 追踪系统调用来检测调试器

# Frida 脚本：绕过 eBPF 追踪检测
frida_script = """
// 检测 eBPF 追踪
Interceptor.attach(Module.getExportByName(null, 'bpf'), {
    onEnter: function(args) {
        var cmd = args[0].toInt32();
        // BPF_PROG_LOAD = 5
        if (cmd === 5) {
            console.log('[!] BPF_PROG_LOAD 检测');
            console.log('    可能用于系统调用追踪');
        }
        // BPF_PROG_ATTACH = 8
        if (cmd === 8) {
            console.log('[!] BPF_PROG_ATTACH 检测');
        }
    }
});

// 检测 seccomp (沙箱)
Interceptor.attach(Module.getExportByName(null, 'prctl'), {
    onEnter: function(args) {
        var option = args[0].toInt32();
        // PR_SET_SECCOMP = 21
        if (option === 21) {
            console.log('[!] seccomp 沙箱检测');
        }
        // PR_SET_PTRACER = 0x59616d61
        if (option === 0x59616d61) {
            console.log('[*] ptrace 权限设置');
        }
    }
});

// 绕过 LD_PRELOAD 检测
Interceptor.attach(Module.getExportByName(null, 'getenv'), {
    onEnter: function(args) {
        this.name = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.name === 'LD_PRELOAD') {
            retval.replace(ptr(0));  // 返回 NULL
        }
    }
});

// 绕过 /proc/self/maps 检测 (检测注入的 .so)
Interceptor.attach(Module.getExportByName(null, 'fopen'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.includes('/proc/self/maps')) {
            // 需要返回伪造的文件内容
            // 过滤掉注入的 .so
            console.log('[*] 过滤 /proc/self/maps 中的注入痕迹');
        }
    }
});
"""
```

### 4. 硬件级反调试检测与绕过

```python
# Intel CET (Control-flow Enforcement Technology) 检测
# ARM PAC (Pointer Authentication) / BTI (Branch Target Identification) 检测

# Frida 脚本：检测和绕过硬件反调试
hardware_bypass = """
// 检测 Intel CET
if (Process.arch === 'x64') {
    // 检查 SHSTK (Shadow Stack) 状态
    // 通过 CPUID 检测
    Interceptor.attach(Module.getExportByName(null, '__cpuid'), {
        onEnter: function(args) {
            this.leaf = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.leaf === 7) {
                // ECX bit 7 = CET_SST (Shadow Stack)
                var ecx = retval.and(0xff).toInt32();
                if (ecx & 0x80) {
                    console.log('[!] Intel CET Shadow Stack 活跃');
                }
            }
        }
    });
}

// 检测 ARM PAC (Apple Silicon / ARM64)
if (Process.arch === 'arm64') {
    // PAC 会在指针中嵌入签名
    // 调试时 PAC 会被禁用或改变
    console.log('[*] ARM64 平台 — 可能使用 PAC');
    
    // 检测 BTI (Branch Target Identification)
    // BTI 指令会检查跳转目标
}

// 检测硬件断点
// 通过读取 DR 寄存器
Interceptor.attach(Module.getExportByName(null, 'get_debug_registers'), {
    onLeave: function(retval) {
        console.log('[!] 硬件断点检测');
    }
});

// 绕过硬件断点检测 (通过修改调试寄存器)
// 这需要在 ring 0 级别操作
// Frida 可以通过 GDB 桥接实现
"""
```

### 5. 反 Frida 检测与绕过

```python
# 检测 Frida 并绕过
anti_frida_bypass = """
// Frida 检测绕过

// 1. 检测 frida-server (端口 27042)
Interceptor.attach(Module.getExportByName(null, 'connect'), {
    onEnter: function(args) {
        var sockaddr = args[1];
        // sockaddr_in 结构: sa_family (2 bytes) + port (2 bytes) + addr (4 bytes)
        var port = sockaddr.add(2).readU16();
        port = ((port & 0xff) << 8) | ((port >> 8) & 0xff);  // network byte order
        if (port === 27042) {
            console.log('[!] Frida 默认端口检测');
            // 修改端口号
            sockaddr.add(2).writeU16(0);
        }
    }
});

// 2. 检测 frida-agent.so / frida-gadget.dylib
Interceptor.attach(Module.getExportByName(null, 'dlopen'), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && (this.path.includes('frida') || this.path.includes('gadget'))) {
            console.log('[!] Frida 库加载检测');
            retval.replace(ptr(0));  // 返回 NULL
        }
    }
});

// 3. 检测 Frida 线程名
Interceptor.attach(Module.getExportByName(null, 'getenv'), {
    onEnter: function(args) {
        this.name = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.name === '_FRIDA fling') {
            retval.replace(ptr(0));
        }
    }
});

// 4. 检测 Frida 内存标记
Interceptor.attach(Module.getExportByName(null, 'mmap'), {
    onEnter: function(args) {
        this.size = args[1].toInt32();
    },
    onLeave: function(retval) {
        // Frida 注入的内存可能有特定标记
        if (retval.toInt32() !== -1) {
            // 可以检查内存标记
        }
    }
});

// 5. 绕过端口检测
function patchPort() {
    var fridaPort = 27042;
    // 修改所有尝试连接 27042 的代码
    var addresses = Module.findExportAddresses(null, 'connect');
    addresses.forEach(function(addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var sockaddr = args[1];
                var port = sockaddr.add(2).readU16();
                port = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
                if (port === fridaPort) {
                    sockaddr.add(2).writeU16(0);  // 改为 0
                }
            }
        });
    });
}
"""
```

### 6. Unicorn 模拟执行绕过反调试

```python
# 使用 Unicorn Engine 模拟执行绕过所有反调试
from unicorn import *
from unicorn.x86_const import *
import struct

def emulate_with_unicorn(binary_path, entry_point, max_instructions=10000):
    """使用 Unicorn 模拟执行绕过反调试"""
    
    with open(binary_path, 'rb') as f:
        code = f.read()
    
    # 初始化模拟器
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # 映射内存
    base_addr = 0x400000
    mu.mem_map(base_addr, 0x100000)
    mu.mem_write(base_addr, code[:0x100000])
    
    # 设置初始寄存器
    mu.reg_write(UC_X86_REG_RSP, 0x7fff0000)
    mu.reg_write(UC_X86_REG_RBP, 0x7fff0000)
    mu.reg_write(UC_X86_REG_RIP, entry_point)
    
    # Hook 系统调用
    def hook_syscall(mu, user_data):
        syscall_num = mu.reg_read(UC_X86_REG_RAX)
        print(f"[*] 系统调用: {syscall_num}")
        
        # ptrace = 101 (x86_64 Linux)
        if syscall_num == 101:
            mu.reg_write(UC_X86_REG_RAX, 0)  # 返回成功
    
    mu.hook_add(UC_HOOK_INTR, hook_syscall)
    
    # 执行
    try:
        mu.emu_start(entry_point, entry_point + len(code[:0x100000]), 
                     count=max_instructions)
    except UcError as e:
        print(f"[*] 执行停止: {e}")
    
    # Dump 结果
    result = mu.mem_read(base_addr, 0x1000)
    return bytes(result)

# 使用示例
# result = emulate_with_unicorn("target", 0x401000)
```

### 7. GDB 反调试绕过脚本

```bash
# GDB 完整反调试绕过脚本
# 保存为 gdb_bypass.gdb

cat > gdb_bypass.gdb << 'GDBEOF'
# 绕过 ptrace 检测
catch syscall ptrace
commands
    silent
    set $rax = 0
    continue
end

# 绕过 /proc/self/status 检测
catch syscall openat
commands
    silent
    # 检查文件名参数
    set $path = (char*)$rdx
    # 如果是 /proc/self/status，修改返回值
    continue
end

# 绕过时间检测
catch syscall clock_gettime
commands
    silent
    set $rax = 0
    continue
end

# 绕过 SIGTRAP
handle SIGTRAP nostop noprint pass

# 绕过 INT3
set *($rip) = 0x90909090  # NOP

# 绕过 IsDebuggerPresent (Windows wine)
# set {char}(*(*(int*)($fs_base + 0x60) + 0x2) = 0

# 自动 patch 已知反调试
# patch_isDebuggerPresent:
#   find 的到地址后直接 patch

define bypass_anti_debug
    # 查找 ptrace 调用
    find /b $rip, $rip+0x1000, 0xff 0xd0
    # NOP 掉
end

GDBEOF

# 使用
gdb -x gdb_bypass.gdb ./target
```

### 8. WinDbg 反调试绕过 (Windows)

```bash
# WinDbg 反调试绕过命令
# 保存为 windbg_bypass.wds

# 绕过 IsDebuggerPresent
ed @$peb+0x2 0  # PEB.BeingDebugged = 0

# 绕过 NtGlobalFlag
ed @$peb+0xbc 0  # PEB.NtGlobalFlag = 0

# 绕过 ProcessDebugPort
!peb  # 查看 PEB
ed @$peb+0x10 0  # ProcessDebugPort

# 绕过硬件断点
r dr0=0
r dr1=0
r dr2=0
r dr3=0
r dr7=0

# 绕过时间检测
# 每次断点后修改时间戳
.format rdtsc
# 或 hook GetTickCount

# 绕过 SEH 链检测
!exchain  # 查看异常链
# 修改异常处理函数指针

# ScyllaHide 自动绕过
# 安装 ScyllaHide 插件
# 或手动绕过
bp ntdll!NtQueryInformationProcess "r rcx = @$peb; r r8 = 0; r r9 = 4; r r10 = 0"
```

### 9. 自动化反调试检测框架

```python
# 自动化反调试检测和绕过框架
import subprocess
import re
import json

class AntiDebugDetector:
    """自动检测二进制中的反调试技术"""
    
    def __init__(self, binary_path):
        self.binary = binary_path
        self.detections = []
    
    def detect(self):
        """执行完整检测"""
        # 1. 字符串检测
        self._check_strings()
        # 2. API 调用检测
        self._check_api_calls()
        # 3. 汇编指令检测
        self._check_asm_patterns()
        return self.detections
    
    def _check_strings(self):
        """检查反调试相关字符串"""
        result = subprocess.run(
            ['strings', self.binary],
            capture_output=True, text=True
        )
        
        patterns = {
            'ptrace': 'ptrace',
            'IsDebuggerPresent': 'IsDebuggerPresent',
            'NtQueryInformationProcess': 'NtQueryInformationProcess',
            '/proc/self/status': '/proc/self/status',
            'TracerPid': 'TracerPid',
            'VMware': 'VMware|VirtualBox|QEMU',
            'sandbox': 'sandbox|Sandbox',
            'debug': 'debug|DEBUG|Debug',
        }
        
        for name, pattern in patterns.items():
            if re.search(pattern, result.stdout, re.IGNORECASE):
                self.detections.append({
                    'type': 'string',
                    'technique': name,
                    'detail': f'发现反调试字符串: {name}'
                })
    
    def _check_api_calls(self):
        """检查反调试 API 调用"""
        # 使用 objdump/nm 检查导入表
        result = subprocess.run(
            ['objdump', '-T', self.binary],
            capture_output=True, text=True
        )
        
        dangerous_apis = [
            'ptrace', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'GetTickCount',
            'QueryPerformanceCounter', '__rdtsc',
            'OutputDebugString', 'FindWindow',
        ]
        
        for api in dangerous_apis:
            if api in result.stdout:
                self.detections.append({
                    'type': 'api',
                    'technique': api,
                    'detail': f'检测到反调试 API: {api}'
                })
    
    def _check_asm_patterns(self):
        """检查汇编模式"""
        result = subprocess.run(
            ['objdump', '-d', self.binary],
            capture_output=True, text=True
        )
        
        # int3 (0xCC) 检测
        int3_count = result.stdout.count('int3')
        if int3_count > 5:
            self.detections.append({
                'type': 'asm',
                'technique': 'INT3',
                'detail': f'发现 {int3_count} 个 INT3 指令'
            })
        
        # cpuid 检测
        if 'cpuid' in result.stdout:
            self.detections.append({
                'type': 'asm',
                'technique': 'CPUID',
                'detail': '检测到 CPUID 使用（可能是反虚拟机）'
            })
    
    def generate_bypass(self):
        """生成绕过脚本"""
        frida_script = '// 自动反调试绕过\n'
        
        for det in self.detections:
            if det['technique'] == 'ptrace':
                frida_script += '''
Interceptor.attach(Module.getExportByName(null, 'ptrace'), {
    onLeave: function(retval) { retval.replace(ptr(0)); }
});
'''
            elif det['technique'] == 'IsDebuggerPresent':
                frida_script += '''
Interceptor.attach(Module.getExportByName(null, 'IsDebuggerPresent'), {
    onLeave: function(retval) { retval.replace(ptr(0)); }
});
'''
            elif det['technique'] == 'NtQueryInformationProcess':
                frida_script += '''
Interceptor.attach(Module.getExportByName(null, 'NtQueryInformationProcess'), {
    onEnter: function(args) { this.cls = args[1].toInt32(); },
    onLeave: function(retval) {
        if (this.cls === 7) retval.replace(ptr(0));
    }
});
'''
        
        return frida_script

# 使用
detector = AntiDebugDetector('./target_binary')
detections = detector.detect()
print(json.dumps(detections, indent=2, ensure_ascii=False))
print('\n--- Frida 绕过脚本 ---')
print(detector.generate_bypass())
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
