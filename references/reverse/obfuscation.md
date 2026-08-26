# 混淆与脱壳 (Obfuscation & Unpacking)

## 原理

程序通过代码混淆、虚拟机保护、加壳等技术增加逆向难度。本文件介绍常见混淆/加壳技术及脱壳/反混淆方法。

## 常见混淆技术

### 1. OLLVM (Obfuscator-LLVM)

```c
// 原始代码
int add(int a, int b) {
    return a + b;
}

// OLLVM 混淆后
int add(int a, int b) {
    int result = 0;
    int state = 0x12345678;
    while (1) {
        switch (state) {
            case 0x12345678:
                result = a;
                state = 0x87654321;
                break;
            case 0x87654321:
                result += b;
                state = 0xdeadbeef;
                break;
            case 0xdeadbeef:
                return result;
        }
    }
}
```

#### OLLVM 特征

- 控制流平坦化（Control Flow Flattening）
- 虚假控制流（Bogus Control Flow）
- 指令替换（Instruction Substitution）

#### 反混淆方法

```python
# 1. 静态分析
# - 识别分发器
# - 还原控制流

# 2. 动态分析
# - Unicorn 模拟执行
# - 记录执行路径

# 3. 符号执行
# - angr
# - manticore

# 4. ML 辅助
# - 使用 LLM 识别模式
```

### 2. 虚拟机保护 (VMP)

```c
// 将代码编译为自定义字节码
// 运行时由虚拟机解释执行

// 特征：
// - 自定义指令集
// - 字节码解释器
// - 难以静态分析
```

#### 常见 VMP

- VMProtect
- Themida
- Code Virtualizer
- Enigma Protector

#### 反 VMP 方法

```python
# 1. 识别虚拟机结构
# - 分发器
# - handler 表
# - 上下文结构

# 2. 还原指令集
# - 分析每个 handler
# - 建立指令映射

# 3. 动态分析
# - 记录执行的 handler
# - 还原执行流程

# 4. 工具
# - VMPAttack
# - Triton
# - 各 VMP 分析工具
```

### 3. 代码加密

```c
// 运行时解密代码
// 执行后重新加密

// 特征：
// - 自修改代码
// - 运行时解密
```

#### 反加密方法

```python
# 1. 内存 dump
# - 等代码解密后 dump
# - 重建 PE/ELF

# 2. 动态分析
# - 在解密后下断点
# - 跟踪执行

# 3. 工具
# - Scylla
# - ImpRec
```

### 4. 反汇编混淆

```asm
// 花指令
jmp label
db 0xe8  ; 假的 call 指令
label:
; 实际代码

// 跳转混淆
jmp label1
label1:
jmp label2
label2:
; 实际代码
```

#### 反混淆方法

```python
# 1. 识别花指令
# - 模式匹配
# - 动态执行

# 2. 修复反汇编
# - 移除花指令
# - 重新反汇编

# 3. 工具
# - IDA Pro
# - Ghidra
# - r2
```

## 常见壳

### 1. UPX

```bash
# 脱壳
upx -d ./packed

# 特征
# - UPX! 标识
# - 简单的压缩算法
```

### 2. ASPack

```bash
# 脱壳
# 1. 内存 dump
# 2. 修复 IAT

# 特征
# - aPLib 压缩
```

### 3. PECompact

```bash
# 脱壳
# 1. 内存 dump
# 2. 修复 IAT
```

### 4. Themida

```bash
# 脱壳
# 1. 反 VM
# 2. 内存 dump
# 3. 修复 IAT

# 特征
# - VM 保护
# - 反调试
```

### 5. VMProtect

```bash
# 脱壳
# 1. 反 VM
# 2. 内存 dump
# 3. 修复 IAT

# 特征
# - VM 保护
# - 反调试
```

## 脱壳方法

### 1. 内存 dump

```bash
# 1. 运行程序
# 2. 等待解密完成
# 3. dump 内存
# 4. 修复 PE/ELF

# 工具
# - Scylla (Windows)
# - ImpRec (Windows)
# - LordPE (Windows)
# - gdb (Linux)
```

### 2. 修复 IAT

```bash
# 1. 找到原始 IAT
# 2. 重建 IAT
# 3. 修复导入表

# 工具
# - Scylla
# - ImpRec
```

### 3. 修复重定位

```bash
# 1. 找到重定位表
# 2. 修复重定位
```

## 反混淆工具

### 1. IDA Pro 插件

```bash
# - Hex-Rays Decompiler
# - FindCrypt
# - Signsrch
# - HexRaysPyTools
# - Microcode 插件
```

### 2. Ghidra 插件

```bash
# - Ghidraa
# - 各反混淆插件
```

### 3. 自动化工具

```python
# angr
# - 符号执行
# - 控制流恢复

# Triton
# - 动态符号执行
# - 反混淆

# miasm
# - 符号执行
# - 反汇编

# Unicorn
# - 模拟执行
# - 代码跟踪
```

## 2024-2026 新技术点

### 1. OLLVM 控制流还原 (angr)

```python
# 使用 angr 进行 OLLVM 控制流还原
import angr
import claripy

def deobfuscate_ollvm(binary_path):
    """使用 angr 符号执行还原 OLLVM 混淆"""
    
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # 创建初始状态
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    
    # 探索所有路径（限制深度避免路径爆炸）
    simgr.explore(n=10000)
    
    # 分析找到的路径
    paths = simgr.found + simgr.active
    print(f"[*] 探索到 {len(paths)} 个状态")
    
    # 提取有效路径
    for state in paths:
        try:
            # 获取反汇编
            cfg = proj.factory.cfg_model
            print(f"[*] RIP: {state.regs.rip}")
        except:
            pass
    
    return simgr

# 使用 IDA Pro 脚本还原 OLLVM 控制流
idascript = '''
# IDA Pro OLLVM 反混淆脚本
import idaapi
import idautils
import idc

def find_switch_dispatcher():
    """查找 OLLVM 分发器 (switch-case 状态机)"""
    # 查找所有 switch 语句
    for head in idautils.Heads():
        if idc.print_insn_mnem(head) == 'jmp':
            # 检查是否是间接跳转 (switch)
            refs = list(idautils.XrefsFrom(head))
            if refs:
                # 分析 switch 表
                target = refs[0].to
                print(f"[*] 分发器跳转: {head:#x} -> {target:#x}")

def identify_bogus_cf():
    """识别虚假控制流"""
    # 查找永远为 true/false 的条件跳转
    for head in idautils.Heads():
        if idc.print_insn_mnem(head) in ['jz', 'jnz', 'je', 'jne']:
            # 检查条件是否恒真/恒假
            prev = idc.prev_head(head)
            if idc.print_insn_mnem(prev) == 'cmp':
                op1 = idc.print_operand(prev, 0)
                op2 = idc.print_operand(prev, 1)
                if op1 == op2:  # cmp reg, reg (恒真)
                    print(f"[*] 虚假条件: {head:#x}")
                    # NOP 掉跳转
                    idc.patch_byte(head, 0x90)
                    idc.patch_byte(head + 1, 0x90)

# 执行
find_switch_dispatcher()
identify_bogus_cf()
'''
```

### 2. VMP 虚拟机保护分析

```python
# VMP (VMProtect) 分析方法
import struct
import re

class VMProtectAnalyzer:
    """VMProtect 分析器"""
    
    def __init__(self, binary_path):
        with open(binary_path, 'rb') as f:
            self.data = f.read()
    
    def find_vm_entry(self):
        """查找 VM 入口点"""
        # VMProtect 入口特征
        patterns = [
            b'\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00',  # push 0; push 0
            b'\x9c\x60',  # pushfd; pushad
            b'\x60\x9c',  # pushad; pushfd
        ]
        
        entries = []
        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break
                entries.append(pos)
                offset = pos + 1
        
        return entries
    
    def find_dispatcher(self):
        """查找 VM 分发器"""
        # 分发器通常是一个间接跳转到 handler table
        # 特征：大量 switch-case 结构
        
        # 查找常见的分发器模式
        # rdx = bytecode[i]; jmp [handler_table + rdx * 8]
        patterns = [
            rb'\x48\x8b\x01\x48\x8d\x0d',  # mov rax, [rcx]; lea rcx, [rip+...]
            rb'\x8a\x01\x0f\xb6\xc0',        # mov al, [rcx]; movzx eax, al
        ]
        
        dispatchers = []
        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break
                dispatchers.append(pos)
                offset = pos + 1
        
        return dispatchers
    
    def extract_bytecode(self, vm_entry_offset):
        """提取 VM 字节码"""
        # 在 VMProtect 中，字节码通常在 .vmp 节中
        # 需要找到 handler table 并逆向指令集
        
        # 查找 .vmp 节
        vmp_start = self.data.find(b'.vmp')
        if vmp_start != -1:
            print(f"[*] 找到 .vmp 节: {vmp_start:#x}")
        
        return None
    
    def analyze_handlers(self):
        """分析 VM handler"""
        # VMProtect handler 通常很小 (< 20 条指令)
        # 每个 handler 实现一个虚拟指令
        
        # 查找 handler table
        # 通常通过相对引用定位
        
        print("[*] Handler 分析需要结合动态调试")
        print("[*] 推荐工具: VMPAttack, x64dbg + VMP 插件")

# 使用
analyzer = VMProtectAnalyzer('protected_binary.exe')
entries = analyzer.find_vm_entry()
print(f"[*] VM 入口点: {[hex(e) for e in entries]}")

dispatchers = analyzer.find_dispatcher()
print(f"[*] 分发器: {[hex(d) for d in dispatchers]}")
```

### 3. angr 自动化反混淆

```python
# 使用 angr 进行自动化反混淆
import angr
import claripy

class AngerDeobfuscation:
    """angr 自动化反混淆"""
    
    def __init__(self, binary_path):
        self.proj = angr.Project(binary_path, auto_load_libs=False)
    
    def symbolic_execution(self, start_addr, end_addr):
        """符号执行获取路径约束"""
        state = self.proj.factory.blank_state(addr=start_addr)
        
        # 设置符号输入
        input_size = 64
        stdin = claripy.BVS('stdin', input_size * 8)
        state.memory.store(0x7fff0000, stdin)
        
        simgr = self.proj.factory.simulation_manager(state)
        
        # 在目标地址下断点
        simgr.explore(find=end_addr)
        
        if simgr.found:
            found_state = simgr.found[0]
            # 获取约束
            constraints = found_state.solver.constraints
            print(f"[*] 约束数量: {len(constraints)}")
            
            # 求解
            try:
                solution = found_state.solver.eval(stdin, cast_to=bytes)
                print(f"[*] 解: {solution}")
            except:
                print("[-] 无法求解")
        
        return simgr
    
    def recover_function(self, func_addr):
        """还原被混淆的函数"""
        cfg = self.proj.analyses.CFGFast()
        
        # 查找函数
        func = cfg.kb.functions.get(func_addr)
        if func:
            print(f"[*] 函数: {func.name}")
            print(f"    基本块: {len(func.blocks)}")
            
            # 分析控制流
            for block in func.blocks:
                print(f"    Block @ {block.addr:#x} ({block.size} bytes)")
    
    def find_hidden_strings(self):
        """查找隐藏字符串"""
        # 符号执行所有路径，收集字符串操作
        state = self.proj.factory.entry_state()
        simgr = self.proj.factory.simulation_manager(state)
        
        strings_found = []
        
        def collect_strings(state):
            # 检查内存中的字符串
            try:
                for addr in range(0x400000, 0x500000, 0x1000):
                    data = state.memory.load(addr, 0x100)
                    if data.concrete:
                        s = bytes(data.concrete_value).decode('ascii', errors='ignore')
                        if s.isprintable() and len(s) > 3:
                            strings_found.append((addr, s))
            except:
                pass
        
        simgr.explore(n=1000, step_func=lambda sm: collect_strings(sm.active[0]) if sm.active else None)
        
        return strings_found

# 使用
deobf = AngerDeobfuscation('./obfuscated_binary')
deobf.recover_function(0x401000)
strings = deobf.find_hidden_strings()
for addr, s in strings[:10]:
    print(f"  {addr:#x}: {s}")
```

### 4. Ghidra 反混淆插件

```bash
# Ghidra 反混淆脚本和插件

# 1. Ghidra Diff (比较混淆前后)
# Script: DiffAnalysis.py

# 2. 使用 Ghidra P-Code 进行反混淆
# P-Code 是 Ghidra 的中间表示
# 可以在 P-Code 级别进行模式匹配

# 3. Ghidra GAN — AI 辅助反编译
# 使用 GAN 模型提升反编译质量

# 4. Ghidra 常用反混淆脚本
cat > DeobfuscateControlFlow.java << 'JAVA'
// Ghidra 脚本：简化控制流
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.CancelledException;

public class DeobfuscateControlFlow extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(true);
        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = iter.next();
            
            // 识别并简化 OLLVM 模式
            if (instr.getMnemonicString().equals("CMP")) {
                // 检查是否是比较恒真/恒假
                // ...
            }
            
            if (instr.getMnemonicString().equals("JMP") && 
                instr.getNumOperands() == 0) {
                // 识别死代码跳转
                println("[*] 死代码跳转: " + instr.getAddress());
            }
        }
    }
}
JAVA

# 5. 使用 Binary Ninja API
# pip install binaryninja
cat > bn_deobfuscate.py << 'PYTHON'
# Binary Ninja 反混淆 API
# from binaryninja import BinaryView
# bv = BinaryView.open('obfuscated_binary')
# 
# for func in bv.functions:
#     for block in func.basic_blocks:
#         # 分析和简化控制流
#         pass
PYTHON
```

### 5. 代码加密壳自动脱壳

```python
# 自动检测和脱壳
import subprocess
import struct
import os

class AutoUnpacker:
    """自动脱壳器"""
    
    def __init__(self, binary_path):
        self.path = binary_path
        with open(binary_path, 'rb') as f:
            self.data = f.read()
    
    def detect_packer(self):
        """检测壳类型"""
        packers = {
            b'UPX!': 'UPX',
            b'aspack': 'ASPack',
            b'.ndata': 'NSIS Installer',
            b'PEC2': 'PECompact',
            b'MEW': 'MEW',
            b'.themida': 'Themida',
            b'VMProtect': 'VMProtect',
        }
        
        for sig, name in packers.items():
            if sig in self.data:
                print(f"[+] 检测到壳: {name}")
                return name
        
        print("[-] 未检测到已知壳")
        return None
    
    def unpack_upx(self):
        """UPX 脱壳"""
        result = subprocess.run(
            ['upx', '-d', self.path, '-o', f'{self.path}.unpacked'],
            capture_output=True, text=True
        )
        print(result.stdout)
        return result.returncode == 0
    
    def memory_dump_approach(self):
        """内存 dump 方法"""
        # 使用 gdb 进行内存 dump
        gdb_script = f'''
set pagination off
b *0x401000  # OEP (Original Entry Point)
run
# 等待解压完成
dump binary memory {self.path}.dump 0x400000 0x500000
quit
'''
        
        with open('/tmp/gdb_unpack.gdb', 'w') as f:
            f.write(gdb_script)
        
        subprocess.run(['gdb', '-batch', '-x', '/tmp/gdb_unpack.gdb', self.path])
        
        if os.path.exists(f'{self.path}.dump'):
            print(f"[+] 内存 dump 已保存: {self.path}.dump")
            return True
        return False
    
    def fix_iat(self, dump_path):
        """修复导入表 (IAT)"""
        # 使用 ImpRec 或 Scylla
        print("[*] 使用 Scylla 修复 IAT")
        print("    1. 在调试器中运行到 OEP")
        print("    2. dump 内存")
        print("    3. 使用 Scylla 修复 IAT")
        
        # 自动化 Scylla 命令
        scylla_script = f'''
# ScyllaEx 自动化
# 1. 获取 IAT 地址
# 2. 重建导入表
# 3. 修复重定位
'''
        return scylla_script

# 使用
unpacker = AutoUnpacker('./packed_binary.exe')
packer = unpacker.detect_packer()
if packer == 'UPX':
    unpacker.unpack_upx()
else:
    unpacker.memory_dump_approach()
```

### 6. Intel PT 处理器跟踪反混淆

```bash
# Intel Processor Trace (PT) — 硬件级执行跟踪
# 可以精确记录程序执行路径，绕过软件反调试

# 1. 使用 perf record + Intel PT
perf record -e intel_pt// -c 1000000 ./target_binary
perf script --itrace=i10us

# 2. 使用 Linux perf + Intel PT 分析
perf report --stdio --header

# 3. 使用 Intel PT 解码器
# apt install intel-pt-tools
ipt_decoded=$(iptdump trace.bin)
echo "$ipt_decoded" | head -50

# 4. 使用 GDB + Intel PT
# gdb 连接到支持 Intel PT 的目标
# set perf event intel_pt
# record

# 5. Python 分析 Intel PT 输出
python3 << 'PYEOF'
# 解析 Intel PT 跟踪数据
# 每条记录包含: IP, 事件类型

def analyze_pt_trace(trace_file):
    """分析 Intel PT 跟踪"""
    with open(trace_file) as f:
        instructions = f.readlines()
    
    # 统计执行的基本块
    from collections import Counter
    block_counter = Counter()
    for line in instructions:
        if 'ip=' in line:
            ip = line.split('ip=')[1].split()[0]
            block_counter[ip] += 1
    
    # 找到执行频率最高的代码段 (可能是反调试检查)
    print("[*] 高频执行地址:")
    for addr, count in block_counter.most_common(10):
        print(f"    {addr}: {count} 次")

# analyze_pt_trace("trace.txt")
PYEOF
```

### 7. LLM 辅助反混淆

```python
# 使用 LLM 辅助反混淆分析
import json

def deobfuscate_with_llm(decompiled_code):
    """使用 LLM 分析混淆代码"""
    
    prompt = f"""分析以下混淆代码，还原其原始逻辑。
重点关注：
1. 控制流平坦化的状态机结构
2. 虚假控制流（永远为 true/false 的分支）
3. 指令替换的原始操作
4. 隐藏的字符串和常量

混淆代码:
```c
{decompiled_code}
```

请提供：
1. 原始逻辑描述
2. 关键变量的含义
3. 还原后的伪代码
"""
    
    # 使用 API 调用 LLM
    # response = openai.ChatCompletion.create(
    #     model="gpt-4",
    #     messages=[{"role": "user", "content": prompt}]
    # )
    
    return prompt  # 返回 prompt 供手动分析

# 自动化分析工作流
def automated_analysis(binary_path):
    """自动化反混淆工作流"""
    steps = [
        "1. 使用 DIE/PEiD 识别壳类型",
        "2. 使用 UPX 脱壳 (如果是 UPX)",
        "3. 使用 IDA Pro/Ghidra 反编译",
        "4. 使用 angr 符号执行还原控制流",
        "5. 使用 Frida 动态 hook 关键函数",
        "6. 使用 LLM 分析反编译结果",
        "7. 手动 patch 和验证",
    ]
    
    for step in steps:
        print(f"[*] {step}")
    
    return steps
```

### 8. Tigress 混淆逆向

```python
# Tigress — 多功能 C 代码混淆器
# 逆向 Tigress 混淆代码

class TigressReverse:
    """Tigress 混淆逆向"""
    
    @staticmethod
    def identify_virtuosifier(func_code):
        """识别 Tigress virtuosifier (虚拟机保护)"""
        # Tigress virtuosifier 特征：
        # 1. 大的 switch-case 状态机
        # 2. 字节数组作为 "代码"
        # 3. 复杂的指针运算
        
        indicators = [
            'switch',  # 状态机分发
            'case 0x',  # 大量 case
            '>>',  # 位移操作
            '& 0xff',  # 字节提取
            'dispatch',  # 分发器
        ]
        
        score = sum(1 for ind in indicators if ind in func_code)
        return score >= 3
    
    @staticmethod
    def identify_encode_decode(func_code):
        """识别 Tigress encode-decode 函数"""
        # Tigress 添加的编码/解码函数
        # 通常在函数开头和结尾
        
        patterns = [
            ('decode', r'decode_[a-z0-9]+'),
            ('encode', r'encode_[a-z0-9]+'),
            ('transform', r'transform_[a-z0-9]+'),
            ('obfuscate', r'obfuscate_[a-z0-9]+'),
        ]
        
        import re
        found = []
        for name, pattern in patterns:
            matches = re.findall(pattern, func_code)
            if matches:
                found.extend(matches)
        
        return found
    
    @staticmethod
    def analyze_split(func_code):
        """分析 Tigress split (函数分裂)"""
        # Tigress 会将一个函数分裂成多个小函数
        # 需要将它们重新组合
        
        print("[*] Tigress split 分析:")
        print("    1. 查找所有被调用的小函数")
        print("    2. 分析参数传递")
        print("    3. 合并逻辑")
        print("    4. 还原原始函数")

# 使用
tigress = TigressReverse()
print(tigress.identify_virtuosifier("switch(state) { case 0x1234: ... }"))
```

### 9. 混淆 Wasm 模块分析

```python
# 分析混淆的 WebAssembly 模块
import struct

class WasmObfuscationAnalysis:
    """混淆 WASM 分析"""
    
    @staticmethod
    def detect_control_flow_flattening(wasm_binary):
        """检测 WASM 控制流平坦化"""
        with open(wasm_binary, 'rb') as f:
            data = f.read()
        
        # 查找 switch (br_table) 指令
        # br_table = 0x0E
        br_table_count = data.count(b'\x0e')
        
        # 查找大量 case 的 br_table
        indicators = {
            'br_table': br_table_count,
            'i32_eqz': data.count(b'\x45'),  # i32.eqz
            'br_if': data.count(b'\x0d'),     # br_if
            'loop': data.count(b'\x03'),       # loop
            'block': data.count(b'\x02'),      # block
        }
        
        is_flattened = br_table_count > 5  # 多个分发表
        return is_flattened, indicators
    
    @staticmethod
    def extract_strings(wasm_binary):
        """提取 WASM 数据段中的字符串"""
        with open(wasm_binary, 'rb') as f:
            data = f.read()
        
        # 查找字符串（可打印 ASCII 序列）
        strings = []
        current = b''
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) > 5:
                    try:
                        s = current.decode('ascii')
                        strings.append(s)
                    except:
                        pass
                current = b''
        
        return strings

# 使用
analyzer = WasmObfuscationAnalysis()
is_flat, indicators = analyzer.detect_control_flow_flattening('obfuscated.wasm')
print(f"控制流平坦化: {is_flat}")
print(f"指标: {indicators}")
strings = analyzer.extract_strings('obfuscated.wasm')
print(f"字符串: {strings[:10]}")
```

## 工具推荐

- **UPX** — UPX 脱壳
- **Scylla** — IAT 修复
- **ImpRec** — IAT 修复
- **LordPE** — PE 编辑
- **IDA Pro** — 反汇编/反编译
- **Ghidra** — 反汇编/反编译
- **angr** — 符号执行
- **Triton** — 动态符号执行
- **Unicorn** — 模拟执行
- **DIE** — 文件类型识别
- **PEiD** — PE 文件识别

## 参考链接

- [ctf-wiki obfuscation](https://ctf-wiki.org/reverse/obfuscation/)
- [OLLVM](https://github.com/obfuscator-llvm/obfuscator)
- [Tigress](https://tigress.wtf/)
- [angr](https://angr.io/)
- [Triton](https://triton-library.github.io/)
