# WASM 逆向 (WebAssembly Reverse)

## 原理

WebAssembly (WASM) 是一种可移植的二进制格式，越来越多 Web 应用使用 WASM 实现核心逻辑。逆向 WASM 需要理解其指令集、内存模型、与 JS 的交互。

## WASM 结构

```
WASM 二进制格式
├── Magic Number: \0asm
├── Version: 1
├── Type Section      # 函数签名
├── Import Section    # 导入函数
├── Function Section  # 函数声明
├── Table Section     # 函数表
├── Memory Section    # 线性内存
├── Global Section    # 全局变量
├── Export Section    # 导出函数
├── Start Section     # 启动函数
├── Element Section   # 表表初始化
├── Code Section      # 函数代码
└── Data Section      # 内存初始化
```

## 攻击链

### 1. 提取 WASM

```bash
# 从 HTML 提取
grep -oP 'src="[^"]*\.wasm"' page.html

# 从 JS 提取
grep -oP 'WebAssembly\.instantiate\([^)]*\)' app.js

# 从浏览器开发者工具
# Network -> Filter: WASM

# 从二进制提取
binwalk ./binary
foremost ./binary
```

### 2. 反编译

```bash
# wasm2wat (WABT 工具包)
wasm2wat ./module.wasm -o module.wat

# wasm-decompile (WABT)
wasm-decompile ./module.wasm -o module.dcmp

# wasm2c (WABT)
wasm2c ./module.wasm -o module.c

# Ghidra WASM 插件
# https://github.com/nneonneo/ghidra-wasm-plugin

# IDA Pro 7.4+ 支持 WASM

# wasm-objdump
wasm-objdump -x ./module.wasm  # 段信息
wasm-objdump -d ./module.wasm  # 反汇编
wasm-objdump -s ./module.wasm  # 数据段
```

### 3. 分析 WASM

```bash
# 函数列表
wasm-objdump -x ./module.wasm | grep "func"

# 导出函数
wasm-objdump -x ./module.wasm | grep "Export"

# 导入函数
wasm-objdump -x ./module.wasm | grep "Import"

# 数据段（可能包含字符串）
wasm-objdump -s ./module.wasm
```

### 4. 动态分析

```javascript
// Chrome DevTools
// Sources -> WASM
// 可以下断点、单步执行

// Frida hook
Interceptor.attach(Module.findExportByName('module.wasm', 'function_name'), {
    onEnter: function(args) {
        console.log('called');
    },
    onLeave: function(retval) {
        console.log('returned:', retval);
    }
});

// 自定义 hook
const original = Module.findExportByName('module.wasm', 'function_name');
Interceptor.replace(original, new NativeCallback(function() {
    console.log('hooked');
    return original();
}, 'int', []));
```

### 5. 内存分析

```javascript
// WASM 线性内存
// 通过 exports 访问
const memory = instance.exports.memory;
const view = new Uint8Array(memory.buffer);

// 读取内存
function readString(addr) {
    let str = '';
    while (view[addr] !== 0) {
        str += String.fromCharCode(view[addr]);
        addr++;
    }
    return str;
}

// 写入内存
function writeString(addr, str) {
    for (let i = 0; i < str.length; i++) {
        view[addr + i] = str.charCodeAt(i);
    }
    view[addr + str.length] = 0;
}
```

### 6. 调用 WASM 函数

```javascript
// 通过 exports 调用
const result = instance.exports.function_name(arg1, arg2);

// 传递字符串
function callWithString(func, str) {
    const addr = instance.exports.malloc(str.length + 1);
    writeString(addr, str);
    const result = func(addr);
    instance.exports.free(addr);
    return result;
}
```

## 常见保护

### 1. 字符串加密

```python
# WASM 中的字符串可能被加密
# 需要找到解密函数
# 动态执行时 dump 解密后的字符串
```

### 2. 控制流混淆

```python
# 类似 OLLVM
# 控制流平坦化
# 虚假控制流
```

### 3. 反调试

```javascript
// 检测调试器
// 1. 时间检测
// 2. 环境检测
// 3. 完整性检测
```

### 4. 完整性校验

```python
# 校验 WASM 模块完整性
# 防止修改
```

## 2024-2026 新技术点

### 1. WASM SIMD 指令分析

```bash
# WASM 2.0 SIMD 指令分析
# SIMD (128-bit 向量操作) 使逆向更复杂

# 使用 wasm-decompile 查看反编译结果
wasm-decompile ./simd_module.wasm -o decompiled.dcmp

# 使用 wasm-objdump 反汇编
wasm-objdump -d ./simd_module.wasm | grep -i "v128\|i32x4\|i64x2\|f32x4\|f64x2"

# SIMD 指令常见于加密/解密函数
# 特征：v128.load, v128.store, i32x4.add 等
python3 << 'PYEOF'
import re

def analyze_simd_usage(wasm_path):
    """分析 WASM 中的 SIMD 使用"""
    import subprocess
    
    result = subprocess.run(
        ['wasm-objdump', '-d', wasm_path],
        capture_output=True, text=True
    )
    
    simd_instructions = {}
    simd_ops = ['v128', 'i32x4', 'i64x2', 'f32x4', 'f64x2', 'i16x8', 'i8x16']
    
    for line in result.stdout.split('\n'):
        for op in simd_ops:
            if op in line:
                simd_instructions.setdefault(op, []).append(line.strip())
    
    print(f"[*] SIMD 指令统计:")
    for op, usages in sorted(simd_instructions.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"    {op}: {len(usages)} 次")
    
    # 如果 SIMD 用于加密，可能是关键算法
    if simd_instructions:
        print("[*] SIMD 可能用于：")
        if any('i32x4' in ops for ops in simd_instructions.values()):
            print("    - 整数向量运算（可能是加密/哈希）")
        if any('f32x4' in ops for ops in simd_instructions.values()):
            print("    - 浮点向量运算（可能是 ML/科学计算）")
    
    return simd_instructions

# analyze_simd_usage("module.wasm")
PYEOF
```

### 2. WASI 系统接口分析

```bash
# WASI (WebAssembly System Interface) 分析
# WASI 模块可以访问文件系统、网络等

# 使用 wasmtime 分析 WASI 模块
wasmtime --dir=. wasi_module.wasm

# 使用 wasm-tools 分析导入/导出
wasm-tools component wit wasi_module.wasm 2>/dev/null || \
wasm-objdump -j Import -x wasi_module.wasm | grep -i "wasi\|fd_\|path_\|env"

# 分析 WASI 能力
python3 << 'PYEOF'
import subprocess
import re

def analyze_wasi_capabilities(wasm_path):
    """分析 WASI 模块的系统调用能力"""
    result = subprocess.run(
        ['wasm-objdump', '-j', 'Import', '-x', wasm_path],
        capture_output=True, text=True
    )
    
    wasi_imports = {
        'file_access': [],
        'network': [],
        'env_vars': [],
        'clock': [],
        'random': [],
        'process': [],
    }
    
    for line in result.stdout.split('\n'):
        line_lower = line.lower()
        
        # 文件操作
        if 'fd_' in line_lower or 'path_' in line_lower:
            wasi_imports['file_access'].append(line.strip())
        
        # 网络（通过 wasi-sockets）
        if 'socket' in line_lower or 'tcp' in line_lower or 'udp' in line_lower:
            wasi_imports['network'].append(line.strip())
        
        # 环境变量
        if 'environ_get' in line_lower or 'environ_sizes' in line_lower:
            wasi_imports['env_vars'].append(line.strip())
        
        # 时钟
        if 'clock' in line_lower:
            wasi_imports['clock'].append(line.strip())
        
        # 随机数
        if 'random' in line_lower:
            wasi_imports['random'].append(line.strip())
        
        # 进程
        if 'proc_' in line_lower or 'exit' in line_lower:
            wasi_imports['process'].append(line.strip())
    
    print("[*] WASI 能力分析:")
    for cap, imports in wasi_imports.items():
        if imports:
            print(f"  {cap}: {len(imports)} 个导入")
            for imp in imports[:3]:
                print(f"    {imp[:100]}")
    
    return wasi_imports

# analyze_wasi_capabilities("wasi_module.wasm")
PYEOF
```

### 3. WASM 混淆检测与反混淆

```python
# WASM 混淆检测和反混淆
import struct
import subprocess

class WasmDeobfuscation:
    """WASM 反混淆"""
    
    def __init__(self, wasm_path):
        self.path = wasm_path
    
    def detect_obfuscation(self):
        """检测混淆类型"""
        with open(self.path, 'rb') as f:
            data = f.read()
        
        obfuscation_types = []
        
        # 检测控制流平坦化 (大量 br_table)
        br_table_count = data.count(b'\x0e')
        if br_table_count > 10:
            obfuscation_types.append(f"控制流平坦化 (br_table: {br_table_count})")
        
        # 检测字符串加密 (大量 i32.const + i32.xor 等)
        xor_count = data.count(b'\x47')  # i32.xor
        if xor_count > 50:
            obfuscation_types.append(f"字符串/数据加密 (xor: {xor_count})")
        
        # 检测死代码注入
        unreachable_count = data.count(b'\x00')  # unreachable
        nop_count = data.count(b'\x01')  # nop
        
        if unreachable_count > 20 or nop_count > 50:
            obfuscation_types.append(f"死代码注入 (unreachable: {unreachable_count}, nop: {nop_count})")
        
        # 检测自定义 VM
        call_indirect_count = data.count(b'\x11')  # call_indirect
        if call_indirect_count > 20:
            obfuscation_types.append(f"自定义 VM (call_indirect: {call_indirect_count})")
        
        return obfuscation_types
    
    def decompile_to_c(self):
        """反编译为 C 代码"""
        output_path = self.path.replace('.wasm', '.c')
        subprocess.run([
            'wasm2c', self.path, '-o', output_path
        ], capture_output=True)
        return output_path
    
    def decompile_to_wat(self):
        """转换为 WAT 文本格式"""
        output_path = self.path.replace('.wasm', '.wat')
        subprocess.run([
            'wasm2wat', self.path, '-o', output_path
        ], capture_output=True)
        return output_path
    
    def analyze_data_section(self):
        """分析数据段 (可能包含字符串/常量)"""
        result = subprocess.run(
            ['wasm-objdump', '-s', self.path],
            capture_output=True, text=True
        )
        
        # 提取可打印字符串
        strings = []
        for line in result.stdout.split('\n'):
            # 寻找可打印 ASCII
            parts = line.strip().split()
            for part in parts:
                try:
                    if all(32 <= ord(c) <= 126 for c in part) and len(part) > 3:
                        strings.append(part)
                except:
                    pass
        
        return strings

# 使用
deobf = WasmDeobfuscation('obfuscated.wasm')
obf_types = deobf.detect_obfuscation()
print(f"[*] 检测到混淆: {obf_types}")
strings = deobf.analyze_data_section()
print(f"[*] 数据段字符串: {strings[:10]}")
```

### 4. Frida 动态分析 WASM

```javascript
// Frida 分析 WASM 模块
// frida -U -l wasm_hook.js -f target_app

// Hook WASM 内存读写
function hookWasmMemory(instance) {
    if (instance.exports && instance.exports.memory) {
        const memory = instance.exports.memory;
        const view = new Uint8Array(memory.buffer);
        
        // 监控内存变化
        console.log('[*] WASM 内存大小:', memory.buffer.byteLength);
        
        // 读取特定地址
        function readString(addr, maxLen) {
            let str = '';
            for (let i = 0; i < maxLen; i++) {
                const byte = view[addr + i];
                if (byte === 0) break;
                str += String.fromCharCode(byte);
            }
            return str;
        }
        
        // Hook malloc/free
        if (instance.exports.malloc) {
            Interceptor.attach(instance.exports.malloc, {
                onEnter: function(args) {
                    this.size = args[0].toInt32();
                },
                onLeave: function(retval) {
                    console.log(`[*] malloc(${this.size}) = ${retval}`);
                }
            });
        }
        
        return { view, readString };
    }
    return null;
}

// Hook WebAssembly.instantiate
const origInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = function() {
    console.log('[*] WebAssembly.instantiate 被调用');
    return origInstantiate.apply(this, arguments).then(result => {
        const instance = result.instance || result;
        const exports = instance.exports || {};
        
        console.log('[*] WASM 导出函数:');
        for (const [name, func] of Object.entries(exports)) {
            if (typeof func === 'function') {
                console.log(`    ${name}(${func.length} params)`);
                
                // Hook 每个导出函数
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        console.log(`[*] ${name} 被调用`);
                    },
                    onLeave: function(retval) {
                        console.log(`[*] ${name} 返回: ${retval}`);
                    }
                });
            }
        }
        
        return result;
    });
};

// Hook WASM 线性内存操作
function dumpWasmMemory(instance, addr, size) {
    const memory = instance.exports.memory;
    const view = new Uint8Array(memory.buffer);
    const data = view.slice(addr, addr + size);
    console.log(`[*] 内存 dump [${addr}..${addr + size}]:`);
    console.log(Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' '));
    return data;
}
```

### 5. WASM 区块链智能合约逆向

```python
# 分析 WASM 智能合约 (Polkadot/EOS/Near)
import subprocess
import json

class WasmContractAnalysis:
    """WASM 智能合约逆向"""
    
    def __init__(self, wasm_path):
        self.path = wasm_path
    
    def analyze_polkadot_contract(self):
        """分析 Polkadot WASM 合约"""
        # Polkadot 合约使用 ink! 语言编译
        # 关键导出函数：
        # - call — 合约入口
        # - deploy — 部署入口
        # - seal_* — 系统调用
        
        result = subprocess.run(
            ['wasm-objdump', '-x', self.path],
            capture_output=True, text=True
        )
        
        exports = []
        imports = []
        for line in result.stdout.split('\n'):
            if 'Export' in line and 'func' in line:
                exports.append(line.strip())
            if 'Import' in line and 'seal_' in line:
                imports.append(line.strip())
        
        print("[*] Polkadot 合约分析:")
        print(f"    导出函数: {len(exports)}")
        for exp in exports:
            print(f"      {exp}")
        
        print(f"    系统调用: {len(imports)}")
        seal_funcs = [i for i in imports if 'seal_' in i]
        for seal in seal_funcs[:10]:
            print(f"      {seal}")
        
        return exports, imports
    
    def analyze_eos_contract(self):
        """分析 EOS WASM 合约"""
        # EOS 合约导出 apply 函数
        result = subprocess.run(
            ['wasm-objdump', '-x', self.path],
            capture_output=True, text=True
        )
        
        has_apply = 'apply' in result.stdout
        print(f"[*] EOS 合约 (apply 导出: {has_apply})")
        
        return has_apply
    
    def find_vulnerabilities(self):
        """查找常见漏洞"""
        # 1. 整数溢出
        # 2. 未检查的外部调用
        # 3. 权限检查缺失
        # 4. 重入攻击
        
        with open(self.path, 'rb') as f:
            data = f.read()
        
        vulns = []
        
        # 检查是否有权限检查 (auth_check)
        if b'auth_check' not in data and b'seal_caller_is_contract' not in data:
            vulns.append("缺少权限检查")
        
        # 检查是否有余额检查
        if b'balance_of' not in data and b'seal_balance' not in data:
            vulns.append("可能缺少余额检查")
        
        return vulns

# 使用
analyzer = WasmContractAnalysis('contract.wasm')
analyzer.analyze_polkadot_contract()
vulns = analyzer.find_vulnerabilities()
if vulns:
    print(f"[!] 潜在漏洞: {vulns}")
```

### 6. WASM 组件模型 (Component Model) 分析

```python
# WASM Component Model — 新的模块化标准
import subprocess

def analyze_component_model(wasm_path):
    """分析 WASM 组件模型"""
    
    # 使用 wasm-tools 分析
    result = subprocess.run(
        ['wasm-tools', 'component', 'wit', wasm_path],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print("[*] WASM Component Model WIT 接口:")
        print(result.stdout[:2000])
    else:
        print("[*] 不是组件模型模块，使用传统分析")
    
    # 分析组件的导入/导出
    result = subprocess.run(
        ['wasm-tools', 'component', 'encode', wasm_path, '--dry-run'],
        capture_output=True, text=True
    )
    
    return result.stdout

# Component Model 特征：
# - 使用 WIT (WebAssembly Interface Types) 描述接口
# - 支持多种语言互操作
# - 可以嵌套组件
```

### 7. WASM 调试与符号恢复

```bash
# WASM 调试信息分析

# 1. 使用 --debug-info 编译 WASM
# clang --target=wasm32 -g -o debug.wasm source.c

# 2. 使用 wasm-objdump 查看调试段
wasm-objdump -x debug.wasm | grep -i "debug\|name\|custom"

# 3. 使用 chrome DevTools 调试
# chrome://inspect → Open dedicated DevTools for Node
# 或在 Edge/Chrome 中加载 WASM 页面

# 4. 使用 wasmtime 调试
wasmtime --debug-info debug.wasm

# 5. 符号恢复脚本
python3 << 'PYEOF'
import subprocess

def recover_symbols(wasm_path):
    """尝试恢复 WASM 符号"""
    
    # 1. 查找 name section (函数名)
    result = subprocess.run(
        ['wasm-objdump', '-j', 'name', '-x', wasm_path],
        capture_output=True, text=True
    )
    
    symbols = {}
    for line in result.stdout.split('\n'):
        if 'func' in line.lower():
            # 解析函数名
            parts = line.strip().split()
            if len(parts) >= 3:
                idx = parts[0]
                name = parts[-1].strip('"')
                symbols[idx] = name
    
    print(f"[*] 恢复的符号: {len(symbols)}")
    for idx, name in list(symbols.items())[:20]:
        print(f"    [{idx}] {name}")
    
    # 2. 查找自定义段
    result = subprocess.run(
        ['wasm-objdump', '-x', wasm_path],
        capture_output=True, text=True
    )
    
    custom_sections = []
    for line in result.stdout.split('\n'):
        if 'custom' in line.lower():
            custom_sections.append(line.strip())
    
    if custom_sections:
        print(f"\n[*] 自定义段:")
        for section in custom_sections:
            print(f"    {section}")
    
    return symbols

# recover_symbols("module.wasm")
PYEOF
```

### 8. WASM 反混淆自动化工具链

```bash
# WASM 反混淆自动化工具链
# 完整分析流程

# Step 1: 提取和分类
wasm-objdump -x module.wasm > sections.txt
wasm-objdump -d module.wasm > disassembly.txt
wasm-decompile module.wasm > decompiled.dcmp
wasm2wat module.wasm > module.wat

# Step 2: 分析导出函数
grep "Export" sections.txt
echo "---"
grep "func" module.wat | head -20

# Step 3: 查找关键函数
grep -n "export" module.wat | head -20

# Step 4: 使用 Ghidra 分析
# 安装 Ghidra WASM 插件
# https://github.com/nneonneo/ghidra-wasm-plugin
# 然后在 Ghidra 中打开 .wasm 文件

# Step 5: 动态分析
# 使用 Node.js 加载和 hook
node << 'JSEOF'
const fs = require('fs');
const wasmBuffer = fs.readFileSync('module.wasm');

WebAssembly.instantiate(wasmBuffer, {
    env: { memory: new WebAssembly.Memory({ initial: 256 }) },
    // 提供必要的导入
}).then(result => {
    const exports = result.instance.exports;
    console.log('Exports:', Object.keys(exports));
    
    // 调用导出函数
    for (const [name, fn] of Object.entries(exports)) {
        if (typeof fn === 'function') {
            console.log(`Calling ${name}...`);
            try {
                const result = fn(42);
                console.log(`  Result: ${result}`);
            } catch(e) {
                console.log(`  Error: ${e.message}`);
            }
        }
    }
});
JSEOF

# Step 6: Python 自动化分析
python3 << 'PYEOF'
import subprocess
import re

def auto_analyze_wasm(wasm_path):
    """WASM 自动化分析"""
    
    # 获取段信息
    result = subprocess.run(
        ['wasm-objdump', '-x', wasm_path],
        capture_output=True, text=True
    )
    
    analysis = {
        'imports': [],
        'exports': [],
        'data_sections': [],
        'functions': 0,
        'tables': 0,
        'memories': 0,
    }
    
    for line in result.stdout.split('\n'):
        if 'Import' in line:
            analysis['imports'].append(line.strip())
        if 'Export' in line:
            analysis['exports'].append(line.strip())
        if 'func' in line:
            analysis['functions'] += 1
        if 'table' in line.lower():
            analysis['tables'] += 1
        if 'memory' in line.lower():
            analysis['memories'] += 1
    
    print(f"[*] WASM 分析结果:")
    print(f"    函数: {analysis['functions']}")
    print(f"    导入: {len(analysis['imports'])}")
    print(f"    导出: {len(analysis['exports'])}")
    print(f"    表: {analysis['tables']}")
    print(f"    内存: {analysis['memories']}")
    
    # 分析数据段中的字符串
    result = subprocess.run(
        ['wasm-objdump', '-s', wasm_path],
        capture_output=True, text=True
    )
    
    strings = re.findall(r'[\x20-\x7e]{5,}', result.stdout)
    if strings:
        print(f"\n[*] 发现 {len(strings)} 个字符串:")
        for s in strings[:20]:
            print(f"    {s}")
    
    return analysis

auto_analyze_wasm("module.wasm")
PYEOF
```

## 工具推荐

- **WABT** — WASM 工具包（wasm2wat, wasm-decompile）
- **Ghidra** — 反编译（需插件）
- **IDA Pro** — 反编译（7.4+ 支持）
- **wasm-objdump** — 段信息查看
- **Chrome DevTools** — 调试
- **Frida** — 动态插桩
- **wasm3** — WASM 解释器
- **wasmer** — WASM 运行时

## 参考链接

- [WebAssembly](https://webassembly.org/)
- [WABT](https://github.com/WebAssembly/wabt)
- [Ghidra WASM Plugin](https://github.com/nneonneo/ghidra-wasm-plugin)
- [WASM Reverse Engineering](https://www.jianshu.com/p/4d7d7a460c0c)
