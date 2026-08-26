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

### 1. WASM 新特性

```python
# WASM 2.0
# - SIMD 指令
# - 异常处理
# - 引用类型
# - 内存64
# - 组件模型

# 各新特性影响逆向
```

### 2. WASM 混淆

```python
# 1. 控制流平坦化
# 2. 虚假控制流
# 3. 指令替换
# 4. 字符串加密
# 5. 自定义 VM
```

### 3. WASM + Native

```python
# WASM 调用 Native
# Native 调用 WASM
# 混合分析
```

### 4. WASM 在服务端

```python
# WASM 作为服务端
# WASI (WebAssembly System Interface)
# 新的攻击面
```

### 5. WASM 在区块链

```python
# 智能合约使用 WASM
# Polkadot
# EOS
# 各区块链平台
```

### 6. WASM 在边缘计算

```python
# Cloudflare Workers
# Fastly Compute@Edge
# 各边缘计算平台
```

### 7. WASM 在 AI

```python
# WASM 运行 ML 模型
# TensorFlow.js
# ONNX Runtime Web
```

### 8. WASM 在游戏

```python
# Unity WebGL
# Unreal Engine HTML5
# 各游戏引擎
```

### 9. AI 辅助逆向

```python
# LLM 辅助
# - 反编译
# - 算法识别
# - 代码理解
```

### 10. 新型工具

```python
# 持续有新的 WASM 工具出现
# 关注最新研究
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
