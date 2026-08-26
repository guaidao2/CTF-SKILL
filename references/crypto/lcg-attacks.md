# LCG 攻击 (Linear Congruential Generator)

## 原理

线性同余生成器（LCG）是简单的伪随机数生成器，公式为 `X_{n+1} = (a*X_n + c) mod m`。LCG 可预测性高，CTF 中常被攻击。

## LCG 基础

```python
# LCG 公式
# X_{n+1} = (a * X_n + c) mod m
# 
# 参数：
# a: 乘数
# c: 增量
# m: 模数
# X_0: 种子

# Python random 模块使用 Mersenne Twister，不是 LCG
# 但 glibc rand() 使用 LCG
```

## 攻击链

### 1. 已知参数恢复种子

```python
# 如果已知 a, c, m 和若干输出
# 可直接恢复种子

def recover_seed(outputs, a, c, m):
    # X_1 = (a * X_0 + c) mod m
    # X_0 = (X_1 - c) * a^(-1) mod m
    X_0 = (outputs[0] - c) * pow(a, -1, m) % m
    return X_0
```

### 2. 未知参数恢复

#### 已知 m，恢复 a, c

```python
# 如果已知 m 和若干连续输出
# X_1 = (a * X_0 + c) mod m
# X_2 = (a * X_1 + c) mod m
# X_3 = (a * X_2 + c) mod m

# X_2 - X_1 = a * (X_1 - X_0) mod m
# a = (X_2 - X_1) * (X_1 - X_0)^(-1) mod m
# c = X_1 - a * X_0 mod m

def recover_params_known_m(outputs, m):
    X_0, X_1, X_2 = outputs[0], outputs[1], outputs[2]
    a = (X_2 - X_1) * pow(X_1 - X_0, -1, m) % m
    c = (X_1 - a * X_0) % m
    return a, c
```

#### 未知 m，恢复 a, c, m

```python
# 如果 m 未知
# 使用格方法

from sage.all import *

def recover_unknown_m(outputs):
    # X_1 - X_0, X_2 - X_1, X_3 - X_2, ...
    diffs = [outputs[i+1] - outputs[i] for i in range(len(outputs)-1)]
    
    # T_i = X_{i+1} - X_i
    # T_{i+1} = a * T_i mod m
    # T_{i+1} * T_{i-1} - T_i^2 ≡ 0 mod m
    
    # 计算 m
    # m = gcd(T_2*T_0 - T_1^2, T_3*T_1 - T_2^2, ...)
    
    from math import gcd
    m = 0
    for i in range(len(diffs) - 2):
        t = diffs[i+2] * diffs[i] - diffs[i+1] ** 2
        m = gcd(m, t)
    
    # 恢复 a, c
    a = (diffs[1] * pow(diffs[0], -1, m)) % m
    c = (outputs[1] - a * outputs[0]) % m
    
    return a, c, m
```

### 3. 截断输出恢复

```python
# 如果只输出高位
# 使用格方法

from sage.all import *

def recover_truncated_lcg(outputs, high_bits, low_bits):
    # outputs: 截断后的输出
    # high_bits: 高位位数
    # low_bits: 低位位数
    # 
    # X_i = output_i << low_bits + unknown_i
    # 使用 LLL 恢复 unknown_i
    
    n = len(outputs)
    m = 2^(high_bits + low_bits)  # 假设 m 是 2 的幂
    
    # 构造格
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = m
        M[n, i] = outputs[i] << low_bits
    M[n, n] = 1
    
    L = M.LLL()
    # 找解
    # ...
    pass
```

### 4. Mersenne Twister 攻击

```python
# Python random 模块使用 MT19937
# 如果获取足够多的输出（624 个 32 位整数）
# 可以恢复内部状态

def untemper(y):
    # MT19937 的逆运算
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor(y, 15, 0xEFC60000)
    y = undo_left_shift_xor(y, 7, 0x9D2C5680)
    y = undo_right_shift_xor(y, 11)
    return y

def undo_right_shift_xor(y, shift):
    result = y
    for i in range(32 // shift + 1):
        result = y ^ (result >> shift)
    return result & 0xFFFFFFFF

def undo_left_shift_xor(y, shift, mask):
    result = y
    for i in range(32 // shift + 1):
        result = y ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF

def recover_mt19937(outputs):
    # 624 个输出恢复状态
    state = [untemper(o) for o in outputs[:624]]
    # 重新初始化
    # ...
    pass
```

### 5. LFG（Lagged Fibonacci Generator）攻击

```python
# X_n = (X_{n-j} OP X_{n-k}) mod m
# 类似 LCG，可被攻击
```

### 6. PCG（Permuted Congruential Generator）攻击

```python
# 现代 PRNG
# 比传统 LCG 安全
# 但仍有弱点
```

### 7. xorshift 攻击

```python
# xorshift PRNG
# 可逆
# 可被攻击
```

### 8. xoroshiro 攻击

```python
# xoroshiro PRNG
# 现代 PRNG
# 可被攻击
```

### 9. 状态恢复

```python
# 通用状态恢复
# 使用格方法
# 使用 SMT 求解器
```

### 10. 种子爆破

```python
# 如果种子空间小
# 可以爆破
import time

def brute_force_seed(oracle, max_seed=2**32):
    for seed in range(max_seed):
        if oracle(seed):
            return seed
    return None
```

## 2024-2026 新技术点

### 1. 现代 PRNG

```python
# PCG
# xoshiro
# 各现代 PRNG
# 新的攻击方法
```

### 2. 密码学 PRNG

```python
# CSPRNG
# /dev/urandom
# 各 CSPRNG
# 侧信道攻击
```

### 3. 硬件随机数

```python
# RDRAND
# 各硬件随机数
# 侧信道攻击
```

### 4. 量子随机数

```python
# 量子随机数生成器
# 新的攻击面
```

### 5. AI 辅助

```python
# ML 辅助
# 状态预测
# 种子爆破
```

### 6. 侧信道

```python
# 时间侧信道
# 缓存侧信道
# 各侧信道
```

### 7. 容器环境

```python
# 容器中的 PRNG
# 种子可预测
```

### 8. 云环境

```python
# 云服务中的 PRNG
# 种子可预测
```

### 9. 移动应用

```python
# Android/iOS 中的 PRNG
# 各移动应用
```

### 10. IoT 设备

```python
# IoT 设备中的 PRNG
# 各 IoT 设备
```

## 工具推荐

- **SageMath** — 格计算
- **z3** — SMT 求解
- **randcrack** — MT19937 攻击
- **untwister** — PRNG 恢复

## 参考链接

- [ctf-wiki LCG](https://ctf-wiki.org/crypto/streamcipher/prng/)
- [LCG Attack](https://github.com/jvdsn/crypto-attacks)
- [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
- [randcrack](https://github.com/tna0y/Python-random-module-cracker)
