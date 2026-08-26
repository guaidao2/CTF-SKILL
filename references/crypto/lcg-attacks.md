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
# OP 可以是 +, -, * (XOR 不安全)
# j, k 是延迟（lag）

class LFG:
    """Lagged Fibonacci Generator"""
    
    def __init__(self, j, k, seed, m=2**32, op='xor'):
        self.j = j
        self.k = k
        self.m = m
        self.op = op
        # 初始化状态
        self.state = list(seed) if isinstance(seed, list) else [seed]
        while len(self.state) < max(j, k):
            self.state.append(self.state[-1] * 1103515245 + 12345)  # LCG 扩展
    
    def next(self):
        xi_j = self.state[-self.j]
        xi_k = self.state[-self.k]
        
        if self.op == 'add':
            val = (xi_j + xi_k) % self.m
        elif self.op == 'xor':
            val = (xi_j ^ xi_k) % self.m
        else:
            val = (xi_j - xi_k) % self.m
        
        self.state.append(val)
        return val


def lfg_known_params(outputs, j, k, m=2**32):
    """LFG 已知参数攻击
    
    如果知道 j, k, m 和若干输出
    可以恢复初始状态
    """
    # 从输出反推
    # X_n = X_{n-j} OP X_{n-k}
    # 如果 OP 是 XOR: X_n ^ X_{n-j} = X_{n-k}
    # 如果 OP 是 +: X_n - X_{n-j} = X_{n-k} (mod m)
    
    # 恢复初始种子
    state = list(outputs[:max(j, k)])
    
    # 验证
    for i in range(max(j, k), len(outputs)):
        if hasattr(LFG, 'next'):
            computed = (state[-j] ^ state[-k]) % m  # XOR 情况
            assert computed == outputs[i]
    
    return state


def lfg_unknown_params(outputs, m=2**32):
    """LFG 未知参数攻击
    
    从输出恢复 j, k 和初始状态
    """
    n = len(outputs)
    
    # 尝试不同的 j, k
    for j in range(2, min(100, n)):
        for k in range(1, j):
            # 检查是否满足 LFG
            valid = True
            for i in range(j, n):
                expected = (outputs[i-j] ^ outputs[i-k]) % m
                if expected != outputs[i]:
                    valid = False
                    break
            
            if valid:
                return j, k, outputs[:j]
    
    return None


def lfg_truncated_attack(truncated_outputs, j, k, bits, m=2**32):
    """LFG 截断输出攻击
    
    如果只输出高位（bits 位）
    使用格方法恢复低位
    """
    from sage.all import *
    
    n = len(truncated_outputs)
    low_bits = m.bit_length() - bits
    
    # 构造格
    # 类似截断 LCG 的攻击
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = m
        M[n, i] = truncated_outputs[i] << low_bits
    M[n, n] = 1
    
    L = M.LLL()
    
    # 找解
    for row in L:
        if all(row[i] % m == truncated_outputs[i] << low_bits for i in range(n)):
            return [row[i] >> low_bits for i in range(n)]
    
    return None
```

### 6. PCG（Permuted Congruential Generator）攻击

```python
# PCG 比 LCG 安全：使用 LCG + 输出置换
# state = state * multiplier + increment (LCG)
# output = permute(state) (输出置换)

class PCG32:
    """PCG-XSH-RR（32 位输出）"""
    
    def __init__(self, state, seq=0):
        self.state = state
        self.inc = (seq << 1) | 1  # 奇数 inc
        self.multiplier = 0x5851F42D4C957F2D  # 64 位乘数
        
        # 初始化：先推进一步
        self.state = (self.state + self.inc) & 0xFFFFFFFFFFFFFFFF
        self.state = (self.state * self.multiplier + self.inc) & 0xFFFFFFFFFFFFFFFF
    
    def next(self):
        # LCG 步骤
        old_state = self.state
        self.state = (old_state * self.multiplier + self.inc) & 0xFFFFFFFFFFFFFFFF
        
        # 输出置换：XSH-RR
        # 右旋转 XOR 右移
        xorshifted = ((old_state >> 18) ^ old_state) >> 27
        rot = old_state >> 59
        result = (xorshifted >> rot) | (xorshifted << ((-rot) & 31))
        
        return result & 0xFFFFFFFF


def pcg_known_params(outputs, multiplier, inc):
    """PCG 已知参数攻击
    
    如果知道 multiplier 和 inc
    可以从输出恢复 state
    """
    # PCG 的输出是 state 的置换
    # 如果置换是可逆的，可以从输出恢复 state
    
    # 对于 XSH-RR，置换是可逆的
    # 需要逆向输出置换
    
    # 简化：直接从 LCG 关系恢复
    # state_{n+1} = state_n * multiplier + inc
    # 已知 state_n，可以预测后续
    
    # 从输出恢复 state（需要逆向 XSH-RR）
    def invert_xsh_rr(output):
        """逆向 XSH-RR 输出置换"""
        # XSH-RR: xorshifted = (s >> 18) ^ s >> 27
        #         rot = s >> 59
        #         output = rotr(xorshifted, rot)
        # 需要暴力搜索 rot (0-31)
        # 然后反推 xorshifted
        
        for rot in range(32):
            xorshifted = (output << rot) | (output >> (32 - rot))
            # 从 xorshifted 反推 old_state
            # xorshifted = ((s >> 18) ^ s) >> 27
            # 这需要更复杂的逆运算
            
            # 简化：使用已知的逆运算
            pass
        
        return None
    
    return None


def pcg_state_recovery(outputs, num_outputs=4):
    """PCG 状态恢复（已知输出序列）
    
    从多个输出恢复完整状态
    """
    # 方法 1：如果知道 inc
    # 可以从 2 个输出恢复 state
    
    # 方法 2：暴力搜索
    # PCG32 状态空间 64 位
    # 但 inc 是奇数，减少搜索空间
    
    # 方法 3：利用 LCG 的线性性质
    # state_n = multiplier^n * state_0 + (multiplier^n - 1) / (multiplier - 1) * inc
    
    # 如果知道 inc，可以解方程
    
    return None


def pcg_prediction_attack(pcg_oracle, num_samples=10):
    """PCG 预测攻击
    
    通过观察输出预测下一个值
    """
    outputs = [pcg_oracle() for _ in range(num_samples)]
    
    # PCG 的输出是确定性的
    # 如果知道种子或状态，可以完全预测
    
    # 攻击方法：
    # 1. 时间攻击：测量生成时间推断状态
    # 2. 侧信道：功耗/电磁泄露
    # 3. 暴力：小种子空间可以爆破
    
    return outputs
```

### 7. xorshift 攻击

```python
# xorshift 是可逆的线性 PRNG
# 基于 XOR 和位移

class XorShift32:
    """XorShift32 PRNG"""
    
    def __init__(self, state):
        self.state = state & 0xFFFFFFFF
        if self.state == 0:
            self.state = 1  # 避免全零
    
    def next(self):
        x = self.state
        x ^= x << 13
        x &= 0xFFFFFFFF
        x ^= x >> 17
        x &= 0xFFFFFFFF
        x ^= x << 5
        self.state = x
        return x


class XorShift64:
    """XorShift64 PRNG"""
    
    def __init__(self, state):
        self.state = state & 0xFFFFFFFFFFFFFFFF
        if self.state == 0:
            self.state = 1
    
    def next(self):
        x = self.state
        x ^= x << 13
        x ^= x >> 7
        x ^= x << 17
        self.state = x
        return x & 0xFFFFFFFFFFFFFFFF


def xorshift32_invert(output):
    """XorShift32 逆运算
    
    给定输出，恢复上一个状态
    XOR 移位操作是可逆的
    """
    # x ^= x << 13  →  逆：x ^= x << 13 (在 mod 2^32 下)
    # x ^= x >> 17  →  逆：x ^= x >> 17
    # x ^= x << 5   →  逆：x ^= x << 5
    
    # 完全可逆
    x = output
    x ^= x << 5
    x &= 0xFFFFFFFF
    x ^= x >> 17
    x &= 0xFFFFFFFF
    x ^= x << 13
    x &= 0xFFFFFFFF
    return x


def xorshift32_state_recovery(outputs):
    """XorShift32 状态恢复
    
    从一个输出即可恢复完整状态
    因为 XOR 移位是可逆的
    """
    if not outputs:
        return None
    
    # 逆向一步
    state = xorshift32_invert(outputs[0])
    
    # 验证
    rng = XorShift32(state)
    for o in outputs:
        if rng.next() != o:
            return None
    
    return state


def xorshift_known_params(outputs, shifts):
    """XorShift 已知参数攻击
    
    shifts: (a, b, c) 移位参数
    """
    # 验证输出是否匹配给定参数
    if len(outputs) < 2:
        return None
    
    # 尝试从输出逆推种子
    # XOR 移位完全可逆
    a, b, c = shifts
    
    # 逆向函数
    def inverse_step(x):
        x ^= x << c
        x &= 0xFFFFFFFF
        x ^= x >> b
        x &= 0xFFFFFFFF
        x ^= x << a
        x &= 0xFFFFFFFF
        return x
    
    state = outputs[0]
    for o in outputs[:3]:
        state = inverse_step(state)
    
    return state


def xorshift_truncated_attack(outputs, known_bits, total_bits=32):
    """XorShift 截断输出攻击
    
    如果只输出高位（known_bits 位）
    使用格方法
    """
    from sage.all import *
    
    n = len(outputs)
    unknown_bits = total_bits - known_bits
    
    # 构造格
    # 利用 XOR 的线性性质
    
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 2 ** total_bits
        M[n, i] = outputs[i] << unknown_bits
    M[n, n] = 1
    
    L = M.LLL()
    
    # 找解
    candidates = []
    for row in L:
        if all(row[i] % (2 ** total_bits) == outputs[i] << unknown_bits for i in range(n)):
            candidates.append(row)
    
    return candidates
```

### 8. xoroshiro 攻击

```python
# xoroshiro 是现代 PRNG（比 xorshift 更好）
# 使用旋转操作而非移位

class Xoroshiro128Plus:
    """Xoroshiro128+ PRNG"""
    
    def __init__(self, s0, s1):
        self.s0 = s0 & 0xFFFFFFFFFFFFFFFF
        self.s1 = s1 & 0xFFFFFFFFFFFFFFFF
    
    def next(self):
        result = (self.s0 + self.s1) & 0xFFFFFFFFFFFFFFFF
        
        self.s1 ^= self.s0
        # 左旋转 s0
        self.s0 = ((self.s0 << 24) | (self.s0 >> 40)) & 0xFFFFFFFFFFFFFFFF
        self.s0 ^= self.s1
        self.s1 = ((self.s1 << 16) | (self.s1 >> 48)) & 0xFFFFFFFFFFFFFFFF
        self.s1 ^= self.s0
        
        return result


def xoroshiro128plus_recover_state(outputs):
    """Xoroshiro128+ 状态恢复
    
    从输出序列恢复 s0, s1
    需要多个输出来解方程
    """
    if len(outputs) < 4:
        return None
    
    # XOR 和旋转是可逆的
    # 但加法不是完全可逆（丢失进位信息）
    
    # 方法：从输出逆推
    # result = s0 + s1 mod 2^64
    # 如果知道 s1，可以从 result 恢复 s0（或反过来）
    
    # 简化：尝试暴力搜索
    # 状态空间 128 位太大
    # 但如果有部分信息可以缩小
    
    # 更实际：使用 Z3 SMT 求解器
    from z3 import *
    
    s0, s1 = BitVecs('s0 s1', 64)
    solver = Solver()
    
    # 模拟前几步
    state_s0, state_s1 = s0, s1
    
    for i, expected in enumerate(outputs[:4]):
        result = (state_s0 + state_s1) & 0xFFFFFFFFFFFFFFFF
        solver.add(result == expected)
        
        # 更新状态
        new_s1 = state_s1 ^ state_s0
        new_s0 = RotateLeft(state_s0, 24) ^ new_s1
        new_s1 = RotateLeft(new_s1, 16) ^ new_s0
        
        state_s0, state_s1 = new_s0, new_s1
    
    if solver.check() == sat:
        model = solver.model()
        s0_val = model[s0].as_long()
        s1_val = model[s1].as_long()
        return s0_val, s1_val
    
    return None


def xoroshiro128starstar_recover_state(outputs):
    """Xoroshiro128** 状态恢复
    
    更安全的变体（使用旋转和乘法）
    """
    # 攻击方法类似，但更复杂
    # 需要考虑乘法的可逆性
    
    return None
```

### 9. 通用状态恢复

```python
# 通用 PRNG 状态恢复方法
# 结合格、SMT 求解器、代数方法

def generic_state_recovery(prng_class, outputs, state_size):
    """通用 PRNG 状态恢复
    
    适用于任何线性或弱非线性 PRNG
    """
    # 方法 1：Z3 SMT 求解器
    from z3 import *
    
    solver = Solver()
    bits = state_size
    
    # 创建状态变量
    state = BitVec('state', bits)
    current = state
    
    # 模拟 PRNG 生成过程
    for i, expected in enumerate(outputs):
        # 这里需要根据具体 PRNG 实现
        # 以下为示例（LCG）
        # next_val = (current * a + c) % m
        # solver.add(next_val == expected)
        # current = next_val
        
        # 简化：假设 PRNG 有简单的逆运算
        pass
    
    if solver.check() == sat:
        model = solver.model()
        return model[state].as_long()
    
    return None


def lattice_state_recovery(outputs, params):
    """格方法状态恢复
    
    对于线性 PRNG，可以用格方法
    """
    from sage.all import *
    
    n = len(outputs)
    
    # 构造格
    # 利用 PRNG 的线性性质
    
    # 例如：对于 LCG
    # X_{n+1} = a * X_n + c mod m
    # 可以用格方法求 a, c, m
    
    # 更通用：将 PRNG 表示为线性变换
    # s_{n+1} = M * s_n mod m
    # 其中 M 是状态转移矩阵
    
    # 构造格
    dim = n + 1
    M = Matrix(ZZ, dim, dim)
    
    for i in range(n):
        M[i, i] = params.get('m', 2**32)
    M[n, n] = 1
    
    # 嵌入输出
    for i in range(n):
        M[n, i] = outputs[i]
    
    L = M.LLL()
    
    # 提取状态
    for row in L:
        if all(row[i] % params.get('m', 2**32) == outputs[i] for i in range(n)):
            return row
    
    return None


def algebraic_state_recovery(prng_class, outputs):
    """代数方法状态恢复
    
    对于非线性 PRNG，构造代数方程组
    """
    # 例如：
    # 1. 将 PRNG 操作表示为 GF(2) 上的多项式
    # 2. 用 Gröbner 基求解
    # 3. 或用 XL/XSL 算法
    
    # SageMath 支持
    from sage.all import *
    
    # 示例：对于简单的 XOR 移位 PRNG
    # 可以在 GF(2) 上表示
    
    return None


def combined_attack(prng_class, outputs, oracle=None):
    """组合攻击
    
    结合多种方法：
    1. 先用格方法缩小搜索空间
    2. 再用 SMT 求解器精确定位
    3. 或用代数方法
    """
    # 步骤：
    # 1. 分析 PRNG 的结构
    # 2. 选择合适的方法
    # 3. 执行攻击
    
    return None
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

### 1. 现代 PRNG 分析

```python
# PCG 系列的最新分析
# xoshiro/xoroshiro 的安全评估

def modern_prng_analysis():
    """现代 PRNG 安全分析"""
    
    # PCG 变体
    # 1. PCG-XSH-RR：最常用，32 位输出
    # 2. PCG-XSL-RR：更安全的输出函数
    # 3. PCG-MCG：乘法 LCG 变体
    
    # xoshiro 变体
    # 1. xoshiro256**：最安全
    # 2. xoshiro256+：更快但有已知弱点
    # 3. xoshiro256++：折中
    
    # xoroshiro 变体
    # 1. xoroshiro128+：已知弱点
    # 2. xoroshiro128**：更安全
    # 3. xoroshiro1024*：大状态
    
    return None


def distinguisher_test(rng_oracle, n=10000):
    """PRNG 区分器测试
    
    判断输出是否来自特定 PRNG
    """
    outputs = [rng_oracle() for _ in range(n)]
    
    # 统计测试
    # 1. 均匀性测试
    # 2. 相关性测试
    # 3. 熵估计
    
    # 对于特定 PRNG 的区分器
    # 例如：LCG 的模结构会暴露
    
    return outputs
```

### 2. 密码学 PRNG

```python
import os
import secrets

def csprng_attack():
    """密码学 PRNG 攻击
    
    CSPRNG 比普通 PRNG 安全得多
    但仍有攻击面：
    """
    # 1. 种子熵不足
    # 如果种子可预测或空间小
    
    # 2. 状态泄露
    # 如果可以从输出恢复状态
    
    # 3. 实现缺陷
    # 时序攻击、侧信道
    
    # 4. 重用种子
    # 并发进程使用相同种子
    
    return None


def urandom_weakness():
    """/dev/urandom 弱点分析"""
    # 1. 启动时熵不足
    # 早期启动阶段可能不够随机
    
    # 2. fork() 问题
    # fork 后子进程状态相同
    
    # 3. 虚拟化环境
    # 虚拟机可能熵不足
    
    return None


def java_random_attack():
    """Java Random 攻击
    
    java.util.Random 使用 LCG
    可以被完全预测
    """
    # Java Random: next(n) = ((a * seed + c) & mask) >>> (48 - n)
    # 已知参数 a=0x5DEECE66D, c=0xB, mask=0xFFFFFFFFFFFF
    
    # 从输出恢复种子
    # 一个输出可以缩小种子空间
    # 2 个输出可以唯一确定种子
    
    return None


def mt19937_seed_recovery():
    """Mersenne Twister 种子恢复
    
    如果知道 MT19937 的输出
    可以恢复完整内部状态
    """
    # MT19937 状态：624 个 32 位整数
    # 需要 624 个输出恢复状态
    
    # 恢复后可以预测所有未来输出
    # 也可以逆推之前的状态
    
    return None
```

### 3. 硬件随机数

```python
def rdrand_attack():
    """Intel RDRAND 攻击
    
    硬件随机数生成器可能有缺陷
    """
    # 1. 后门风险
    # 如果 RDRAND 有后门
    
    # 2. 实现缺陷
    # 重试机制可能导致偏差
    
    # 3. 侧信道
    # 功耗/时间分析
    
    return None


def trng_analysis():
    """真随机数生成器分析
    
    TRNG 基于物理过程
    但可能有偏差或可预测性
    """
    # 攻击方法：
    # 1. 偏差测试
    # 2. 可预测性测试
    # 3. 物理攻击（故障注入）
    
    return None
```

### 4. 量子随机数

```python
def quantum_rng_analysis():
    """量子随机数生成器
    
    QRNG 基于量子力学
    理论上不可预测
    """
    # 但实际实现可能有漏洞：
    # 1. 探测器缺陷
    # 2. 光子数分裂攻击
    # 3. 侧信道
    
    return None
```

### 5. 容器/云环境

```python
def container_prng():
    """容器环境中的 PRNG
    
    容器可能有熵不足问题
    """
    # 1. 共享内核熵池
    # 2. 容器启动时熵不足
    # 3. 种子可预测
    
    # 攻击：如果知道容器创建时间
    # 可能推断种子
    
    return None


def vm_prng():
    """虚拟机环境中的 PRNG
    
    VM 可能有熵不足
    """
    # 1. 共享主机熵池
    # 2. 快照恢复后状态重复
    # 3. 嵌套虚拟化
    
    return None
```

### 6. 移动应用

```python
def mobile_prng():
    """移动应用 PRNG
    
    Android/iOS 的 PRNG 使用
    """
    # Android：
    # - java.util.Random（弱）
    # - SecureRandom（强，但有历史漏洞）
    # - /dev/urandom
    
    # iOS：
    # - arc4random（强）
    # - SecRandomCopyBytes
    
    # 攻击点：
    # 1. 旧版本 Android 的熵问题
    # 2. 种子预测
    # 3. 侧信道
    
    return None
```

### 7. IoT 设备

```python
def iot_prng():
    """IoT 设备 PRNG
    
    资源受限设备的随机数问题
    """
    # 问题：
    # 1. 没有硬件 RNG
    # 2. 熵源有限
    # 3. 种子空间小
    
    # 攻击：
    # 1. 暴力种子
    # 2. 利用确定性行为
    # 3. 侧信道
    
    return None
```

### 8. 混合攻击

```python
def hybrid_prng_attack():
    """混合 PRNG 攻击
    
    结合多种技术
    """
    # 1. 网络侧信道 + PRNG 状态恢复
    # 2. 时间攻击 + 格方法
    # 3. 代数攻击 + SMT 求解
    
    return None


def neural_network_prng():
    """神经网络辅助 PRNG 分析
    
    ML 可以帮助：
    1. 识别 PRNG 类型
    2. 预测输出
    3. 恢复状态
    """
    # 使用 RNN/LSTM 学习 PRNG 模式
    # 对于简单 PRNG 有效
    
    return None
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
