# RSA 攻击

## 原理

RSA 是非对称加密算法，安全性基于大整数分解难题。CTF 中常因参数选择不当导致可被攻击。

## RSA 基础

```python
# 密钥生成
# 1. 选两个大素数 p, q
# 2. n = p * q
# 3. phi = (p-1) * (q-1)
# 4. 选 e（通常 65537）
# 5. d = e^(-1) mod phi

# 加密
c = m^e mod n

# 解密
m = c^d mod n
```

## 攻击链

### 1. 分解 n

#### 在线分解

```python
# FactorDB
# http://factordb.com/
import requests

def factordb(n):
    r = requests.get(f'http://factordb.com/api?query={n}')
    data = r.json()
    if data['status'] == 'FF':
        return [int(f) for f in data['factors']]
    return None
```

#### yafu

```bash
# 大数分解
yafu "factor(n)"
```

#### sympy

```python
from sympy import factorint
factors = factorint(n)
```

### 2. 小 e 攻击

#### 低加密指数攻击（e=3）

```python
# 如果 m^3 < n，则 c = m^3（无模运算）
# 直接开立方
import gmpy2

m = gmpy2.iroot(c, 3)[0]
print(bytes.fromhex(hex(m)[2:]))
```

#### 低加密指数广播攻击

```python
# 同一消息用多个不同 n 加密（e 相同）
# 中国剩余定理 CRT
from sympy.ntheory.modular import crt

# c1 = m^e mod n1
# c2 = m^e mod n2
# c3 = m^e mod n3
# m^e = CRT([c1, c2, c3], [n1, n2, n3])
m_e = crt([n1, n2, n3], [c1, c2, c3])[0]
m = gmpy2.iroot(m_e, e)[0]
```

### 3. 小 d 攻击（Wiener 攻击）

```python
# d < n^0.25 时可被攻击
# 连分数展开
from sage.all import *

def wiener_attack(e, n):
    cf = continued_fraction(e/n)
    convergents = cf.convergents()
    for k, d in enumerate(convergents):
        if k == 0:
            continue
        if d.denominator() == 0:
            continue
        d = d.denominator()
        phi = (e * d - 1) // k.numerator()
        # 检查是否正确
        # ...
    return d
```

### 4. 共享素数攻击

```python
# 两个 n 共享一个素数
# GCD(n1, n2) = p
import gmpy2

p = gmpy2.gcd(n1, n2)
q1 = n1 // p
q2 = n2 // p
```

### 5. 共模攻击

```python
# 同一 n，不同 e1, e2
# gcd(e1, e2) = 1
# 找 s1, s2 使得 s1*e1 + s2*e2 = 1
# m = c1^s1 * c2^s2 mod n
import gmpy2

_, s1, s2 = gmpy2.gcdext(e1, e2)
m = (gmpy2.powmod(c1, s1, n) * gmpy2.powmod(c2, s2, n)) % n
```

### 6. Fermat 分解

```python
# p, q 接近时
import gmpy2

def fermat_factor(n):
    a = gmpy2.isqrt(n) + 1
    b2 = a*a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a*a - n
    b = gmpy2.isqrt(b2)
    return a - b, a + b
```

### 7. Pollard's p-1

```python
# p-1 有小素因子时
def pollard_p_minus_1(n, B=2**20):
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
    return None
```

### 8. Williams' p+1

```python
# p+1 有小素因子时（类似 Pollard's p-1）
# 使用 Lucas 序列
import math

def lucas_sequence(n, P, Q, k):
    """计算 Lucas 序列 V_k(P, Q) mod n"""
    # 使用倍增法
    def _lucas_step(V, Qk, k):
        if k == 0:
            return V, Qk
        if k % 2 == 0:
            V = V * V - 2 * Qk
            Qk = Qk * Qk
            V %= n
            Qk %= n
            return _lucas_step(V, Qk, k // 2)
        else:
            V2 = V * V - 2 * Qk
            Qk2 = Qk * Qk
            V = (P * V + V2) // 2  # 需要根据奇偶调整
            # 实际使用加倍-加一法
            return V, Qk  # 简化
    
    # 更实用的实现
    V = P
    Vn1 = 2  # V_0 = 2
    Qk = Q
    
    # 计算 V_k 使用 double-and-add
    bits = bin(k)[2:]
    Vk = V
    Qk_acc = Q
    for bit in bits[1:]:
        # Double
        Vk = Vk * Vk - 2 * Qk_acc
        Vk %= n
        Qk_acc = Qk_acc * Qk_acc
        Qk_acc %= n
        if bit == '1':
            # Add
            Vk = P * Vk - Qk_acc
            Vk %= n
            Qk_acc = Qk_acc * Q
            Qk_acc %= n
    return Vk


def williams_p_plus_1(n, B=2**20):
    """Williams' p+1 分解
    当 p+1 有小素因子时有效
    需要多次尝试不同初始值
    """
    import random
    for _ in range(10):  # 多次尝试不同参数
        P = random.randint(3, n - 3)
        # 计算 Q = P^2 - 4 需要是二次非剩余（即 Legendre symbol = -1）
        # 简化：直接使用小素数
        P = 3
        Q = (P * P - 4) % n  # Lucas 序列参数
        
        for j in range(2, B):
            # 计算 gcd(V_j! - 2, n)
            Vj = 2  # V_0
            for p in range(2, j + 1):
                # 计算 V_p^e 通过重复加倍
                e = j
                Vj = lucas_sequence(n, P, Q, j)
                break  # 简化实现
            # 更高效：逐步累加
            break
        
        # 实际使用逐步计算
        V = 2  # V_0(P) = 2
        Qk = 1
        for j in range(2, B):
            # 逐步计算：利用 V_{ab} = V_a(V_b) 的性质
            # 简化：每次都计算 V_j
            V = lucas_sequence(n, P, Q, j)
            d = math.gcd(V - 2, n)
            if 1 < d < n:
                return d
    
    return None


# 更简洁的实现
def williams_p1_simple(n, B=10000):
    """Williams' p+1 简化版"""
    import gmpy2
    
    def lucasV(P, k, n):
        """快速计算 Lucas V 序列"""
        def double(V, Qk):
            return (V * V - 2 * Qk) % n, (Qk * Qk) % n
        
        def add(P, V, Qk, Q):
            return (P * V - Qk) % n, (Qk * Q) % n
        
        V, Qk = P, 1
        bits = bin(k)[2:]
        for b in bits[1:]:
            V, Qk = double(V, Qk)
            if b == '1':
                V, Qk = add(P, V, Qk, 1)
        return V
    
    # 多次尝试不同 P 值
    for P in [3, 5, 7, 11, 13]:
        V = 2  # V_0 = 2
        for j in range(2, B):
            V = lucasV(P, j, n)
            d = gmpy2.gcd(int(V) - 2, n)
            if 1 < d < n:
                return int(d)
    return None
```

### 9. 已知 phi(n)

```python
# 已知 phi(n)
# n = p*q
# phi = (p-1)*(q-1)
# p + q = n - phi + 1
# p * q = n
# 解二次方程
import gmpy2

s = n - phi + 1  # p + q
# p^2 - s*p + n = 0
# p = (s ± sqrt(s^2 - 4n)) / 2
discriminant = s*s - 4*n
p = (s + gmpy2.isqrt(discriminant)) // 2
q = n // p
```

### 10. 已知 d

```python
# 已知 d
# k = e*d - 1
# k 是 phi(n) 的倍数
# 分解 n
def factor_with_d(n, e, d):
    k = e * d - 1
    # 找 k = 2^s * t
    s = 0
    t = k
    while t % 2 == 0:
        s += 1
        t //= 2
    # 随机选 g
    import random
    while True:
        g = random.randint(2, n-1)
        x = pow(g, t, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            y = pow(x, 2, n)
            if y == 1:
                return gcd(x-1, n)
            if y == n-1:
                break
            x = y
```

### 11. Coppersmith 攻击

```python
# 已知 m 的高位或低位
# sage
from sage.all import *

def coppersmith_low_bits(n, e, c, known_bits, low=True):
    # m = m0 + x，其中 m0 已知
    # m^e - c ≡ 0 mod n
    R.<x> = PolynomialRing(Zmod(n))
    if low:
        m0 = known_bits
        f = (m0 + x)^e - c
    else:
        m0 = known_bits << (n.bit_length() - known_bits.bit_length())
        f = (m0 + x)^e - c
    roots = f.small_roots(X=2^unknown_bits, beta=1)
    return roots
```

### 12. Bleichenbacher 攻击

```python
# PKCS1 v1.5 padding oracle（百万消息攻击）
# 通过服务器对 padding 错误的不同响应，逐步缩小明文范围
# 适用于 RSA PKCS#1 v1.5 解密 oracle

import math

def bleichenbacher_attack(n, e, oracle, block_size=256):
    """Bleichenbacher 攻击（百万消息攻击）
    
    n, e: RSA 公钥
    oracle: 函数，输入密文返回是否 padding 正确 (True/False)
    block_size: 密文块大小（字节）
    
    返回: 恢复的明文（数字）
    """
    B = 2 ** (8 * (block_size - 2))
    B2 = 2 * B
    B3 = 3 * B
    
    # Step 1: Blinding - 找 s_0 使得 c' = c * s_0^e mod n 有正确的 padding
    c0 = c  # 原始密文
    s0 = 1
    c_prime = c0
    
    # 如果原始密文已经有效，s0=1
    # 否则尝试找到 s0
    if not oracle(c_prime.to_bytes(block_size, 'big')):
        for s0 in range(1, n):
            c_prime = (c0 * pow(s0, e, n)) % n
            if oracle(c_prime.to_bytes(block_size, 'big')):
                break
        else:
            raise ValueError("无法找到有效的初始 padding")
    
    # Step 2: 开始迭代
    M = [(B2, B3 - 1)]  # 可能的明文区间
    
    s = 1  # s_0
    i = 1
    
    while True:
        if i == 1:
            # Step 2a: 从 s_0 开始
            s = math.ceil(n / B3)
            while True:
                c_s = (c_prime * pow(s, e, n)) % n
                if oracle(c_s.to_bytes(block_size, 'big')):
                    break
                s += 1
        elif len(M) > 1:
            # Step 2b: 多个区间
            s = s + 1
            while True:
                c_s = (c_prime * pow(s, e, n)) % n
                if oracle(c_s.to_bytes(block_size, 'big')):
                    break
                s += 1
        else:
            # Step 2c: 单个区间
            a, b = M[0]
            r = 2 * (b * s - B2) // n
            found = False
            for r_i in range(r, r + 2):
                s_lo = math.ceil((B2 + r_i * n) / b)
                s_hi = math.floor((B3 - 1 + r_i * n) / a)
                for s_candidate in range(s_lo, s_hi + 1):
                    c_s = (c_prime * pow(s_candidate, e, n)) % n
                    if oracle(c_s.to_bytes(block_size, 'big')):
                        s = s_candidate
                        found = True
                        break
                if found:
                    break
        
        # Step 3: 窄化区间
        M_new = []
        for a, b in M:
            r_lo = math.ceil((a * s - B3 + 1) / n)
            r_hi = math.floor((b * s - B2) / n)
            for r_i in range(r_lo, r_hi + 1):
                new_a = max(a, math.ceil((B2 + r_i * n) / s))
                new_b = min(b, math.floor((B3 - 1 + r_i * n) / s))
                if new_a <= new_b:
                    M_new.append((new_a, new_b))
        M = M_new
        
        # Step 4: 检查结果
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                # 找到唯一明文
                m = (a * pow(s0, -1, n)) % n  # 去盲
                return m
        elif len(M) == 0:
            raise ValueError("区间为空，攻击失败")
        
        i += 1
        if i > 100000:
            raise ValueError("迭代次数过多")


def bleichenbacher_simple(n, e, oracle, block_size=256):
    """简化版 Bleichenbacher（CTF 常用）"""
    B = 2 ** (8 * (block_size - 2))
    s = math.ceil(n / (3 * B))
    
    while True:
        # 测试当前 s
        c_s = (c * pow(s, e, n)) % n
        if oracle(c_s.to_bytes(block_size, 'big')):
            break
        s += 1
    
    M = [(2 * B, 3 * B - 1)]
    
    while True:
        s += 1
        c_s = (c * pow(s, e, n)) % n
        if not oracle(c_s.to_bytes(block_size, 'big')):
            continue
        
        M_new = []
        for a, b in M:
            for r in range(0, n):
                new_a = max(a, math.ceil((2 * B + r * n) / s))
                new_b = min(b, math.floor((3 * B - 1 + r * n) / s))
                if new_a <= new_b:
                    M_new.append((new_a, new_b))
        M = M_new
        
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]


# 快速测试函数
def is_pkcs1_valid(data, block_size=256):
    """检查是否是有效的 PKCS#1 v1.5 padding"""
    if len(data) != block_size:
        return False
    if data[0] != 0x00 or data[1] != 0x02:
        return False
    # 找到 0x00 分隔符
    idx = 2
    while idx < len(data) and data[idx] != 0x00:
        idx += 1
    if idx < 10:  # 至少 8 字节随机数据
        return False
    if idx >= len(data) - 1:
        return False
    return True
```

## 2024-2026 新技术点

### 1. RSA-OAEP 攻击

```python
# RSA-OAEP 是推荐的 RSA padding 方案
# Manger 攻击：利用 OAEP 解密时的 oracle 差异

def manger_attack(n, e, oracle, block_size=256):
    """Manger 攻击 — RSA-OAEP padding oracle
    
    利用 OAEP 解密时长度检查和哈希检查的差异
    逐步恢复明文
    
    oracle: 输入密文，返回:
        0 = padding 错误
        1 = 格式错误（长度/哈希）
        2 = 解密成功
    """
    k = block_size  # RSA 模块字节长度
    hLen = 20  # SHA-1 哈希长度
    mLen = k - 2 * hLen - 2  # 最大消息长度
    
    # Step 1: 找到 i 使得解密结果在 [0, 2^(8hLen) - 1] 范围
    f = 2 ** (8 * (k - hLen - 1))
    
    # 构造 c' = c * f^e mod n
    # 这会将解密结果左移
    # 如果 oracle 返回 1，说明解密后的格式检查失败
    
    s = 1  # 初始乘数
    # 找到 f
    for i in range(k - hLen):
        f_candidate = pow(2, 8 * i, n)
        c_test = (c * f_candidate) % n
        if oracle(c_test.to_bytes(k, 'big')) == 1:
            f = f_candidate
            break
    
    # Step 2: 细化范围
    # 使用区间缩小法
    l, h = 0, n
    
    # 通过不同的乘数 s 缩小区间
    # 类似 Bleichenbacher 的迭代方法
    
    while l < h:
        # 构造测试密文
        # 利用 f 的特性
        
        # 找到 s 使得 s*f 产生可区分的响应
        s = pow(2, 8 * (k - hLen - 1), n) // (h + 1) + 1
        
        # 测试
        c_test = (c * pow(s, e, n)) % n
        resp = oracle(c_test.to_bytes(k, 'big'))
        
        # 根据响应缩小区间
        if resp == 0:  # padding 错误
            # 明文在某个范围内
            l_new = max(l, n // s + 1)
            # h_new = min(h, ...)
        elif resp == 1:  # 格式错误
            h = h * 2 - b
        elif resp == 2:  # 成功
            b = h
        elif resp == 0:  # padding oracle
            return l  # 找到有效明文
        
        # 继续缩小区间...
        break  # 简化
    
    return l  # 近似恢复的明文


# 简化的 Manger 攻击实用函数
def is_oaep_valid(data, block_size=256):
    """检查 OAEP padding 是否有效"""
    if len(data) != block_size:
        return False
    if data[0] != 0x00:
        return False
    
    # 提取 maskedSeed 和 maskedDB
    maskedSeed = data[1:21]  # hLen = 20 for SHA-1
    maskedDB = data[21:]
    
    # 反掩码
    dbMask = MGF1(maskedSeed, block_size - 21 - 1)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    
    seedMask = MGF1(DB, 21 - 1)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    
    # 检查 DB 的最左字节是否为 0
    return DB[0] == 0x00


def MGF1(seed, mask_len):
    """MGF1 掩码生成函数（SHA-1）"""
    import hashlib
    result = b''
    for i in range((mask_len + 19) // 20):
        result += hashlib.sha1(seed + i.to_bytes(4, 'big')).digest()
    return result[:mask_len]
```

### 2. RSA-PSS 签名攻击

```python
# RSA-PSS 是推荐的 RSA 签名 padding 方案
# 常见攻击：签名伪造、盲签名

import hashlib

def pss_sign(message, d, n, salt_length=20):
    """RSA-PSS 签名（简化版）"""
    hLen = 32  # SHA-256
    em_len = 256  # 模块字节长度
    
    # 1. 计算消息哈希
    m_hash = hashlib.sha256(message).digest()
    
    # 2. 生成 salt
    import os
    salt = os.urandom(salt_length)
    
    # 3. 构造 M'
    M_prime = b'\x00' * 8 + m_hash + salt
    
    # 4. 计算 H
    H = hashlib.sha256(M_prime).digest()
    
    # 5. 构造 DB
    db_length = em_len - hLen - 1
    ps = b'\x00' * (db_length - salt_length - 1)
    DB = ps + b'\x01' + salt
    
    # 6. 掩码
    db_mask = hashlib.sha256(H + b'\x00' * (db_length // 32 + 1)).digest()[:db_length]
    masked_DB = bytes(a ^ b for a, b in zip(DB, db_mask))
    
    # 7. 设置最左位
    masked_DB = bytes([masked_DB[0] & 0x7F]) + masked_DB[1:]
    
    # 8. 构造 EM
    EM = masked_DB + H + b'\xbc'
    
    # 9. 签名
    m_int = int.from_bytes(EM, 'big')
    s_int = pow(m_int, d, n)
    return s_int.to_bytes(em_len, 'big')


def pss_verify(message, signature, e, n):
    """RSA-PSS 验证（可利用 oracle）"""
    hLen = 32
    em_len = 256
    
    s_int = int.from_bytes(signature, 'big')
    EM = pow(s_int, e, n).to_bytes(em_len, 'big')
    
    # 检查最后字节
    if EM[-1:] != b'\xbc':
        return False
    
    # 分离 components
    masked_DB = EM[:em_len - hLen - 1]
    H = EM[em_len - hLen - 1:em_len - 1]
    
    # 反掩码
    db_mask = hashlib.sha256(H + b'\x00' * ((em_len - hLen - 1) // 32 + 1)).digest()[:em_len - hLen - 1]
    DB = bytes(a ^ b for a, b in zip(masked_DB, db_mask))
    
    # 检查最左位
    if DB[0] & 0x80 != 0:
        return False
    
    # 提取 salt
    # DB = PS + 0x01 + salt
    idx = len(DB) - 1
    while idx >= 0 and DB[idx] != 0x01:
        idx -= 1
    if idx < 0:
        return False
    salt = DB[idx + 1:]
    
    # 验证
    m_hash = hashlib.sha256(message).digest()
    M_prime = b'\x00' * 8 + m_hash + salt
    H_prime = hashlib.sha256(M_prime).digest()
    
    return H == H_prime


def pss_signature_forgery(n, e):
    """RSA-PSS 签名伪造（当 e 较小时）"""
    # 如果 e=3，可以构造自己的 EM 并直接开立方根
    # 要求 EM 是一个完美的 e 次幂
    
    if e == 3:
        # 构造一个有效的 EM
        # 但这很困难：需要构造一个 H 使得 Padding Oracle 返回特定值
        # 实际攻击需要更复杂的构造（如加密 oracle + 前缀攻击）
        break  # 需要根据具体 oracle 类型实现
    
    # 更实际：利用验证 oracle
    # 多次查询验证 oracle 恢复字节级信息
    for i in range(256):
        oracle.query(ciphertext)  # 需实现具体的 oracle 查询
```

### 3. RSA 时间侧信道攻击

```python
# 利用解密时间差异恢复私钥
# Kocher 攻击：测量解密时间

import time
import statistics

def timing_attack_known_crt(n, d, oracle, num_samples=10000):
    """RSA 时间侧信道攻击（Kocher 攻击）
    
    利用 CRT 优化的 RSA 实现中
    签名时间与私钥位的相关性
    
    oracle: 签名函数，输入消息返回签名和时间
    """
    # 收集时间数据
    # 发送随机消息，记录签名时间
    measurements = []
    
    for _ in range(num_samples):
        m = random.randint(1, n - 1)
        start = time.perf_counter_ns()
        sig = oracle(m)
        elapsed = time.perf_counter_ns() - start
        measurements.append((m, sig, elapsed))
    
    # 分析时间差异
    # 当 d 的某位为 1 时，签名时间略有不同
    
    # 统计分析
    bit_times = {i: [] for i in range(n.bit_length())}
    
    for m, sig, t in measurements:
        for bit in range(n.bit_length()):
            if (m >> bit) & 1:
                bit_times[bit].append(t)
            else:
                bit_times[bit].append(-t)  # 取反
    
    # 计算每位的时间差异
    recovered_d = 0
    for bit in range(n.bit_length()):
        avg = statistics.mean(bit_times[bit])
        if avg > 0:  # 位为 1
            recovered_d |= (1 << bit)
    
    return recovered_d


def blinding_attack(n, d, oracle):
    """RSA 盲签名攻击 — 提取私钥
    
    如果 oracle 接受盲签名请求
    可以恢复私钥 d
    """
    # 选择随机 r
    r = random.randint(2, n - 1)
    
    # 盲化消息: m' = m * r^e mod n
    # 签名: sig' = (m')^d mod n = m^d * r mod n
    # 去盲: sig = sig' * r^(-1) mod n = m^d mod n
    
    # 攻击：如果 oracle 不检查消息格式
    # 可以让 oracle 签名 r^e mod n
    # 得到 r^d mod n = r^(d-1) * r^(-1) * r^d ...
    
    # 更实际：CRT 故障攻击
    # 在签名时注入故障，比较正常和故障签名
    # 恢复 p, q
    
    # 正常签名
    msg = random.randint(1, n - 1)
    sig_normal = oracle(msg)
    
    # 故障签名（如果可以注入故障）
    # sig_fault = msg^d mod q （假设 CRT 的 q 部分出错）
    
    # 恢复
    # p = gcd(msg^(d_normal) - msg^(d_fault), n)
    
    return None
```

### 4. RSA 多素数攻击

```python
# n = p * q * r (多素数 RSA)
# 可以分解较小的素数

import gmpy2

def multi_prime_rsa_attack(n, e, c):
    """多素数 RSA 攻击
    当 n 由多个较小素数组成时
    """
    # 1. 尝试分解
    # 多素数 RSA 的 phi(n) = (p1-1)*(p2-1)*...*(pk-1)
    # 每个素数较小，更容易分解
    
    # 2. 如果知道部分素数
    # 可以从 n 中除以已知素数
    # 剩余部分更容易分解
    
    # 3. 使用 Pollard's p-1 或 Williams' p+1
    # 因为素数较小，p-1 或 p+1 也较小
    
    from math import gcd
    
    # 尝试小素数试除
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    remaining = n
    factors = []
    
    for p in small_primes:
        while remaining % p == 0:
            factors.append(p)
            remaining //= p
    
    if len(factors) >= 3:
        # 找到足够多的素数
        phi = 1
        for p in factors:
            phi *= (p - 1)
        
        d = gmpy2.invert(e, phi)
        m = gmpy2.powmod(c, d, n)
        return int(m)
    
    return None


def chinese_remainder_rsa(n_list, e, c):
    """中国剩余定理加速 RSA
    
    多素数 RSA 使用 CRT 加速解密
    攻击者可以利用这一点
    """
    # CRT 解密
    # m_i = c^(d mod (p_i-1)) mod p_i
    # 然后 CRT 组合
    
    # 如果知道 p_i，可以加速计算
    
    return None
```

### 5. RSA 签名伪造

```python
# RSA 签名是 s = m^d mod n
# 验证是 m = s^e mod n
# 可能的攻击：签名伪造

import gmpy2

def rsa_signature_forge_unpadded(n, e, m):
    """无 padding 的 RSA 签名伪造
    
    如果签名没有 padding，可以直接构造
    """
    # 如果知道 m = s^e mod n
    # 可以构造任意消息的签名
    
    # 例如：伪造两个消息的签名
    # s1 * s2 = (m1 * m2)^d mod n
    
    # 选择 s1 = 1, 则 s2 = (m1 * m2)^d
    # 这等于对 m1*m2 的签名
    
    return None


def rsa_signature_forge_hash(n, e, hash_func):
    """RSA 签名哈希伪造
    
    如果使用简单的哈希签名
    可以构造碰撞
    """
    # 1. 计算目标消息的哈希
    # 2. 寻找另一个消息具有相同哈希
    # 3. 这个消息的签名也是有效的
    
    # 更实际：利用签名 oracle
    # 如果有选择性签名 oracle
    # 可以伪造任意消息的签名
    
    # 例如：签名 f(m) 形式的消息
    # 如果 f 是可预测的，可以构造
    
    return None


def rsa_bundling_attack(n, e, signatures):
    """RSA 签名捆绑攻击
    
    如果允许签名 s1, s2
    可以得到 s1 * s2 = (m1 * m2)^d mod n
    这是对 m1 * m2 的有效签名
    """
    # 这是签名方案的设计缺陷
    # 需要使用 padding (PSS) 来防止
    
    # 攻击示例：
    # 1. 获取对 m1 的签名 s1
    # 2. 获取对 m2 的签名 s2
    # 3. s1 * s2 mod n 是对 m1 * m2 mod n 的签名
    
    return None
```

### 6. RSA 格攻击（Coppersmith 扩展）

```python
# Coppersmith 方法在 RSA 中的应用
# 已知明文部分、未知部分的情况

from sage.all import *

def rsa_partial_key_exposure(n, e, d_low, low_bits):
    """RSA 部分私钥泄露恢复完整私钥
    
    已知 d 的低位（low_bits 位）
    使用 Coppersmith 方法恢复完整 d
    """
    R.<x> = PolynomialRing(Zmod(n))
    
    # e*d = 1 + k*phi(n)
    # e*(d_low + x * 2^low_bits) = 1 + k*(n + 1 - p - q)
    # 已知 d_low，求 x 和 k
    
    # 构造多项式
    f = e * (d_low + x * 2^low_bits) - 1
    
    # 需要更多信息来约束 k
    # 通常使用 lattice 方法
    
    roots = f.small_roots(X=2^(n.bit_length() - low_bits), beta=0.5)
    return roots


def rsa_known_high_bits_attack(n, e, c, m_high, unknown_bits):
    """RSA 已知高位攻击"""
    R.<x> = PolynomialRing(Zmod(n))
    f = (m_high + x)^e - c
    roots = f.small_roots(X=2^unknown_bits, beta=1)
    return roots


def rsa_boneh_durfee(n, e):
    """Boneh-Durfee 攻击
    
    当 d < n^0.292 时有效
    使用格方法
    """
    # 构造格
    # e*d = 1 + k*phi(n) = 1 + k*(n + 1 - p - q)
    # 设 s = n + 1 - p - q
    # 则 e*d - k*s = 1
    
    # 使用 Coppersmith 方法求解
    
    R.<x, y> = PolynomialRing(Zmod(e))
    f = 1 + x * (n + 1 - y) - x * e  # 简化
    
    # 实际实现更复杂，需要构造合适的格
    
    return None
```

### 7. RSA-OAEP Padding Oracle

```python
# RSA-OAEP padding oracle 攻击
# 利用解密时的 oracle 差异

def oaep_padding_oracle_attack(n, e, oracle, block_size=256):
    """RSA-OAEP padding oracle
    
    oracle 返回:
        0: padding 格式错误
        1: padding 哈希错误
        2: 完全正确
    """
    # Manger 攻击的简化实现
    
    # Step 1: 确定消息长度
    # 发送 0^k, 检查 oracle 响应
    
    c_zero = pow(0, e, n).to_bytes(block_size, 'big')
    resp_zero = oracle(c_zero)
    
    # Step 2: 利用 padding 结构
    # OAEP 结构：0x00 || maskedSeed || maskedDB
    # maskedDB 包含: PS || 0x01 || message
    
    # 通过乘以 2^(8*i) 改变解密后的值
    # 观察 oracle 响应
    
    # 简化：逐步恢复字节
    known = b''
    
    for i in range(block_size - 1, -1, -1):
        # 构造 s 使得 c' = c * s^e mod n
        # 解密后变为 m * s mod n
        
        # 尝试不同的 s 值
        for s in range(256):
            # 构造 c'
            c_prime = (c * pow(s, e, n)) % n
            
            # 查询 oracle
            resp = oracle(c_prime.to_bytes(block_size, 'big'))
            
            if resp == 2:  # 正确
                # s 对应的明文字节
                # m_byte * s mod 256 = ...
                break
        
        # 继续下一个字节...
    
    return known
```

### 8. RSA + ECC 混合攻击

```python
# RSA + ECC 混合加密
# 先用 ECC 交换密钥，再用 RSA 加密

def hybrid_rsa_ecc_attack(rsa_pub, ecc_pub, encrypted_key, encrypted_data):
    """RSA + ECC 混合加密攻击
    
    常见模式：
    1. 用 RSA 加密 ECC 会话密钥
    2. 用会话密钥加密数据
    
    攻击目标：
    1. 攻破 RSA 部分，恢复会话密钥
    2. 攻破 ECC 部分，恢复私钥
    """
    # 1. 如果 RSA 实现有漏洞
    # 使用 Bleichenbacher 等攻击
    
    # 2. 如果 ECC 实现有漏洞
    # 使用 MOV 攻击（短周期）
    # 使用 Smart 攻击（异常曲线）
    
    # 3. 混合攻击
    # 如果两个算法都有部分弱点
    # 可能结合起来攻击
    
    # 例如：RSA 使用了弱 padding
    # 可以恢复一些信息
    # 帮助攻击 ECC 部分
    
    return None


def key_encapsulation_attack(kem):
    """KEM 攻击
    
    Key Encapsulation Mechanism
    RSA-KEM, ECC-KEM 等
    """
    # 攻击点：
    # 1. 随机数生成缺陷
    # 2. Padding 缺陷
    # 3. 侧信道泄露
    
    return None
```

### 9. RSA 后量子威胁

```python
# 量子计算对 RSA 的威胁
# Shor 算法可以在多项式时间内分解大数

def shor_algorithm_concept(n):
    """Shor 算法概念（非实际实现）
    
    量子计算机可以在 O((log n)^3) 时间内分解 n
    这将完全破解 RSA
    
    影响：
    1. RSA-2048 在经典计算机上安全
    2. 量子计算机可能在 10-20 年内破解
    3. 需要迁移到后量子密码
    """
    # 1. 找到周期 f(x) = a^x mod n 的周期 r
    # 2. 如果 r 是偶数，a^(r/2) ± 1 可能给出因子
    
    # 量子部分：使用 QFT 找到周期
    # |x⟩ → |f(x)⟩ → |x, f(x)⟩ → QFT → |r⟩
    
    # 经典部分：
    # 如果找到 r (偶数)
    # a^(r/2) ≡ ±1 mod n
    # gcd(a^(r/2) - 1, n) 可能给出因子
    
    return None


def post_quantum_migration():
    """后量子迁移建议
    
    1. 监控 NIST 后量子标准
    2. 评估现有系统
    3. 制定迁移计划
    4. 实施混合方案
    """
    # 推荐的后量子算法：
    # 1. 格密码：CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (签名)
    # 2. 哈希签名：SPHINCS+
    # 3. 编码密码：Classic McEliece
    
    # CTF 中的后量子挑战：
    # 1. Lattice-based RSA
    # 2. 格攻击实现
    # 3. 后量子协议分析
    
    return None
```

### 10. RSA 自动化工具

```python
# RSA 攻击自动化
# 在 CTF 中快速识别和利用 RSA 弱点

import gmpy2
from math import gcd

def auto_rsa_attack(n, e, c, **kwargs):
    """自动化 RSA 攻击
    
    尝试多种已知攻击方法
    自动识别弱点并利用
    """
    results = {}
    
    # 1. 因子分解
    # 检查是否可分解
    p = None
    q = None
    
    # 尝试 yafu/在线分解
    # 如果 n 较小 (< 256 bit)
    if n.bit_length() < 256:
        # 使用 sympy
        from sympy import factorint
        factors = factorint(n)
        if len(factors) == 2:
            p, q = list(factors.keys())
    
    # 2. 共享素数
    if 'n_list' in kwargs:
        n_list = kwargs['n_list']
        for other_n in n_list:
            if other_n != n:
                g = gcd(n, other_n)
                if g != 1 and g != n:
                    p = g
                    q = n // p
                    break
    
    # 3. Wiener 攻击（小 d）
    if p is None:
        d = wiener_attack(e, n)
        if d is not None:
            m = gmpy2.powmod(c, d, n)
            return int(m)
    
    # 4. Fermat 分解
    if p is None and n.bit_length() < 1024:
        p, q = fermat_factor(n)
    
    # 5. Pollard's p-1
    if p is None:
        p = pollard_p_minus_1(n)
        if p:
            q = n // p
    
    # 6. 解密
    if p is not None and q is not None:
        phi = (p - 1) * (q - 1)
        d = int(gmpy2.invert(e, phi))
        m = gmpy2.powmod(c, d, n)
        return int(m)
    
    # 7. 低加密指数
    if e == 3:
        m, exact = gmpy2.iroot(c, 3)
        if exact:
            return int(m)
    
    return None


def rsa_signature_auto(sig, e, n, **kwargs):
    """RSA 签名自动化分析"""
    from Crypto.PublicKey import RSA
    try:
        key = RSA.import_key(open(pubkey_file).read())
        return key
    except Exception:
        return None


# 快速工具函数
def quick_rsa(n, e, c):
    """快速 RSA 分解和解密"""
    # 使用 RsaCtfTool
    # 或手动尝试
    
    import subprocess
    import tempfile
    import json
    
    # 写入参数
    params = {"n": hex(n), "e": hex(e), "c": hex(c)}
    
    # 尝试 RsaCtfTool
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(params, f)
            f.flush()
            
        result = subprocess.run(
            ['python3', 'RsaCtfTool.py', '--publickey', f.name, '--uncipher', hex(c)],
            capture_output=True, text=True, timeout=60
        )
        
        if result.returncode == 0:
            # 解析输出
            return result.stdout
    except:
        pass
    
    return None
```

## 工具推荐

- **RsaCtfTool** — RSA 自动化
- **yafu** — 大数分解
- **FactorDB** — 在线分解
- **SageMath** — 数学计算
- **gmpy2** — 大整数运算
- **PyCryptodome** — Python 加密库

## 参考链接

- [ctf-wiki RSA](https://ctf-wiki.org/crypto/asymmetric/rsa/)
- [RSA Attack](https://github.com/Ganapati/RsaCtfTool)
- [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/pubs/papers/RSAattack-survey.pdf)
