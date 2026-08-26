# ECC 攻击

## 原理

椭圆曲线密码学（ECC）基于椭圆曲线离散对数难题。CTF 中常因曲线参数选择不当、实现错误被攻击。

## ECC 基础

```python
# 椭圆曲线方程：y^2 = x^3 + ax + b mod p
# 基点 G，阶 n，余因子 h
# 私钥 d，公钥 Q = d*G

# 加密
# 1. 选随机数 k
# 2. C1 = k*G
# 3. C2 = M + k*Q

# 解密
# 1. M = C2 - d*C1
```

## 攻击链

### 1. 曲线参数弱点

#### 异常曲线攻击

```python
# 如果曲线阶等于 p（anomalous curve）
# 可在多项式时间内求解 ECDLP
# Smart 攻击
from sage.all import *

def smart_attack(p, a, b, G, Q):
    E = EllipticCurve(GF(p), [a, b])
    # 提升 p-adic
    Ep = EllipticCurve(Qp(p), [a, b])
    Gp = Ep(G[0], G[1])
    Qp = Ep(Q[0], Q[1])
    # 计算
    p_times_G = p * Gp
    p_times_Q = p * Qp
    # 求解
    x = p_times_G[0] / p_times_G[1]
    y = p_times_Q[0] / p_times_Q[1]
    return int(-y / x) % p
```

#### 弱曲线攻击

```python
# 如果曲线阶光滑（有小素因子）
# Pohlig-Hellman 攻击
from sage.all import *

def pohlig_hellman(G, Q, n):
    E = G.curve()
    order = E.order()
    # 分解 order
    factors = factor(order)
    d = 0
    for p, e in factors:
        # 求解 mod p^e
        Gi = G * (order // (p^e))
        Qi = Q * (order // (p^e))
        di = discrete_log(Qi, Gi, Gi.order(), operation='+')
        d += di * (order // (p^e)) * inverse_mod(order // (p^e), p^e)
        d %= order
    return d
```

### 2. 无效曲线攻击

```python
# 如果不验证点是否在曲线上
# 攻击者发送不在曲线上的点
# 利用弱曲线求解

def invalid_curve_attack(p, a, b, G, Q, n):
    # 尝试不同的 b'
    for b_prime in range(p):
        try:
            E_prime = EllipticCurve(GF(p), [a, b_prime])
            # 检查阶是否光滑
            order = E_prime.order()
            if is_smooth(order):
                # 在弱曲线上求解
                # ...
                pass
        except:
            continue
```

### 3. 小步大步（Baby-Step Giant-Step）

```python
# 通用 ECDLP 求解
def bsg(G, Q, n):
    m = isqrt(n) + 1
    # Baby step
    table = {}
    for j in range(m):
        table[j * G] = j
    # Giant step
    for i in range(m):
        if Q - i * m * G in table:
            return i * m + table[Q - i * m * G]
    return None
```

### 4. Pollard's rho

```python
# 概率性算法
# 时间复杂度 O(sqrt(n))
```

### 5. 共享 G 攻击

```python
# 多个用户共享基点 G
# 如果随机数 k 重用
# 可恢复私钥
```

### 6. 随机数弱点

#### k 重用

```python
# ECDSA 中 k 重用
# 两个签名使用相同 k
# 可恢复 k，进而恢复私钥
# s1 = k^(-1) * (h1 + r * d) mod n
# s2 = k^(-1) * (h2 + r * d) mod n
# s1 - s2 = k^(-1) * (h1 - h2) mod n
# k = (h1 - h2) / (s1 - s2) mod n
# d = (s1 * k - h1) / r mod n
```

#### 弱随机数

```python
# 如果 k 可预测
# 可恢复私钥
```

### 7. ECDH 攻击

```python
# 如果不验证对方公钥
# 可被中间人攻击
# 无效曲线攻击
```

### 8. ECDSA 攻击

```python
# 1. k 重用
# 2. 弱随机数
# 3. 侧信道
# 4. 故障注入
```

### 9. 退化曲线攻击

```python
# 如果曲线参数选择不当
# 可能退化到有限域
# ECDLP 变简单
```

### 10. MOV 攻击

```python
# 如果曲线嵌入度小
# 可将 ECDLP 归约到有限域 DLP
from sage.all import *

def mov_attack(E, G, Q, n):
    # 找嵌入度 k
    # 使用 Weil 配对
    # ...
    pass
```

## 2024-2026 新技术点

### 1. 后量子 ECC

```python
# 同源密码（Isogeny-based）
# SIDH
# CSIDH
# 后量子 ECC
```

### 2. Pairing-friendly 曲线

```python
# BN 曲线
# BLS 曲线
# 配对计算
```

### 3. 侧信道攻击

```python
# 时间攻击
# 功耗分析
# 电磁分析
# 各侧信道
```

### 4. 故障攻击

```python
# 硬件故障注入
# 恢复密钥
```

### 5. 白盒 ECC

```python
# 白盒实现
# 提取密钥
```

### 6. 国密 SM2

```python
# SM2 算法
# 基于 ECC
# 各 SM2 攻击
```

### 7. Ed25519

```python
# Ed25519 签名
# 新的攻击
```

### 8. 量子攻击

```python
# Shor 算法
# 影响 ECC 安全性
```

### 9. 新型曲线

```python
# 新的安全曲线
# Curve25519
# Curve448
# 各新型曲线
```

### 10. AI 辅助

```python
# ML 辅助
# 侧信道分析
# 参数预测
```

## 工具推荐

- **SageMath** — 椭圆曲线计算
- **PyCryptodome** — Python 加密库
- **fastecdsa** — 快速 ECC 库
- **ecpy** — ECC 工具

## 参考链接

- [ctf-wiki ECC](https://ctf-wiki.org/crypto/asymmetric/ecc/)
- [ECC Attack](https://github.com/jvdsn/crypto-attacks)
- [SEC1](https://www.secg.org/sec1-v2.pdf)
