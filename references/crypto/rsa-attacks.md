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
# p+1 有小素因子时
# 类似 Pollard's p-1
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
# PKCS1 v1.5 padding oracle
# 通过错误信息判断 padding 是否正确
# 逐步恢复明文
```

## 2024-2026 新技术点

### 1. 后量子 RSA

```python
# 多素数 RSA
# n = p1 * p2 * ... * pk
# 各素数较小
# 可分解
```

### 2. RSA-CRT 故障攻击

```python
# 硬件故障注入
# 签名时注入故障
# 恢复 d
```

### 3. 侧信道攻击

```python
# 时间攻击
# 功耗分析
# 电磁分析
# 各侧信道
```

### 4. 白盒 RSA

```python
# 白盒实现
# 提取密钥
# 各白盒攻击
```

### 5. RSA + ECC

```python
# RSA + ECC 混合
# 各组合攻击
```

### 6. RSA in TLS

```python
# TLS 中的 RSA
# Bleichenbacher 变种
# ROBOT 攻击
```

### 7. RSA 签名攻击

```python
# 签名伪造
# Hash 延展
# 各签名攻击
```

### 8. RSA-OAEP 攻击

```python
# OAEP padding
# Manger 攻击
# 各 OAEP 攻击
```

### 9. 量子计算

```python
# Shor 算法
# 量子分解
# 影响 RSA 安全性
```

### 10. AI 辅助

```python
# ML 辅助
# 参数预测
# 弱点识别
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
