# 格攻击 (Lattice Attacks)

## 原理

格（Lattice）是 n 维空间中离散点的集合。格基规约（LLL/BKZ）可以找到短向量，用于攻击多种密码学问题（RSA、ECC、背包密码等）。

## 格基础

```python
from sage.all import *

# 格定义
# L = {a1*v1 + a2*v2 + ... + an*vn | ai ∈ Z}
# v1, v2, ..., vn 是基向量

# 创建格
M = Matrix(ZZ, [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 10]
])
L = M.LLL()  # LLL 规约
```

## 攻击链

### 1. LLL 算法

```python
# 格基规约
from sage.all import *

def lll_attack(basis):
    M = Matrix(ZZ, basis)
    return M.LLL()

# 找短向量
def shortest_vector(basis):
    M = Matrix(ZZ, basis)
    L = M.LLL()
    return L[0]  # 最短向量
```

### 2. Coppersmith 攻击

```python
# 已知明文高位
# m = m0 + x，x 未知且小
# f(x) = (m0 + x)^e - c ≡ 0 mod n
# 使用 Coppersmith 方法求小根

from sage.all import *

def coppersmith_univariate(f, n, beta=1.0, X=None):
    # f: 多项式
    # n: 模数
    # beta: n 的因子占比
    # X: x 的上界
    if X is None:
        X = 2^(n.bit_length() // 4)
    roots = f.small_roots(X=X, beta=beta)
    return roots

# RSA 已知明文高位
def rsa_known_high_bits(n, e, c, m_high, unknown_bits):
    R.<x> = PolynomialRing(Zmod(n))
    f = (m_high + x)^e - c
    roots = coppersmith_univariate(f, n, X=2^unknown_bits)
    return roots
```

### 3. Coppersmith 多变量

```python
# 多变量 Coppersmith
# 使用 Herrmann-May 方法

from sage.all import *

def coppersmith_multivariate(f, bounds, m=1, t=1):
    # f: 多变量多项式
    # bounds: 各变量上界
    # ...
    pass
```

### 4. RSA 相关消息攻击

```python
# 两个消息有线性关系
# m2 = a*m1 + b
# 可用 Franklin-Reiter 相关消息攻击

from sage.all import *

def franklin_reiter(n, e, c1, c2, a, b):
    R.<x> = PolynomialRing(Zmod(n))
    f1 = x^e - c1
    f2 = (a*x + b)^e - c2
    # 求公因式
    g = gcd(f1, f2)
    if g.degree() == 1:
        return -g[0] * inverse_mod(g[1], n) % n
    return None
```

### 5. 背包密码攻击

```python
# Merkle-Hellman 背包密码
# 使用 CJLOSS 算法

from sage.all import *

def knapsack_attack(public_key, ciphertext):
    n = len(public_key)
    # 构造格
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = public_key[i]
    M[n, n] = -ciphertext
    # LLL 规约
    L = M.LLL()
    # 找解
    for row in L:
        if all(x in [0, 1] for x in row[:-1]):
            return row[:-1]
    return None
```

### 6. 隐藏数问题（HNP）

```python
# 已知 d 的高位
# 利用 HNP 求解

from sage.all import *

def hnp_attack(n, known_bits, leak_bits):
    # 构造格
    # ...
    pass
```

### 7. DSA nonce 攻击

```python
# DSA 中 nonce 部分泄露
# 利用格恢复 nonce

from sage.all import *

def dsa_nonce_attack(n, signatures, h, r, s, leak_bits):
    # 构造格
    # ...
    pass
```

### 8. ECDSA nonce 攻击

```python
# ECDSA 中 nonce 部分泄露
# 类似 DSA

from sage.all import *

def ecdsa_nonce_attack(n, signatures, h, r, s, leak_bits):
    # 构造格
    # ...
    pass
```

### 9. NTRU 攻击

```python
# NTRU 是格密码
# 某些参数可被 LLL 攻击

from sage.all import *

def ntru_attack(N, p, q, h):
    # 构造格
    M = Matrix(ZZ, 2*N, 2*N)
    # ...
    L = M.LLL()
    # 找私钥
    # ...
    pass
```

### 10. LWE 攻击

```python
# LWE (Learning With Errors)
# 某些参数可被攻击

from sage.all import *

def lwe_attack(n, q, m, A, b, error_bound):
    # 构造格
    # ...
    pass
```

## 2024-2026 新技术点

### 1. 后量子密码分析

```python
# NTRU
# LWE
# Ring-LWE
# Module-LWE
# 各后量子密码的格攻击
```

### 2. BKZ 算法改进

```python
# BKZ 2.0
# BKZ 3.0
# 更高效的格基规约
```

### 3. 量子算法

```python
# 量子格算法
# 影响后量子密码
```

### 4. 侧信道 + 格

```python
# 侧信道泄露 + 格攻击
# 恢复密钥
```

### 5. AI 辅助

```python
# ML 辅助
# 格基选择
# 参数优化
```

### 6. 新型格攻击

```python
# 持续有新的格攻击方法
# 关注最新研究
```

### 7. 同态加密攻击

```python
# FHE 中的格攻击
# 新的攻击面
```

### 8. 零知识证明攻击

```python
# zk-SNARK 中的格攻击
# 新的攻击面
```

### 9. 多方安全计算攻击

```python
# MPC 中的格攻击
# 新的攻击面
```

### 10. 实战应用

```python
# 实际系统中的格攻击
# TLS
# 区块链
# 各实际应用
```

## 工具推荐

- **SageMath** — 格计算
- **fpylll** — Python LLL 库
- **PARI/GP** — 数学计算
- **NTL** — C++ 数论库

## 参考链接

- [ctf-wiki lattice](https://ctf-wiki.org/crypto/asymmetric/lattice/)
- [Lattice Attack](https://github.com/jvdsn/crypto-attacks)
- [Coppersmith Method](https://en.wikipedia.org/wiki/Coppersmith_method)
- [LLL Algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
