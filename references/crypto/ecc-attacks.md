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
    Qp_pt = Ep(Q[0], Q[1])
    # 计算
    p_times_G = p * Gp
    p_times_Q = p * Qp_pt
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
from sage.all import *

def is_smooth(n, bound=2**20):
    """检查 n 是否为光滑数（所有素因子 ≤ bound）"""
    for p in range(2, bound):
        while n % p == 0:
            n //= p
        if n == 1:
            return True
    return False

def invalid_curve_attack(p, a, G, Q, n):
    """
    无效曲线攻击：遍历 b' 找光滑阶弱曲线，
    在每条弱曲线上用 Pohlig-Hellman 恢复 d mod order_i，
    最后用 CRT 合并。
    """
    from collections import defaultdict
    remainders = []  # (r_i, n_i) 表示 d ≡ r_i mod n_i

    for b_prime in range(1, min(p, 10000)):  # 限制搜索范围
        try:
            E_prime = EllipticCurve(GF(p), [a, b_prime])
            order = E_prime.order()
            if order < 4 or not is_smooth(order):
                continue
            # 在弱曲线上取 G, Q
            try:
                Gp = E_prime(G[0], G[1])
                Qp = E_prime(Q[0], Q[1])
            except:
                continue
            # Pohlig-Hellman 在弱曲线上求解
            di = discrete_log(Qp, Gp, operation='+')
            remainders.append((di, order))
            print(f"[+] b'={b_prime}, weak order={factor(order)}, d mod {order} = {di}")
        except:
            continue

    if not remainders:
        print("[-] 未找到足够弱曲线")
        return None

    # CRT 合并所有余数
    from sympy.ntheory.modular import crt
    moduli = [r[1] for r in remainders]
    residues = [r[0] for r in remainders]
    d, _ = crt(moduli, residues)
    print(f"[+] Recovered private key d = {d % n}")
    return d % n
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

### 4. Pollard's rho 攻击

```python
from sage.all import *
from random import randint

def pollard_rho_ecdl(E, G, Q, n, max_iter=1000000):
    """
    Pollard's rho 算法求解椭圆曲线离散对数 Q = d*G。
    时间复杂度 O(√n)，空间复杂度 O(1)。
    适用于已知 n 较大但无法 Pohlig-Hellman 的情况。

    原理：构造伪随机行走 x_{i+1} = f(x_i)，
    其中 f 按 x_i = a_i*G + b_i*Q 分类为三类：
    - X_i ≡ 0 mod 3: X_{i+1} = X_i + G   => a_{i+1}=a_i+1, b_{i+1}=b_i
    - X_i ≡ 1 mod 3: X_{i+1} = 2*X_i     => a_{i+1}=2a_i,   b_{i+1}=2b_i
    - X_i ≡ 2 mod 3: X_{i+1} = X_i + Q   => a_{i+1}=a_i,     b_{i+1}=b_i+1

    Floyd 判圈：若 X_j = X_{2j}，则 a_j+G*b_j ≡ a_{2j}+G*b_{2j}
    => d = (a_j - a_{2j}) * (b_{2j} - b_j)^{-1} mod n
    """
    def split(X):
        """将点 X 按 x 坐标分为三类"""
        x_val = int(X[0]) % 3
        return x_val

    def step(X, a, b):
        """执行一步伪随机行走"""
        kind = split(X)
        if kind == 0:
            return (X + G, (a + 1) % n, b)
        elif kind == 1:
            return (2 * X, (2 * a) % n, (2 * b) % n)
        else:
            return (X + Q, a, (b + 1) % n)

    # 初始化
    a0 = randint(1, n - 1)
    b0 = randint(1, n - 1)
    X0 = a0 * G + b0 * Q

    # Floyd 循环检测
    # tortoise: 每步走1次, hare: 每步走2次
    Xt, at, bt = X0, a0, b0
    Xh, ah, bh = X0, a0, b0

    for _ in range(max_iter):
        # tortoise 走一步
        Xt, at, bt = step(Xt, at, bt)
        # hare 走两步
        Xh, ah, bh = step(Xh, ah, bh)
        Xh, ah, bh = step(Xh, ah, bh)

        if Xt == Xh:
            # 找到碰撞：at*G + bt*Q = ah*G + bh*Q
            # => (at - ah)*G = (bh - bt)*Q
            # => d = (at - ah) * inverse_mod(bh - bt, n) mod n
            db = (bh - bt) % n
            if db == 0:
                # 退化情况，重新开始
                continue
            inv_db = inverse_mod(db, n)
            d = ((at - ah) % n) * inv_db % n
            return d

    print("[-] Pollard's rho 未在迭代上限内找到解")
    return None


# ---------- 三路并行版本（更快，竞赛常用） ----------

def pollard_rho_parallel(E, G, Q, n, num_threads=4):
    """
    多起点并行 Pollard's rho，共享查找表加速碰撞检测。
    每个起点用不同随机种子，写入共享字典。
    """
    from threading import Lock
    table = {}
    lock = Lock()
    found = [False]
    result = [None]

    def random_walk(tid):
        a = randint(1, n - 1)
        b = randint(1, n - 1)
        X = a * G + b * Q

        while not found[0]:
            kind = int(X[0]) % 3
            if kind == 0:
                X = X + G
                a = (a + 1) % n
            elif kind == 1:
                X = 2 * X
                a = (2 * a) % n
                b = (2 * b) % n
            else:
                X = X + Q
                b = (b + 1) % n

            key = X
            lock.acquire()
            if key in table:
                a_prev, b_prev = table[key]
                db = (b - b_prev) % n
                if db != 0:
                    d = ((a_prev - a) % n) * inverse_mod(db, n) % n
                    found[0] = True
                    result[0] = d
            else:
                table[key] = (a, b)
            lock.release()

    import threading
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=random_walk, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return result[0]
```

### 5. 共享 G 攻击

```python
from sage.all import *

def shared_G_attack(G, Q1, Q2, n1, n2):
    """
    共享 G 攻击（两个用户使用相同基点 G）。

    场景：
    - Alice: Q_a = d_a * G,  公开 (G, Q_a, Q_b)
    - Bob:   Q_b = d_b * G

    如果曲线阶 n = n1 * n2，其中 n1, n2 较小（光滑因子），
    则对每个因子子群分别用 Pohlig-Hellman 求解，CRT 合并。

    特殊情况：两个用户用相同 k（nonce reuse）时，
    还可以利用双重签名恢复私钥（见 ECDSA k-reuse）。

    进阶：当曲线阶无小因子时，若攻击者知道 G 生成的子群阶 n，
    可构造双线性映射（pairing）辅助攻击，或利用共享私钥的统计弱点。
    """
    E = G.curve()
    order = E.order()
    factors = factor(order)

    def _pohlig_hellman_sub(Gp, Qp, ord_G):
        """对子群阶 ord_G 执行 Pohlig-Hellman"""
        sub_factors = factor(ord_G)
        d_sub = 0
        for p_i, e_i in sub_factors:
            pe = p_i ^ e_i
            Gi = Gp * (ord_G // pe)
            Qi = Qp * (ord_G // pe)
            di = discrete_log(Qi, Gi, operation='+')
            d_sub += di * (ord_G // pe) * inverse_mod(ord_G // pe, pe)
        return d_sub % ord_G

    print("[*] 分别对 Q1, Q2 执行 Pohlig-Hellman 恢复 d1, d2")

    d1 = _pohlig_hellman_sub(G, Q1, order)
    d2 = _pohlig_hellman_sub(G, Q2, order)

    print(f"[+] d1 = {d1}")
    print(f"[+] d2 = {d2}")
    print(f"[+] 验证: d1*G == Q1 ? {d1 * G == Q1}")
    print(f"[+] 验证: d2*G == Q2 ? {d2 * G == Q2}")

    return d1, d2


def shared_G_nonce_reuse(r1, s1, h1, r2, s2, h2, n):
    """
    共享 G 且 k 重用攻击：两个 ECDSA 签名使用相同随机数 k。

    s1 = k^{-1} * (h1 + r * d) mod n
    s2 = k^{-1} * (h2 + r * d) mod n

    s1 - s2 = k^{-1} * (h1 - h2) mod n
    => k = (h1 - h2) * inverse_mod(s1 - s2, n) mod n
    => d = (s1 * k - h1) * inverse_mod(r, n) mod n
    """
    ds = (s1 - s2) % n
    dh = (h1 - h2) % n
    if ds == 0:
        print("[-] s1 == s2, 无法恢复 k")
        return None

    k = dh * inverse_mod(ds, n) % n
    d = (s1 * k - h1) * inverse_mod(r1, n) % n

    print(f"[+] Recovered k = {k}")
    print(f"[+] Recovered private key d = {d}")
    return d
```

### 6. 随机数弱点

#### k 重用

```python
from sage.all import *

def ecdsa_k_reuse(r, s1, h1, s2, h2, n):
    """
    ECDSA nonce (k) 重用攻击：
    两个签名使用相同 k，可直接恢复私钥。

    签名公式：
      s1 = k^{-1} * (h1 + r * d) mod n
      s2 = k^{-1} * (h2 + r * d) mod n

    两式相减：
      s1 - s2 = k^{-1} * (h1 - h2) mod n
      => k = (h1 - h2) / (s1 - s2) mod n

    代回：
      d = (s1 * k - h1) / r mod n
    """
    ds = (s1 - s2) % n
    dh = (h1 - h2) % n
    if ds == 0:
        raise ValueError("s1 == s2, 无法恢复 k (可能 h1 == h2)")

    k = dh * inverse_mod(ds, n) % n
    d = (s1 * k - h1) * inverse_mod(r, n) % n

    print(f"[+] Recovered nonce  k = {k}")
    print(f"[+] Recovered private key d = {d}")
    return d, k


def ecdsa_k_reuse_multi(signatures, n):
    """
    多签名 k-reuse 批量恢复：
    输入: signatures = [(r, s_i, h_i), ...]
    所有签名共享同一个 r（意味着 k 相同）。
    任取两对即可恢复 d，可交叉验证。
    """
    r = signatures[0][0]
    recovered_keys = []

    for i in range(len(signatures)):
        for j in range(i + 1, len(signatures)):
            r_i, s_i, h_i = signatures[i]
            r_j, s_j, h_j = signatures[j]
            if r_i != r_j:
                continue
            ds = (s_i - s_j) % n
            if ds == 0:
                continue
            dh = (h_i - h_j) % n
            k = dh * inverse_mod(ds, n) % n
            d = (s_i * k - h_i) * inverse_mod(r_i, n) % n
            recovered_keys.append(d)

    if recovered_keys:
        # 验证一致性
        assert len(set(recovered_keys)) == 1, "k-reuse 恢复结果不一致！"
        print(f"[+] 从 {len(signatures)} 个签名中恢复私钥 d = {recovered_keys[0]}")
        return recovered_keys[0]
    print("[-] 未能恢复私钥")
    return None
```

#### 弱随机数

```python
import hashlib

def ecdsa_weak_nonce_known_range(G, r, s, h, n, k_known_range):
    """
    ECDSA 弱随机数攻击：已知 k 的取值范围，暴力搜索。

    当 k 不是密码学安全随机数时（例如线性同余生成器、
    时间戳、小范围随机数），可直接枚举。

    输入：
      G       - 基点
      r, s    - 签名 (r, s)
      h       - 签名消息的哈希
      n       - 曲线阶
      k_known_range - (k_min, k_max) 或可迭代对象
    """
    for k in k_known_range:
        d_candidate = (s * k - h) * inverse_mod(r, n) % n
        # 验证：用 d_candidate 和 k 重新计算 r
        R = k * G
        r_check = int(R[0]) % n
        if r_check == r:
            print(f"[+] Found k = {k}")
            print(f"[+] Recovered private key d = {d_candidate}")
            return d_candidate, k
    print("[-] 在给定范围内未找到有效 k")
    return None, None


def ecdsa_weak_nonce_known_bits(G, r, s, h, n, known_bits):
    """
    ECDSA 弱随机数 —— 已知 k 的部分比特（高位已知）攻击。
    利用格基归约（LLL）恢复剩余比特。

    参考: Howgrave-Graham, "A Hash Function for Hash Tables",
    以及 Bleichenbacher 对 DSA nonce 部分泄漏的攻击。

    输入 known_bits: k 的已知高位比特数
    """
    bit_length = n.bit_length()
    unknown_bits = bit_length - known_bits

    if unknown_bits <= 0:
        print("[*] 已知全部 k 比特，直接计算")
        d = (s * k - h) * inverse_mod(r, n) % n
        return d

    # 构造格
    # s*k ≡ h + r*d (mod n)
    # k = 2^unknown_bits * k_upper + k_lower
    # 用 LLL 在格中找短向量恢复 k_lower
    B = 2^unknown_bits
    M = Matrix(ZZ, 3, 3)
    M[0] = [n, 0, 0]
    M[1] = [0, B, 0]
    M[2] = [int(r), int(s), 1]

    # 目标向量
    target = vector(ZZ, [int(h), 0, 0])

    # 增广格
    aug = block_matrix(ZZ, [[M, target], [0, 1]])
    L = aug.LLL()

    print(f"[*] 对 k 的 {unknown_bits} 个未知比特进行 LLL 格攻击")
    # 解析结果（实际竞赛中需根据具体参数调整）
    for row in L:
        if row[-1] != 0:
            continue
        # 检查是否为有效解
        k_candidate = abs(row[1]) % n
        if k_candidate == 0:
            continue
        R = k_candidate * G
        r_check = int(R[0]) % n
        if r_check == r:
            d = (s * k_candidate - h) * inverse_mod(r, n) % n
            print(f"[+] Recovered k = {k_candidate}")
            print(f"[+] Recovered private key d = {d}")
            return d

    print("[-] LLL 未找到有效解")
    return None
```

### 7. ECDH 攻击

```python
from sage.all import *

def ecdh_shared_secret_leak(p, a, b, n, G, Qa, Qb, shared_secret_x):
    """
    ECDH 共享密钥泄漏攻击。

    场景：攻击者截获 ECDH 密钥交换，获取：
    - Alice 公钥 Qa = da * G
    - Bob 公钥 Qb = db * G
    - 共享密钥的 x 坐标 shared_secret_x
    （或完整的共享密钥点 S）

    攻击方法：
    如果已知 S = da * Qb = db * Qa，且知道 S 的 x 坐标，
    可以在曲线上求解对应的 y（可能有两个），然后暴力尝试。

    如果曲线阶 n 较小，可直接用 Pollard rho 从 S 反推 da 或 db。
    """
    E = EllipticCurve(GF(p), [a, b])

    # 从 x 坐标恢复完整点
    x = GF(p)(shared_secret_x)
    # y^2 = x^3 + ax + b
    y_sq = x^3 + a*x + b
    y = y_sq.sqrt()

    candidates = [E(x, y), E(x, -y)]

    for S in candidates:
        try:
            # 尝试从 S = da * Qb 求 da
            da = discrete_log(S, Qb, operation='+')
            print(f"[+] Recovered da = {da}")
            print(f"[+] 验证: da*G == Qa ? {da * G == Qa}")
            return da
        except:
            continue
        try:
            db = discrete_log(S, Qa, operation='+')
            print(f"[+] Recovered db = {db}")
            print(f"[+] 验证: db*G == Qb ? {db * G == Qb}")
            return db
        except:
            continue

    print("[-] 未能恢复私钥")
    return None


def ecdh_invalid_curve(p, a, G, n):
    """
    ECDH 无效曲线攻击：利用实现不验证点是否在曲线上的漏洞。

    攻击步骤：
    1. 选取弱曲线 E'（阶光滑），使得 y'^2 = x'^3 + a*x' + b'
    2. 构造 E' 上的点 P'，其 x 坐标与合法公钥相同
    3. 发送 P' 作为公钥给对方
    4. 对方计算 S' = d * P'（在 E' 上）
    5. 攻击者在 E' 上用 Pohlig-Hellman 从 S' 恢复 d mod order(E')
    6. 重复获取足够余数，CRT 合并得 d

    注意：此攻击要求对方不验证接收的公钥是否在原曲线上。
    """
    # 示例：遍历小 b' 寻找光滑阶曲线
    for b_prime_int in range(1, 1000):
        try:
            E_prime = EllipticCurve(GF(p), [a, b_prime_int])
            order = E_prime.order()
            if order < 100:
                continue
            factors = factor(order)
            # 检查是否所有素因子都较小
            if all(pi < 1000 for pi, _ in factors):
                print(f"[+] 弱曲线 b'={b_prime_int}, order={order}, factors={factors}")
                # 实际攻击中还需构造 E' 上的点并执行上述步骤
                return E_prime, order
        except:
            continue
    return None, None
```

### 8. ECDSA 攻击

```python
from sage.all import *

def ecdsa_nonce_bit_leak(G, Q, n, r, s, h, leaked_bits, bit_position):
    """
    ECDSA nonce 部分比特泄漏攻击。

    当 nonce k 的某些比特通过侧信道泄漏时，
    可以利用格方法恢复完整的 k，进而恢复私钥。

    leaked_bits: 泄漏的 k 的比特值（整数）
    bit_position: 泄漏比特的位置（从最低位开始）

    参考: Bleichenbacher & Ng (2005), "Attacking RSA Tokens with DSA"
    """
    k_bits = len(bin(leaked_bits)) - 2  # 泄漏比特数
    mask = (1 << bit_position) - 1
    k_upper = leaked_bits << bit_position  # 已知高位部分

    # 目标：找到 k_lower (未知的低位部分)，使得:
    # k = k_upper + k_lower, 0 <= k_lower < 2^bit_position
    # s*k ≡ h + r*d (mod n)

    # 构造格 (HNP 变体)
    B = 2^bit_position
    # 格基矩阵
    L = Matrix(ZZ, 4, 4)
    L[0] = [n,       0,       0, 0]
    L[1] = [0,       B,       0, 0]
    L[2] = [0,       0,       B, 0]
    L[3] = [int(r),  int(s),  int(s) * k_upper - int(h), int(s)]

    # 约简
    red = L.LLL()

    # 检查每行是否对应有效解
    for row in red:
        if row[3] == 0:
            continue
        k_cand = row[1] % n
        if k_cand == 0:
            continue
        R_check = k_cand * G
        if int(R_check[0]) % n == r:
            d = (s * k_cand - h) * inverse_mod(r, n) % n
            print(f"[+] Recovered k = {k_cand}")
            print(f"[+] Recovered d = {d}")
            return d

    print("[-] 格攻击未能恢复私钥")
    return None


def ecdsa_fault_attack(G, Q, n, r, s1, s2, h):
    """
    ECDSA 故障注入攻击（Bellcore 攻击变体）：
    对同一个签名计算两次，第二次注入故障使 r 被篡改。

    两个签名有相同的 k（因为是同一随机数生成），
    但 r' ≠ r（因为故障影响了 R 的 x 坐标）。

    s1 = k^{-1} * (h + r * d) mod n
    s2 = k^{-1} * (h + r' * d) mod n

    已知 r, r', s1, s2, h, n，两式联立消去 k:
    s1 - s2 = k^{-1} * d * (r - r') mod n
    k = d * (r - r') / (s1 - s2) mod n

    代入第一式：
    s1 * d * (r - r') / (s1 - s2) = h + r * d (mod n)
    s1 * d * (r - r') = (s1 - s2) * (h + r * d) (mod n)
    d * [s1*(r-r') - r*(s1-s2)] = h*(s1-s2) (mod n)
    d * [s1*r - s1*r' - r*s1 + r*s2] = h*(s1-s2)
    d * [r*s2 - s1*r'] = h*(s1-s2) (mod n)

    => d = h*(s1-s2) / (r*s2 - s1*r') mod n
    """
    num = h * (s1 - s2) % n
    den = (r * s2 - s1 * r) % n  # 注意：实际中 r' ≠ r

    if den == 0:
        print("[-] 分母为零，无法恢复")
        return None

    d = num * inverse_mod(den, n) % n
    print(f"[+] 故障攻击恢复私钥 d = {d}")
    return d


def ecdsa_malleable_signature(G, Q, n, r, s):
    """
    ECDSA 签名延展性攻击：

    ECDSA 签名 (r, s) 的有效签名还有 (r, n-s)。
    如果系统只检查 r 而不检查 s 的范围，
    攻击者可以翻转 s 来构造不同签名通过验证。

    在比特币等区块链中，这会导致交易 malleability。
    """
    s_alt = (n - s) % n
    print(f"[*] 原始签名: (r={r}, s={s})")
    print(f"[*] 延展签名: (r={r}, s'={s_alt})")
    print(f"[*] 两个签名验证同一条消息")
    return (r, s_alt)
```

### 9. 退化曲线攻击

```python
from sage.all import *

def degenerate_curve_attack(p, a, b, G, Q, n):
    """
    退化曲线攻击：当椭圆曲线参数选择不当时，
    曲线可能退化或具有特殊结构，使 ECDLP 变得容易。

    常见退化情况：
    1. 曲线阶很小，直接暴力搜索
    2. 曲线嵌入度小，MOV 攻击有效
    3. 曲线同构于加法群（超奇异曲线）
    4. a*b = c 且曲线上的点构成小阶循环群
    5. 乘法群结构（曲线同构于 F_p^* 的子群）

    具体：若曲线参数满足 a*b = small_value，
    则曲线阶可能只有几个点，直接枚举所有可能的 d。
    """
    E = EllipticCurve(GF(p), [a, b])
    order = E.order()

    print(f"[*] 曲线阶: {order}")
    print(f"[*] 因子分解: {factor(order)}")

    # 情况 1：阶很小，暴力搜索
    if order < 10^8:
        print("[*] 曲线阶较小，暴力搜索 d...")
        for d_candidate in range(order):
            if d_candidate * G == Q:
                print(f"[+] Recovered d = {d_candidate}")
                return d_candidate
        return None

    # 情况 2：检查是否为乘法群嵌入
    # 若曲线阶 = p（anomalous）或有特殊因子结构
    if order == p:
        print("[*] 异常曲线 (order == p)，使用 Smart 攻击")
        return smart_attack(p, a, b, [G[0], G[1]], [Q[0], Q[1]])

    # 情况 3：嵌入度很小
    k = E.embedding_degree()
    print(f"[*] 嵌入度: {k}")
    if k <= 20:
        print("[*] 嵌入度小，尝试 MOV 攻击")
        return mov_attack(E, G, Q, order)

    # 情况 4：通用 Pohlig-Hellman
    factors = factor(order)
    max_factor = max(pi for pi, _ in factors)
    print(f"[*] 最大素因子: {max_factor}")
    if max_factor < 2^40:
        print("[*] 阶光滑，Pohlig-Hellman")
        return pohlig_hellman(G, Q, order)

    print("[-] 未发现明显退化特征")
    return None


def degenerate_small_order(G, Q, p, a, b):
    """
    当 a*b 的值很小或特殊时，曲线可能只有很少的点。
    直接枚举所有可能的私钥。

    例如：a=0, b=1 在某些域上可能退化。
    """
    E = EllipticCurve(GF(p), [a, b])
    order = E.order()

    if order <= 100000:
        print(f"[*] 退化曲线，仅 {order} 个点，暴力枚举...")
        for d in range(1, order + 1):
            if d * G == Q:
                print(f"[+] Recovered d = {d}")
                return d

    return None
```

### 10. MOV 攻击与 Frey-Ruck 攻击

```python
from sage.all import *

def mov_attack(E, G, Q, n):
    """
    MOV 攻击（Menezes-Okamoto-Vanstone）：
    将椭圆曲线上的 DLP 转化为有限域乘法群上的 DLP。

    原理：
    - 利用 Weil 配对 e_k: E[n] × E[n] → μ_n ⊂ F_{p^k}^*
    - 嵌入度 k 满足 n | (p^k - 1)
    - e_k(G, Q) = e_k(G, d*G) = e_k(G, G)^d
    - 在 F_{p^k}^* 中求 d = DLP(e_k(G,G), e_k(G,Q))

    适用条件：嵌入度 k 足够小（通常 k ≤ 12）。

    输入：
      E - 椭圆曲线
      G - 基点（生成元）
      Q - 目标点（Q = d*G）
      n - G 的阶
    """
    # 找嵌入度 k：最小的 k 使得 n | (p^k - 1)
    k = E.embedding_degree(n)
    print(f"[*] 嵌入度 k = {k}")

    if k > 20:
        print("[-] 嵌入度过大，MOV 攻击不适用")
        return None

    # 使用 Weil 配对
    pair = E.weil_pairing(G, Q, k)
    print(f"[*] Weil 配对 e(G, Q) = {pair}")

    # 基点配对
    pair_G = E.weil_pairing(G, G, k)
    print(f"[*] Weil 配对 e(G, G) = {pair_G}")

    # 在有限域 F_{p^k}^* 中求解 DLP
    # pair = pair_G^d, 求 d
    d = discrete_log(pair, pair_G, operation='*')

    if d is not None:
        d = int(d)
        print(f"[+] MOV 攻击成功: d = {d}")
        print(f"[+] 验证: d*G == Q ? {d * G == Q}")
        return d
    else:
        print("[-] DLP 求解失败")
        return None


def frey_ruck_attack(E, G, Q, n, P_extra=None):
    """
    Frey-Ruck 攻击（Tate 配对变体）：
    使用 Tate 配对替代 Weil 配对，计算更高效。

    Tate 配对定义：
    ê(P, Q) = f_{P,n}(Q)^{(p^k-1)/n}

    优势：
    - 计算速度比 Weil 配对快约 2 倍
    - 不需要 k 次扩展运算
    - 对超奇异曲线特别高效

    在 CTF 中，如果已知曲线是 pairing-friendly 的（如 BN 曲线），
    可以利用 Tate 配对快速将 ECDLP 归约到有限域 DLP。
    """
    k = E.embedding_degree(n)
    print(f"[*] Frey-Ruck: 嵌入度 k = {k}")

    if k > 20:
        print("[-] 嵌入度过大")
        return None

    # 使用 Tate 配对
    try:
        tp_GQ = E.tate_pairing(Q, G, k)
        tp_GG = E.tate_pairing(G, G, k)
    except:
        # 尝试用 Weil 配对作为后备
        tp_GQ = E.weil_pairing(G, Q, k)
        tp_GG = E.weil_pairing(G, G, k)

    print(f"[*] Tate 配对 t(Q, G) = {tp_GQ}")
    print(f"[*] Tate 配对 t(G, G) = {tp_GG}")

    d = discrete_log(tp_GQ, tp_GG, operation='*')

    if d is not None:
        d = int(d)
        print(f"[+] Frey-Ruck 攻击成功: d = {d}")
        print(f"[+] 验证: d*G == Q ? {d * G == Q}")
        return d
    return None


def pairing_based_secret_sharing_attack(p, a, b, G, shares):
    """
    基于配对的门限签名攻击（Boneh-Gentry-Lynn-Shacham）：

    场景：Shamir 秘密共享 + 椭圆曲线配对实现门限签名。
    攻击者收集到 ≥ threshold 个份额后，利用配对
    验证/恢复原始私钥。

    shares: [(x_i, s_i*G), ...] 即 (份额编号, 份额点)
    """
    E = EllipticCurve(GF(p), [a, b])
    n = E.order()
    k = E.embedding_degree(n)

    if k > 10:
        print("[-] 嵌入度太大，配对攻击不可行")
        return None

    # 拉格朗日插值恢复秘密（在椭圆曲线上）
    recovered = E(0)  # 无穷远点
    for i, (xi, Si) in enumerate(shares):
        # 拉格朗日系数
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num *= (-xj)      # L_i(0) = prod(-xj / (xi - xj))
                den *= (xi - xj)
        lam = (num * inverse_mod(den, n)) % n
        recovered += lam * Si

    print(f"[+] 恢复的秘密点: {recovered}")
    return recovered
```

## 2024-2026 新技术点

### 1. 后量子 ECC

```python
# 同源密码（Isogeny-based）
# SIDH / SIKE (2022 被攻破，但思想仍有价值)
# CSIDH - 交换群结构，天然适合 Diffie-Hellman

# === CSIDH 基本概念 ===
# CSIDH 基于超奇异椭圆曲线的同源图
# 公钥: curve E', 由基曲线 E 经过密钥 m 对应的同源得到
# 密钥交换: Alice 用 m_A 推动 E -> E_A, Bob 用 m_B 推动 E -> E_B
# Alice 接收 E_B, 用 m_A 推动 -> 共享曲线
# Bob 接收 E_A, 用 m_B 推动 -> 共享曲线

# === SIDH 攻击 (Castryck-Decru 2022) ===
# 利用辅助点的 torsion structure
# 通过 Kani 构造恢复同源

# === 量子计算影响 ===
# Shor 算法可多项式时间求解 ECDLP
# 256-bit ECC ≈ 128-bit 对称安全 (量子计算机下)
# 目前无实用量子计算机，但需关注

# 实用代码：使用 sage 检查曲线是否受量子威胁
def quantum_security_check(n):
    """评估 ECC 参数的量子安全性"""
    classical_bits = int(log(n, 2))
    quantum_bits = int(classical_bits / 2)  # Grover 近似
    print(f"[*] 经典安全强度: ~{classical_bits} bits")
    print(f"[*] 量子安全强度 (Grover): ~{quantum_bits} bits")
    print(f"[*] Shor 算法: ECDLP 在量子计算机上为多项式时间")
    if classical_bits < 224:
        print("[!] 不安全：建议 ≥ 224 bit ECC (NIST 2024)")
    return classical_bits
```

### 2. Pairing-friendly 曲线

```python
from sage.all import *

def bn_curve_example():
    """
    BN 曲线 (Barreto-Naehrig)：
    y^2 = x^3 + b，定义在 F_p 上
    嵌入度 k=12，常用配对友好曲线之一。

    参数形式:
      p = 36x^4 + 36x^3 + 24x^2 + 6x + 1
      n = 36x^4 + 36x^3 + 18x^2 + 6x + 1
      t = 6x^2 + 1
    """
    # BN-254 曲线参数 (以太坊使用)
    x = 0x6000000000000001
    p = 36*x**4 + 36*x**3 + 24*x**2 + 6*x + 1
    n = 36*x**4 + 36*x**3 + 18*x**2 + 6*x + 1
    b = 3

    E = EllipticCurve(GF(p), [0, b])
    k = 12  # 嵌入度

    print(f"[*] BN-254 曲线:")
    print(f"    p = {hex(p)}")
    print(f"    n = {hex(n)}")
    print(f"    嵌入度 k = {k}")
    print(f"    E.order() = {E.order()}")
    return E


def bls_curve_example():
    """
    BLS 曲线 (Barreto-Lynn-Scott)：
    嵌入度 k=12，常用于 BLS 签名方案和零知识证明。
    BLS12-381 是当前 ZK 领域最流行的曲线。
    """
    # BLS12-381 简化参数
    p = 0x1a0111ea397fe69a4c15314dabca5ac4602a1e4a1a0e1f1f7c72f2d96404a5b57ed80e8f4c8c7c4c5c3a4c3b5d5e5f6
    # 实际使用中应加载完整参数
    print(f"[*] BLS12-381:")
    print(f"    p (508 bits)")
    print(f"    嵌入度 k = 12")
    print(f"    双线性配对: G1 × G2 -> GT")
    print(f"    用途: 聚合签名, 零知识证明, VRF")


def pairing_computation_example(E, P, Q, k):
    """
    配对计算示例：Miller 算法 + 最终幂次。

    Miller 算法核心:
    1. 初始化 T = P, f = 1
    2. 对 k 的二进制位循环:
       - 如果该位为 1: f = f * line(T, Q), T = T + P
       - 否则:         f = f * line(T, Q), T = 2*T
    3. 最终幂: result = f^{(p^k - 1) / n}

    Miller 算法复杂度: O(k * log(p))
    """
    # Sage 内置配对计算
    weil = E.weil_pairing(P, Q, k)
    tate = E.tate_pairing(P, Q, k)

    print(f"[*] Weil 配对: {weil}")
    print(f"[*] Tate 配对: {tate}")
    return weil, tate


def bls_signature_attack(G1, G2, pubkeys, messages):
    """
    BLS 聚合签名攻击场景：

    1. 短签名攻击：如果消息空间小，可对签名做散列碰撞
    2. 无效公钥攻击：注入无穷远点或低阶点
    3. 随机预言模型下安全性：改变哈希函数可能破坏安全证明

    pubkeys: [(Q_i, sig_i), ...] 公钥-签名对
    """
    print("[*] BLS 聚合签名验证")
    print("[*] 聚合: σ_agg = σ_1 + σ_2 + ... + σ_n")
    print("[*] 验证: e(G, σ_agg) == e(H(m_1), Q_1) * ... * e(H(m_n), Q_n)")

    # 检查无效公钥（低阶点）
    for i, (Q, sig) in enumerate(pubkeys):
        try:
            order = Q.order()
            if order < 1000:
                print(f"[!] 公钥 {i} 可能是低阶点，阶 = {order}")
        except:
            print(f"[!] 公钥 {i} 验证异常")

    return None
```

### 3. 侧信道攻击

```python
import time
import statistics

def timing_attack_scalar_mult leaked_times, base_points, n):
    """
    时间侧信道攻击：通过测量标量乘法的时间差异恢复私钥。

    简单时序攻击（Simple Timing Attack）：
    - 监测 d*G 的计算时间
    - 对不同 d' 计算 d'*G 的时间
    - 时间匹配时 d' ≈ d

    差分时序攻击（Differential Timing Attack）：
    - Kocher 攻击：通过统计分析不同输入的时间差
    - 利用平方-乘算法中 conditional branch 的时间差异

    Kocher (1996): "Timing Attacks on Implementations of
    Diffie-Hellman, RSA, DSS, and Other Systems"
    """
    print("[*] 时序攻击: 分析标量乘法的时间模式")
    print("[*] Kocher 方法:")
    print("    1. 对同一 G，用不同 d 测量 d*G 的时间")
    print("    2. 统计时间分布，定位 conditional branch")
    print("    3. 逐比特恢复 d")

    # 差分时序分析示例
    if leaked_times and len(leaked_times) > 10:
        mean_t = statistics.mean(leaked_times)
        std_t = statistics.stdev(leaked_times)
        print(f"    平均时间: {mean_t:.6f}s, 标准差: {std_t:.6f}s")
        # 利用时间差推断 bits
        return mean_t, std_t
    return None


def power_analysis_sca(traces, plaintexts):
    """
    功耗分析 (Power Analysis) 攻击 ECC:

    1. SPA (Simple Power Analysis):
       - 单次追踪即可识别操作模式
       - 双重-倍加: double-then-add (1) vs double-only (0)
       - 直接从功耗轨迹读出私钥比特

    2. DPA (Differential Power Analysis):
       - 统计分析大量功耗轨迹
       - 利用汉明重量/汉明距离模型
       - 逐步恢复每个比特

    3. CPA (Correlation Power Analysis):
       - 计算假设功耗与实际功耗的相关性
       - 适用于带噪声的环境

    traces: 2D numpy array, shape=(num_traces, num_samples)
    plaintexts: 对应的输入点列表
    """
    print("[*] 功耗分析:")
    print("    SPA: 从单条轨迹识别 double/add 模式")
    print("    DPA: 统计分析差异功耗")
    print("    CPA: 相关性分析")

    # SPA 简单示例：识别 double-add 模式
    # 在 scalar multiplication 中:
    #   double 操作功耗特征
    #   add 操作功耗特征不同
    if traces is not None and len(traces) > 0:
        trace = traces[0]
        print(f"    轨迹长度: {len(trace)} 采样点")
        # 检测功耗尖峰（简化示例）
        threshold = statistics.mean(trace) + 2 * statistics.stdev(trace)
        peaks = [i for i, v in enumerate(trace) if v > threshold]
        print(f"    检测到 {len(peaks)} 个操作峰值")
    return None


def electromagnetic_analysis():
    """
    电磁 (EM) 侧信道分析：
    与功耗分析类似，但使用近场 EM 探针采集信号。

    优势：
    - 可局部定位芯片特定区域
    - 更高的空间分辨率
    - 不需要物理接触电源引脚

    常见方法：
    1. EM-SPA: 电磁简单分析
    2. EM-DPA: 电磁差分分析
    3. EM-CPA: 电磁相关性分析

    在 ECC 中：
    - 标量乘法的 double/add 操作产生可区分的 EM 信号
    - 通过门控时钟同步采集
    """
    print("[*] EM 侧信道:")
    print("    - 近场 EM 探针采集信号")
    print("    - 门控时钟同步")
    print("    - 局部化分析特定运算单元")

    # 攻击流程
    print("    攻击流程:")
    print("    1. 选择明文 (基点 G)")
    print("    2. 触发标量乘法 d*G")
    print("    3. 采集 EM 轨迹")
    print("    4. SPA/DPA/CPA 分析")
    print("    5. 逐比特恢复 d")
    return None
```

### 4. 故障攻击

```python
def ecc_fault_injection(p, a, b, G, Q, n):
    """
    ECC 故障注入攻击：

    1. Bellcore 攻击 (针对签名):
       - 在签名计算中注入故障
       - 用正确签名和故障签名恢复私钥

    2. 故障-敏感染色体攻击 (Fault-Mensitivity):
       - 利用 faulty vs correct 标量乘法结果
       - X : d*G (正确), X' : d*G' (故障)
       - X - X' = d*(G - G'), 由此恢复 d

    3. Piret-Quisquater 故障攻击:
       - 针对 Montgomery Ladder
       - 单次故障注入
       - O(n) 恢复所有比特

    4. Lenstra 故障攻击:
       - 针对 RSA/ECC 签名验证
       - 故障后的签名可以分解公钥

    硬件攻击方式:
    - 电压毛刺 (Voltage Glitching)
    - 时钟毛刺 (Clock Glitching)
    - 激光注入 (Laser Fault Injection)
    - EM 脉冲 (EM Pulses)
    """
    E = EllipticCurve(GF(p), [a, b])

    print("[*] 故障注入攻击 ECC:")
    print("    1. Bellcore: d = (s' - s) / (h' - h) mod n")
    print("    2. Piret-Quisquater: 单次故障恢复 Montgomery Ladder 密钥")
    print("    3. Puncturing: 修改计算中间值")

    # 模拟 Piret-Quisquater 攻击
    print("\n[*] Piret-Quisquater 故障攻击模拟:")
    print("    假设 Montgomery Ladder 在第 i 步出错")
    print("    X_i = a_i * G + b_i * Q (正确)")
    print("    X_i' = a_i' * G + b_i' * Q (故障)")
    print("    d = (a_i - a_i') * inverse(b_i' - b_i) mod n")

    return None


def fault_attack_ladder(G, Q, n, i, X_correct, X_faulty):
    """
    Montgomery Ladder 故障攻击：

    在第 i 步注入故障，使得 R0 或 R1 被修改。
    通过比较正确和故障的最终结果，
    利用中间值关系恢复 d 的各比特。

    输入:
      G, Q, n: 基点, 公钥, 曲线阶
      i: 故障注入的位置 (比特索引)
      X_correct: 正确的 d*G 结果
      X_faulty: 故障注入后的结果
    """
    # 故障前的中间值 X_{i-1} 可以从已知比特推导
    d_bits = bin(n)[2:]  # d 的比特表示（模拟）

    # 在 Montgomery Ladder 中:
    # R0, R1 初始化为 O, G
    # 对 d 的每个比特 b_i:
    #   if b_i == 0: R1 = R0 + R1, R0 = 2*R0
    #   if b_i == 1: R0 = R0 + R1, R1 = 2*R1

    diff = X_faulty - X_correct  # 曲线点减法
    print(f"[*] 差异点: {diff}")
    print(f"[*] 差异点阶: {diff.order() if hasattr(diff, 'order') else 'unknown'}")

    # 通过差分分析恢复 d 的比特
    print("[*] 故障差分分析:")
    print("    从差异点与 G, Q 的关系推断故障注入位置")
    print("    逐步恢复 d 的每个比特")

    return None
```

### 5. 白盒 ECC

```python
def whitebox_ecc_extract():
    """
    白盒 ECC 实现中的密钥提取攻击：

    白盒环境假设攻击者完全控制执行环境
    （可调试、可读内存、可修改代码）。

    攻击方法：
    1. 表查找攻击: ECC 的标量乘法通常用查表实现
       - 直接读取嵌入的私钥 d
       - 或从查表的输入/输出推导

    2. DBI (Differential Bytevalue Inspection):
       - 通过修改表条目观察输出变化
       - 定位私钥比特位置

    3. 污点分析 (Taint Analysis):
       - 标记私钥数据为 "tainted"
       - 追踪 taint 在计算中的传播
       - 从最终输出反推私钥

    4. 代数攻击:
       - 将白盒实现建模为代数方程组
       - 用 SAT/SMT 求解器恢复密钥

    常见白盒 ECC 方案:
    - 白盒 SM2 (国密)
    - 白盒 ECDSA
    - 白盒 EdDSA
    """
    print("[*] 白盒 ECC 密钥提取:")
    print("    1. 直接内存读取（最简单）")
    print("    2. 表查找分析: 修改/观察查找表输入输出")
    print("    3. DBI: 差分字节值检查")
    print("    4. 污点追踪: 从输入到输出的完整数据流")
    print("    5. 符号执行: 用 angr 等工具自动分析")
    print("    6. SAT/SMT 求解: 建模为约束满足问题")

    # angr 污点分析示例（伪代码）
    print("\n[*] angr 符号执行示例框架:")
    print("""
    import angr
    proj = angr.Project('whitebox_ecc.bin', auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)

    # 标记输入为符号变量
    key_bytes = state.solver.BVS('key', 8 * 32)  # 256-bit key

    # 执行到输出点
    simgr.explore(find=0x401000)  # 输出地址

    # 提取约束中的密钥值
    for found in simgr.found:
        sol = found.solver.eval(key_bytes, cast_to=bytes)
        print(f"Extracted key: {sol.hex()}")
    """)
    return None
```

### 6. 国密 SM2

```python
def sm2_attack_scenarios():
    """
    SM2 算法攻击：

    SM2 基于椭圆曲线 y^2 = x^3 + ax + b over GF(2^{256} - 2^{224} - 2^{96} + 2^{64} - 1)
    标准曲线参数: a = -3, b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

    常见攻击：
    1. Nonce 重用: 与 ECDSA 相同
    2. 边信道: 计算 SM2 签名时的功耗/时序泄漏
    3. 随机数弱点: 如果随机数生成器有偏差
    4. 签名伪造: 利用 SM2 的特殊结构 (Z 值, 用户 ID)
    """
    print("[*] SM2 攻击场景:")

    # SM2 Nonce 重用
    print("""
    SM2 签名 (r, s):
      e = Hash(Z_A || M)
      r = (e + x1) mod n
      s = (1 + d_A)^{-1} * (k - r * d_A) mod n

    Nonce k 重用攻击:
      s1 = (1 + d_A)^{-1} * (k - r1 * d_A) mod n
      s2 = (1 + d_A)^{-1} * (k - r2 * d_A) mod n

      s1 - s2 = (1 + d_A)^{-1} * (-r1 * d_A + r2 * d_A) mod n
              = d_A * (r2 - r1) / (1 + d_A) mod n

      => d_A = s1 - s2 / (r2 - r1 + s1 - s2) mod n
    """)
    return None


def sm2_nonce_reuse(r1, s1, h1, r2, s2, h2, n):
    """
    SM2 签名 nonce (k) 重用攻击。

    SM2 签名公式:
      r = (e + x_R) mod n
      s = (1 + d)^{-1} * (k - r * d) mod n

    SM2 与 ECDSA 不同:
      s = (1+d)^{-1} * (k - r*d)
      => k = s*(1+d) + r*d = s + d*(s + r)

    两个签名 k 相同:
      s1 + d*(s1 + r1) = s2 + d*(s2 + r2)
      d*(s1 + r1 - s2 - r2) = s2 - s1
      d = (s2 - s1) / (s1 + r1 - s2 - r2) mod n
    """
    num = (s2 - s1) % n
    den = (s1 + r1 - s2 - r2) % n

    if den == 0:
        print("[-] 分母为零")
        return None

    d = num * inverse_mod(den, n) % n
    print(f"[+] SM2 nonce 重用恢复私钥: d = {d}")
    return d


def sm2_gost_identical_k(r1, s1, h1, r2, s2, h2, n):
    """
    GOST R 34.10-2012 / SM2 变体:
    当两个不同消息的签名使用相同 k 时。
    """
    # GOST 签名: s = (r * d + k) mod n
    # s1 = r1 * d + k mod n
    # s2 = r2 * d + k mod n
    # s1 - s2 = (r1 - r2) * d mod n
    dr = (r1 - r2) % n
    ds = (s1 - s2) % n
    if dr == 0:
        return None
    d = ds * inverse_mod(dr, n) % n
    print(f"[+] GOST nonce 重用恢复 d = {d}")
    return d
```

### 7. Ed25519

```python
import hashlib

def ed25519_nonce_recover(message, sig, public_key_bytes):
    """
    Ed25519 签名 nonce 泄漏/重用攻击:

    Ed25519 签名: (R, S) 其中 R = r*G, S = r + H(R || pk || msg) * s
    验证: S*G == R + H(R || pk || msg) * pk

    1. nonce 重用: 同 ECDSA
    2. nonce 泄漏: 如果 r 的某些比特泄漏
    3. 签名延展性: S 和 l - S 都有效 (l 为子群阶)

    Ed25519 细节:
    - 紧凑编码: 64 字节签名 = 32 字节 R + 32 字节 S
    - SHA-512 哈希: H(prefix || msg) 生成 nonce
    - 如果 prefix 有偏差，nonce 可预测
    """
    print("[*] Ed25519 攻击向量:")
    print("    1. 签名延展性: S' = l - S, (R, S') 也有效")
    print("    2. Nonce 泄漏: 时序/功耗泄漏 r 的部分比特")
    print("    3. 确定性 nonce: H(secret || msg), 如果 H 实现有缺陷")
    print("    4. 弱随机前缀: H(weak_seed || msg) → nonce 可预测")

    # 签名延展性示例
    l = 2**252 + 27742317777372353535851937790883648493  # Ed25519 子群阶
    print(f"\n[*] Ed25519 子群阶 l = {hex(l)}")
    print(f"[*] 如果 S 已知，S' = l - S 也是有效签名")
    return None


def ed25519_biased_nonce(known_nonce_bits, nonce_bit_length=256):
    """
    Ed25519 偏差 nonce 攻击：

    如果 nonce 生成器有偏差（例如某些比特总是 0），
    可以通过遍历或格方法恢复私钥。

    参考: Howgrave-Graham, Smart "Lattice Attacks on Digital Signature Schemes"
    和 De Micco et al. "On the Security of Ed25519"
    """
    unknown_bits = nonce_bit_length - known_nonce_bits
    print(f"[*] 偏差 nonce 攻击:")
    print(f"    已知 nonce 位数: {known_nonce_bits}")
    print(f"    未知位数: {unknown_bits}")
    print(f"    搜索空间: 2^{unknown_bits}")

    if unknown_bits <= 40:
        print(f"    可行: 暴力搜索 2^{unknown_bits} ≈ {2**unknown_bits} 次")
        return True
    elif unknown_bits <= 128:
        print(f"    可行: LLL 格攻击")
        return True
    else:
        print(f"    不可行: 搜索空间过大")
        return False
```

### 8. 量子攻击

```python
def quantum_shor_ecdlp():
    """
    Shor 算法对 ECC 的影响：

    1. 经典 ECDLP: 最佳算法 O(√n), n 为群阶
    2. Shor 算法: O((log n)^3) 量子门, O(log n) 量子比特

    量子优势:
    - ECDLP: 经典 O(2^{128}) → 量子 O(1) (多项式)
    - RSA-2048: 经典 O(2^{112}) → 量子 O(1)
    - 对称密码: 仅 Grover O(√n) 优势

    NIST PQC 标准 (2024):
    - ML-KEM (Kyber): 格基加密
    - ML-DSA (Dilithium): 格基签名
    - SLH-DSA (SPHINCS+): 哈希签名
    - FN-DSA (Falcon): 格基签名

    后量子 ECC 替代方案:
    - CSIDH: 基于超奇异同源的 DH (仍有安全争议)
    - SQISign: 基于同源的签名 (紧凑但慢)
    """
    print("[*] Shor 算法时间复杂度:")
    print("    经典最佳: O(exp(1.923 * (log n)^{1/3} * (log log n)^{2/3}))")
    print("    Shor:     O((log n)^2 * (log log n) * (log log log n))")
    print()

    print("[*] ECC 安全位数对比:")
    print("    ECC-256  经典: 128 bits 安全")
    print("    ECC-256  量子: ~0 bits 安全 (Shor 攻破)")
    print("    AES-128  经典: 128 bits 安全")
    print("    AES-128  量子: ~64 bits 安全 (Grover)")
    print("    AES-256  经典: 256 bits 安全")
    print("    AES-256  量子: ~128 bits 安全 (Grover)")
    print()

    print("[*] NIST PQC 标准 (2024 年发布):")
    print("    加密:    ML-KEM-512/768/1024 (Kyber)")
    print("    签名:    ML-DSA-44/65/87 (Dilithium)")
    print("    签名:    SLH-DSA (SPHINCS+, 哈希基)")
    print("    签名:    FN-DSA (Falcon, NTRU 格)")

    # 量子攻击时间估算（以 Toffoli 门为单位）
    def shor_gate_count(bits):
        """估算 Shor 算法破解 ECC 所需的 Toffoli 门数"""
        return 9 * bits**3 + 4 * bits**2

    ecc_256 = shor_gate_count(256)
    ecc_384 = shor_gate_count(384)
    ecc_521 = shor_gate_count(521)

    print(f"\n[*] 估算 Shor Toffoli 门数:")
    print(f"    ECC-256: {ecc_256:.2e}")
    print(f"    ECC-384: {ecc_384:.2e}")
    print(f"    ECC-521: {ecc_521:.2e}")

    return None
```

### 9. 新型曲线

```python
def curve25519_attack_vectors():
    """
    Curve25519 (X25519, Ed25519) 攻击向量:

    参数: y^2 = x^3 + 486662x^2 + x over GF(2^255 - 19)
    阶: 8 * l (l 为素数, l ≈ 2^252)

    1. 无效曲线: X25519 不验证输入点是否在曲线上
    2. 小子群攻击: 余因子 8 导致 8 个低阶点
    3. 共谋攻击: 多个低阶输入可以泄露私钥比特
    4. Lim-Lee 攻击: 利用 cofactor

    安全特性:
    - 完全加法定理 (Complete Addition): 所有输入对都安全
    - 盲化: 防止侧信道
    - 常量时间: 防止时序攻击
    """
    print("[*] Curve25519 攻击向量:")

    print("""
    1. 小子群攻击 (Lim-Lee):
       X25519 的余因子 h = 8
       输入低阶点 P (阶 2, 4, 8)
       d*P 的 x 坐标泄露 d mod 阶(P)
       攻击者收集多个小阶信息，CRT 合并

       防御: 强制校验输出 != 无穷远点

    2. 无效曲线攻击:
       X25519 不验证 x 坐标是否对应有效点
       攻击者发送不合法 x
       如果实现有 bug 可能泄露信息

    3. 随机数偏差:
       Ed25519 用 H(secret, msg) 生成 nonce
       如果 secret 有偏差 (如部分比特固定)
       可能导致 nonce 可预测

    4. 签名延展性:
       Ed25519 签名 (R, S), (R, l-S) 都有效
       需要实现层修复
    """)

    # 小子群攻击示例
    print("[*] 小子群攻击:")
    print("    Ed25519 子群阶 l ≈ 2^252")
    print("    余因子群阶: 2, 4, 8")
    print("    输入: l-order 点 P_i")
    print("    计算: S_i = s * P_i (每个只泄露 s mod order(P_i))")
    print("    CRT:  s mod (2 * 4 * 8) 可能泄露 s 的低 5 bits")
    return None


def curve448_attack():
    """
    Curve448 (Goldilocks, X448, Ed448):

    参数: y^2 = x^3 - x over GF(2^448 - 2^224 - 1)
    阶: 4 * l (l 为素数)
    安全强度: ~224 bits

    与 Curve25519 的区别:
    - 余因子 4 (vs 8)
    - 完全加法定理
    - Ed448 使用 SHAKE256 (可扩展输出)
    - Ed448 有内置抗延展性

    攻击向量类似 Curve25519 但更小:
    - 小子群攻击 (余因子 4)
    - 侧信道
    - 实现 bug
    """
    print("[*] Curve448 攻击向量:")
    print("    余因子: 4")
    print("    小子群攻击: 类似 Curve25519, 但余因子更小")
    print("    Ed448 抗延展性: 内置 r 值检查")
    print("    安全性: ~224 bits 经典, ~112 bits 量子 (Grover)")
    return None


def pairing_curves_comparison():
    """
    各类配对友好曲线对比:
    """
    print("[*] 配对友好曲线对比:")
    print("""
    | 曲线        | 安全性  | 嵌入度 | 用途                  |
    |-------------|---------|--------|-----------------------|
    | BN-254      | ~128bit | 12     | 以太坊, Groth16      |
    | BLS12-381   | ~128bit | 12     | ZK-SNARK, 聚合签名    |
    | BLS12-461   | ~150bit | 12     | ZK-STARK 等           |
    | BW6-761     | ~256bit | 6      | 高安全 ZK            |
    | MNT4-292    | ~146bit | 4      | 轻量级配对            |
    | BN256       | ~128bit | 12     | 前一代标准           |
    """)

    # 攻击配对友好曲线
    print("[*] 配对友好曲线的特殊攻击:")
    print("    1. MOV 攻击: 嵌入度小，ECDLP 可归约到有限域 DLP")
    print("    2. Pairing 操作本身的安全性:")
    print("       - 配对输入验证必须严格")
    print("       - 无效输入可能导致信息泄漏")
    print("    3. Zero-Knowledge 证明中的 curve-specific 攻击:")
    print("       - 双随机数攻击 (Double Randomness)")
    print("       - 签名延展性")
    return None
```

### 10. AI 辅助分析

```python
def ai_assisted_ecc_attack():
    """
    AI/ML 辅助 ECC 攻击：

    1. 侧信道 + ML:
       - CNN/RNN 分析功耗轨迹
       - 自动识别操作模式
       - 比传统 SPA/DPA 更鲁棒

    2. 神经网络辅助 LLL:
       - 预测最佳格基参数
       - 加速格约简

    3. 漏洞检测:
       - 静态分析: ML 模型识别加密实现中的 bug
       - Fuzzing + ML: 智能生成测试用例

    4. 自动化 CTF:
       - LLM 分析题目描述
       - 自动生成解题脚本
       - 但需要人工验证

    实际工具:
    - tlsc (Side-Channel + ML)
    - CryptoML (加密库漏洞检测)
    - angr + ML (符号执行优化)
    """
    print("[*] AI 辅助 ECC 分析:")

    print("""
    1. 侧信道机器学习:
       - 训练 CNN 分类 double/add 操作
       - 输入: 功耗轨迹 (1D 信号)
       - 输出: 操作序列 (比特恢复)
       - 比传统 SPA 更抗噪声

    2. 自动化漏洞检测:
       - 训练 ML 模型识别:
         * 未验证的点 (invalid curve)
         * 可预测的 nonce
         * 侧信道泄漏
       - 工具: angr + 自定义 ML 插件

    3. 密码分析辅助:
       - LLM 辅助理解论文
       - 自动生成 SageMath 代码
       - 参数推荐 (曲线选择)

    4. 局限性:
       - ML 不提供安全证明
       - 需要大量标注数据
       - 对新攻击类型泛化能力有限
       - 仍需密码学专家验证
    """)
    return None
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
- [Shor's Algorithm for ECC](https://arxiv.org/abs/quant-ph/0301141)
- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
