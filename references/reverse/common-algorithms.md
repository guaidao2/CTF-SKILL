# 常见算法 (Common Algorithms)

## 原理

逆向时识别常见加密/哈希算法，提取密钥/参数，编写解密脚本。

## 算法识别特征

### 1. 常量识别

| 算法 | 特征常量 |
|------|---------|
| MD5 | 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 |
| SHA1 | 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 |
| SHA256 | 0x6a09e667, 0xbb67ae85, ... |
| CRC32 | 表 0xedb88320 |
| TEA/XTEA/XXTEA | delta = 0x9e3779b9 |
| AES | S 盒 0x63, 0x7c, 0x77, ... |
| RC4 | S 盒初始化 0-255 |
| Blowfish | P 数组 0x243f6a88, ... |
| DES | S 盒、置换表 |
| SM4 | S 盒 0xd6, 0x90, 0xe9, ... |
| SM3 | 0x7380166f, ... |

### 2. 工具识别

```bash
# FindCrypt (IDA 插件)
# Signsrch
signsrch ./reverse

# Detect It Easy
DIE ./reverse

# PEiD
PEiD ./reverse.exe
```

## 常见算法详解

### 1. 异或 (XOR)

```python
# 加密
def xor_encrypt(data, key):
    return bytes([d ^ key for d in data])

# 解密（异或的逆操作是异或）
def xor_decrypt(data, key):
    return bytes([d ^ key for d in data])

# 多字节 key
def xor_multi(data, key):
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])
```

### 2. Base64

```python
import base64

# 编码
encoded = base64.b64encode(b'hello')

# 解码
decoded = base64.b64decode(b'aGVsbG8=')

# 变种
# - Base32
# - Base58
# - Base85
# - 自定义字母表
```

### 3. RC4

```python
def rc4(key, data):
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)
```

### 4. TEA / XTEA / XXTEA

```python
# TEA
def tea_encrypt(v, k):
    delta = 0x9e3779b9
    v0, v1 = v
    sum_ = 0
    for _ in range(32):
        sum_ = (sum_ + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
    return [v0, v1]

def tea_decrypt(v, k):
    delta = 0x9e3779b9
    v0, v1 = v
    sum_ = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        sum_ = (sum_ - delta) & 0xffffffff
    return [v0, v1]

# XTEA
def xtea_encrypt(v, k):
    delta = 0x9e3779b9
    v0, v1 = v
    sum_ = 0
    for _ in range(32):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_ + k[sum_ & 3]))) & 0xffffffff
        sum_ = (sum_ + delta) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_ + k[(sum_ >> 11) & 3]))) & 0xffffffff
    return [v0, v1]

# XXTEA
def xxtea_encrypt(v, k):
    delta = 0x9e3779b9
    n = len(v)
    rounds = 6 + 52 // n
    sum_ = 0
    z = v[n - 1]
    while rounds > 0:
        sum_ = (sum_ + delta) & 0xffffffff
        e = (sum_ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xffffffff
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (k[((n - 1) & 3) ^ e] ^ z)))) & 0xffffffff
        z = v[n - 1]
        rounds -= 1
    return v
```

### 5. AES

```python
from Crypto.Cipher import AES

# ECB
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(data)
decrypted = cipher.decrypt(encrypted)

# CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(data)
decrypted = cipher.decrypt(encrypted)

# CTR
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
encrypted = cipher.encrypt(data)

# GCM
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
encrypted, tag = cipher.encrypt_and_digest(data)
```

### 6. SM4（国密）

```python
# 需要安装 gmssl
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

sm4 = CryptSM4()
sm4.set_key(key, SM4_ENCRYPT)
encrypted = sm4.crypt_ecb(data)

sm4.set_key(key, SM4_DECRYPT)
decrypted = sm4.crypt_ecb(encrypted)
```

### 7. MD5 / SHA

```python
import hashlib

# MD5
hash_md5 = hashlib.md5(b'hello').hexdigest()

# SHA1
hash_sha1 = hashlib.sha1(b'hello').hexdigest()

# SHA256
hash_sha256 = hashlib.sha256(b'hello').hexdigest()

# SM3（国密）
from gmssl.sm3 import sm3_hash
hash_sm3 = sm3_hash(b'hello')
```

### 8. RSA

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP

# 生成密钥
key = RSA.generate(2048)

# 加密
cipher = PKCS1_v1_5.new(key.publickey())
encrypted = cipher.encrypt(b'hello')

# 解密
cipher = PKCS1_v1_5.new(key)
decrypted = cipher.decrypt(encrypted, None)
```

### 9. 自定义算法

```python
# 1. 识别算法逻辑
# 2. 提取常量/密钥
# 3. 编写解密脚本

# 常见操作
# - 移位
# - 查表
# - 矩阵变换
# - 自定义运算
```

## 2024-2026 新技术点

### 1. ChaCha20/Salsa20 流密码

```python
# ChaCha20 — 现代流密码，广泛用于 TLS 1.3
from Crypto.Cipher import ChaCha20
import os

def chacha20_demo():
    """ChaCha20 加解密演示"""
    key = os.urandom(32)
    nonce = os.urandom(12)
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = b'CTF{chacha20_is_secure}'
    ciphertext = cipher.encrypt(plaintext)
    
    # 解密
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

# ChaCha20-Poly1305 认证加密
from Crypto.Cipher import ChaCha20_Poly1305

def chacha20_poly1305_demo():
    """ChaCha20-Poly1305 AEAD"""
    key = os.urandom(32)
    cipher = ChaCha20_Poly1305.new(key=key)
    
    plaintext = b'Secret message'
    aad = b'Additional authenticated data'
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext, aad)
    
    # 解密验证
    cipher = ChaCha20_Poly1305.new(key=key)
    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag, aad)
        return decrypted
    except ValueError:
        print("[!] 认证失败 — 数据被篡改")
        return None

# Salsa20 (ChaCha20 的前身，CTF 中仍常见)
def salsa20_encrypt(data, key, nonce):
    """Salsa20 加密（使用 PyCryptodome 或手动实现）"""
    try:
        from Crypto.Cipher import Salsa20
        cipher = Salsa20.new(key=key, nonce=nonce)
        return cipher.encrypt(data)
    except ImportError:
        # 使用 ChaCha20 代替（近似兼容）
        cipher = ChaCha20.new(key=key, nonce=nonce + b'\x00\x00\x00\x00')
        return cipher.encrypt(data)
```

### 2. SM2/SM3/SM4 国密算法

```python
# SM2 — 非对称加密（椭圆曲线）
# SM3 — 哈希算法（类似 SHA-256）
# SM4 — 对称加密（类似 AES-128）

from gmssl import sm2, sm3, sm4
from gmssl.sm2 import CryptSM2, SM2_ENCRYPT, SM2_DECRYPT
import binascii

def sm2_demo():
    """SM2 非对称加密"""
    # 生成密钥对
    private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED8378'
    public_key = '2442A5CC56C70FB5A002A6D70EFFC64610E35AFED09799CBDC78A956AE5E99E3'
    
    crypt = CryptSM2(private_key=private_key, public_key=public_key)
    
    # 加密
    data = b'CTF{sm2_crypto}'
    ciphertext = crypt.encrypt(data)
    
    # 解密
    plaintext = crypt.decrypt(ciphertext)
    return plaintext

def sm3_demo():
    """SM3 哈希"""
    data = b'hello world'
    hash_value = sm3.sm3_hash(data)
    return binascii.hexlify(bytes(hash_value)).decode()

def sm4_demo():
    """SM4 对称加密"""
    key = b'1234567890abcdef'  # 128-bit key
    iv = b'0000000000000000'
    
    crypt = sm4.CryptSM4()
    
    # ECB 加密
    crypt.set_key(key, SM4_ENCRYPT)
    encrypted = crypt.crypt_ecb(b'CTF{sm4_test_16}')  # 需要 16 字节
    
    # CBC 加密
    crypt.set_key(key, SM4_ENCRYPT)
    crypt.crypt_cbc(iv, b'CTF{sm4_test_16}')
    
    # 解密
    crypt.set_key(key, SM4_DECRYPT)
    decrypted = crypt.crypt_ecb(encrypted)
    return decrypted

# SM2 数字签名
def sm2_sign():
    """SM2 数字签名"""
    crypt = CryptSM2(private_key=private_key, public_key=public_key)
    message = b'Important message'
    
    # 生成签名
    signature = crypt.sign(message)
    
    # 验证签名
    is_valid = crypt.verify(signature, message)
    return is_valid
```

### 3. 后量子密码 (Post-Quantum)

```python
# 后量子密码算法实现
# 适用于：CTF 中的 PQC 挑战

# NTRU — 格基密码
class NTRU:
    """简化的 NTRU 加密"""
    
    def __init__(self, N=503, p=3, q=2048):
        self.N = N
        self.p = p
        self.q = q
    
    def keygen(self):
        """生成密钥对"""
        import random
        # 私钥：小多项式
        f = [random.choice([-1, 0, 1]) for _ in range(self.N)]
        g = [random.choice([-1, 0, 1]) for _ in range(self.N)]
        
        # 公钥: h = g * f^(-1) mod q
        # 简化：直接返回
        return f, g
    
    def encrypt(self, message, public_key):
        """加密"""
        import random
        # 使用小随机多项式 r
        r = [random.choice([-1, 0, 1]) for _ in range(self.N)]
        # e = r * h + m mod q
        return r  # 简化返回
    
    def decrypt(self, ciphertext, private_key):
        """解密"""
        # 使用私钥 f 解密
        # m = f * e mod p
        return ciphertext  # 简化返回

# Kyber — 基于 Module-LWE 的 KEM
# 参考: https://pq-crystals.org/kyber/
# pip install pqcrypto

# CRYSTALS-Dilithium — 后量子签名
# CRYSTALS-Kyber — 后量子 KEM
# Falcon — 基于 NTRU 的签名
# SPHINCS+ — 基于哈希的签名

# 实际使用
try:
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
    # 生成密钥
    pk, sk = generate_keypair()
    # 密钥封装
    ct, ss = encrypt(pk)
    # 解封装
    ss2 = decrypt(sk, ct)
    assert ss == ss2
except ImportError:
    print("[*] 安装后量子密码库: pip install pqcrypto")
```

### 4. 椭圆曲线密码 (ECC) 攻击

```python
# ECC 常见攻击方法
from Crypto.PublicKey import ECC
import hashlib

def ecc_pohlig_hellman(curve, G, Q, order):
    """Pohlig-Hellman 攻击 — 当阶是光滑数时"""
    from sympy import factorint
    factors = factorint(order)
    
    results = []
    for p, e in factors.items():
        # 计算子群上的离散对数
        subgroup_order = p ** e
        # G' = G^(order/subgroup_order)
        # Q' = Q^(order/subgroup_order)
        # 解决子问题
        pass
    
    return results

def ecc_transfer_attack(G, kG):
    """转移攻击 — 当随机数可预测时"""
    # 如果 k 是小整数，暴力搜索
    for k in range(1, 100000):
        if k * G == kG:
            return k
    return None

def ecc_fault_attack():
    """故障攻击 — 利用计算错误"""
    # 在签名过程中注入故障
    # 通过两个不同签名恢复私钥
    pass

# 使用 sympy 进行椭圆曲线计算
from sympy import mod_inverse, sqrt_mod

def ecc_point_add(P, Q, a, p):
    """椭圆曲线点加"""
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 == y2:
        # 点倍
        lam = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    elif x1 == x2:
        return None  # 无穷远点
    else:
        lam = (y2 - y1) * mod_inverse(x2 - x1, p) % p
    
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def ecc_scalar_mult(k, P, a, p):
    """椭圆曲线标量乘法"""
    result = None
    addend = P
    
    while k > 0:
        if k & 1:
            result = ecc_point_add(result, addend, a, p)
        addend = ecc_point_add(addend, addend, a, p)
        k >>= 1
    
    return result
```

### 5. Blake3/KangarooTwelve 新型哈希

```python
# Blake3 — 高速哈希算法
import hashlib

def blake3_demo():
    """Blake3 哈希"""
    try:
        import blake3
        h = blake3.blake3(b'CTF{blake3_hash}')
        return h.hexdigest()
    except ImportError:
        # 使用 hashlib 的 BLAKE2b (近似)
        h = hashlib.blake2b(b'CTF{blake3_hash}', digest_size=32)
        return h.hexdigest()

def kangaroo_twelve_demo():
    """KangarooTwelve (Keccak 变体)"""
    try:
        import hashlib
        # Python 3.11+ 可能支持
        h = hashlib.new('shake_128', b'CTF{k12_hash}')
        return h.hexdigest(32)
    except:
        return None

# CTF 中常见的哈希攻击
def length_extension_attack(original_hash, original_len, append_data):
    """MD5/SHA1 长度扩展攻击"""
    # 使用 hlextend 库
    try:
        import hlextend
        sha = hlextend.new('sha1')
        new_hash = sha.extend(
            append_data,
            original_hash,
            original_len,
            b''  # salt (未知)
        )
        return new_hash
    except ImportError:
        print("[*] pip install hlextend")
        return None

# Hash length extension 演示
def simple_length_extension():
    """简单的 MD5 长度扩展演示"""
    import struct
    
    # MD5 内部状态
    def md5_compress(state, block):
        # 简化 — 实际需要完整的 MD5 压缩函数
        pass
    
    # 如果知道 MD5(secret + message) 和 len(secret + message)
    # 可以计算 MD5(secret + message + padding + append)
    # 而不需要知道 secret
    print("[*] MD5 长度扩展攻击")
    print("    需要知道: 原始哈希值 + 原始消息长度")
    print("    可以构造: 原始消息 + 填充 + 附加数据")
```

### 6. 同态加密基础

```python
# Paillier 同态加密 — 支持加法同态
class PaillierSimple:
    """简化的 Paillier 加密"""
    
    def __init__(self, bits=512):
        from Crypto.Util.number import getPrime, inverse, GCD
        import random
        
        # 生成素数 p, q
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.n_sq = self.n * self.n
        self.g = self.n + 1  # 简化选择
        
        # λ = lcm(p-1, q-1)
        from math import gcd
        self.lam = (self.p - 1) * (self.q - 1) // gcd(self.p - 1, self.q - 1)
        
        # μ = L(g^λ mod n²)^(-1) mod n
        def L(x):
            return (x - 1) // self.n
        
        self.mu = inverse(L(pow(self.g, self.lam, self.n_sq)), self.n)
    
    def encrypt(self, plaintext):
        """加密"""
        import random
        r = random.randint(1, self.n - 1)
        while GCD(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        
        # c = g^m * r^n mod n²
        ciphertext = (pow(self.g, plaintext, self.n_sq) * 
                      pow(r, self.n, self.n_sq)) % self.n_sq
        return ciphertext
    
    def decrypt(self, ciphertext):
        """解密"""
        def L(x):
            return (x - 1) // self.n
        
        # m = L(c^λ mod n²) * μ mod n
        m = L(pow(ciphertext, self.lam, self.n_sq)) * self.mu % self.n
        return m
    
    def add_encrypted(self, c1, c2):
        """同态加法: E(m1) * E(m2) mod n² = E(m1 + m2)"""
        return (c1 * c2) % self.n_sq

# 使用
paillier = PaillierSimple(bits=256)
e1 = paillier.encrypt(10)
e2 = paillier.encrypt(20)
e_sum = paillier.add_encrypted(e1, e2)
m_sum = paillier.decrypt(e_sum)
print(f"10 + 20 = {m_sum}")  # 输出 30
```

### 7. 零知识证明基础

```python
# Schnorr 零知识证明协议
import hashlib
import random

class SchnorrZKP:
    """Schnorr 零知识证明"""
    
    def __init__(self, p, g, q):
        """
        p: 大素数
        g: 生成元
        q: 阶 (q = (p-1)/2)
        """
        self.p = p
        self.g = g
        self.q = q
    
    def keygen(self):
        """生成密钥对"""
        x = random.randint(1, self.q - 1)  # 私钥
        y = pow(self.g, x, self.p)  # 公钥
        return x, y
    
    def prove(self, x):
        """生成证明"""
        # 随机数 r
        r = random.randint(1, self.q - 1)
        
        # 承诺 t = g^r mod p
        t = pow(self.g, r, self.p)
        
        # 挑战 c = H(g, y, t) mod q
        c = int(hashlib.sha256(
            f"{self.g}{y}{t}".encode()
        ).hexdigest(), 16) % self.q
        
        # 响应 s = r + c * x mod q
        s = (r + c * x) % self.q
        
        return t, c, s
    
    def verify(self, y, t, c, s):
        """验证证明"""
        # 验证: g^s mod p == t * y^c mod p
        lhs = pow(self.g, s, self.p)
        rhs = (t * pow(y, c, self.p)) % self.p
        
        # 验证 c == H(g, y, t) mod q
        c_verify = int(hashlib.sha256(
            f"{self.g}{y}{t}".encode()
        ).hexdigest(), 16) % self.q
        
        return lhs == rhs and c == c_verify

# 使用
p = 2027  # 简化示例 — 实际需要更大的素数
g = 3
q = (p - 1) // 2

zkp = SchnorrZKP(p, g, q)
x, y = zkp.keygen()  # 私钥 x, 公钥 y

t, c, s = zkp.prove(x)
valid = zkp.verify(y, t, c, s)
print(f"证明有效: {valid}")
```

### 8. 多方安全计算 (MPC) 基础

```python
# 秘密共享 (Shamir's Secret Sharing)
import random

class ShamirSecretSharing:
    """Shamir 秘密共享"""
    
    PRIME = 2**127 - 1  # Mersenne 素数
    
    @staticmethod
    def split(secret, n, k):
        """将秘密分成 n 份，需要 k 份恢复"""
        prime = ShamirSecretSharing.PRIME
        
        # 生成 k-1 个随机系数
        coefficients = [secret] + [
            random.randint(0, prime - 1) for _ in range(k - 1)
        ]
        
        # 计算 n 个点
        shares = []
        for x in range(1, n + 1):
            y = 0
            for i, coeff in enumerate(coefficients):
                y = (y + coeff * pow(x, i, prime)) % prime
            shares.append((x, y))
        
        return shares
    
    @staticmethod
    def recover(shares, k):
        """从 k 份恢复秘密 (Lagrange 插值)"""
        prime = ShamirSecretSharing.PRIME
        secret = 0
        
        for i, (xi, yi) in enumerate(shares[:k]):
            # 计算 Lagrange 系数
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(shares[:k]):
                if i != j:
                    numerator = (numerator * (-xj)) % prime
                    denominator = (denominator * (xi - xj)) % prime
            
            lagrange = (numerator * pow(denominator, -1, prime)) % prime
            secret = (secret + yi * lagrange) % prime
        
        return secret

# 使用
secret = 1234567890
shares = ShamirSecretSharing.split(secret, 5, 3)
print(f"Shares: {shares}")

recovered = ShamirSecretSharing.recover(shares[:3], 3)
print(f"Recovered: {recovered}")
assert recovered == secret
```

### 9. Format-String 攻击中的内存读取

```python
# Format String 攻击利用
from pwn import *

def format_string_leak(printf_addr, target_addr):
    """计算 format string 偏移量"""
    # 在栈上查找 printf 的位置
    # 然后用 %n 写入任意地址
    
    payload = b''
    payload += f'%{printf_addr & 0xffff}x'.encode()
    payload += f'%<n>%hn'.encode()
    
    return payload

def format_string_write(target_addr, value):
    """使用 format string 写入任意值"""
    # 将 value 分成两个 16-bit 值
    low = value & 0xffff
    high = (value >> 16) & 0xffff
    
    # 计算偏移
    payload = b''
    
    # 先写低位
    if low > 0:
        payload += f'%{low}x%<n>%hn'.encode()
    else:
        payload += f'%<n>%hn'.encode()
    
    # 再写高位
    diff = high - low
    if diff > 0:
        payload += f'%{diff}x%<n>%hn'.encode()
    else:
        payload += f'%{abs(diff)}x%<n>%hn'.encode()
    
    # 填充到 8 字节对齐
    payload = payload.ljust(8 * 2, b'\x00')
    payload += p64(target_addr) + p64(target_addr + 2)
    
    return payload
```

## 工具推荐

- **FindCrypt** (IDA 插件) — 算法识别
- **Signsrch** — 算法识别
- **Detect It Easy** — 文件类型识别
- **PyCryptodome** — Python 加密库
- **gmssl** — 国密算法库
- **hashcat** — 哈希爆破

## 参考链接

- [ctf-wiki encryption](https://ctf-wiki.org/reverse/identify-encryption/)
- [Crypto++](https://www.cryptopp.com/)
- [PyCryptodome](https://pycryptodome.readthedocs.io/)
- [gmssl](https://github.com/duanhongyi/gmssl)
