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

### 1. 新型加密算法

```python
# ChaCha20
# Salsa20
# Serpent
# Twofish
# Camellia
# 各新型加密算法
```

### 2. 国密算法

```python
# SM2（非对称）
# SM3（哈希）
# SM4（对称）
# SM9（标识密码）
# 国密算法越来越多
```

### 3. 后量子密码

```python
# NTRU
# LWE
# Ring-LWE
# 后量子密码学
```

### 4. 同态加密

```python
# Paillier
# CKKS
# BGV
# 同态加密算法
```

### 5. 零知识证明

```python
# zk-SNARK
# zk-STARK
# 零知识证明算法
```

### 6. 多方安全计算

```python
# MPC
# 秘密共享
# 多方安全计算
```

### 7. AI 加密

```python
# 基于 ML 的加密
# 神经网络加密
# 各新型加密
```

### 8. 量子安全

```python
# 量子密钥分发
# 量子随机数
# 量子安全算法
```

### 9. 区块链密码学

```python
# 椭圆曲线
# 配对友好曲线
# 各区块链密码学
```

### 10. 新型哈希

```python
# Blake3
# KangarooTwelve
# 各新型哈希
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
