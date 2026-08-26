# 哈希攻击 (Hash Attacks)

## 原理

哈希函数将任意长度输入映射为固定长度输出。CTF 中常因哈希算法弱点（碰撞、长度扩展、预映射）被攻击。

## 常见哈希算法

| 算法 | 输出长度 | 已知弱点 |
|------|---------|---------|
| MD5 | 128 bit | 碰撞、长度扩展 |
| SHA1 | 160 bit | 碰撞（SHAttered） |
| SHA256 | 256 bit | 长度扩展 |
| SHA512 | 512 bit | 长度扩展 |
| SHA3 | 224/256/384/512 bit | 无已知弱点 |
| BLAKE2/3 | 任意 | 无已知弱点 |
| SM3 | 256 bit | 无已知弱点 |
| CRC32 | 32 bit | 非加密哈希 |

## 攻击链

### 1. 哈希碰撞

#### MD5 碰撞

```python
# MD5 已被攻破
# 可以构造碰撞
# 工具：hashclash, fastcoll

# fastcoll
fastcoll -o msg1.bin msg2.bin
# 生成两个不同但 MD5 相同的文件
```

#### SHA1 碰撞

```python
# SHAttered 攻击
# https://shattered.io/
# 可以构造 SHA1 碰撞
```

#### 生日攻击

```python
# 寻找碰撞
# 时间复杂度 O(2^(n/2))
# 对于 64 位哈希，需要 2^32 次运算
```

### 2. 长度扩展攻击

```python
# MD5/SHA1/SHA256 等 Merkle-Damgård 结构
# 已知 H(secret || message) 和 secret 长度
# 可计算 H(secret || message || padding || extension)
# 无需知道 secret

import struct

def md5_length_extension(original_hash, original_data_length, extension):
    # 1. 从 original_hash 恢复内部状态
    a, b, c, d = struct.unpack('<4I', bytes.fromhex(original_hash))
    
    # 2. 计算填充
    padding = md5_padding(original_data_length)
    
    # 3. 使用恢复的内部状态继续哈希 extension
    import struct
    # 内部状态恢复后，构造新的 padding
    state = struct.pack('<I', h0) + struct.pack('<I', h1) + struct.pack('<I', h2) + struct.pack('<I', h3)
    print(f'[+] Recovered internal state: {state.hex()}')

# 工具
# hashpumpy
import hashpumpy

new_hash, new_data = hashpumpy.hashpump(original_hash, original_data, extension, key_length)
```

### 3. 预映射攻击

```python
# 寻找特定哈希值的原像
# 暴力破解
import hashlib

def preimage_attack(target_hash, charset='abcdefghijklmnopqrstuvwxyz', max_len=8):
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if hashlib.md5(candidate.encode()).hexdigest() == target_hash:
                return candidate
    return None
```

### 4. 彩虹表

```python
# 预计算哈希表
# 工具：rainbowcrack, ophcrack

# 在线彩虹表
# https://crackstation.net/
# https://cmd5.com/
```

### 5. 字典攻击

```python
# 使用常见密码字典
# hashcat
hashcat -m 0 hash.txt wordlist.txt  # MD5
hashcat -m 100 hash.txt wordlist.txt  # SHA1
hashcat -m 1400 hash.txt wordlist.txt  # SHA256

# John the Ripper
john --format=raw-md5 hash.txt
```

### 6. 盐值攻击

```python
# 如果盐值已知
# 可以针对特定盐值计算哈希
# hashcat
hashcat -m 10 hash:salt wordlist.txt  # md5($pass.$salt)
```

### 7. 哈希链

```python
# H(H(H(x)))
# 可被长度扩展攻击
```

### 8. HMAC 攻击

```python
# HMAC = H(key ^ opad || H(key ^ ipad || message))
# 如果 key 可预测
# 可伪造 HMAC

# 时序攻击
# 逐字节比较，通过响应时间判断
def hmac_timing_attack(oracle, known=b''):
    for i in range(32):  # HMAC-MD5 长度
        best_time = 0
        best_byte = 0
        for b in range(256):
            test = known + bytes([b])
            start = time.time()
            oracle(test)
            elapsed = time.time() - start
            if elapsed > best_time:
                best_time = elapsed
                best_byte = b
        known += bytes([best_byte])
    return known
```

### 9. CRC32 攻击

```python
# CRC32 不是加密哈希
# 基于多项式除法，完全可逆
# 可碰撞、可构造特定值

import zlib
import struct

def crc32_reverse(target_crc, length=4):
    """CRC32 逆运算 — 构造特定 CRC32 值
    
    方法 1：已知长度，直接计算对应输入
    方法 2：利用 CRC32 的线性性质
    方法 3：暴力搜索（小空间）
    """
    # CRC32 的数学性质：
    # CRC32(x) = (x * G(x)) mod P(x)
    # 其中 P(x) = 0x04C11DB7
    
    # 方法 1：已知长度的逆运算
    # CRC32 是线性的：CRC(a ^ b) = CRC(a) ^ CRC(b)
    # 所以：CRC32(target) = CRC32(known) ^ CRC32(unknown)
    # unknown = target ^ known
    
    # 计算单位向量的 CRC32
    def crc32_unit(i):
        """计算单位向量 (1 << i) 的 CRC32"""
        data = b'\x00' * (i // 8)
        data += bytes([1 << (i % 8)])
        return zlib.crc32(data) & 0xFFFFFFFF
    
    # 构造目标 CRC32
    # 利用线性性质：CRC32(a) ^ CRC32(b) = CRC32(a ^ b)
    
    # 简化：暴力搜索小输入
    if length <= 4:
        for i in range(256 ** length):
            candidate = i.to_bytes(length, 'big')
            if zlib.crc32(candidate) & 0xFFFFFFFF == target_crc:
                return candidate
    
    # 方法 2：使用线性代数
    # 将 CRC32 表示为 GF(2) 上的线性变换
    # 然后求逆
    
    # 方法 3：增量构造
    # 从任意值开始，逐步修改字节使 CRC32 匹配
    
    return None


def crc32_collision(prefix, target_crc):
    """CRC32 碰撞构造
    
    已知 prefix，找到 suffix 使 CRC32(prefix || suffix) = target_crc
    """
    # 利用 CRC32 的线性性质
    current_crc = zlib.crc32(prefix) & 0xFFFFFFFF
    
    # 需要：CRC32(suffix) = target_crc ^ current_crc
    # 因为 CRC32(a || b) = CRC32(b) ^ (CRC32(a) << 32 的效果)
    
    # 实际上：CRC32(a || b) 不等于 CRC32(a) ^ CRC32(b)
    # 但有：CRC32(a || b) = CRC32(CRC32(a) << 32 | b)
    
    # 简化：暴力搜索
    target = target_crc ^ current_crc
    
    # 构造 suffix 使得 CRC32(suffix) = target
    for length in range(1, 8):
        for i in range(256 ** length):
            suffix = i.to_bytes(length, 'big')
            if zlib.crc32(prefix + suffix) & 0xFFFFFFFF == target_crc:
                return suffix
    
    return None


def crc32_forge_with_known_prefix(data, target_crc):
    """已知前缀的 CRC32 伪造
    
    在已知数据后追加字节使 CRC32 匹配
    """
    # CRC32 的更新：每添加一个字节，CRC32 线性更新
    # CRC32(data || byte) = (CRC32(data) >> 8) ^ crc_table[(CRC32(data) ^ byte) & 0xFF]
    
    current = zlib.crc32(data) & 0xFFFFFFFF
    
    # 计算需要的修正
    # 通过添加 4 字节可以匹配任意 CRC32 值
    
    # 使用 CRC32 的线性性质
    # CRC32(x || y) = f(CRC32(x), y)
    
    # 简化：尝试追加 4 字节
    for extra in range(0x100000000):
        suffix = extra.to_bytes(4, 'big')
        if zlib.crc32(data + suffix) & 0xFFFFFFFF == target_crc:
            return suffix
    
    return None


def crc32_fast_reverse(target_crc, length):
    """CRC32 快速逆运算（利用查表）"""
    # 预计算每个字节的 CRC32 贡献
    # 然后组合
    
    # CRC32 查找表
    crc_table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        crc_table.append(crc)
    
    # 线性构造
    # CRC32(a || b) = CRC32(a) ^ CRC32(b) ^ ...
    # 这个关系比较复杂
    
    # 简化：使用逆向 CRC32 更新
    def crc32_update_inv(crc, byte):
        """逆向 CRC32 更新"""
        # CRC = (CRC >> 8) ^ table[(CRC ^ byte) & 0xFF]
        # 逆向：给定 crc 和 byte，求前一个 crc
        for prev_crc in range(0x100000000):
            if ((prev_crc >> 8) ^ crc_table[(prev_crc ^ byte) & 0xFF]) & 0xFFFFFFFF == crc:
                return prev_crc
        return None
    
    # 从目标 CRC 逆推
    current = target_crc
    result = bytearray(length)
    
    for i in range(length - 1, -1, -1):
        # 尝试所有字节值
        for b in range(256):
            prev = crc32_update_inv(current, b)
            if prev is not None:
                result[i] = b
                current = prev
                break
    
    return bytes(result)


def crc32_msb_oracle(oracle, known_prefix=b''):
    """CRC32 MSB Oracle 攻击
    
    如果 oracle 只返回 CRC32 的高位
    可以逐字节恢复完整 CRC32
    """
    recovered = b''
    
    for i in range(4):  # CRC32 是 4 字节
        for b in range(256):
            test = known_prefix + recovered + bytes([b])
            response = oracle(test)
            
            if response == (target_crc >> (8 * (3 - i))) & 0xFF:
                recovered += bytes([b])
                break
    
    return recovered
```

### 10. 国密 SM3

```python
# SM3 算法
# 目前无已知弱点
# 但实现可能有问题
```

## 2024-2026 新技术点

### 1. SHA1 碰撞实战

```python
# SHA1 已被实际攻破
# 可以构造选择前缀碰撞

def sha1_chosen_prefix_collision():
    """SHA1 选择前缀碰撞
    
    可以构造任意两个前缀的碰撞
    """
    # 工具：
    # 1. sha1collisiondetection
    # 2. hashclash
    # 3. fastcoll
    
    # 攻击：
    # - 证书伪造
    # - 文档篡改
    # - Git 碰撞
    
    return None


def sha1_shambles_attack():
    """SHA-1 is a Shambles 攻击
    
    Leurent & Peyrin 的选择前缀碰撞
    可以在实际系统中利用
    """
    # 例如：
    # - 伪造 CA 签名
    # - 创建碰撞 PDF
    # - 创建碰撞 X.509 证书
    
    return None
```

### 2. SHA3 安全性

```python
def sha3_analysis():
    """SHA3/Keccak 安全性分析"""
    
    # SHA3 基于 sponge 结构
    # 安全性：
    # - 无长度扩展攻击
    # - 抗量子（Grover 算法的 √2 加速）
    
    # 已知弱点：
    # - 某些参数选择有弱点
    # - 需要足够的 capacity
    
    return None
```

### 3. BLAKE3

```python
def blake3_analysis():
    """BLAKE3 安全性分析"""
    
    # BLAKE3 基于 BLAKE2
    # 使用 Merkle tree 结构
    # 非常快速
    
    # 安全性：
    # - 继承 BLAKE2 的安全性
    # - 树状结构可能有弱点
    
    return None
```

### 4. 量子攻击影响

```python
def quantum_hash_attacks():
    """量子计算对哈希函数的影响"""
    
    # Grover 算法：
    # - 暴力搜索加速 √N
    # - MD5: 64 位量子安全性
    # - SHA256: 128 位量子安全性
    # - SHA512: 256 位量子安全性
    
    # 建议：
    # - 使用 SHA256 或更高
    # - 密码哈希使用更多迭代
    
    return None
```

### 5. 侧信道攻击

```python
def hash_side_channel():
    """哈希函数侧信道攻击"""
    
    # 攻击：
    # 1. 时间攻击（哈希计算时间）
    # 2. 缓存攻击（S-box 访问）
    # 3. 功耗分析
    
    # 防御：
    # 1. 常数时间实现
    # 2. 内存访问随机化
    
    return None
```

### 6. 硬件加速安全

```python
def hash_hardware():
    """哈希硬件加速安全"""
    
    # SHA-NI（Intel）：
    # - 通常抗侧信道
    # - 但可能有微架构漏洞
    
    # GPU 破解：
    # - MD5/SHA1 破解速度：数十亿次/秒
    # - 密码学哈希难以 GPU 加速
    
    return None
```

### 7. ML 辅助分析

```python
def ml_hash_analysis():
    """机器学习辅助哈希分析"""
    
    # 应用：
    # 1. 哈希函数区分器
    # 2. 碰撞搜索
    # 3. 预像攻击
    
    # 例如：
    # - 使用 RNN 学习 MD5 的轮函数
    # - 使用 GAN 生成碰撞
    
    return None
```

### 8. 新型哈希函数

```python
def new_hash_functions():
    """新型哈希函数"""
    
    # 2024-2026 新设计：
    # 1. KangarooTwelve（Keccak 变体）
    # 2. PHOTON（轻量级）
    # 3. AScon-Hash（NIST 轻量级）
    
    return None
```

### 9. 密码哈希安全

```python
def password_hash_security():
    """密码哈希函数安全"""
    
    # 现代推荐：
    # 1. Argon2id（首选）
    # 2. scrypt
    # 3. bcrypt
    
    # 参数建议：
    # - Argon2id: 64MB 内存, 3 次迭代, 4 并行度
    # - scrypt: N=16384, r=8, p=1
    # - bcrypt: cost=12
    
    # 攻击：
    # - GPU/ASIC 破解
    # - 暴力搜索
    # - 字典攻击
    
    return None
```

### 10. 零知识证明中的哈希

```python
def zkp_hash():
    """零知识证明中的哈希函数"""
    
    # 应用：
    # 1. Merkle tree（状态承诺）
    # 2. 哈希承诺
    # 3. Fiat-Shamir 变换
    
    # 要求：
    # - 抗碰撞性
    # - 零知识性
    # - 可高效计算
    
    return None
```

## 工具推荐

- **hashcat** — 哈希爆破
- **John the Ripper** — 哈希爆破
- **hashpumpy** — 长度扩展
- **fastcoll** — MD5 碰撞
- **hashclash** — SHA1 碰撞
- **CrackStation** — 在线彩虹表
- **cmd5** — 在线破解

## 参考链接

- [ctf-wiki hash](https://ctf-wiki.org/crypto/hash/)
- [Hash Length Extension](https://github.com/bwall/HashPump)
- [SHAttered](https://shattered.io/)
- [Hashcat](https://hashcat.net/)
