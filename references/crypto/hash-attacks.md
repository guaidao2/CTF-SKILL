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
    
    # 3. 继续哈希 extension
    # 使用恢复的内部状态
    # ...
    pass

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
# 可逆
# 可碰撞

import zlib

# CRC32 逆运算
def crc32_reverse(target_crc, length=4):
    # 构造特定 CRC32 的输入
    # ...
    pass
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
# SHAttered 攻击
# 选择前缀碰撞
# SHA-1 is a Shambles
# 实际攻击
```

### 2. SHA3

```python
# Keccak 结构
# 无长度扩展
# 新的分析
```

### 3. BLAKE3

```python
# 树状哈希
# 高速
# 新的分析
```

### 4. 量子攻击

```python
# Grover 算法
# 降低安全强度
# MD5 → 64 位
# SHA256 → 128 位
```

### 5. 侧信道攻击

```python
# 时间攻击
# 缓存攻击
# 功耗分析
```

### 6. 硬件加速

```python
# GPU 破解
# ASIC 破解
# 量子计算
```

### 7. AI 辅助

```python
# ML 辅助
# 密码预测
# 哈希分析
```

### 8. 新型哈希

```python
# KangarooTwelve
# Photon
# 各新型哈希
```

### 9. 密码哈希

```python
# Argon2
# scrypt
# bcrypt
# 各密码哈希
```

### 10. 零知识证明

```python
# zk-SNARK 中的哈希
# 新的攻击面
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
