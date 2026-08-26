# AES 攻击

## 原理

AES 是对称分组密码，CTF 中常因模式选择不当、IV 重用、密钥泄露等问题被攻击。

## AES 基础

```python
from Crypto.Cipher import AES

# 分组大小：16 字节
# 密钥长度：16/24/32 字节（AES-128/192/256）
# 模式：ECB/CBC/CTR/CFB/OFB/GCM

# ECB
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(pt, 16))

# CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(pt, 16))

# CTR
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ct = cipher.encrypt(pt)

# GCM
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(pt)
```

## 攻击链

### 1. ECB 模式攻击

#### ECB 重排攻击

```python
# ECB 模式每个块独立加密
# 可以重排密文块
# 例如：将块 1 和块 2 交换

# 经典题目：ECB oracle
# 通过逐字节爆破恢复明文
def ecb_oracle_attack(oracle, block_size=16):
    known = b''
    for i in range(block_size):
        padding = b'A' * (block_size - 1 - i)
        target = oracle(padding)
        for j in range(256):
            test = padding + known + bytes([j])
            if oracle(test)[:block_size] == target[:block_size]:
                known += bytes([j])
                break
    return known
```

#### ECB 字节翻转

```python
# 修改密文块，影响下一块明文
# 但当前块会损坏
```

### 2. CBC 模式攻击

#### 字节翻转攻击

```python
# CBC: P_i = D(C_i) ^ C_{i-1}
# 修改 C_{i-1} 的某字节，会影响 P_i 的对应字节
# 但 P_{i-1} 会损坏

def cbc_byte_flip(ciphertext, target_byte, target_value, block_index, byte_index):
    # 修改前一块的对应字节
    modified = bytearray(ciphertext)
    # P_i = D(C_i) ^ C_{i-1}
    # 我们想 P_i[byte_index] = target_value
    # D(C_i)[byte_index] = P_i[byte_index] ^ C_{i-1}[byte_index]
    # 修改 C_{i-1}[byte_index] = D(C_i)[byte_index] ^ target_value
    # 但我们不知道 D(C_i)
    # 如果知道原明文 original_byte
    # C_{i-1}[byte_index] ^= original_byte ^ target_value
    modified[block_index * 16 + byte_index] ^= original_byte ^ target_value
    return bytes(modified)
```

#### Padding Oracle 攻击

```python
# 详见 padding-oracle.md
# 通过错误信息判断 padding 是否正确
# 逐字节恢复明文
```

#### IV 重用攻击

```python
# 如果 IV 重用
# 相同明文产生相同密文
# 可恢复明文
```

#### CBC-MAC 攻击

```python
# CBC-MAC 用于消息认证
# 长度扩展攻击
# 消息拼接攻击
```

### 3. CTR 模式攻击

#### Nonce 重用攻击

```python
# CTR 模式：C = P ^ keystream
# 如果 nonce 重用，keystream 相同
# C1 ^ C2 = P1 ^ P2
# 如果知道 P1，可恢复 P2
# P2 = C1 ^ C2 ^ P1
```

#### 字节翻转

```python
# CTR 模式直接 XOR
# 修改密文，影响对应明文
# C' = C ^ delta
# P' = P ^ delta
```

### 4. GCM 模式攻击

#### Nonce 重用攻击

```python
# GCM nonce 重用
# 可恢复认证密钥 H
# 可伪造认证标签
```

#### 弱密钥攻击

```python
# 某些密钥导致 H = 0
# 可绕过认证
```

### 5. 密钥恢复

#### 密钥扩展攻击

```python
# 通过部分密钥恢复完整密钥
# AES-256 密钥扩展弱点
```

#### 侧信道攻击

```python
# 时间攻击
# 缓存攻击
# 功耗分析
```

### 6. 差分故障分析

```python
# 注入故障
# 恢复密钥
# DFA (Differential Fault Analysis)
```

## 2024-2026 新技术点

### 1. AES-NI 旁路

```python
# AES 硬件加速
# 新的侧信道
# Cache-timing 攻击
```

### 2. 白盒 AES

```python
# 白盒实现
# 提取密钥
# Chow 攻击
# 各白盒攻击
```

### 3. AES-XTS

```python
# 磁盘加密模式
# 新的攻击
```

### 4. AES-GCM-SIV

```python
# 抗 nonce 重用
# 新的分析
```

### 5. 量子攻击

```python
# Grover 算法
# 降低密钥强度
# AES-128 → 64 位安全
# AES-256 → 128 位安全
```

### 6. 后量子对称

```python
# 抗量子对称密码
# 新算法
```

### 7. 国密 SM4

```python
# SM4 算法
# 类似 AES
# 各 SM4 攻击
```

### 8. 轻量级密码

```python
# PRESENT
# Speck
# SIMON
# 各轻量级密码
```

### 9. 同态加密

```python
# FHE 中的对称密码
# 新的攻击面
```

### 10. AI 辅助

```python
# ML 辅助
# 侧信道分析
# 密钥恢复
```

## 工具推荐

- **PyCryptodome** — Python 加密库
- **SageMath** — 数学计算
- **padding-oracle-tool** — Padding Oracle 自动化
- **Hashcat** — 密钥爆破

## 参考链接

- [ctf-wiki AES](https://ctf-wiki.org/crypto/blockcipher/)
- [AES Attack](https://github.com/ctfs/write-ups-2014/tree/master/plaidctf-2014/aes)
- [Padding Oracle](https://github.com/AonCyberLabs/padding-oracle-tool)
