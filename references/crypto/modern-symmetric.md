# 现代对称密码 (Modern Symmetric)

## 原理

介绍现代对称密码算法（ChaCha20、SM4、Salsa20 等）及其在 CTF 中的攻击方法。

## 常见现代对称密码

| 算法 | 类型 | 特点 |
|------|------|------|
| ChaCha20 | 流密码 | 高速、移动端常用 |
| Salsa20 | 流密码 | ChaCha20 前身 |
| SM4 | 分组密码 | 国密标准 |
| Serpent | 分组密码 | AES 候选 |
| Twofish | 分组密码 | AES 候选 |
| Camellia | 分组密码 | 日本标准 |
| ARIA | 分组密码 | 韩国标准 |
| Speck/Simon | 轻量级 | NSA 设计 |
| PRESENT | 轻量级 | 国际标准 |
| Trivium | 流密码 | eSTREAM |
| Rabbit | 流密码 | eSTREAM |
| RC4 | 流密码 | 已被弃用 |

## 攻击链

### 1. ChaCha20

```python
# ChaCha20 是流密码
# 基于 ARX（Add-Rotate-XOR）
# 256 位密钥，96 位 nonce，32 位计数器

from Crypto.Cipher import ChaCha20

# 加密
cipher = ChaCha20.new(key=key, nonce=nonce)
ct = cipher.encrypt(pt)

# 解密
cipher = ChaCha20.new(key=key, nonce=nonce)
pt = cipher.decrypt(ct)

# 攻击点：
# 1. Nonce 重用
# 2. 计数器重用
# 3. 密钥泄露
```

#### Nonce 重用攻击

```python
# ChaCha20 是流密码
# C = P ^ keystream
# 如果 nonce 重用，keystream 相同
# C1 ^ C2 = P1 ^ P2
# 如果知道 P1，可恢复 P2
# P2 = C1 ^ C2 ^ P1
```

### 2. Salsa20

```python
# Salsa20 类似 ChaCha20
# 基于 ARX
# 256 位密钥，64 位 nonce，64 位计数器

from Crypto.Cipher import Salsa20

cipher = Salsa20.new(key=key, nonce=nonce)
ct = cipher.encrypt(pt)

# 攻击点类似 ChaCha20
```

### 3. SM4

```python
# SM4 是国密分组密码
# 128 位密钥，128 位分组
# 类似 AES

from gmssl import sm4

# 加密
crypt_sm4 = sm4.CryptSM4()
crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
ct = crypt_sm4.crypt_ecb(pt)  # ECB 模式
ct = crypt_sm4.crypt_cbc(iv, pt)  # CBC 模式

# 解密
crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
pt = crypt_sm4.crypt_ecb(ct)
pt = crypt_sm4.crypt_cbc(iv, ct)

# 攻击点类似 AES
# 1. ECB 模式重排
# 2. CBC 字节翻转
# 3. Padding Oracle
```

### 4. Serpent

```python
# Serpent 是 AES 候选
# 128/192/256 位密钥，128 位分组
# 安全性高，但速度慢

# 攻击点类似 AES
```

### 5. Twofish

```python
# Twofish 是 AES 候选
# 128/192/256 位密钥，128 位分组

# 攻击点类似 AES
```

### 6. Camellia

```python
# Camellia 是日本标准
# 128/192/256 位密钥，128 位分组

# 攻击点类似 AES
```

### 7. Speck/Simon

```python
# 轻量级密码
# NSA 设计
# 适用于 IoT 设备

# 攻击点：
# 1. 弱密钥
# 2. 差分分析
# 3. 线性分析
```

### 8. PRESENT

```python
# 轻量级密码
# 国际标准
# 适用于 RFID

# 攻击点：
# 1. 差分分析
# 2. 线性分析
# 3. 代数攻击
```

### 9. Trivium

```python
# 流密码
# eSTREAM 标准
# 80 位密钥，80 位 IV

# 攻击点：
# 1. 代数攻击
# 2. 立方攻击
```

### 10. RC4

```python
# RC4 已被弃用
# 但仍在 CTF 中出现

# 攻击点：
# 1. 弱密钥
# 2. FMS 攻击
# 3. Bar-mitzvah 攻击
# 4. NOMORE 攻击
```

## 2024-2026 新技术点

### 1. AEAD 模式

```python
# GCM
# ChaCha20-Poly1305
# AES-GCM-SIV
# 各 AEAD 模式
```

### 2. XChaCha20

```python
# 扩展 nonce 的 ChaCha20
# 192 位 nonce
# 更安全
```

### 3. 国密算法

```python
# SM4
# SM7
# SM9
# 各国密算法
```

### 4. 轻量级密码

```python
# PRESENT
# Speck/Simon
# ASCON
# 各轻量级密码
```

### 5. 后量子对称

```python
# 抗量子对称密码
# 新算法
```

### 6. 同态加密

```python
# FHE 中的对称密码
# 新的攻击面
```

### 7. 侧信道攻击

```python
# 时间攻击
# 缓存攻击
# 功耗分析
# 各侧信道
```

### 8. 硬件加速

```python
# AES-NI
# ARM Crypto Extension
# 各硬件加速
```

### 9. 量子攻击

```python
# Grover 算法
# 降低密钥强度
```

### 10. AI 辅助

```python
# ML 辅助
# 侧信道分析
# 密钥恢复
```

## 工具推荐

- **PyCryptodome** — Python 加密库
- **gmssl** — 国密算法库
- **SageMath** — 数学计算
- **hashcat** — 密钥爆破

## 参考链接

- [ChaCha20](https://tools.ietf.org/html/rfc8439)
- [SM4](http://www.gmbz.org.cn/main/viewfile/20180110022005901417.html)
- [eSTREAM](https://www.ecrypt.eu.org/stream/)
- [Lightweight Crypto](https://csrc.nist.gov/projects/lightweight-cryptography)
