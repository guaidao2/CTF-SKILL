# Crypto 方向总览

Crypto（密码学）是 CTF 中分析加密算法、寻找弱点、解密密文的方向。本目录按算法类型拆分。

## 子路由表（症状 → 文件）

| 题目症状 | 算法类型 | 文件 |
|---------|---------|------|
| `n e c`、RSA 参数、公钥加密 | RSA 攻击 | `rsa-attacks.md` |
| AES、CBC/ECB/CTR/GCM、分组密码 | AES 攻击 | `aes-attacks.md` |
| ECC、椭圆曲线、`p a b G n h` | ECC 攻击 | `ecc-attacks.md` |
| MD5/SHA1/SHA256、哈希碰撞、长度扩展 | 哈希攻击 | `hash-attacks.md` |
| LLL、Coppersmith、格基规约 | 格攻击 | `lattice-attacks.md` |
| Padding Oracle、CBC、错误信息 | 填充预言 | `padding-oracle.md` |
| LCG、线性同余生成器、随机数 | LCG 攻击 | `lcg-attacks.md` |
| ChaCha20、SM4、现代对称密码 | 现代对称密码 | `modern-symmetric.md` |

## Crypto 通用解题流程

### 1. 识别算法

```python
# 常见特征
# RSA: n, e, c, d, p, q
# AES: key, iv, plaintext, ciphertext, mode
# ECC: p, a, b, G, n, h, Q
# LCG: a, c, m, seed
# 哈希: 固定长度输出

# 工具
# - SageMath
# - PyCryptodome
# - gmpy2
# - sympy
```

### 2. 分析弱点

```python
# 常见弱点
# 1. 弱参数（小 e、小 d、共享素数）
# 2. 实现错误（CBC 重用 IV、ECB 模式）
# 3. 侧信道（时间、错误信息）
# 4. 数学弱点（Coppersmith、LLL）
# 5. 随机数弱点（LCG、MT19937）
```

### 3. 编写解密脚本

```python
# SageMath
from sage.all import *

# PyCryptodome
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# gmpy2
import gmpy2

# 自定义实现
# ...
```

## 工具清单

| 工具 | 用途 |
|------|------|
| SageMath | 数学计算（格、椭圆曲线） |
| PyCryptodome | Python 加密库 |
| gmpy2 | 大整数运算 |
| sympy | 符号计算 |
| RsaCtfTool | RSA 自动化 |
| yafu | 大数分解 |
| FactorDB | 在线分解 |
| Hashcat | 哈希爆破 |
| CyberChef | 编码解码 |

## 2024-2026 Crypto 新趋势

- **后量子密码**：NTRU、LWE、Ring-LWE 题目增多
- **同态加密**：Paillier、CKKS、BGV
- **零知识证明**：zk-SNARK、zk-STARK
- **多方安全计算**：MPC、秘密共享
- **国密算法**：SM2/SM3/SM4/SM9
- **格密码**：基于格的密码学
- **椭圆曲线新攻击**：CVE-2023-4863 等
- **侧信道攻击**：时间、功耗、电磁
- **白盒密码**：白盒 AES/SM4
- **AI 密码分析**：ML 辅助密码分析

具体技术细节见各文件末尾的"2024-2026 新技术点"小节。
