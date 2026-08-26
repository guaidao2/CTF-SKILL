# AES 攻击

## 原理

AES 是对称分组密码，CTF 中常因模式选择不当、IV 重用、密钥泄露等问题被攻击。

## AES 基础

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def ecb_oracle_attack(oracle, block_size=16):
    """
    ECB 逐字节爆破攻击
    oracle: 接受 bytes 输入，返回密文
    通过控制明文长度使目标字节落在块边界，逐字节爆破
    """
    known = b''
    for i in range(block_size):
        # 构造填充使目标字节位于块末尾
        padding = b'A' * (block_size - 1 - i)
        target = oracle(padding)[:block_size]
        for j in range(256):
            test = padding + known + bytes([j])
            if oracle(test)[:block_size] == target:
                known += bytes([j])
                break
    return known
```

#### ECB 字节翻转（选择前缀注入）

```python
def ecb_controlled_suffix(oracle, controlled_prefix, target_suffix, block_size=16):
    """
    ECB 模式下，如果攻击者可控前缀 + 服务端拼接固定后缀
    可以通过爆破逐字节控制最终拼接结果的每一字节
    适用于 cookie 伪造、session 劫持等场景
    """
    # 计算填充偏移，使目标字节落在已知块位置
    known = b''
    offset = block_size - (len(controlled_prefix) % block_size) - 1
    for i in range(len(target_suffix)):
        padding = b'A' * (offset - i % block_size)
        target_block_idx = (len(controlled_prefix) + offset + i) // block_size
        target = oracle(padding)[:target_block_idx * block_size + block_size]
        for j in range(256):
            test = padding + known + bytes([j])
            if oracle(test)[:target_block_idx * block_size + block_size] == target:
                known += bytes([j])
                break
    return known
```

### 2. CBC 模式攻击

#### 字节翻转攻击

```python
def cbc_byte_flip(ciphertext, original_byte, target_value, block_index, byte_index, block_size=16):
    """
    CBC 字节翻转攻击
    P_i = D(C_i) ^ C_{i-1}
    修改 C_{i-1}[byte_index] 可控制 P_i[byte_index]

    参数:
        ciphertext:  完整密文（IV + CT blocks 或纯 CT blocks）
        original_byte: 原始明文字节（已知或可猜测）
        target_value:  目标明文字节
        block_index:   要影响的明文块索引
        byte_index:    块内字节偏移
        block_size:    块大小，默认 16

    原理:
        C_{i-1}[j] ^= original_byte ^ target_value
        则 P_i[j] = D(C_i)[j] ^ (C_{i-1}[j] ^ original_byte ^ target_value)
                    = D(C_i)[j] ^ C_{i-1}[j] ^ original_byte ^ target_value
                    = P_i[j] ^ original_byte ^ target_value
        如果原 P_i[j] == original_byte，则新 P_i[j] == target_value
    """
    modified = bytearray(ciphertext)
    # block_index 对应密文块（不含 IV 则直接偏移；含 IV 则 block_index=0 表示第一个密文块）
    modified[block_index * block_size + byte_index] ^= original_byte ^ target_value
    return bytes(modified)


def cbc_byte_flip_example():
    """
    完整示例：翻转 CBC 密文中的用户名字段
    场景：cookie = IV || Encrypt("role=user&name=alice")
    目标：将 "user" 改为 "admin"
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    import os

    key = os.urandom(16)
    iv = os.urandom(16)

    pt = b'role=user&name=alice'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(pt, 16))

    # 假设我们知道 "user" 在明文中的位置（offset=5..8）
    # 计算它在哪个密文块的哪个字节
    block_size = 16
    target_offset = 5  # "user" 的起始偏移
    block_idx = target_offset // block_size  # 在哪个密文块
    byte_idx = target_offset % block_size     # 块内偏移

    original_bytes = b'user'
    target_bytes = b'admin'

    # 逐字节翻转（注意：翻转会影响前一个密文块对应的明文块）
    modified = bytearray(iv + ct)
    for i in range(len(target_bytes)):
        pos = block_idx * block_size + byte_idx + i
        modified[pos] ^= original_bytes[i] ^ target_bytes[i]

    return bytes(modified)
```

#### Padding Oracle 攻击

```python
from Crypto.Cipher import AES

def padding_oracle_attack(oracle, ciphertext, iv, block_size=16):
    """
    Padding Oracle 攻击
    oracle: 接受 (iv, ciphertext)，返回 True/False（padding 是否合法）
    逐块恢复明文

    原理:
        1. 修改 IV 的第 i 字节，使解密后该字节为 0x01
        2. 反推：IV'[i] = IV[i] ^ intermediate[i] ^ 0x01
        3. 用 intermediate 可继续爆破其他字节
    """
    plaintext = b''
    blocks = [iv] + [ciphertext[i:i+block_size]
                     for i in range(0, len(ciphertext), block_size)]

    for block_num in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        intermediate = bytearray(block_size)

        for byte_idx in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_idx  # 期望的 padding 值

            # 构造前缀：已爆破的字节 XOR pad_val
            prefix = bytearray(block_size)
            for k in range(byte_idx + 1, block_size):
                prefix[k] = intermediate[k] ^ pad_val

            for guess in range(256):
                prefix[byte_idx] = guess
                test_iv = bytes(prefix)

                if oracle(test_iv, bytes(blocks[block_num])):
                    # 排除误判：修改更高字节验证
                    if byte_idx > 0:
                        prefix_check = bytearray(prefix)
                        prefix_check[byte_idx - 1] ^= 0x01
                        if not oracle(bytes(prefix_check), bytes(blocks[block_num])):
                            continue

                    intermediate[byte_idx] = guess ^ pad_val
                    decrypted_block[byte_idx] = intermediate[byte_idx] ^ blocks[block_num - 1][byte_idx]
                    break

        plaintext += bytes(decrypted_block)

    return plaintext.rstrip(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')
```

#### IV 重用攻击

```python
def cbc_iv_reuse_attack(ct1, ct2, known_pt1=None):
    """
    CBC IV 重用攻击
    如果两条消息使用相同 (key, IV)，则:
        C1[0] = E(P1 ^ IV)
        C2[0] = E(P2 ^ IV)
    可得: P1 ^ P2 = C1[0] ^ C2[0]

    参数:
        ct1, ct2:   两条密文（不含 IV）
        known_pt1:  已知的第一条明文片段（可选）

    返回:
        P1 ^ P2 的异或结果
    """
    # 首块 XOR 即可得到明文异或
    xored = bytes(a ^ b for a, b in zip(ct1[:16], ct2[:16]))

    if known_pt1:
        # 知道 P1 的一部分 → 恢复 P2 对应部分
        recovered = bytes(a ^ b for a, b in zip(xored, known_pt1))
        return xored, recovered

    return xored


def cbc_iv_reuse_xor_recover(ct1, ct2):
    """
    利用 IV 重用 + 已知明文字典恢复完整消息
    适用于已知明文为 ASCII 可打印字符的场景
    """
    xored = bytes(a ^ b for a, b in zip(ct1, ct2))
    # 假设明文为 ASCII，逐字节判断
    # 如果 ct1 和 ct2 有相同的结构（如固定前缀），可缩小候选范围
    return xored
```

#### CBC-MAC 攻击

```python
from Crypto.Cipher import AES

def cbc_mac_length_extension(key, mac, original_msg_length, append_data, block_size=16):
    """
    CBC-MAC 长度扩展攻击
    如果 MAC = CBC-MAC(key, msg)，攻击者可在不知道 key 的情况下
    计算 CBC-MAC(key, msg || padding || append_data)

    前提: 攻击者知道原消息的 MAC 和长度

    参数:
        key:              密钥（攻击者不知道，但服务器使用）
        mac:              原消息的 CBC-MAC
        original_msg_length: 原消息字节长度
        append_data:      要追加的数据
    """
    # 填充原消息使其达到块边界
    pad_len = block_size - (original_msg_length % block_size)
    if pad_len == 0:
        pad_len = block_size

    # 用原 MAC 作为中间值（IV），继续加密追加数据
    cipher = AES.new(key, AES.MODE_CBC, iv=mac)
    # 注意：这里模拟服务器端行为，实际攻击中攻击者只需提交
    # padded_original || append_data 并使用已知的 MAC 作为伪造 MAC 的起点
    padded_append = pad(append_data, block_size)
    new_mac = cipher.encrypt(padded_append)[-block_size:]
    return new_mac


def cbc_mac_concatenation_attack(key):
    """
    CBC-MAC 消息拼接攻击
    如果服务器接受 "msg1 || MAC(msg1) || msg2" 并验证 MAC(msg1)
    攻击者可以用 MAC(msg1) 作为 IV 计算 MAC(msg1 || msg2)
    """
    # 第一步：获取 msg1 的 MAC
    msg1 = b"from=alice&to=bob&amount=100"
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
    mac1 = cipher.encrypt(pad(msg1, 16))[-16:]

    # 第二步：构造 msg2，以 mac1 作为 IV
    msg2 = b";from=alice&to=attacker&amount=9999"
    cipher2 = AES.new(key, AES.MODE_CBC, iv=mac1)
    fake_mac = cipher2.encrypt(pad(msg2, 16))[-16:]

    # 提交: msg1 || msg2，MAC = fake_mac（如果服务器将 msg1 || msg2 拼接后验证）
    # 或者提交: msg1 || mac1 || msg2，MAC = fake_mac（如果服务器分段验证）
    return msg1 + msg2, fake_mac
```

### 3. CTR 模式攻击

#### Nonce 重用攻击

```python
def ctr_nonce_reuse_decrypt(ct1, ct2, known_pt1=None):
    """
    CTR Nonce 重用解密
    CTR 模式: C = P ^ keystream
    Nonce 重用时 keystream 相同:
        C1 ^ C2 = P1 ^ P2

    如果知道 P1 的任何片段，即可恢复 P2 对应位置
    """
    max_len = max(len(ct1), len(ct2))
    ct1_padded = ct1.ljust(max_len, b'\x00')
    ct2_padded = ct2.ljust(max_len, b'\x00')

    xored = bytes(a ^ b for a, b in zip(ct1_padded, ct2_padded))

    if known_pt1:
        # 恢复 P2 = C1 ^ C2 ^ P1
        recovered = bytes(a ^ b for a, b in zip(xored, known_pt1))
        return xored, recovered

    return xored


def ctr_nonce_reuse_xor_decrypt(ct1, ct2, known_pt1):
    """
    CTR Nonce 重用 XOR 解密
    利用已知明文 P1 恢复 P2 = C1 ^ C2 ^ P1

    参数:
        ct1:       第一条密文
        ct2:       第二条密文（目标）
        known_pt1: 已知的 P1 明文（长度可小于密文）

    返回:
        P2 的恢复结果（已知部分 + 未知部分标记为 ?）
    """
    result = bytearray()
    for i in range(len(ct2)):
        if i < len(known_pt1):
            result.append(ct1[i] ^ ct2[i] ^ known_pt1[i])
        else:
            result.append(ct1[i] ^ ct2[i])  # 仅 C1[i] ^ C2[i]，需其他手段
    return bytes(result)


def ctr_keystream_reuse_attack():
    """
    CTR 模式下，若同一密钥+Nonce 加密了多条已知明文
    可提取 keystream 并解密未知密文

    场景：加密 oracle 暴露了部分明文-密文对
    """
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(16)
    nonce = get_random_bytes(8)

    def encrypt(msg):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(msg)

    # 已知明文获取 keystream
    known_msg = b'\x00' * 16
    known_ct = encrypt(known_msg)
    # keystream = known_ct ^ known_msg = known_ct（因为 known_msg 全零）

    # 用 keystream 解密目标密文
    target_ct = get_random_bytes(32)
    keystream = known_ct[:16]  # 16 字节 keystream
    # 扩展 keystream（如果有更多已知明文-密文对）
    target_pt = bytes(a ^ b for a, b in zip(target_ct[:16], keystream))
    return target_pt
```

#### 字节翻转

```python
def ctr_byte_flip(ciphertext, delta, byte_offset):
    """
    CTR 模式字节翻转
    C = P ^ keystream
    修改 C[byte_offset] ^= delta
    则 P'[byte_offset] = P[byte_offset] ^ delta

    CTR 的优势：翻转密文字节只影响对应明文字节，不影响其他块
    """
    modified = bytearray(ciphertext)
    modified[byte_offset] ^= delta
    return bytes(modified)


def ctr_bit_flip_target(ciphertext, target_offset, target_char, current_char):
    """
    CTR 位翻转：将明文中的 current_char 翻转为目标字符
    delta = ord(target_char) ^ ord(current_char)
    """
    delta = ord(target_char) ^ ord(current_char)
    return ctr_byte_flip(ciphertext, delta, target_offset)
```

### 4. GCM 模式攻击

#### Nonce 重用攻击

```python
from Crypto.Cipher import AES

def gcm_nonce_reuse_forge_tag(key, nonce, ct1, tag1, ct2):
    """
    GCM Nonce 重用攻击
    GCM 认证标签: T = GHASH(H, AAD, C) ^ E_K(J0)
    如果 nonce 重用，E_K(J0) 相同

    已知 (ct1, tag1) 为合法密文，可伪造 (ct2, tag2)

    原理:
        tag1 = GHASH(H, aad1, ct1) ^ E_K(J0)
        tag2 = GHASH(H, aad2, ct2) ^ E_K(J0)
        tag1 ^ tag2 = GHASH(H, aad1, ct1) ^ GHASH(H, aad2, ct2)

    GHASH 是线性的（在 GF(2^128) 上），因此:
        可构造任意密文的合法标签
    """
    from struct import pack

    def ghash_sub(key, data):
        """GHASH 子计算：将数据分块后在 GF(2^128) 上乘 H"""
        h = b'\x00' * 16  # 简化：实际需解密第一块得到 H
        # 完整实现需要 GF(2^128) 乘法
        pass

    # 实际攻击步骤：
    # 1. 从已知 (ct1, tag1) 和 (ct2, tag2) 恢复 H
    # 2. 用 H 伪造任意密文的标签
    # 3. 提交伪造密文

    # 简化版：利用 nonce 重用的 XOR 关系
    print("攻击步骤：")
    print("1. 收集同一 nonce 下的多条 (ciphertext, tag) 对")
    print("2. 利用 GHASH 线性性恢复认证密钥 H")
    print("3. 用 H 伪造任意密文的合法 tag")
    print("4. 提交伪造密文绕过认证")

    return None  # 需要完整的 GF(2^128) 实现


def gcm_nonce_reuse_h_recovery():
    """
    GCM Nonce 重用：恢复认证密钥 H

    GHASH: S = aad_len || aad_padded || ct_len || ct_padded
    tag = GHASH(H, S) ^ E_K(J0)

    对于两组 (S1, tag1) 和 (S2, tag2)（同一 nonce）:
        tag1 ^ tag2 = GHASH(H, S1) ^ GHASH(H, S2)
                     = H * (S1[0] ^ S2[0]) + H^2 * (S1[1] ^ S2[1]) + ...

    通过解线性方程组可恢复 H
    """
    # 需要多项式方程求解（在 GF(2^128) 上）
    # 这里给出框架
    pass


def gcm_forge_without_key(key, nonce, aad, original_ct, original_tag, target_pt):
    """
    GCM Nonce 重用：在不知道 key 的情况下伪造密文
    利用 nonce 重用时 GHASH 的线性性

    实际 CTF 中的简化场景：
    服务器使用固定 nonce，攻击者可构造任意明文的合法密文
    """
    cipher_real = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct_real, tag_real = cipher_real.encrypt_and_digest(b"known_plaintext")

    # 如果可以获取 oracle（加密服务），直接调用即可
    # 如果不能，需要恢复 H 然后计算

    # 场景：服务器接受 "密文 + tag"，用固定 nonce 验证
    # 攻击：直接加密目标明文（因为 nonce 相同，key 也相同）
    # 但攻击者不知道 key...

    # 正确方法：利用 GHASH 线性性
    # tag_new = tag1 ^ GHASH(H, S1) ^ GHASH(H, S2)
    #         = tag1 ^ GHASH(H, S1 ^ S2)
    pass
```

#### 弱密钥攻击

```python
def gcm_weak_key_check():
    """
    GCM 弱密钥检查
    如果 H = GHASH key = 0（极小概率），则认证完全失效
    任何 tag 都有效

    检测方法：发送空密文 + 任意 tag，如果验证通过则 H = 0
    """
    # 实际中几乎不可能遇到，但理论上有此攻击
    pass
```

#### GCM 长度泄露攻击

```python
def gcm_length_leakage(ciphertext_with_tag):
    """
    GCM 密文格式: nonce (12) || ciphertext (variable) || tag (16)
    通过密文总长度可推断明文长度

    某些实现中，密文长度泄露可辅助其他攻击
    """
    if len(ciphertext_with_tag) < 28:
        raise ValueError("密文过短")
    nonce = ciphertext_with_tag[:12]
    tag = ciphertext_with_tag[-16:]
    ct = ciphertext_with_tag[12:-16]
    pt_length = len(ct)  # GCM 不填充，明文长度 == 密文长度
    return nonce, ct, tag, pt_length
```

### 5. 密钥恢复

#### 已知明文部分恢复密钥

```python
from Crypto.Cipher import AES

def key_recovery_partial_known_plaintext(ciphertext, known_plaintext, known_offset, block_size=16):
    """
    已知部分明文恢复密钥（暴力搜索 + 剪枝）

    场景：已知明文的一部分（如固定头部、已知格式等）
    如果密钥空间较小（如弱密钥、部分泄露），可暴力搜索

    参数:
        ciphertext:       密文
        known_plaintext:  已知的明文片段
        known_offset:     已知明文在完整明文中的偏移
    """
    # 计算已知明文所在的密文块
    block_idx = known_offset // block_size
    byte_idx = known_offset % block_size

    # 取对应密文块
    ct_block = ciphertext[block_idx * block_size:(block_idx + 1) * block_size]

    # 暴力搜索密钥
    # 这里假设密钥空间已缩小（如已知部分密钥字节）
    # 实际中需要结合其他信息缩小搜索空间
    for key_candidate in range(0, 0xFFFFFFFF + 1):
        key = key_candidate.to_bytes(4, 'big').ljust(block_size, b'\x00')
        cipher = AES.new(key, AES.MODE_ECB)
        pt_block = cipher.decrypt(ct_block)
        # 检查已知位置是否匹配
        if pt_block[byte_idx:byte_idx + len(known_plaintext)] == known_plaintext:
            return key
    return None


def key_recovery_ecb_multiblock(oracle, block_size=16):
    """
    ECB 模式下，通过选择明文恢复完整密钥
    当密钥空间足够小，或可结合已知明文信息时有效

    利用 ECB 的确定性：相同明文 → 相同密文
    """
    # 方法 1：已知明文字典攻击
    # 构造所有可能的明文块，查询 oracle 获取密文
    # 建立明文→密文映射表
    # 对目标密文查表

    # 方法 2：Meet-in-the-Middle
    # 将密钥分为两部分，分别正向/反向计算
    # 在中间值处匹配
    pass
```

#### AES-256 密钥扩展攻击

```python
def aes256_key_schedule_attack():
    """
    AES-256 密钥扩展弱点
    AES-256 的密钥扩展使用两个 32 字节子密钥 (K0, K1)
    如果攻击者能泄露部分轮密钥，可恢复原始密钥

    攻击方法:
    1. 从轮密钥反推密钥扩展
    2. 利用 AES-256 密钥扩展的非线性变换
    3. 结合侧信道泄露的中间值

    时间复杂度: O(2^256) 暴力搜索
    但如果有部分泄露，可显著降低复杂度
    """
    # AES-256 密钥扩展
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f]

    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        # ... 完整 S-box
    ]

    def rot_word(w):
        return bytes([w[1], w[2], w[3], w[0]])

    def sub_word(w):
        return bytes([SBOX[b] for b in w])

    # 演示密钥扩展
    key = bytes(range(32))  # 示例密钥
    w = [key[i:i+4] for i in range(0, 32, 4)]

    for i in range(4, 60):  # AES-256 需要 60 个 32-bit 字
        temp = w[i-1]
        if i % 8 == 0:
            temp = bytes([SBOX[b] ^ (RCON[i//8-1] if j == 0 else 0)
                         for j, b in enumerate(rot_word(temp))])
        elif i % 4 == 0:
            temp = sub_word(temp)
        w.append(bytes([a ^ b for a, b in zip(w[i-4], temp)]))

    return w
```

#### 侧信道攻击

```python
def timing_attack_aes():
    """
    AES 时间攻击
    利用 S-box 查表的时间差异恢复密钥
    原理: 不同输入的 cache 命中/未命中时间不同

    攻击步骤:
    1. 大量采样加密时间
    2. 统计每个密钥字节候选的时间分布
    3. 选择平均时间最长/最短的候选
    """
    import time
    import statistics

    # 模拟时间攻击
    NUM_SAMPLES = 10000
    BLOCK_SIZE = 16

    # 假设已知第一轮密钥字节的候选值
    # 对每个候选值，测量大量加密时间
    # 统计时间分布，选择异常值作为正确密钥字节

    # 实际攻击中:
    # 1. 收集大量 (plaintext, ciphertext, time) 三元组
    # 2. 对每个密钥字节候选 k:
    #    - 计算部分中间值
    #    - 按中间值分组
    #    - 检查时间分布是否有显著差异
    # 3. 选择统计显著的候选值

    pass


def cache_timing_attack():
    """
    AES Cache-Timing 攻击
    Flush+Reload / Prime+Probe 等技术

    原理:
    AES S-box 查表会访问 cache line
    通过监控 cache 访问模式可推断密钥

    攻击能力:
    - AES-128: ~1 次加密即可恢复完整密钥
    - AES-256: 需要约 2 次加密

    防御: AES-NI 硬件指令 / bitsliced 实现
    """
    pass


def power_analysis_aes():
    """
    AES 功耗分析攻击
    SPA (Simple Power Analysis): 直接观察功耗波形
    DPA (Differential Power Analysis): 统计分析

    DPA 攻击步骤:
    1. 收集大量 (plaintext, power_trace) 对
    2. 对每个候选密钥字节:
       - 计算假设中间值
       - 将功耗轨迹按中间值分为两组
       - 计算两组的功耗差分
       - 差分峰值最大的候选即为正确密钥字节

    适用于嵌入式设备、智能卡等物理可接触场景
    """
    pass
```

### 6. 差分故障分析 (DFA)

```python
from Crypto.Cipher import AES

def dfa_attack_aes(key, block_size=16):
    """
    AES 差分故障分析 (Differential Fault Analysis)

    攻击原理:
    在 AES 最后一轮加密前注入随机故障（如翻转某些比特）
    比较正确密文和故障密文的差异，可恢复轮密钥

    几种经典 DFA 攻击:
    1. Piret-Quisquater (2003): 单字节故障注入最后两轮
    2. rijndael-fault-attack: 多字节故障
    3. Bellcore 攻击: 随机字节故障

    参数:
        key: 用于模拟加密的密钥
    """
    # S-box 和逆 S-box
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]
    INV_SBOX = [0] * 256
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i

    def add_round_key(state, rk):
        return [s ^ r for s, r in zip(state, rk)]

    def sub_bytes(state):
        return [SBOX[s] for s in state]

    def inv_sub_bytes(state):
        return [INV_SBOX[s] for s in state]

    def shift_rows(state):
        # 将 state 视为 4x4 矩阵（列主序）
        s = [state[i*4:(i+1)*4] for i in range(4)]
        s[1] = [s[1][(1+j)%4] for j in range(4)]
        s[2] = [s[2][(2+j)%4] for j in range(4)]
        s[3] = [s[3][(3+j)%4] for j in range(4)]
        return [s[j][i] for i in range(4) for j in range(4)]

    def gf_mul(a, b):
        """GF(2^8) 乘法"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return p

    def mix_columns(state):
        s = [state[i*4:(i+1)*4] for i in range(4)]
        r = [[0]*4 for _ in range(4)]
        for c in range(4):
            r[0][c] = gf_mul(2,s[0][c]) ^ gf_mul(3,s[1][c]) ^ s[2][c] ^ s[3][c]
            r[1][c] = s[0][c] ^ gf_mul(2,s[1][c]) ^ gf_mul(3,s[2][c]) ^ s[3][c]
            r[2][c] = s[0][c] ^ s[1][c] ^ gf_mul(2,s[2][c]) ^ gf_mul(3,s[3][c])
            r[3][c] = gf_mul(3,s[0][c]) ^ s[1][c] ^ s[2][c] ^ gf_mul(2,s[3][c])
        return [r[j][i] for i in range(4) for j in range(4)]

    def encrypt_block(pt, rk, rounds=10):
        state = list(pt)
        state = add_round_key(state, rk[:16])
        for r in range(1, rounds):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, rk[r*16:(r+1)*16])
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, rk[rounds*16:(rounds+1)*16])
        return bytes(state)

    # 模拟 DFA 攻击
    import os

    pt = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)

    # 正常加密
    ct_good = cipher.encrypt(pt)

    # 模拟故障注入：在第 9 轮后注入单字节故障
    fault_byte = 7  # 故障位置（字节索引）
    fault_value = os.urandom(1)[0]  # 随机故障值

    # 计算故障密文（模拟）
    cipher_fault = AES.new(key, AES.MODE_ECB)
    # 实际中通过故障注入获取，这里用已知密钥模拟
    pt_fault = bytearray(pt)
    # 简化：直接对密文进行故障模拟
    ct_fault = bytearray(ct_good)
    ct_fault[fault_byte] ^= fault_value  # 模拟故障效果

    print(f"正常密文: {ct_good.hex()}")
    print(f"故障密文: {bytes(ct_fault).hex()}")
    print(f"故障位置: 字节 {fault_byte}")
    print(f"差分值: {ct_good[fault_byte] ^ ct_fault[fault_byte]:02x}")

    # DFA 攻击步骤:
    # 1. 从 ct_good 和 ct_fault 反推最后一轮输入
    # 2. 利用 MixColumns 逆运算恢复部分轮密钥
    # 3. 重复多次故障恢复完整密钥

    # 单字节 DFA 恢复最后一轮密钥
    # diff = ct_good ^ ct_fault
    # 由于差分仅在单字节，可缩小候选密钥空间
    candidates = {}
    for byte_idx in range(16):
        diff = ct_good[byte_idx] ^ ct_fault[byte_idx]
        if diff == 0:
            continue
        # 对每个候选密钥字节
        for k_guess in range(256):
            s1 = INV_SBOX[ct_good[byte_idx] ^ k_guess]
            s2 = INV_SBOX[ct_fault[byte_idx] ^ k_guess]
            # MixColumns 差分约束
            # 简化：直接匹配
            if True:  # 实际需要完整的 MixColumns 约束
                candidates.setdefault(byte_idx, []).append(k_guess)

    return ct_good, bytes(ct_fault)


def dfa_piret_quisquater():
    """
    Piret-Quisquater DFA 攻击

    在 AES 第 9 轮后注入单字节故障
    利用 MixColumns 的差分性质恢复最后一轮密钥

    步骤:
    1. 获取 (ct_good, ct_fault) 对
    2. 对故障列的 4 个字节:
       - 计算 MixColumns 逆差分
       - 列出满足差分约束的候选密钥字节
    3. 多次故障取交集，确定唯一密钥

    时间复杂度: O(n) 次故障即可恢复 AES-128 完整密钥
    """
    # 完整实现需要 GF(2^128) 运算和 MixColumns 逆差分计算
    pass


def dfa_random_byte_fault():
    """
    随机字节故障 DFA

    在任意位置注入随机字节故障
    比单字节故障更通用，但需要更多样本

    适用于:
    - 软件实现的 AES
    - 嵌入式设备
    - 智能卡

    防御:
    - 故障检测（校验和）
    - 双重加密
    - 随机化运算顺序
    """
    pass


def dfa_double_fault():
    """
    双故障 DFA

    同时注入两个故障，利用故障间的相关性
    可减少所需故障数量

    适用于:
    - 需要绕过故障检测的场景
    - 高级攻击技术
    """
    pass
```

## 2024-2026 新技术点

### 1. AES-GCM-SIV（抗 Nonce 重用模式）

```python
from Crypto.Cipher import AES

def aes_gcm_siv_demo():
    """
    AES-GCM-SIV (RFC 8452)
    NIST 标准化的 nonce-misuse-resistant 认证加密

    核心特性:
    1. Nonce 重用时仅泄露明文相等性，不泄露认证密钥 H
    2. 不可伪造任意密文的合法标签（与 GCM 不同）
    3. 基于 POLY1305-MAC 和 AES-CTR

    与 GCM 的区别:
    - GCM: nonce 重用 → 认证密钥 H 泄露 → 可伪造任意密文
    - GCM-SIV: nonce 重用 → 仅泄露 P1 == P2（明文相等性）

    攻击面:
    - 如果只泄露明文相等性，某些场景仍可能被利用
    - 慢速加密（比 GCM 慢约 2-3 倍）
    - 不支持随机访问（需要完整解密）

    CTF 场景:
    - 服务器使用 GCM-SIV，攻击者获取多条密文
    - 通过密文长度 + 明文相等性推断敏感信息
    """
    # PyCryptodome 尚未内置 GCM-SIV，需手动实现或使用第三方库
    # 这里展示使用 AES-GCM 模拟（仅说明概念）

    key = b'\x00' * 16  # 示例密钥
    nonce = b'\x00' * 12

    # 实际使用:
    # from Crypto.Cipher import AES
    # cipher = AES.new(key, AES.MODE_GCM_SIV, nonce=nonce)
    # ct, tag = cipher.encrypt_and_digest(pt)

    print("AES-GCM-SIV 特性:")
    print("1. Nonce 重用安全: 仅泄露明文相等性")
    print("2. 认证标签基于 SIV 模式（合成初始化向量）")
    print("3. 加密过程: 先计算 SIV = MAC(key, plaintext || AAD)")
    print("   再用 SIV 作为 IV 进行 AES-CTR 加密")
    print("4. 解密时先解密，再验证 MAC")


def aes_gcm_siv_nonce_misuse_analysis():
    """
    AES-GCM-SIV Nonce 误用分析

    当 nonce 重用时:
    - SIV 相同 → 密文的 CTR 部分相同
    - 但认证标签基于 SIV，不会泄露 H

    安全边界:
    - Nonce 重用次数越多，泄露的明文相等性信息越多
    - 极端情况: 所有消息相同 nonce → 只能判断明文是否相同

    与 GCM 对比:
    - GCM nonce 重用: 认证密钥 H 完全泄露 → 可伪造任意密文
    - GCM-SIV nonce 重用: 仅泄露明文相等性 → 不可伪造
    """
    pass
```

### 2. AES-CCM（CTR + CBC-MAC 组合模式）

```python
from Crypto.Cipher import AES

def aes_ccm_demo():
    """
    AES-CCM (NIST SP 800-38C)
    组合加密 (CTR) + 认证 (CBC-MAC) 的 AEAD 模式

    广泛用于:
    - WPA2/WPA3 (802.11)
    - Bluetooth Low Energy
    - Zigbee
    - IPSec

    结构:
    1. 计算 CBC-MAC (认证): 标签 = CBC-MAC(key, Nonce || AAD || Padded PT)
    2. CTR 加密: C = P ^ keystream(key, Nonce || counter)

    Nonce 格式: flags (1) || N (7-14) || Q (2-8)
    - flags: 指定 AAD 长度字段大小、L 值等
    - N: 随机数
    - Q: 消息计数器（部分 NIST 推荐）

    攻击面:
    - Nonce 重用: 同 GCM，会导致认证密钥泄露
    - 长度泄露: CCM 不填充，密文长度 = 明文长度
    - 实现缺陷: 某些实现的 CBC-MAC 可能被利用

    CTF 场景:
    - 识别加密模式（WPA2/蓝牙/Zigbee 包）
    - Nonce 重用攻击（同 GCM）
    - 实现漏洞利用
    """
    key = b'\x00' * 16
    nonce = b'\x00' * 7

    # PyCryptodome CCM
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    aad = b"additional data"
    pt = b"plaintext message"
    ct, tag = cipher.encrypt_and_digest(pt)

    print(f"密文: {ct.hex()}")
    print(f"标签: {tag.hex()}")
    print(f"密文长度: {len(ct)} (与明文相同)")
    print(f"标签长度: {len(tag)} 字节")


def aes_ccm_nonce_reuse():
    """
    AES-CCM Nonce 重用攻击

    与 GCM 类似，nonce 重用导致:
    1. CTR keystream 重用 → 可恢复明文异或
    2. CBC-MAC 可能被分析

    差异:
    - CCM 的 CBC-MAC 不使用 GHASH，无法像 GCM 那样直接伪造
    - 但 nonce 重用仍会导致密钥流重用

    防御:
    - 每次加密使用唯一 nonce
    - 使用计数器而非随机 nonce
    - 实现 nonce 检查和拒绝重复
    """
    pass
```

### 3. CCM*S（扩展 CCM 模式）

```python
def aes_ccm_star_demo():
    """
    AES-CCM* (IEEE 802.15.4)
    CCM* 是 CCM 的扩展，用于 Zigbee/IPSP

    关键差异:
    1. 支持可变 nonce 长度
    2. 支持更短的认证标签
    3. 增强了 Nonce 的灵活性

    攻击面:
    - 较短的标签增加了暴力伪造风险
    - 实现缺陷可能导致 nonce 重用
    - Zigbee 安全问题（密钥派生、信任中心）

    CTF 场景:
    - Zigbee 协议分析
    - IoT 设备安全
    - 802.15.4 数据包解析
    """
    pass
```

### 4. AES-CMAC 侧信道攻击

```python
from Crypto.Cipher import AES

def aes_cmac_side_channel():
    """
    AES-CMAC (RFC 4493) 侧信道攻击

    CMAC 结构:
    1. 分块消息，对每个块进行 CBC-MAC
    2. 最后一块使用特殊子密钥 (K1, K2)
    3. 输出截断标签

    侧信道攻击目标:
    1. 恢复 MAC 密钥 → 可伪造任意消息的合法标签
    2. 恢复加密密钥（如果使用相同密钥）

    攻击方法:
    - 时间攻击: CMAC 计算时间与密钥相关
    - 缓存攻击: S-box 查表泄露密钥信息
    - 功耗分析: SPA/DPA 恢复中间值

    应用场景:
    - WPA2 四次握手
    - TLS 1.2 PRF
    - ISO/IEC 9797-1 MAC

    防御:
    - 恒定时间实现
    - 随机化运算
    - 硬件 AES 加速
    """
    key = b'\x00' * 16
    mac = AES.new(key, AES.MODE_CMAC)
    msg = b"test message"
    mac.update(msg)
    tag = mac.digest()

    print(f"CMAC 标签: {tag.hex()}")
    print(f"标签长度: {len(tag)} 字节")


def aes_cmac_key_recovery_partial():
    """
    AES-CMAC 部分密钥恢复

    利用 CMAC 的结构特性:
    1. 最后一块使用子密钥 K1/K2
    2. K1/K2 通过密钥扩展从主密钥派生
    3. 如果能控制消息长度，可选择使用 K1 还是 K2

    攻击步骤:
    1. 获取多个 (message, tag) 对
    2. 利用 CBC-MAC 的线性性分析
    3. 结合已知明文恢复子密钥
    4. 从子密钥恢复主密钥

    时间复杂度: O(2^n) 其中 n 为密钥长度
    """
    pass
```

### 5. AES-NI 旁路攻击

```python
def aes_ni_timing_attack():
    """
    AES-NI 指令级旁路攻击

    AES-NI (AES New Instructions) 是 Intel/AMD 的硬件加速指令
    虽然设计上抗侧信道，但仍有攻击面:

    1. 缓存时序:
       - S-box 查表仍可能通过 cache 泄露
       - 某些实现混合使用 AES-NI 和软件

    2. 功耗分析:
       - 仍可从功耗曲线提取密钥
       - 需要物理访问

    3. 微架构攻击:
       - Spectre/Meltdown 变种
       - 跨虚拟机攻击（云环境）

    防御:
    - 纯 AES-NI 实现（无软件回退）
    - 随机化执行
    - 恒定时间保证
    """
    pass


def aes_ni_vs_software():
    """
    AES-NI vs 软件实现的安全对比

    AES-NI:
    - 恒定时间执行（抗时间攻击）
    - 无 cache 依赖（抗缓存攻击）
    - 功耗仍可能泄露（需物理访问）

    软件实现:
    - 依赖 S-box 查表（cache 攻击）
    - 分支依赖（时间攻击）
    - bitsliced 实现可抗缓存攻击

    CTF 建议:
    - 首先检查是否使用 AES-NI
    - 如果是，转向其他攻击面（协议、实现逻辑）
    - 软件实现优先考虑 cache/timing 攻击
    """
    pass
```

### 6. 白盒 AES 攻击

```python
def whitebox_aes_chow_attack():
    """
    白盒 AES (Chow et al.) 攻击

    白盒攻击模型: 攻击者完全控制执行环境
    可以观察/修改内存、寄存器、执行流程

    Chow 白盒 AES:
    1. 使用查找表 (T-box) 实现 AES
    2. 表项与密钥混合（嵌入密钥）
    3. 通过仿射变换隐藏中间值

    攻击方法:
    1. 攻击者提取 T-box 内容
    2. 分析表项结构恢复密钥
    3. 时间/内存访问模式分析

    应用:
    - DRM 系统
    - 移动支付
    - 软件保护

    防御:
    - 动态白盒（定期更新表项）
    - 混淆技术
    - 安全硬件模块
    """
    pass


def whitebox_aes_extraction():
    """
    白盒 AES 密钥提取

    从 T-box 提取密钥:
    1. 逐个读取 T-box 表项
    2. 分析输入-输出关系
    3. 逆向仿射变换
    4. 恢复轮密钥

    工具:
    - 静态分析: IDA Pro, Ghidra
    - 动态分析: 调试器, 内存转储
    - 自动化: angr, Triton

    时间复杂度: O(1)（一旦获取 T-box）
    """
    pass
```

### 7. AES-XTS（磁盘加密模式）

```python
def aes_xts_attack():
    """
    AES-XTS (IEEE 1619)
    用于磁盘加密 (BitLocker, LUKS, FileVault)

    结构:
    1. 使用两个密钥: 数据密钥 K1 + tweak 密钥 K2
    2. 每个扇区使用不同的 tweak（扇区号）
    3. tweak 用 AES-ECB 加密后参与数据加密

    攻击面:
    1. Tweak 重用: 不同数据使用相同 tweak → CTR 模式弱点
    2. 弱 tweak: 可预测/可控的 tweak 值
    3. 边界处理: 最后块的特殊处理可能被利用

    已知攻击:
    - BitLocker 漏洞 (CVE-2023-21563)
    - LUKS1 弱密钥派生
    - 冷启动攻击（物理访问）

    CTF 场景:
    - 磁盘镜像分析
    - 加密分区恢复
    - BitLocker/LUKS 密码恢复
    """
    pass
```

### 8. 量子攻击

```python
def grover_aes():
    """
    Grover 算法对 AES 的影响

    Grover 算法: 量子搜索，将暴力搜索从 O(2^n) 降至 O(2^{n/2})

    对 AES 的影响:
    - AES-128: 量子暴力搜索 O(2^64) → 实际不可行（需大量量子比特）
    - AES-192: O(2^{96}) → 安全
    - AES-256: O(2^{128}) → 足够安全

    实际威胁:
    1. 量子计算机尚无法运行 Grover 算法（需要数千逻辑量子比特）
    2. 当前最大量子计算机约 1000 物理量子比特
    3. 运行 AES 攻击需要数十亿物理量子比特（含纠错）

    后量子对称密码:
    - AES-256 被认为足够安全
    - NIST 推荐使用更长密钥
    - 新标准正在制定中

    CTF 场景:
    - 量子算法理论题
    - 密码强度分析
    - 后量子迁移规划
    """
    pass


def quantum_symmetric_crypto():
    """
    后量子对称密码学

    量子计算对对称密码的影响:
    1. Grover 算法: 搜索加速 → 有效密钥长度减半
    2. Simon 算法: 对某些 MAC 模式有二次加速
    3. 量子随机预言机: 新的安全模型

    新兴对称密码:
    - AES-256/512: 足够抵御量子攻击
    - SPECK/SIMON: NSA 设计的轻量级密码
    - NIST 后量子标准化: 主要针对公钥密码

    NIST 后量子标准 (2024):
    - FIPS 203 (ML-KEM/Kyber): 密钥封装
    - FIPS 204 (ML-DSA/Dilithium): 数字签名
    - FIPS 205 (SLH-DSA/SPHINCS+): 无状态签名

    对称密码迁移建议:
    1. 使用 AES-256 或更长密钥
    2. 避免使用 AES-128（理论上有风险）
    3. 关注 NIST 后量子对称标准
    """
    pass
```

### 9. 国密 SM4 与 AES 对比

```python
def sm4_vs_aes():
    """
    SM4 (GB/T 32907-2016) 与 AES 对比

    SM4 特性:
    1. 分组大小: 128 位（与 AES 相同）
    2. 密钥长度: 128 位
    3. 轮数: 32 轮（AES-128 为 10 轮）
    4. S-box: 固定 8-bit S-box
    5. 非线性变换: 32-bit 并行

    与 AES 的区别:
    - SM4 没有 MixColumns（使用非线性变换）
    - SM4 的密钥扩展更简单
    - SM4 的 S-box 与 AES 不同

    攻击方法:
    1. 差分密码分析: 已知最佳攻击约 22 轮
    2. 线性密码分析: 已知最佳攻击约 24 轮
    3. 侧信道: 与 AES 类似（cache, timing, power）

    应用:
    - 中国国家密码标准
    - WAPI (无线局域网安全)
    - TLS 1.3 国密套件
    - 金融、政务系统

    CTF 场景:
    - 国密算法实现
    - SM4 侧信道分析
    - 与 AES 的混合使用
    """
    pass


def sm4_weak_key():
    """
    SM4 弱密钥分析

    SM4 理论上无弱密钥（密钥空间均匀）
    但某些实现可能存在:

    1. 密钥派生弱点:
       - 不当的密钥派生函数
       - 可预测的 IV

    2. 侧信道泄露:
       - 缓存攻击
       - 功耗分析

    3. 协议层弱点:
       - 密钥协商缺陷
       - 重放攻击

    与 AES 弱密钥对比:
    - AES: 某些弱密钥导致部分轮简化
    - SM4: 无已知弱密钥类
    """
    pass
```

### 10. 轻量级密码

```python
def lightweight_cipher_comparison():
    """
    轻量级密码与 AES 的对比

    轻量级密码设计目标:
    1. 极低硬件面积（< 2000 GE）
    2. 低功耗
    3. 适合 IoT / RFID / 传感器

    代表算法:
    1. PRESENT (2007): SPN 结构, 31 轮, 64-bit 分组
    2. SIMON/SPECK (2013): NSA 设计, Feistel 结构
    3. GIFT (2017): PRESENT 后继, 更高效
    4. QARMA (2016): 面向内存加密, 可逆性

    与 AES 的对比:
    - 安全性: AES 更强（128-bit 分组, 10-14 轮）
    - 效率: 轻量级密码硬件面积更小
    - 实现: AES 有硬件加速（AES-NI）

    攻击方法:
    1. 差分分析: 轻量级密码轮数少，更容易受到
    2. 积分分析: 适用于 SPN 结构
    3. 侧信道: 与 AES 类似

    CTF 场景:
    - IoT 设备安全
    - 嵌入式系统分析
    - 新兴密码学研究
    """
    pass
```

### 11. 同态加密中的对称密码

```python
def he_symmetric_cipher():
    """
    全同态加密 (FHE) 中的对称密码应用

    FHE 允许在密文上直接计算:
    1. 加法同态: E(a) + E(b) = E(a+b)
    2. 乘法同态: E(a) * E(b) = E(a*b)

    对称密码在 FHE 中的作用:
    1. 数据预加密: 明文先用对称密码加密，再用 FHE
    2. 混合加密: FHE 加密对称密钥，对称密码加密数据
    3. 安全计算: 对称密码作为构建模块

    安全考虑:
    1. 密钥管理: FHE 密钥 + 对称密钥双重保护
    2. 实现安全: 避免侧信道泄露
    3. 性能优化: 对称密码加速 FHE 操作

    CTF 场景:
    - FHE 实现分析
    - 混合加密方案
    - 安全多方计算

    新兴方向:
    - TFHE/CKKS: 实用化 FHE
    - 可验证计算: FHE + 零知识证明
    - 隐私保护机器学习: FHE + AI
    """
    pass
```

### 12. AI 辅助密码分析

```python
def ai_assisted_cryptoanalysis():
    """
    机器学习辅助密码分析

    应用领域:
    1. 侧信道分析:
       - 神经网络自动提取密钥
       - 比传统 DPA 更高效
       - 减少样本需求

    2. 密码破解:
       - 强化学习优化暴力搜索
       - 生成模型预测密码
       - GAN 生成攻击样本

    3. 漏洞检测:
       - 代码审计自动化
       - 模糊测试引导
       - 异常行为检测

    已知研究:
    - 深度学习侧信道 (CHES 2019)
       - 使用 CNN/MLP 从功耗曲线恢复密钥
       - 样本需求减少 100 倍
    - 密码强度预测 (IEEE S&P 2020)
       - 机器学习预测密码强度
       - 辅助密码策略制定

    局限性:
    1. 需要大量训练数据
    2. 泛化能力有限
    3. 可解释性差
    4. 仍需传统密码学分析验证

    CTF 场景:
    - 侧信道数据分析
    - 密码破解工具
    - 安全评估
    """
    pass


def ai_side_channel_attack():
    """
    AI 辅助侧信道攻击

    传统 DPA:
    1. 收集大量功耗轨迹
    2. 手动选择中间值
    3. 统计分析

    AI 方法:
    1. 自动特征提取
    2. 端到端学习
    3. 少样本学习

    深度学习模型:
    - CNN: 时序功耗分析
    - LSTM: 长序列依赖
    - Transformer: 全局注意力
    - GAN: 生成对抗训练样本

    实际效果:
    - 样本需求: 从 10^6 降至 10^3
    - 时间: 从数小时降至数分钟
    - 精度: 接近理论极限

    防御:
    1. 随机化执行
    2. 噪声注入
    3. 安全硬件设计
    """
    pass
```

## 工具推荐

- **PyCryptodome** — Python 加密库
- **SageMath** — 数学计算
- **padding-oracle-tool** — Padding Oracle 自动化
- **Hashcat** — 密钥爆破
- **Scapy** — 网络协议分析（用于 AES-CCM/XTS 数据包解析）
- **Ghidra/IDA** — 逆向工程（白盒 AES 分析）
- **ChipWhisperer** — 侧信道攻击平台
- **rqcrypto** — 后量子密码学库

## 参考链接

- [ctf-wiki AES](https://ctf-wiki.org/crypto/blockcipher/)
- [AES Attack](https://github.com/ctfs/write-ups-2014/tree/master/plaidctf-2014/aes)
- [Padding Oracle](https://github.com/AonCyberLabs/padding-oracle-tool)
- [NIST SP 800-38D (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST SP 800-38C (CCM)](https://csrc.nist.gov/publications/detail/sp/800-38c/final)
- [RFC 8452 (GCM-SIV)](https://datatracker.ietf.org/doc/html/rfc8452)
- [AES-GCM-SIV 分析](https://eprint.iacr.org/2018/229)
- [DFA 攻击](https://academic.oup.com/journals/pages/cryptanalysis-of-aes-with-differential-fault-analysis)
- [侧信道攻击指南](https://book.douban.com/subject/3012497/)
- [后量子密码学](https://csrc.nist.gov/projects/post-quantum-cryptography)
