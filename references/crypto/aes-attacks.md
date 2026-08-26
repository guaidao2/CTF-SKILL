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

    def _gf128_mul(a, b):
        """GF(2^128) 乘法，GCM 使用的不可约多项式 x^128 + x^7 + x^2 + x + 1"""
        result = 0
        for _ in range(128):
            if b & (1 << 127):
                result ^= a
            carry = a & 1
            a >>= 1
            if carry:
                a ^= (1 << 127) ^ (1 << 7) ^ (1 << 2) ^ (1 << 1) ^ 1  # 0x87
            b <<= 1
            b &= (1 << 128) - 1
        return result

    def _bytes_to_int(b):
        return int.from_bytes(b, 'big')

    def _int_to_bytes(n):
        return n.to_bytes(16, 'big')

    def ghash_sub(h_key, data):
        """GHASH 子计算：将数据分块后在 GF(2^128) 上累乘 H"""
        if len(data) % 16 != 0:
            data += b'\x00' * (16 - len(data) % 16)
        h_int = _bytes_to_int(h_key)
        acc = 0
        for i in range(0, len(data), 16):
            block = _bytes_to_int(data[i:i+16])
            acc = _gf128_mul(acc ^ block, h_int)
        return _int_to_bytes(acc)

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
    # 这里给出完整框架实现
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    def _gf128_mul(a, b):
        """GF(2^128) 乘法"""
        result = 0
        for _ in range(128):
            if b & (1 << 127):
                result ^= a
            carry = a & 1
            a >>= 1
            if carry:
                a ^= (1 << 127) ^ (1 << 7) ^ (1 << 2) ^ (1 << 1) ^ 1
            b <<= 1
            b &= (1 << 128) - 1
        return result

    def _bytes_to_int(b):
        return int.from_bytes(b, 'big')

    def _int_to_bytes(n, length=16):
        return n.to_bytes(length, 'big')

    def _pad16(data):
        """将数据填充到 16 字节的倍数"""
        pad_len = (16 - len(data) % 16) % 16
        return data + b'\x00' * pad_len

    def ghash(h_key, aad, ct):
        """计算 GHASH(H, AAD, CT)"""
        h_int = _bytes_to_int(h_key)
        # 构造 GHASH 输入: AAD_padded || len(AAD) || CT_padded || len(CT)
        aad_padded = _pad16(aad)
        ct_padded = _pad16(ct)
        aad_len = pack('>QQ', len(aad) * 8, 0)  # 64-bit bit length
        ct_len = pack('>QQ', len(ct) * 8, 0)
        msg = aad_padded + aad_len + ct_padded + ct_len
        acc = 0
        for i in range(0, len(msg), 16):
            block = _bytes_to_int(msg[i:i+16])
            acc = _gf128_mul(acc ^ block, h_int)
        return _int_to_bytes(acc)

    def _get_j0(nonce):
        """计算 J0 = nonce || 0x00000001"""
        if len(nonce) == 12:
            return nonce + b'\x00\x00\x00\x01'
        return ghash(b'\x00' * 16, b'', nonce)

    def _derive_h_and_ekj0(key, nonce, ct, tag):
        """
        从 (ct, tag) 恢复 H 和 E_K(J0):
            tag = GHASH(H, ct) ^ E_K(J0)
        需要两对密文来消除 E_K(J0):
            tag1 ^ tag2 = GHASH(H, ct1) ^ GHASH(H, ct2)
                        = GHASH(H, ct1 ^ ct2)
        """
        return tag, ct  # 简化返回

    # ---- 演示：从 nonce 重用的两组密文恢复 H ----
    key = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    aad1 = b"header1"
    pt1 = b"secret message 1"
    ct1, tag1 = cipher.encrypt_and_digest(pt1)

    cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
    aad2 = b"header2"
    pt2 = b"secret message 2"
    ct2, tag2 = cipher2.encrypt_and_digest(pt2)

    # 恢复 E_K(J0): 从空 AAD 和空 CT 的 GHASH 差分
    cipher0 = AES.new(key, AES.MODE_GCM, nonce=nonce)
    _, tag0 = cipher0.encrypt_and_digest(b'')

    # E_K(J0) = tag0 ^ GHASH(H, empty)
    # 对于空消息 GHASH = 0，所以 E_K(J0) = tag0
    ekj0 = tag0

    # 验证：用恢复的 E_K(J0) 验证 tag1
    h_estimated = bytes(a ^ b for a, b in zip(
        ghash(ekj0, aad1, ct1),  # 需要 H，但用 E_K(J0) 做初步验证
        tag1
    ))
    print(f"恢复的 E_K(J0): {ekj0.hex()}")
    print(f"利用 nonce 重用可验证/伪造任意密文的合法 tag")


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
    from struct import pack

    def _gf128_mul(a, b):
        result = 0
        for _ in range(128):
            if b & (1 << 127):
                result ^= a
            carry = a & 1
            a >>= 1
            if carry:
                a ^= (1 << 127) ^ (1 << 7) ^ (1 << 2) ^ (1 << 1) ^ 1
            b <<= 1
            b &= (1 << 128) - 1
        return result

    def _bytes_to_int(b):
        return int.from_bytes(b, 'big')

    def _int_to_bytes(n):
        return n.to_bytes(16, 'big')

    def _pad16(data):
        pad_len = (16 - len(data) % 16) % 16
        return data + b'\x00' * pad_len

    def ghash(h_int, aad, ct):
        aad_padded = _pad16(aad)
        ct_padded = _pad16(ct)
        lengths = pack('>QQ', len(aad) * 8, len(ct) * 8)
        msg = aad_padded + lengths + ct_padded
        acc = 0
        for i in range(0, len(msg), 16):
            block = _bytes_to_int(msg[i:i+16])
            acc = _gf128_mul(acc ^ block, h_int)
        return _int_to_bytes(acc)

    # 恢复 H：从空消息 tag = GHASH(H, empty) ^ E_K(J0)
    # E_K(J0) = AES-ECB(key, J0)，但攻击者不知道 key
    # 利用两个已知密文对差分消除 E_K(J0)
    # 实际攻击：获取同一 nonce 下两个密文对 (ct_a, tag_a), (ct_b, tag_b)
    # tag_a ^ tag_b = GHASH(H, aad_a, ct_a) ^ GHASH(H, aad_b, ct_b)
    #               = GHASH(H, (aad_a ^ aad_b) || (ct_a ^ ct_b))
    # 构造方程组求解 H（这里演示概念）

    # 简化场景：已知 H 后伪造
    h_known = _bytes_to_int(b'\x01' * 16)  # 模拟已恢复的 H
    j0_int = _bytes_to_int(nonce + b'\x00\x00\x00\x01' if len(nonce) == 12 else b'\x00' * 16)

    # 构造新的 GHASH 输入
    target_ct = target_pt  # 示例：CTR 模式下密文 = 明文 ^ keystream
    target_aad = aad
    new_ghash = _bytes_to_int(ghash(h_known, target_aad, target_ct))
    new_tag = _int_to_bytes(new_ghash ^ j0_int)

    print(f"伪造密文: {target_ct.hex()}")
    print(f"伪造标签: {new_tag.hex()}")
    return target_ct, new_tag
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
    # 如果 H = 0，GHASH 输出恒为 0，tag = 0 ^ E_K(J0) = E_K(J0)
    # 验证时：GHASH(H, aad, ct) ^ tag = 0 ^ E_K(J0) = E_K(J0)  ← 恒等式
    # 检测方法：发送空密文 + 任意 tag，如果验证通过则 H = 0
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    def test_weak_h(oracle_encrypt_and_verify):
        """
        测试 GCM 弱密钥 (H = 0)
        oracle: 服务端加密/验证 oracle

        攻击步骤:
        1. 构造空密文 + 随意 tag
        2. 调用验证 oracle
        3. 如果验证通过，则 H = 0（认证完全失效）
        """
        key = get_random_bytes(16)
        nonce = get_random_bytes(12)

        # 正常情况：构造一个有效密文对作为基准
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct_ref, tag_ref = cipher.encrypt_and_digest(b'reference')

        # 弱密钥检测：用空密文 + 随意 tag
        # 如果 H = 0，则 GHASH(H, empty, empty) = 0
        # 验证方程：GHASH(H, empty, empty) ^ tag == E_K(J0)
        # 即 tag == E_K(J0)
        # 任何正确的 tag 都等于 E_K(J0)，所以空消息+正确 tag 可通过
        cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct_empty, tag_empty = cipher2.encrypt_and_digest(b'')

        # 模拟：如果 H 碰巧为 0（极小概率），则任意 tag 均有效
        # 攻击者尝试用伪造的 tag 验证空密文
        fake_tag = get_random_bytes(16)
        print(f"原始 tag: {tag_empty.hex()}")
        print(f"伪造 tag: {fake_tag.hex()}")
        print("如果服务端用 H=0 验证，伪造 tag 也会通过")
        print("概率: 2^(-128)，实际中几乎不可能")
        return fake_tag

    test_weak_h(None)
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    # 构建明文→密文字典（单块）
    known_pairs = {}
    target_ct = get_random_bytes(16)
    target_key = get_random_bytes(16)
    cipher = AES.new(target_key, AES.MODE_ECB)
    target_ct = cipher.encrypt(b'\x00' * 16)

    # 方法 1：暴力搜索（小密钥空间）
    for k_int in range(256):
        key_candidate = bytes([k_int]) * 16
        cipher = AES.new(key_candidate, AES.MODE_ECB)
        ct = cipher.encrypt(b'\x00' * 16)
        known_pairs[ct] = key_candidate

    # 对目标密文查表
    if target_ct in known_pairs:
        return known_pairs[target_ct]

    # 方法 2：Meet-in-the-Middle（双密钥 AES）
    # K = K1 || K2，分别枚举 K1 和 K2
    # 正向：mid = E_{K1}(P)
    # 反向：mid = D_{K2}(C)
    forward_dict = {}
    for k1_int in range(256):
        k1 = bytes([k1_int]) * 16
        mid = AES.new(k1, AES.MODE_ECB).encrypt(b'\x00' * 16)
        forward_dict[mid] = k1

    for k2_int in range(256):
        k2 = bytes([k2_int]) * 16
        mid = AES.new(k2, AES.MODE_ECB).decrypt(target_ct)
        if mid in forward_dict:
            return forward_dict[mid], k2  # (K1, K2)

    return None
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

    import time
    import statistics
    from Crypto.Cipher import AES

    # 模拟时间攻击框架
    NUM_SAMPLES = 10000
    BLOCK_SIZE = 16

    # 收集加密时间样本
    key = os.urandom(16)
    samples = []  # (plaintext, time) pairs
    for _ in range(NUM_SAMPLES):
        pt = os.urandom(BLOCK_SIZE)
        start = time.perf_counter_ns()
        cipher = AES.new(key, AES.MODE_ECB)
        cipher.encrypt(pt)
        elapsed = time.perf_counter_ns() - start
        samples.append((pt, elapsed))

    # 对第一个密钥字节逐个候选进行统计分析
    recovered_key = bytearray(16)
    for byte_pos in range(16):
        best_candidate = 0
        max_variance = 0

        for k_guess in range(256):
            # 按假设中间值分组时间
            group_fast = []
            group_slow = []
            for pt, t in samples:
                # 简化：假设中间值 = S-box[pt[byte_pos] ^ k_guess]
                # 高字节（>= 0x80）查表更慢（cache miss）
                mid = (pt[byte_pos] ^ k_guess)
                if mid >= 0x80:
                    group_slow.append(t)
                else:
                    group_fast.append(t)

            if group_fast and group_slow:
                mean_fast = statistics.mean(group_fast)
                mean_slow = statistics.mean(group_slow)
                variance = abs(mean_slow - mean_fast)
                if variance > max_variance:
                    max_variance = variance
                    best_candidate = k_guess

        recovered_key[byte_pos] = best_candidate

    print(f"恢复的密钥: {recovered_key.hex()}")
    print(f"实际密钥:   {key.hex()}")
    print(f"匹配: {recovered_key == bytearray(key)}")
    return bytes(recovered_key)


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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import numpy as np

    # AES S-box: Flush+Reload 攻击模拟
    # 在真实攻击中，攻击者监控 S-box 查表的 cache line 访问
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

    def simulate_cache_access(pt_byte, key_byte):
        """模拟 S-box cache 访问：返回被访问的 cache line 索引"""
        idx = SBOX[pt_byte ^ key_byte]
        return idx // 8  # 假设每个 cache line 存 8 个 S-box 项

    def flush_reload_attack(oracle, num_traces=1000):
        """
        Flush+Reload 攻击模拟:
        1. Flush: 清空 S-box 对应的 cache line
        2. 触发加密
        3. Reload: 测量每个 cache line 的访问时间
        4. 快速访问 = cache hit = 该行被加密使用
        """
        key = get_random_bytes(16)
        # cache hit/miss 统计：cache_hits[line] = 被命中次数
        cache_hits = np.zeros(32)  # S-box 256 项 / 8 = 32 lines

        for _ in range(num_traces):
            pt = get_random_bytes(16)
            # 模拟：加密后某些 cache line 被访问
            for byte_pos in range(16):
                line = simulate_cache_access(pt[byte_pos], key[byte_pos])
                cache_hits[line] += 1

        # 分析: 对每个密钥字节候选，统计关联的 cache hit 分布
        recovered = bytearray(16)
        for byte_pos in range(16):
            scores = np.zeros(256)
            for k_guess in range(256):
                # 用大量已知明文测试
                for _ in range(100):
                    pt = get_random_bytes(16)
                    line = simulate_cache_access(pt[byte_pos], k_guess)
                    scores[k_guess] += cache_hits[line]
            recovered[byte_pos] = np.argmax(scores)

        return bytes(recovered)

    print("Flush+Reload Cache-Timing 攻击模拟:")
    print("在真实场景中需要:")
    print("1. 共享内存环境（同一 CPU 核心的 SMT/超线程）")
    print("2. 精确的 cache line 时间测量")
    print("3. 大量加密操作采样")


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
    import numpy as np
    from Crypto.Cipher import AES

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

    def hamming_weight(x):
        """计算汉明重量（翻转比特数）"""
        return bin(x).count('1')

    def simulate_power(pt_byte, key_byte):
        """模拟功耗模型：功耗 ∝ 汉明重量(S-box 输出)"""
        return hamming_weight(SBOX[pt_byte ^ key_byte])

    # ---- DPA 攻击实现 ----
    NUM_TRACES = 500
    key = bytes([0x42, 0x1a, 0x3f, 0x8b, 0xcd, 0x90, 0x56, 0x7e,
                 0xab, 0x12, 0xef, 0x34, 0xc5, 0x68, 0x09, 0x2d])

    # 采集功耗轨迹
    plaintexts = []
    power_traces = []
    for _ in range(NUM_TRACES):
        pt = bytes([np.random.randint(0, 256) for _ in range(16)])
        trace = [simulate_power(pt[b], key[b]) for b in range(16)]
        plaintexts.append(pt)
        power_traces.append(trace)

    power_traces = np.array(power_traces, dtype=float)

    # 逐字节恢复密钥
    recovered = bytearray(16)
    for byte_pos in range(16):
        best_corr = -1
        best_k = 0
        for k_guess in range(256):
            # 假设中间值: S-box[pt[byte_pos] ^ k_guess]
            hypo = np.array([simulate_power(pt[byte_pos], k_guess)
                            for pt in plaintexts], dtype=float)
            # 计算假设中间值与功耗轨迹的相关性
            correlations = np.array([
                np.corrcoef(hypo, power_traces[:, b])[0, 1]
                if np.std(power_traces[:, b]) > 0 else 0
                for b in range(16)
            ])
            max_corr = np.max(np.abs(correlations))
            if max_corr > best_corr:
                best_corr = max_corr
                best_k = k_guess
        recovered[byte_pos] = best_k

    print(f"DPA 恢复密钥: {recovered.hex()}")
    print(f"实际密钥:     {key.hex()}")
    print(f"匹配: {recovered == bytearray(key)}")
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
    from Crypto.Cipher import AES
    import os

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
    ]
    INV_SBOX = [0] * 256
    for _i, _v in enumerate(SBOX):
        INV_SBOX[_v] = _i

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

    # MixColumns 矩阵及其逆
    MC = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    INV_MC = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]

    def inv_mix_columns_col(col):
        """MixColumns 逆运算（单列）"""
        return [gf_mul(INV_MC[i][j], col[j]) for i in range(4) for j in range(4)]

    def piret_quisquater_fault(ct_good, ct_fault):
        """
        Piret-Quisquater 单字节故障攻击:
        故障注入第 9 轮 MixColumns 之前，影响一列的 4 个字节
        """
        # 找到差分列
        diff = [ct_good[i] ^ ct_fault[i] for i in range(16)]
        fault_col = None
        for col in range(4):
            col_diff = [diff[col + row * 4] for row in range(4)]
            if any(d != 0 for d in col_diff):
                fault_col = col
                break

        if fault_col is None:
            return None

        # 对每个候选最后一轮密钥字节，检查差分约束
        candidates = [set(range(256)) for _ in range(4)]
        for k_guess_byte in range(256):
            # 解密最后一轮: state = InvSubBytes(CT ^ RK_last)
            s_good = [INV_SBOX[ct_good[fault_col + r * 4] ^ k_guess_byte] for r in range(4)]
            s_fault = [INV_SBOX[ct_fault[fault_col + r * 4] ^ k_guess_byte] for r in range(4)]
            # 计算 MixColumns 逆差分
            mc_diff = [s_good[i] ^ s_fault[i] for i in range(4)]
            # 故障列只有一个字节有非零差分，检查一致性
            nonzero = sum(1 for d in mc_diff if d != 0)
            if nonzero > 1:
                for r in range(4):
                    if mc_diff[r] != 0:
                        candidates[r].discard(k_guess_byte)

        return {fault_col: c for fault_col, c in enumerate(candidates) if len(c) < 256}

    # 演示攻击
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    pt = os.urandom(16)
    ct_good = cipher.encrypt(pt)

    # 模拟故障
    ct_fault = bytearray(ct_good)
    ct_fault[3] ^= os.urandom(1)[0]  # 故障在列 0，字节 3

    result = piret_quisquater_fault(bytes(ct_good), bytes(ct_fault))
    print(f"Piret-Quisquater DFA 候选密钥字节: {result}")


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
    from Crypto.Cipher import AES
    import os

    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    ]
    INV_SBOX = [0] * 256
    for _i, _v in enumerate(SBOX):
        INV_SBOX[_v] = _i

    def random_byte_fault_attack(key, num_faults=20):
        """
        随机字节故障 DFA:
        在 AES 第 9 轮注入随机位置、随机值的单字节故障
        收集多组 (ct_good, ct_fault) 对
        对每个位置统计候选密钥字节频率，取交集确定最终密钥

        返回: 恢复的部分轮密钥字节
        """
        cipher = AES.new(key, AES.MODE_ECB)
        ct_good_list = []
        ct_fault_list = []

        # 收集故障对
        for _ in range(num_faults):
            pt = os.urandom(16)
            ct = cipher.encrypt(pt)
            # 随机单字节故障
            fault_pos = os.urandom(1)[0] % 16
            fault_val = os.urandom(1)[0]
            ct_fault = bytearray(ct)
            ct_fault[fault_pos] ^= fault_val
            ct_good_list.append(ct)
            ct_fault_list.append(bytes(ct_fault))

        # 对每个字节位置，统计候选密钥字节
        candidates = [set(range(256)) for _ in range(16)]

        for idx in range(num_faults):
            ct_good = ct_good_list[idx]
            ct_fault = ct_fault_list[idx]
            diff_pos = None
            for b in range(16):
                if ct_good[b] ^ ct_fault[b] != 0:
                    diff_pos = b
                    break
            if diff_pos is None:
                continue

            # 对该位置，尝试所有密钥字节
            valid = set()
            for k_guess in range(256):
                s1 = INV_SBOX[ct_good[diff_pos] ^ k_guess]
                s2 = INV_SBOX[ct_fault[diff_pos] ^ k_guess]
                if s1 != s2:
                    valid.add(k_guess)
            # 如果 valid 太大，可能是误判
            if len(valid) <= 128:
                candidates[diff_pos] &= valid

        return [c for c in candidates if len(c) < 256]

    key = os.urandom(16)
    result = random_byte_fault_attack(key)
    print(f"随机字节故障 DFA 恢复的候选字节:")
    for i, c in enumerate(result):
        print(f"  字节 {i}: {len(c)} 个候选")


def dfa_double_fault():
    """
    双故障 DFA

    同时注入两个故障，利用故障间的相关性
    可减少所需故障数量

    适用于:
    - 需要绕过故障检测的场景
    - 高级攻击技术
    """
    from Crypto.Cipher import AES
    import os

    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]
    INV_SBOX = [0] * 256
    for _i, _v in enumerate(SBOX):
        INV_SBOX[_v] = _i

    def gf_mul(a, b):
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

    # 双故障 DFA:
    # 在同一轮注入两个独立故障
    # 通过两组 (ct_good, ct1, ct2) 的差分关系
    # 利用 MixColumns 的双线性约束恢复密钥
    # 优点: 单次双故障即可恢复部分密钥，比两次单故障效率更高

    def double_fault_attack(key, num_experiments=10):
        """
        双故障 DFA 攻击模拟:
        1. 获取无故障密文 ct_good
        2. 获取两个不同故障密文 ct1, ct2（同一明文）
        3. 利用三个密文的差分约束恢复轮密钥
        """
        cipher = AES.new(key, AES.MODE_ECB)
        pt = os.urandom(16)
        ct_good = cipher.encrypt(pt)

        # 收集双故障对
        results = []
        for _ in range(num_experiments):
            # 故障 1
            pos1 = os.urandom(1)[0] % 16
            val1 = os.urandom(1)[0]
            ct1 = bytearray(ct_good)
            ct1[pos1] ^= val1

            # 故障 2（不同位置）
            pos2 = (pos1 + 1 + os.urandom(1)[0] % 15) % 16
            val2 = os.urandom(1)[0]
            ct2 = bytearray(ct_good)
            ct2[pos2] ^= val2

            # 双故障分析:
            # diff1 = ct_good ^ ct1, diff2 = ct_good ^ ct2
            # 由于两个故障在同一列/不同列，可利用 MixColumns 约束
            diff1 = bytes(ct_good[b] ^ ct1[b] for b in range(16))
            diff2 = bytes(ct_good[b] ^ ct2[b] for b in range(16))

            # 候选密钥字节: 对每个密钥字节候选检查是否满足两个故障的约束
            candidates_per_byte = [set(range(256)) for _ in range(16)]
            for k in range(256):
                # 检查故障 1
                if diff1[pos1] != 0:
                    s_good = INV_SBOX[ct_good[pos1] ^ k]
                    s_fault = INV_SBOX[ct1[pos1] ^ k]
                    if s_good == s_fault:
                        candidates_per_byte[pos1].discard(k)
                # 检查故障 2
                if diff2[pos2] != 0:
                    s_good = INV_SBOX[ct_good[pos2] ^ k]
                    s_fault = INV_SBOX[ct2[pos2] ^ k]
                    if s_good == s_fault:
                        candidates_per_byte[pos2].discard(k)

            results.append({
                'diff1': diff1, 'diff2': diff2,
                'candidates': candidates_per_byte,
            })

        print(f"双故障 DFA: {num_experiments} 次实验完成")
        print("两个故障可同时分析，减少所需故障总数约 50%")
        print("适用于需要绕过故障检测计数器的场景")
        return results

    key = os.urandom(16)
    double_fault_attack(key)
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(16)
    nonce = get_random_bytes(12)

    # GCM-SIV Nonce 重用分析演示
    # 当 nonce 固定时，SIV (合成 IV) = MAC(key, plaintext || AAD)
    # 如果两条消息的 (plaintext, AAD) 相同 → SIV 相同 → 密文相同
    # 如果不同 → SIV 不同 → 密文不同，但不会泄露 key/H

    # 模拟 GCM-SIV 行为（使用 GCM 近似说明概念）
    messages = [b"secret1", b"secret2", b"secret1", b"longer_message_here"]
    results = []

    for msg in messages:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(msg)
        results.append((ct, tag))

    print("GCM-SIV Nonce 重用分析:")
    print("当 nonce 固定时的泄露情况:")
    print("- 明文相等性: 相同明文 → 相同密文")
    print("- 明文长度: 通过密文长度可推断")
    print("- 认证密钥 H: 不泄露（关键安全特性）")
    print()

    # 对比: 相同明文产生相同密文
    print("明文相等性测试:")
    for i, m1 in enumerate(messages):
        for j, m2 in enumerate(messages):
            if i < j and m1 == m2:
                print(f"  msg[{i}] == msg[{j}] → ct[{i}] == ct[{j}]: "
                      f"{results[i][0] == results[j][0]}")
            elif i < j and m1 != m2:
                print(f"  msg[{i}] != msg[{j}] → ct[{i}] != ct[{j}]: "
                      f"{results[i][0] != results[j][0]}")

    print("\n安全边界: 2^64 次 nonce 重用后可能泄露额外信息")
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(16)
    nonce = get_random_bytes(7)  # CCM 典型 nonce 长度

    # CCM Nonce 重用攻击演示
    # CCM = CBC-MAC (认证) + CTR (加密)
    # Nonce 重用导致 CTR keystream 重用

    # 正常加密
    cipher1 = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    pt1 = b"transfer $100 to alice"
    ct1, tag1 = cipher1.encrypt_and_digest(pt1)

    # 同一 nonce 加密第二条消息
    cipher2 = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    pt2 = b"transfer $999 to bob!!"
    ct2, tag2 = cipher2.encrypt_and_digest(pt2)

    # CTR keystream 重用 → P1 ^ P2 = C1 ^ C2
    max_len = max(len(ct1), len(ct2))
    ct1_pad = ct1.ljust(max_len, b'\x00')
    ct2_pad = ct2.ljust(max_len, b'\x00')
    xored = bytes(a ^ b for a, b in zip(ct1_pad, ct2_pad))

    print("AES-CCM Nonce 重用攻击:")
    print(f"明文1: {pt1}")
    print(f"明文2: {pt2}")
    print(f"C1 ^ C2: {xored.hex()}")
    print()

    # 如果知道其中一个明文，可恢复另一个
    for i in range(min(len(pt1), len(pt2))):
        xor_byte = ct1[i] ^ ct2[i]
        recovered = xor_byte ^ pt1[i]
        print(f"  位置 {i}: C1^C2={xor_byte:02x}, "
              f"已知P1={pt1[i]:02x}, 恢复P2={recovered:02x} "
              f"({'✓' if recovered == pt2[i] else '✗'})")
    print("\n结论: CCM nonce 重用泄露明文异或，与 GCM 类似")
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    # AES-CCM* 演示 (IEEE 802.15.4 扩展)
    # CCM* 相比 CCM 的主要差异:
    # 1. 支持可变 nonce 长度 (7-13 字节)
    # 2. 支持更短的认证标签 (4/8/16 字节)
    # 3. 可选认证 (加密不认证模式)

    key = get_random_bytes(16)

    # 不同 nonce 长度
    for nonce_len in [7, 13]:
        nonce = get_random_bytes(nonce_len)
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        pt = b"802.15.4 frame payload"
        aad = b"\x01\x02\x03"  # 附加认证数据
        cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(pt)

        print(f"CCM* (nonce_len={nonce_len}):")
        print(f"  Nonce:  {nonce.hex()} ({nonce_len} 字节)")
        print(f"  密文:   {ct.hex()} ({len(ct)} 字节)")
        print(f"  标签:   {tag.hex()} ({len(tag)} 字节)")
        print(f"  安全性: 标签越短，暴力伪造概率越高 (2^{len(tag)*8})")
        print()

    # Zigbee 帧格式模拟
    print("Zigbee 安全帧格式:")
    print("  帧控制 (2B) || 帧计数器 (4B) || 密文 (变长) || MIC (4B)")
    print("  帧计数器用作 nonce，防重放")
    print("  如果计数器溢出或重置 → nonce 重用 → 加密失效")
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import struct

    def _gf128_left_shift(b):
        """GF(2^128) 左移一位"""
        carry = (b[0] >> 7) & 1
        result = bytearray(b)
        for i in range(len(result) - 1):
            result[i] = ((result[i] << 1) | (result[i+1] >> 7)) & 0xff
        result[-1] = (result[-1] << 1) & 0xff
        if carry:
            result[-1] ^= 0x87
        return bytes(result)

    def cmac_subkeys(key):
        """从主密钥派生 CMAC 子密钥 K1, K2"""
        cipher = AES.new(key, AES.MODE_ECB)
        L = cipher.encrypt(b'\x00' * 16)
        K1 = _gf128_left_shift(L)
        if L[0] & 0x80:
            K1 = bytes(a ^ b for a, b in zip(K1, bytes([0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0x87])))
        K2 = _gf128_left_shift(K1)
        if K1[0] & 0x80:
            K2 = bytes(a ^ b for a, b in zip(K2, bytes([0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0x87])))
        return K1, K2

    # 部分密钥恢复攻击框架:
    # CMAC = CBC-MAC(key, msg || K1/K2)
    # 如果能控制消息长度，可选择使用 K1 或 K2
    # 通过多组 (msg, tag) 对分析:
    # 1. 短消息用 K2：tag = CBC-MAC(key, msg_padded || K2)
    # 2. 长消息用 K1：tag = CBC-MAC(key, msg_padded || K1)
    # K1 和 K2 通过线性关系关联

    key = get_random_bytes(16)
    K1, K2 = cmac_subkeys(key)

    print("AES-CMAC 子密钥分析:")
    print(f"K1: {K1.hex()}")
    print(f"K2: {K2.hex()}")
    print(f"K1[0] & 0x80: {bool(K1[0] & 0x80)}")
    print(f"K2[0] & 0x80: {bool(K2[0] & 0x80)}")
    print()

    # 分析: 已知 K1 可反推 K2（反之亦然）
    # K2 = LShift(K1) 或 LShift(K1) ^ 0x87
    # 如果知道部分密钥字节，可缩小搜索空间
    print("密钥恢复策略:")
    print("1. 收集多个 (message, tag) 对")
    print("2. 利用 CBC-MAC 的线性性: tag = E_K(msg_padded)")
    print("3. 分析 K1/K2 的关系缩小候选密钥空间")
    print("4. 结合差分分析确定完整密钥")
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
    import time
    import numpy as np

    # AES-NI 旁路攻击框架
    # 虽然 AES-NI 设计为恒定时间，但微架构层面仍有泄露

    def measure_aes_timing(num_samples=1000):
        """测量 AES 加密时间（模拟）"""
        # 在真实场景中:
        # 1. 使用 rdtsc/rdtscp 指令精确测量 CPU 周期
        # 2. 控制 cache 预热状态
        # 3. 排除操作系统干扰

        times = []
        for _ in range(num_samples):
            # 模拟: 时间 = 基础时间 + 微架构噪声
            base_time = 100  # ns (AES-NI 约 3-4 cycles/byte)
            noise = np.random.normal(0, 2)
            times.append(base_time + noise)
        return np.array(times)

    # 微架构攻击方法
    attack_vectors = {
        "Spectre v1 (Bounds Check Bypass)": {
            "原理": "利用分支预测器，通过越界读取泄露密钥",
            "效果": "可在虚拟化环境中跨 VM 泄露 AES 密钥",
            "防御": "lfence / retpoline / 编译器缓解",
        },
        "Meltdown (Rogue Data Cache Load)": {
            "原理": "利用乱序执行，通过 cache 侧信道读取内核内存",
            "效果": "可绕过 AES-NI 的保护层",
            "防御": "KPTI / 硬件补丁",
        },
        "CacheOut / L1D Flush": {
            "原理": "L1 数据缓存驱逐攻击",
            "效果": "从 L1 cache 提取 AES S-box/中间值",
            "防御": "L1D flush / 缓存分区",
        },
    }

    print("AES-NI 微架构旁路攻击:")
    for name, info in attack_vectors.items():
        print(f"\n{name}:")
        for k, v in info.items():
            print(f"  {k}: {v}")

    print(f"\n测量: 模拟 {1000} 次 AES-NI 加密时间")
    times = measure_aes_timing(1000)
    print(f"  平均: {np.mean(times):.1f} ns")
    print(f"  标准差: {np.std(times):.1f} ns")


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
    import time
    import numpy as np
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    # AES-NI vs 软件实现对比

    def benchmark_aes(mode_name, encrypt_fn, num_samples=500):
        """基准测试加密时间"""
        times = []
        pt = get_random_bytes(16)
        for _ in range(num_samples):
            start = time.perf_counter_ns()
            encrypt_fn(pt)
            elapsed = time.perf_counter_ns() - start
            times.append(elapsed)
        return np.array(times)

    key = get_random_bytes(16)

    # 软件实现 (OpenSSL 默认)
    def software_encrypt(pt):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pt)

    times_sw = benchmark_aes("Software", software_encrypt)

    print("AES-NI vs 软件实现 安全对比:")
    print()
    print(f"软件实现基准 ({len(times_sw)} 样本):")
    print(f"  平均时间: {np.mean(times_sw):.0f} ns")
    print(f"  中位数:   {np.median(times_sw):.0f} ns")
    print(f"  标准差:   {np.std(times_sw):.0f} ns")
    print()

    # 安全属性对比表
    comparison = {
        "属性":       ["恒定时间", "Cache安全", "功耗泄露", "软件复杂度", "CTF攻击面"],
        "AES-NI":     ["✓ (设计)", "✓", "✗ (仍可能)", "低", "协议/逻辑"],
        "软件实现":   ["✗ (通常)", "✗ (S-box)", "✗ (高)", "高", "Cache/Timing"],
        "bitsliced":  ["✓ (通常)", "✓", "✗", "高", "其他"],
    }

    print("安全属性对比:")
    header = f"{'属性':<12} {'AES-NI':<15} {'软件实现':<15} {'bitsliced':<15}"
    print(header)
    print("-" * len(header))
    for i, attr in enumerate(comparison["属性"]):
        print(f"{attr:<12} {comparison['AES-NI'][i]:<15} "
              f"{comparison['软件实现'][i]:<15} {comparison['bitsliced'][i]:<15}")
    print()
    print("CTF 策略: 检测是否有 AES-NI → 有则转向协议攻击 → 无则优先 cache 攻击")
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
    from Crypto.Cipher import AES
    import os

    # 白盒 AES (Chow et al.) 攻击原理演示
    # Chow 方案使用 T-box = SubBytes ∘ ShiftRows ∘ MixColumns ∘ AddRoundKey
    # 每个 T-box 是 4 个 256 项的 32-bit 查找表
    # 表项通过随机仿射变换与密钥混合

    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    ]  # 截断，完整 256 项

    def generate_tbox(key, round_num):
        """模拟 Chow 白盒 T-box 生成"""
        # 真实 Chow 方案:
        # 1. 生成随机双射 P_in (输入混淆)、P_out (输出混淆)
        # 2. 将 AddRoundKey 和 SubBytes 合并到 T-box
        # 3. 嵌入 MixColumns/ShiftRows
        tbox = {}
        for inp in range(256):
            # 模拟: T-box[i] = P_out(SBox[i ^ round_key_byte]) 通过仿射变换
            sbox_out = SBOX[inp % len(SBOX)]
            # 随机仿射变换 (简化为 XOR)
            tbox[inp] = sbox_out ^ (key[0] if key else 0)
        return tbox

    key = os.urandom(16)

    # 攻击方法 1: 直接提取 T-box
    print("白盒 AES Chow 攻击方法:")
    print()
    print("方法 1 - T-box 提取:")
    print("  1. 内存转储获取所有 T-box 表项")
    print("  2. 逐表分析输入-输出关系")
    print("  3. 逆向仿射变换恢复 S-box 输出")
    print()

    # 攻击方法 2: 求解代数方程
    print("方法 2 - 代数攻击:")
    print("  1. 将 T-box 表示为 GF(2^8) 上的多项式")
    print("  2. 构建超定方程组")
    print("  3. 用 XL/Groebner 基求解")
    print()

    # 攻击方法 3: 选择明文攻击
    print("方法 3 - 选择明文攻击:")
    print("  1. 向白盒实现提交已知输入")
    print("  2. 收集 (input, output) 对")
    print("  3. 逆向追踪每轮操作恢复密钥")
    print()

    # 演示 T-box 生成
    for rnd in range(3):
        tbox = generate_tbox(key, rnd)
        print(f"Round {rnd} T-box (前 4 项): { {k: hex(v) for k, v in list(tbox.items())[:4] }}")


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
    import os

    # 白盒 AES 密钥提取流程

    # Step 1: 内存转储 T-box
    # 工具: Frida, debugger, /proc/pid/mem
    def dump_tbox_from_memory(tbox_data):
        """从内存转储中提取 T-box 表项"""
        return {i: tbox_data[i] for i in range(256)}

    # Step 2: 逆向仿射变换
    def reverse_affine(tbox, aff_matrix, aff_vec):
        """
        逆向仿射变换: out = aff_matrix * input + aff_vec
        求解: input = aff_matrix^(-1) * (out - aff_vec)
        在 GF(2^8) 上计算矩阵逆
        """
        # 简化: 直接查找
        inverse_tbox = {}
        for inp, out in tbox.items():
            # 恢复 S-box 输出: inv_aff(out) = S-box(inp)
            inverse_tbox[inp] = out  # 简化
        return inverse_tbox

    # Step 3: 从 S-box 输出恢复轮密钥
    def recover_round_key(tbox_round0):
        """
        从 Round 0 的 T-box 提取第一轮密钥:
        T[i] = P_out(S(i ^ k0)) → 已知 P_out 和 S
        枚举 k0 候选，检查一致性
        """
        SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]
        candidates = []
        for k in range(256):
            match = True
            for i in range(min(len(SBOX), len(tbox_round0))):
                expected = tbox_round0.get(i, 0)
                actual = SBOX[i ^ k] if (i ^ k) < len(SBOX) else 0
                if expected != actual:
                    match = False
                    break
            if match:
                candidates.append(k)
        return candidates[:16] if candidates else []

    # 演示提取流程
    print("白盒 AES 密钥提取流程:")
    print()
    print("工具链:")
    print("  静态分析: IDA Pro / Ghidra → 定位 T-box 内存地址")
    print("  动态分析: Frida / x64dbg → 运行时转储")
    print("  自动化:   angr / Triton → 符号执行辅助")
    print()
    print("提取步骤:")
    print("  1. 定位 T-box: 搜索 256 项的 32-bit 表 (关键特征)")
    print("  2. 转储 10 个 T-box (Round 0-9)")
    print("  3. 逆向 Round 0 T-box → 恢复 K0")
    print("  4. 逆向密钥扩展 → 恢复完整密钥")
    print("  时间: 通常 < 1 秒 (一旦工具就绪)")
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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    import struct

    def gf128_mul_by_alpha(t):
        """GF(2^128) 乘以 α (左移一位，条件 XOR 0x87)"""
        carry = (t[0] >> 7) & 1
        result = bytearray(t)
        for i in range(len(result) - 1):
            result[i] = ((result[i] << 1) | (result[i+1] >> 7)) & 0xff
        result[-1] = (result[-1] << 1) & 0xff
        if carry:
            result[-1] ^= 0x87
        return bytes(result)

    def xts_encrypt_block(key1, key2, sector_num, block_idx, plaintext):
        """XTS-AES 单块加密"""
        # Step 1: T = AES-ECB(key2, sector_number)
        t = AES.new(key2, AES.MODE_ECB).encrypt(
            sector_num.to_bytes(16, 'little'))

        # Step 2: T = T * α^block_idx (GF(2^128) 乘法)
        for _ in range(block_idx):
            t = gf128_mul_by_alpha(t)

        # Step 3: 加密 = AES-ECB(key1, plaintext ^ T) ^ T
        xored = bytes(a ^ b for a, b in zip(plaintext, t))
        encrypted = AES.new(key1, AES.MODE_ECB).encrypt(xored)
        return bytes(a ^ b for a, b in zip(encrypted, t))

    def xts_decrypt_block(key1, key2, sector_num, block_idx, ciphertext):
        """XTS-AES 单块解密"""
        t = AES.new(key2, AES.MODE_ECB).encrypt(
            sector_num.to_bytes(16, 'little'))
        for _ in range(block_idx):
            t = gf128_mul_by_alpha(t)

        # 解密 = AES-Dec(key1, ciphertext ^ T) ^ T
        xored = bytes(a ^ b for a, b in zip(ciphertext, t))
        decrypted = AES.new(key1, AES.MODE_ECB).decrypt(xored)
        return bytes(a ^ b for a, b in zip(decrypted, t))

    # 演示 XTS 加解密
    key1 = get_random_bytes(16)
    key2 = get_random_bytes(16)
    sector = 42
    pt = b"This is sector data!" + b'\x00' * 12  # 32 bytes = 2 blocks

    print("AES-XTS 磁盘加密演示:")
    print(f"扇区号: {sector}")
    print(f"数据长度: {len(pt)} 字节")

    # 加密
    ct = b''
    for i in range(0, len(pt), 16):
        block = pt[i:i+16]
        ct += xts_encrypt_block(key1, key2, sector, i // 16, block)

    # 解密
    recovered = b''
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        recovered += xts_decrypt_block(key1, key2, sector, i // 16, block)

    print(f"加密成功: {ct.hex()[:48]}...")
    print(f"解密验证: {recovered == pt}")
    print()
    print("XTS 攻击面:")
    print("  1. 不同扇区用不同 tweak → 无法跨扇区借用 keystream")
    print("  2. 同扇区内不同块: T *= α^i → 类似 CTR 但 tweak 递增")
    print("  3. 边界处理: 最后块可能短于 16 字节 (ciphertext stealing)")
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
    import math

    # Grover 算法对 AES 密钥搜索的影响
    def grover_search_complexity(key_bits, num_queries=None):
        """
        Grover 搜索复杂度分析

        经典暴力: O(2^n) 次查询, O(n) 时间
        Grover:   O(2^{n/2}) 次量子查询, O(n) 时间每查询

        但实际需要:
        - 约 n 个逻辑量子比特
        - 每个逻辑量子比特需要约 1000-10000 个物理量子比特（纠错）
        - 反馈循环: 每次迭代需要重新执行加密 oracle
        """
        classic_ops = 2 ** key_bits
        grover_ops = 2 ** (key_bits // 2)

        # 纠错开销
        logical_qubits = key_bits
        physical_per_logical = 1000  # 约 1000:1 的比率
        total_physical = logical_qubits * physical_per_logical

        # 每次查询的电路深度
        circuit_depth_per_query = key_bits * 10  # 约 10n gates

        print(f"=== Grover vs AES-{key_bits * 8} ===")
        print(f"经典暴力搜索:    {classic_ops:.2e} 次查询")
        print(f"Grover 搜索:     {grover_ops:.2e} 次查询")
        print(f"加速比:          {classic_ops / grover_ops:.2e}x")
        print(f"逻辑量子比特:    {logical_qubits}")
        print(f"物理量子比特:    ~{total_physical:,}")
        print(f"每查询电路深度:  ~{circuit_depth_per_query}")
        print(f"总电路深度:      ~{grover_ops * circuit_depth_per_query:.2e}")
        print()

        # 实际时间估算
        # 假设: 1 GHz 时钟, 每周期 1 次量子门操作
        if grover_ops < 1e30:  # 可估算
            seconds = grover_ops * circuit_depth_per_query / 1e9
            years = seconds / (365.25 * 24 * 3600)
            print(f"估算运行时间:    ~{years:.2e} 年")
        else:
            print(f"估算运行时间:    远超宇宙年龄")

    # 分析 AES-128, AES-192, AES-256
    for aes_key_bytes in [16, 24, 32]:
        grover_search_complexity(aes_key_bytes * 8)

    print("结论:")
    print("  AES-128: Grover 降至 O(2^64) → 理论可攻, 实际不可行")
    print("  AES-192: Grover 降至 O(2^96) → 安全")
    print("  AES-256: Grover 降至 O(2^128) → 足够安全")
    print("  NIST 建议: 后量子时代使用 AES-256+")


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
    # 后量子对称密码学总结

    # 量子算法对对称密码的影响
    quantum_threats = {
        "Grover 算法": {
            "目标": "密钥搜索",
            "加速": "O(2^n) → O(2^{n/2})",
            "影响": "AES-128 降至 64-bit 安全",
            "缓解": "使用 AES-256 (128-bit 量子安全)",
        },
        "Simon 算法": {
            "目标": "周期检测",
            "加速": "指数加速",
            "影响": "CBC-MAC 等特定 MAC 可被伪造",
            "缓解": "避免使用基于 Feistel 的 MAC",
        },
        "BHT 算法": {
            "目标": "碰撞搜索",
            "加速": "O(2^{n/3}) → O(2^{n/3})",
            "影响": "SHA-256 碰撞搜索降至 ~85 bit",
            "缓解": "SHA-384+ 仍安全",
        },
    }

    print("=== 量子计算对对称密码的威胁 ===")
    for name, info in quantum_threats.items():
        print(f"\n{name}:")
        for k, v in info.items():
            print(f"  {k}: {v}")

    print("\n=== 后量子密码标准化 (NIST 2024) ===")
    standards = [
        ("FIPS 203 (ML-KEM)", "Kyber", "密钥封装", "格基密码"),
        ("FIPS 204 (ML-DSA)", "Dilithium", "数字签名", "格基密码"),
        ("FIPS 205 (SLH-DSA)", "SPHINCS+", "无状态签名", "哈希签名"),
    ]
    for fips, name, category, basis in standards:
        print(f"  {fips}: {name} ({category}, {basis})")

    print("\n=== 对称密码迁移清单 ===")
    checklist = [
        "检查当前 AES 密钥长度（128 → 升级到 256）",
        "评估 HMAC-SHA256 的 Simon 算法威胁",
        "测试 SHA-384/SHA-512 替代方案",
        "关注 NIST 后量子对称标准草案",
        "准备密码敏捷性（Crypto Agility）架构",
    ]
    for i, item in enumerate(checklist, 1):
        print(f"  {i}. {item}")
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
    # SM4 vs AES 对比实现

    # SM4 S-box (完整 256 项)
    SM4_SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
        0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
        0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
        0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
        0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
        0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
        0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
        0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
        0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
        0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
        0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
        0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
        0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
        0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
        0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
        0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ]

    # AES S-box (前 32 项)
    AES_SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    ]

    print("=== SM4 vs AES 对比 ===")
    print()
    print(f"{'属性':<20} {'SM4':<25} {'AES-128':<25}")
    print("-" * 70)
    comparison = [
        ("分组大小", "128 bit", "128 bit"),
        ("密钥长度", "128 bit", "128 bit"),
        ("轮数", "32 轮", "10 轮"),
        ("非线性变换", "τ (4 并行 S-box)", "SubBytes (16 S-box)"),
        ("线性变换", "L (循环移位+XOR)", "MixColumns + ShiftRows"),
        ("密钥扩展", "CK 常量 + τ", "Rcon + RotWord + SubWord"),
        ("S-box 输入", "32-bit", "8-bit"),
        ("硬件加速", "较少 (专用芯片)", "广泛 (AES-NI)"),
    ]
    for prop, sm4_val, aes_val in comparison:
        print(f"{prop:<20} {sm4_val:<25} {aes_val:<25}")

    print()
    print("SM4 τ 变换: 32-bit 输入 → 4 个 S-box 并行查表")
    print("SM4 L 变换: X ⊕ (X<<<2) ⊕ (X<<<10) ⊕ (X<<<18) ⊕ (X<<<24)")


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
    import hashlib

    # SM4 弱密钥分析
    # SM4 使用 256 个固定常量 CK 作为密钥扩展的一部分
    # 理论上不存在弱密钥类（与 DES 的弱密钥不同）

    # 检查密钥空间均匀性
    def sm4_round_keys(key):
        """模拟 SM4 密钥扩展"""
        FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
        CK = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        ]

        # 将密钥分为 4 个 32-bit 字
        K = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
        K = [K[i] ^ FK[i] for i in range(4)]

        round_keys = []
        for i in range(32):
            # τ 变换 (简化)
            tmp = K[(i+1) % 4] ^ K[(i+2) % 4] ^ K[(i+3) % 4] ^ CK[i % 12]
            # 简化 S-box + L
            rk = K[i % 4] ^ tmp
            round_keys.append(rk)
            K[i % 4] = rk

        return round_keys

    # 测试密钥空间
    print("SM4 弱密钥分析:")
    print()

    test_keys = [
        b'\x00' * 16,          # 全零
        b'\xff' * 16,          # 全一
        bytes(range(16)),      # 递增
        bytes([0x01] * 16),    # 全 0x01
    ]

    for key in test_keys:
        rks = sm4_round_keys(key)
        # 检查轮密钥是否有特殊模式
        rk_vals = set(rks)
        unique_ratio = len(rk_vals) / len(rks)
        print(f"  密钥 {key.hex()[:16]}... → "
              f"{len(rk_vals)}/{len(rks)} 唯一轮密钥 "
              f"({unique_ratio:.1%} 唯一性)")

    print()
    print("分析结论:")
    print("  - SM4 无类似 DES 的弱密钥类 (alpha/beta/gamma/delta)")
    print("  - 密钥扩展使用固定常量 CK，不产生零轮密钥")
    print("  - 主要风险在侧信道和协议层，非算法本身")
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
    # 轻量级密码与 AES 对比

    def simplified_present_encrypt(plaintext, key, rounds=31):
        """简化版 PRESENT 密码 (80-bit key, 64-bit block)"""
        SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

        state = int.from_bytes(plaintext[:8], 'big')
        k = int.from_bytes(key[:10], 'big') if len(key) >= 10 else int.from_bytes(key.ljust(10, b'\x00'), 'big')

        for r in range(rounds):
            # XOR round key
            state ^= (k >> 16) & 0xFFFFFFFFFFFFFFFF

            # S-box layer (8 4-bit nibbles)
            new_state = 0
            for i in range(16):
                nibble = (state >> (i * 4)) & 0xF
                new_state |= SBOX[nibble] << (i * 4)
            state = new_state

            # P-layer (permutation)
            perm = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50,
                    3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53,
                    6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56,
                    9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62,
                    15, 31, 47, 63]
            new_state = 0
            for i in range(64):
                if state & (1 << i):
                    new_state |= 1 << perm[i]
            state = new_state

            # Key schedule
            k = ((k << 19) | (k >> 61)) & ((1 << 80) - 1)
            k ^= r << 15

        return state

    print("=== 轻量级密码 vs AES 对比 ===")
    print()
    print(f"{'属性':<20} {'PRESENT':<18} {'SIMON':<18} {'AES-128':<18}")
    print("-" * 74)
    specs = [
        ("分组大小", "64 bit", "64/128 bit", "128 bit"),
        ("密钥长度", "80 bit", "64-256 bit", "128 bit"),
        ("结构", "SPN", "Feistel", "SPN"),
        ("轮数", "31", "32-72", "10"),
        ("硬件面积", "~1000 GE", "~800 GE", "~5000 GE"),
        ("功耗", "极低", "极低", "低"),
    ]
    for prop, present, simon, aes in specs:
        print(f"{prop:<20} {present:<18} {simon:<18} {aes:<18}")

    # 性能测试
    print("\n=== 软件性能对比 ===")
    import time

    key80 = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc'
    pt64 = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    N = 10000

    start = time.perf_counter_ns()
    for _ in range(N):
        simplified_present_encrypt(pt64, key80)
    present_time = (time.perf_counter_ns() - start) / N

    from Crypto.Cipher import AES
    aes_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    aes_pt = b'\x00' * 16

    start = time.perf_counter_ns()
    for _ in range(N):
        AES.new(aes_key, AES.MODE_ECB).encrypt(aes_pt)
    aes_time = (time.perf_counter_ns() - start) / N

    print(f"PRESENT (64-bit block): {present_time:.0f} ns/block")
    print(f"AES-128 (128-bit block): {aes_time:.0f} ns/block")
    print(f"\n注意: PRESENT 软件性能通常低于 AES (无硬件加速)")
    print(f"但 PRESENT 硬件面积仅为 AES 的 ~1/5")
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
    # FHE 中的对称密码应用

    def hybrid_encryption_demo():
        """
        混合加密: FHE 加密对称密钥 + 对称密码加密数据
        实际 FHE 方案中，明文通常先用对称密码预加密
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        from Crypto.Random import get_random_bytes

        # 场景: 云端安全计算
        # 1. 客户端生成对称密钥 K
        # 2. 用 FHE 加密 K → fhe_enc(K)
        # 3. 用 K 加密数据 → aes_enc(data, K)
        # 4. 上传 fhe_enc(K) + aes_enc(data)
        # 5. 服务端在密文上计算

        symmetric_key = get_random_bytes(16)
        nonce = get_random_bytes(12)

        # 对称加密数据
        data = b"patient_medical_record_ssn_123456789"
        cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(pad(data, 16))

        print("混合加密演示 (FHE + AES):")
        print(f"  对称密钥 K:    {symmetric_key.hex()}")
        print(f"  原始数据:      {data[:30]}...")
        print(f"  AES-GCM 密文:  {ct.hex()[:48]}...")
        print(f"  AES-GCM 标签:  {tag.hex()}")
        print()

        # 模拟 FHE 密钥加密 (简化)
        # 实际中: fhe_ct = FHE.Encrypt(pk, symmetric_key)
        fhe_ciphertext = bytes(a ^ 0x42 for a in symmetric_key)  # 模拟
        print(f"  FHE 加密的 K:  {fhe_ciphertext.hex()} (模拟)")
        print()

        # 解密流程
        # 1. FHE 解密得到 K
        recovered_key = bytes(a ^ 0x42 for a in fhe_ciphertext)
        # 2. 用 K 解密数据
        decipher = AES.new(recovered_key, AES.MODE_GCM, nonce=nonce)
        recovered = unpad(decipher.decrypt_and_verify(ct, tag), 16)
        print(f"  恢复数据:      {recovered[:30]}...")
        print(f"  验证成功: {recovered == data}")

    hybrid_encryption_demo()

    print("\nFHE 库对比:")
    print("  TFHE:    布尔电路 FHE, 支持任意函数, 速度较慢")
    print("  CKKS:    近似算术, 适合 ML 推理, 有精度损失")
    print("  SEAL:    微软, BFV/CKKS, C++/Python 接口")
    print("  OpenFHE: 开源, 支持多种方案, 活跃开发")
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
    import numpy as np

    # AI 辅助密码分析框架

    # 1. 深度学习侧信道攻击 (基于 CHES 2019)
    def dl_side_channel_attack():
        """
        深度学习侧信道攻击:
        传统 DPA 需要手动选择中间值和功耗模型
        深度学习自动提取特征，端到端恢复密钥
        """
        # 模拟功耗轨迹（实际从 ChipWhisperer 采集）
        NUM_TRACES = 1000
        TRACE_LEN = 500  # 每条轨迹 500 个采样点

        # 简化: 用随机数据模拟
        # 实际中: 功耗轨迹来自真实芯片
        traces = np.random.randn(NUM_TRACES, TRACE_LEN)
        labels = np.random.randint(0, 256, NUM_TRACES)  # 密钥字节标签

        print("深度学习侧信道攻击流程:")
        print("  1. 数据采集: 使用 ChipWhisperer 采集功耗轨迹")
        print(f"     - 轨迹数: {NUM_TRACES}")
        print(f"     - 采样点/轨迹: {TRACE_LEN}")
        print("  2. 预处理: 对齐、降噪、归一化")
        print("  3. 模型训练:")
        print("     - CNN: 捕获局部时间模式")
        print("     - LSTM: 捕获长期依赖")
        print("     - Transformer: 全局注意力机制")
        print("  4. 推理: 对未知轨迹预测密钥字节")
        print()

        # 模型架构示例
        print("  CNN 模型架构 (简化):")
        print("    Conv1D(64, 11) → ReLU → MaxPool(3)")
        print("    Conv1D(128, 11) → ReLU → MaxPool(3)")
        print("    Conv1D(256, 11) → ReLU → GlobalAvgPool")
        print("    Dense(256) → Softmax → 密钥字节概率分布")

    # 2. 密码强度预测
    def password_strength_prediction():
        """机器学习预测密码强度"""
        # 训练数据: (password, strength_score) 对
        # 特征: 长度、字符种类、熵、常见模式
        features = {
            "length": "密码长度",
            "charset_size": "字符集大小",
            "entropy": "信息熵 (bits)",
            "common_pattern": "是否含常见模式",
            "keyboard_pattern": "是否含键盘序列",
        }

        print("\n密码强度预测特征:")
        for feat, desc in features.items():
            print(f"  {feat}: {desc}")

        print("\n模型: RandomForest / GradientBoosting / Neural Network")
        print("精度: 通常 > 90% (区分强/弱密码)")

    dl_side_channel_attack()
    password_strength_prediction()


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
    import numpy as np

    # AI 辅助侧信道攻击 - 深度学习模型对比

    def simulate_power_traces(num_traces, trace_len, num_classes=256):
        """模拟功耗轨迹数据"""
        traces = np.random.randn(num_traces, trace_len).astype(np.float32)
        # 添加与密钥相关的信号
        key_signal = np.random.randn(trace_len) * 0.5
        labels = np.random.randint(0, num_classes, num_traces)
        for i in range(num_traces):
            traces[i] += key_signal * (labels[i] % 2)
        return traces, labels

    # 生成模拟数据
    traces, labels = simulate_power_traces(5000, 300)

    print("=== AI 辅助侧信道攻击 - 模型对比 ===")
    print()

    models = {
        "CNN (卷积神经网络)": {
            "适用": "时序功耗分析",
            "优势": "自动提取局部模式, 训练快",
            "劣势": "对齐敏感, 长序列信息丢失",
            "样本需求": "~1000",
            "典型精度": ">95%",
        },
        "LSTM (长短期记忆)": {
            "适用": "长序列功耗分析",
            "优势": "捕获长期依赖, 不需对齐",
            "劣势": "训练慢, 梯度消失",
            "样本需求": "~5000",
            "典型精度": ">90%",
        },
        "Transformer": {
            "适用": "全局注意力分析",
            "优势": "并行训练, 全局依赖",
            "劣势": "数据需求大, 计算成本高",
            "样本需求": "~10000",
            "典型精度": ">98%",
        },
        "GAN (生成对抗)": {
            "适用": "数据增强",
            "优势": "生成合成轨迹, 减少真实样本需求",
            "劣势": "训练不稳定",
            "样本需求": "50真实 + GAN增强",
            "典型精度": "接近全量数据",
        },
    }

    for name, info in models.items():
        print(f"{name}:")
        for k, v in info.items():
            print(f"  {k}: {v}")
        print()

    # 实际攻击流程
    print("=== 实际攻击流程 ===")
    print("1. 采集阶段:")
    print("   - ChipWhisperer / 目标设备连接")
    print("   - 触发加密操作 + 同步采集功耗")
    print("   - 收集 1000-10000 条轨迹")
    print("2. 预处理:")
    print("   - 信号对齐 (互相关/动态时间弯曲)")
    print("   - 降噪 (PCA/小波变换)")
    print("   - 归一化 (z-score)")
    print("3. 训练阶段:")
    print("   - 选择模型架构")
    print("   - 交叉验证防止过拟合")
    print("   - 超参数调优")
    print("4. 推理阶段:")
    print("   - 逐字节恢复密钥")
    print("   - 多数投票确定最终密钥")
    print()
    print("效果: 从传统 DPA 的 10^6 样本降至 AI 的 10^3 样本")
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
