# 编码与解码 (Encoding)

## 原理

CTF 中常见各种编码，需要识别并解码。本文件介绍常见编码及其特征。

## 常见编码

### 1. Base 系列

#### Base16 (Hex)

```python
# 特征：0-9, A-F
# 示例：48656C6C6F

import binascii
encoded = binascii.hexlify(b'Hello').decode()  # '48656c6c6f'
decoded = binascii.unhexlify('48656c6c6f')  # b'Hello'
```

#### Base32

```python
# 特征：A-Z, 2-7, =
# 示例：JBSWY3DPEBLW64TMMQ======

import base64
encoded = base64.b32encode(b'Hello').decode()
decoded = base64.b32decode('JBSWY3DPEBLW64TMMQ======')
```

#### Base58

```python
# 特征：无 0, O, I, l
# 比特币地址使用
# 示例：6MRyAjQq8ud7XVvpnyYgW

import base58
encoded = base58.b58encode(b'Hello').decode()
decoded = base58.b58decode('6MRyAjQq8ud7XVvpnyYgW')
```

#### Base62

```python
# 特征：0-9, A-Z, a-z
# URL 短链接使用

import base62
encoded = base62.encodebytes(b'Hello')
decoded = base62.decodebytes('8UQDKm')
```

#### Base64

```python
# 特征：A-Z, a-z, 0-9, +, /, =
# 示例：SGVsbG8=

import base64
encoded = base64.b64encode(b'Hello').decode()
decoded = base64.b64decode('SGVsbG8=')

# URL Safe
encoded = base64.urlsafe_b64encode(b'Hello').decode()
decoded = base64.urlsafe_b64decode('SGVsbG8=')
```

#### Base85 (Ascii85)

```python
# 特征：可打印 ASCII
# PDF 使用

import base64
encoded = base64.a85encode(b'Hello').decode()
decoded = base64.a85decode('87cURD]i,"E')
```

#### Base91

```python
# 特征：除 -, \ 外的可打印 ASCII

import base91
encoded = base91.encode(b'Hello')
decoded = base91.decode('TPwJ>')
```

#### Base92

```python
# 特征：所有可打印 ASCII
```

### 2. URL 编码

```python
# 特征：%XX
# 示例：%48%65%6C%6C%6F

from urllib.parse import quote, unquote
encoded = quote('Hello World')  # 'Hello%20World'
decoded = unquote('Hello%20World')  # 'Hello World'
```

### 3. HTML 实体编码

```python
# 特征：&name; 或 &#XX;
# 示例：&lt; &gt; &#60;

import html
encoded = html.escape('<script>')  # '&lt;script&gt;'
decoded = html.unescape('&lt;script&gt;')  # '<script>'
```

### 4. Unicode 编码

```python
# 特征：\uXXXX
# 示例：\u0048\u0065\u006c\u006c\u006f

encoded = 'Hello'.encode('unicode_escape').decode()  # 'Hello'
decoded = '\\u0048\\u0065'.encode().decode('unicode_escape')  # 'He'
```

### 5. 摩斯密码

```python
# 特征：. - / 空格
# 示例：.... . .-.. .-.. ---

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.',
}

def decode_morse(morse):
    reverse = {v: k for k, v in MORSE_CODE.items()}
    words = morse.split(' / ')
    result = []
    for word in words:
        chars = word.split(' ')
        result.append(''.join(reverse[c] for c in chars))
    return ' '.join(result)
```

### 6. 二进制/八进制/十进制/十六进制

```python
# 二进制
# 特征：0, 1
# 示例：01001000 01100101

# 八进制
# 特征：0-7
# 示例：110 145

# 十进制
# 特征：0-9
# 示例：72 101

# 十六进制
# 特征：0-9, A-F
# 示例：48 65

# 转换
binary = '0100100001100101'
text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
```

### 7. ASCII 编码

```python
# 标准 ASCII
# 0-127

# 扩展 ASCII
# 128-255

# 转换
char = chr(65)  # 'A'
code = ord('A')  # 65
```

### 8. Brainfuck

```python
# 特征：> < + - . , [ ]
# 示例：++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.

def brainfuck(code, input_data=''):
    tape = [0] * 30000
    ptr = 0
    ip = 0
    input_ptr = 0
    output = ''
    
    # 预处理跳转表
    brackets = {}
    stack = []
    for i, c in enumerate(code):
        if c == '[':
            stack.append(i)
        elif c == ']':
            j = stack.pop()
            brackets[j] = i
            brackets[i] = j
    
    while ip < len(code):
        c = code[ip]
        if c == '>':
            ptr += 1
        elif c == '<':
            ptr -= 1
        elif c == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '.':
            output += chr(tape[ptr])
        elif c == ',':
            if input_ptr < len(input_data):
                tape[ptr] = ord(input_data[input_ptr])
                input_ptr += 1
            else:
                tape[ptr] = 0
        elif c == '[':
            if tape[ptr] == 0:
                ip = brackets[ip]
        elif c == ']':
            if tape[ptr] != 0:
                ip = brackets[ip]
        ip += 1
    
    return output
```

### 9. JSFuck

```python
# 特征：[]()!+
# 示例：[][(![]+[])[+[]]+...]

# 在浏览器控制台执行
# 或使用 Node.js
```

### 10. 其他编码

#### ROT13

```python
import codecs
encoded = codecs.encode('Hello', 'rot_13')  # 'Uryyb'
decoded = codecs.encode('Uryyb', 'rot_13')  # 'Hello'
```

#### ROT47

```python
def rot47(s):
    result = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr(33 + (o - 33 + 47) % 94))
        else:
            result.append(c)
    return ''.join(result)
```

#### 凯撒密码

```python
def caesar(text, shift):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)
```

#### 培根密码

```python
# 特征：A, B
# 示例：AABBB BAABB

BACON = {
    'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
    'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
    'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
    'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P',
    'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
    'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
    'BBAAA': 'Y', 'BBAAB': 'Z',
}
```

#### 栅栏密码

```python
def rail_fence(text, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for c in text:
        fence[rail].append(c)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return ''.join(''.join(f) for f in fence)
```

#### 维吉尼亚密码

```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key_idx = 0
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = key[key_idx % len(key)]
            k_base = ord('A') if k.isupper() else ord('a')
            result.append(chr((ord(c) - base - (ord(k) - k_base)) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return ''.join(result)
```

#### 社会主义核心价值观编码

```python
# 特征：富强民主文明和谐...
# 工具：https://github.com/sym233/core-values-encoder
```

#### 与佛论禅

```python
# 特征：佛经文字
# 工具：http://www.keyfc.net/bbs/tools/tudoucode.aspx
```

## 2024-2026 新技术点

### 1. Base65536/Base2048 编解码

```python
# Base65536 — 将二进制数据编码为 Unicode 字符
# 常用于 CTF 中隐藏 flag
import struct

def base65536_decode(encoded):
    """Base65536 解码"""
    # Base65536 使用 Unicode 区块 U+00000 - U+FFFFF
    result = bytearray()
    for char in encoded:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            continue  # 跳过代理对
        result.append((cp >> 8) & 0xFF)
        result.append(cp & 0xFF)
    # 移除填充
    # 去除前导零字节
    while result and result[0] == 0:
        result.pop(0)
    return bytes(result)

def base2048_decode(encoded):
    """Base2048 解码"""
    # Base2048 使用更大的 Unicode 范围
    # 参考: https://github.com/qntm/base2048
    result = 0
    for char in encoded:
        cp = ord(char)
        # 查找字符在 Base2048 表中的索引
        # 简化版本
        result = result * 2048 + cp
    return result.to_bytes((result.bit_length() + 7) // 8, 'big')

# CTF 中常见：使用 CyberChef 搜索 "Base65536"
# 在线工具: https://www.dcode.fr/base-65536-encoding
```

### 2. Bech32/Bech32m 编解码 (比特币隔离见证)

```python
# Bech32 编码 — 比特币 SegWit 地址
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Bech32 校验"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_decode(addr):
    """Bech32 地址解码"""
    # 分离 human readable part (hrp) 和数据部分
    pos = addr.rfind('1')
    if pos < 1:
        return None, None, None
    
    hrp = addr[:pos]
    data_part = addr[pos+1:]
    
    # 解码数据
    data = []
    for c in data_part:
        idx = CHARSET.find(c.lower())
        if idx < 0:
            return None, None, None
        data.append(idx)
    
    # 验证校验和
    polymod = bech32_polymod([0] * (len(addr) - pos - 6) + data + [0, 0, 0, 0, 0, 0])
    if polymod != 1:  # Bech32m 校验
        if polymod != 0x2bc830a3:  # Bech32m
            return None, None, None
    
    # 转换为 5-bit 到 8-bit
    conv = []
    acc = 0
    bits = 0
    for d in data[:-6]:
        acc = (acc << 5) | d
        bits += 5
        while bits >= 8:
            bits -= 8
            conv.append((acc >> bits) & 0xff)
    
    return hrp, conv, "bech32m" if polymod == 0x2bc830a3 else "bech32"
```

### 3. 多重编码自动识别与解码

```python
# 自动识别并解码多层编码
import base64
import binascii
import codecs
import re

class MultiDecoder:
    """多重编码自动识别与解码"""
    
    @staticmethod
    def auto_detect_and_decode(data):
        """自动检测并解码"""
        result = data
        chain = []
        max_iterations = 20
        
        for i in range(max_iterations):
            decoded = MultiDecoder._try_decode(result)
            if decoded and decoded != result:
                chain.append(f"第 {i+1} 层: {MultiDecoder._identify_encoding(result)}")
                result = decoded
            else:
                break
        
        return result, chain
    
    @staticmethod
    def _identify_encoding(data):
        """识别编码类型"""
        if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) % 4 == 0:
            return "Base64"
        if re.match(r'^[A-Z2-7]+=+$', data):
            return "Base32"
        if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
            return "Hex"
        if re.match(r'^[01]+$', data) and len(data) % 8 == 0:
            return "Binary"
        if re.match(r'^[\x20-\x7E]+$', data) and '.' in data or '-' in data:
            return "Morse?"
        return "Unknown"
    
    @staticmethod
    def _try_decode(data):
        """尝试各种解码"""
        # Base64
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='strict')
            if decoded.isprintable():
                return decoded
        except:
            pass
        
        # Base32
        try:
            decoded = base64.b32decode(data).decode('utf-8', errors='strict')
            if decoded.isprintable():
                return decoded
        except:
            pass
        
        # Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
                decoded = bytes.fromhex(data).decode('utf-8', errors='strict')
                if decoded.isprintable():
                    return decoded
        except:
            pass
        
        # URL decode
        if '%' in data:
            from urllib.parse import unquote
            decoded = unquote(data)
            if decoded != data:
                return decoded
        
        # HTML entities
        import html
        if '&amp;' in data or '&lt;' in data or '&#' in data:
            decoded = html.unescape(data)
            if decoded != data:
                return decoded
        
        # ROT13
        decoded = codecs.decode(data, 'rot_13')
        if decoded != data and decoded.isprintable():
            return decoded
        
        # Unicode escape
        try:
            if '\\u' in data:
                decoded = data.encode('utf-8').decode('unicode_escape')
                return decoded
        except:
            pass
        
        return None

# 使用
decoder = MultiDecoder()
encoded = "VklYa04="  # Base64("VIXN") 
decoded, chain = decoder.auto_detect_and_decode(encoded)
print(f"解码链: {chain}")
print(f"结果: {decoded}")
```

### 4. 区块链编码 (Base58Check/Bech32)

```python
# 区块链常用编码完整实现
import hashlib
import struct

def base58_encode(payload):
    """Base58 编码"""
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    # 计算前导零
    n_pad = 0
    for byte in payload:
        if byte == 0:
            n_pad += 1
        else:
            break
    
    # 转换
    n = int.from_bytes(payload, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    
    return '1' * n_pad + ''.join(reversed(result))

def base58check_encode(version, payload):
    """Base58Check 编码（比特币地址）"""
    data = version + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

def base58check_decode(addr):
    """Base58Check 解码"""
    ALPHABET = '12356789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    n = 0
    for char in addr:
        n = n * 58 + ALPHABET.index(char)
    
    # 转换为字节
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    
    # 补齐前导 1
    n_pad = len(addr) - len(addr.lstrip('1'))
    full = b'\x00' * n_pad + full
    
    # 校验
    data = full[:-4]
    checksum = full[-4:]
    verify = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    
    if checksum != verify:
        raise ValueError("校验和错误")
    
    return data[0], data[1:]  # version, payload

# 比特币地址验证
def validate_btc_address(address):
    """验证比特币地址"""
    try:
        version, payload = base58check_decode(address)
        if version == 0x00 and len(payload) == 20:
            return "P2PKH (Legacy)"
        elif version == 0x05 and len(payload) == 20:
            return "P2SH"
        elif address.startswith('bc1'):
            return "Bech32 (SegWit)"
        return f"Unknown (version={version:#x})"
    except:
        return "Invalid"
```

### 5. Enigma 密码机模拟

```python
# Enigma 密码机模拟器
class Enigma:
    """Enigma M3 模拟器"""
    
    ROTORS = {
        'I':    'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
        'II':   'AJDKSIRUXBLHWTMCQGZNPYFVOE',
        'III':  'BDFHJLCPRTXVZNYEIWGAKMUSQO',
        'IV':   'ESOVPZJAYQUIRHXLNFTGKDCMWB',
        'V':    'VZBRGITYUPSDNHLXAWMJQOFECK',
    }
    REFLECTOR = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    def __init__(self, rotors, reflector='B', ring_settings='AAA', plugboard=''):
        self.rotors = list(rotors)
        self.reflector = self.REFLECTOR if reflector == 'B' else reflector
        self.ring_settings = [self.ALPHABET.index(c) for c in ring_settings]
        self.positions = [0, 0, 0]
        self.plugboard = {}
        
        # 解析接线板
        if plugboard:
            pairs = plugboard.split()
            for pair in pairs:
                if len(pair) == 2:
                    self.plugboard[pair[0]] = pair[1]
                    self.plugboard[pair[1]] = pair[0]
    
    def step_rotors(self):
        """转子步进"""
        if self.rotors[2] in ['V']:  # Double stepping
            if self.positions[1] == self.ALPHABET.index(self.ROTORS[self.rotors[1]][0]):
                self.positions[1] = (self.positions[1] + 1) % 26
                self.positions[0] = (self.positions[0] + 1) % 26
            else:
                self.positions[2] = (self.positions[2] + 1) % 26
        else:
            if self.positions[2] == 0:
                self.positions[1] = (self.positions[1] + 1) % 26
            self.positions[2] = (self.positions[2] + 1) % 26
    
    def encrypt_char(self, char):
        """加密单个字符"""
        if char not in self.ALPHABET:
            return char
        
        self.step_rotors()
        
        # 接线板
        idx = self.ALPHABET.index(char)
        char = self.plugboard.get(char, char)
        idx = self.ALPHABET.index(char)
        
        # 反向通过转子
        for i in range(2, -1, -1):
            rotor = self.ROTORS[self.rotors[i]]
            offset = (self.positions[i] - self.ring_settings[i]) % 26
            idx = (idx - offset) % 26
            idx = rotor.index(self.ALPHABET[idx])
            idx = (idx + offset) % 26
        
        # 反射器
        idx = self.ALPHABET.index(self.reflector[idx])
        
        # 正向通过转子
        for i in range(3):
            rotor = self.ROTORS[self.rotors[i]]
            offset = (self.positions[i] - self.ring_settings[i]) % 26
            idx = (idx - offset) % 26
            idx = self.ALPHABET.index(rotor[idx])
            idx = (idx + offset) % 26
        
        char = self.ALPHABET[idx]
        char = self.plugboard.get(char, char)
        
        return char
    
    def process(self, text):
        """处理文本"""
        return ''.join(self.encrypt_char(c.upper()) for c in text)

# 使用
enigma = Enigma(['I', 'II', 'III'], ring_settings='AAA', plugboard='AB CD EF')
encoded = enigma.process("HELLO")
print(f"Enigma 编码: {encoded}")

# 暴力破解需要尝试: 26^3 * 26^3 * 接线板组合
```

### 6. 自动编码识别器

```python
# 快速识别未知编码
import base64
import re
import codecs

def identify_encoding(data):
    """识别编码类型"""
    results = []
    
    # Base64
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
    if b64_pattern.match(data) and len(data) % 4 == 0:
        try:
            decoded = base64.b64decode(data)
            results.append(('Base64', decoded))
        except:
            pass
    
    # Base32
    b32_pattern = re.compile(r'^[A-Z2-7]+=+$')
    if b32_pattern.match(data):
        try:
            decoded = base64.b32decode(data)
            results.append(('Base32', decoded))
        except:
            pass
    
    # Hex
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if hex_pattern.match(data) and len(data) % 2 == 0:
        try:
            decoded = bytes.fromhex(data)
            results.append(('Hex', decoded))
        except:
            pass
    
    # Binary
    if re.match(r'^[01]+$', data) and len(data) % 8 == 0:
        decoded = bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8))
        results.append(('Binary', decoded))
    
    # URL encoding
    if '%' in data:
        from urllib.parse import unquote
        decoded = unquote(data)
        if decoded != data:
            results.append(('URL', decoded.encode()))
    
    # Morse code
    if re.match(r'^[\.\- /]+$', data):
        MORSE = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z',
        }
        words = data.split(' / ')
        decoded = ''
        for word in words:
            chars = word.split(' ')
            decoded += ''.join(MORSE.get(c, '?') for c in chars)
            decoded += ' '
        results.append(('Morse', decoded.strip().encode()))
    
    return results

# 使用
data = "SGVsbG8gV29ybGQ="
results = identify_encoding(data)
for name, decoded in results:
    print(f"{name}: {decoded}")
```

### 7. 栅栏密码自动破解

```python
# 栅栏密码 (Rail Fence Cipher) 自动破解
def rail_fence_decrypt(ciphertext, rails):
    """栅栏密码解密"""
    n = len(ciphertext)
    # 创建空栅栏
    fence = [['' for _ in range(n)] for _ in range(rails)]
    
    # 标记位置
    direction = 1
    row = 0
    positions = []
    for col in range(n):
        positions.append((row, col))
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    
    # 填充密文
    idx = 0
    for row in range(rails):
        for col in range(n):
            if positions[col][0] == row:
                fence[row][col] = ciphertext[idx]
                idx += 1
    
    # 读取
    result = []
    for col in range(n):
        result.append(fence[positions[col][0]][col])
    
    return ''.join(result)

def auto_crack_rail_fence(ciphertext):
    """自动破解栅栏密码"""
    for rails in range(2, 20):
        decrypted = rail_fence_decrypt(ciphertext, rails)
        # 检查是否可读
        if any(word in decrypted.lower() for word in ['flag', 'ctf', 'the', 'and', 'is']):
            print(f"[+] 栅栏数 {rails}: {decrypted}")
            return rails, decrypted
    
    return None, None

# 使用
ciphertext = "TCEHATEARFTAOFETRH "
rails, plaintext = auto_crack_rail_fence(ciphertext)
```

### 8. 维吉尼亚密码自动破解

```python
# 维吉尼亚密码自动破解 (Kasiski + 频率分析)
import re
from collections import Counter

def kasiski_examination(ciphertext):
    """Kasiski 检验 — 确定密钥长度"""
    # 查找重复序列
    repeats = {}
    for length in range(3, len(ciphertext) // 2):
        for i in range(len(ciphertext) - length):
            seq = ciphertext[i:i+length]
            if seq in repeats:
                repeats[seq].append(i)
            else:
                repeats[seq] = [i]
    
    # 计算重复序列的间距
    distances = []
    for seq, positions in repeats.items():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                distances.append(positions[i] - positions[i-1])
    
    # 使用 GCD 找密钥长度
    from math import gcd
    from functools import reduce
    
    key_length = reduce(gcd, distances) if distances else 1
    return key_length

def frequency_analysis(segment):
    """频率分析 — 确定单个密钥字符"""
    english_freq = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
                    0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
                    0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
                    0.020, 0.001]
    
    best_shift = 0
    best_score = 0
    
    for shift in range(26):
        # 移位后计算频率
        shifted = Counter()
        for c in segment:
            shifted[(ord(c) - ord('A') - shift) % 26] += 1
        
        total = len(segment)
        score = sum(
            (shifted[i] / total - english_freq[i]) ** 2
            for i in range(26)
        )
        
        if score < best_score or best_score == 0:
            best_score = score
            best_shift = shift
    
    return chr(best_shift + ord('A'))

def vigenere_auto_crack(ciphertext):
    """自动破解维吉尼亚密码"""
    ciphertext = re.sub(r'[^A-Za-z]', '', ciphertext.upper())
    
    key_length = kasiski_examination(ciphertext)
    print(f"[*] 推测密钥长度: {key_length}")
    
    key = ''
    for i in range(key_length):
        segment = ciphertext[i::key_length]
        key_char = frequency_analysis(segment)
        key += key_char
    
    print(f"[*] 推测密钥: {key}")
    
    # 解密
    result = []
    key_idx = 0
    for c in ciphertext:
        shift = ord(key[key_idx % len(key)]) - ord('A')
        decrypted = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        result.append(decrypted)
        key_idx += 1
    
    return ''.join(result), key

# 使用
ciphertext = "LXFOPV EFVNHR"
plaintext, key = vigenere_auto_crack(ciphertext)
print(f"密钥: {key}")
print(f"明文: {plaintext}")
```

## 工具推荐

- **CyberChef** — 编码解码瑞士军刀
- **dcode.fr** — 在线解码
- **CTF在线工具** — https://ctf.bugku.com/
- **Python** — 编程实现

## 参考链接

- [CyberChef](https://gchq.github.io/CyberChef/)
- [dcode.fr](https://www.dcode.fr/)
- [ctf-wiki encoding](https://ctf-wiki.org/crypto/classical/)
- [Base64](https://en.wikipedia.org/wiki/Base64)
