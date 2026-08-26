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

### 1. 新型编码

```python
# Base65536
# Base2048
# 各新型编码
```

### 2. 量子编码

```python
# 量子比特编码
# 量子纠错码
# 新的编码方法
```

### 3. DNA 编码

```python
# DNA 序列编码
# A, T, C, G
# 新的编码方法
```

### 4. AI 编码

```python
# 基于 ML 的编码
# 神经网络编码
# 新的编码方法
```

### 5. 区块链编码

```python
# Base58Check
# Bech32
# 各区块链编码
```

### 6. 容器编码

```python
# 容器镜像编码
# 各容器编码
```

### 7. 云编码

```python
# 云服务编码
# 各云编码
```

### 8. 新型密码

```python
# Enigma
# 各新型密码
```

### 9. 多重编码

```python
# 多重编码嵌套
# 自动识别
# 自动解码
```

### 10. AI 辅助

```python
# ML 辅助
# 自动识别编码
# 自动解码
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
