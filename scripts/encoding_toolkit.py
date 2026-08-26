#!/usr/bin/env python3
"""
CTF 编码工具包
支持多种编码/解码
"""

import base64
import binascii
import urllib.parse
import html
import codecs
import re
from typing import Optional


class EncodingToolkit:
    """CTF 编码工具集"""

    # ==================== Base 系列 ====================

    @staticmethod
    def base16_encode(data: str) -> str:
        return binascii.hexlify(data.encode()).decode().upper()

    @staticmethod
    def base16_decode(data: str) -> str:
        return binascii.unhexlify(data).decode()

    @staticmethod
    def base32_encode(data: str) -> str:
        return base64.b32encode(data.encode()).decode()

    @staticmethod
    def base32_decode(data: str) -> str:
        return base64.b32decode(data).decode()

    @staticmethod
    def base58_encode(data: str) -> str:
        # Base58 字母表（比特币）
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = int.from_bytes(data.encode(), 'big')
        result = ''
        while num > 0:
            num, rem = divmod(num, 58)
            result = alphabet[rem] + result
        # 处理前导 0
        for byte in data.encode():
            if byte == 0:
                result = '1' + result
            else:
                break
        return result

    @staticmethod
    def base58_decode(data: str) -> str:
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = 0
        for char in data:
            num = num * 58 + alphabet.index(char)
        # 转字节
        result = num.to_bytes((num.bit_length() + 7) // 8, 'big')
        # 处理前导 1
        for char in data:
            if char == '1':
                result = b'\x00' + result
            else:
                break
        return result.decode()

    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> str:
        # 自动补齐 padding
        missing_padding = 4 - len(data) % 4
        if missing_padding != 4:
            data += '=' * missing_padding
        return base64.b64decode(data).decode()

    @staticmethod
    def base64_url_encode(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')

    @staticmethod
    def base64_url_decode(data: str) -> str:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data).decode()

    @staticmethod
    def base85_encode(data: str) -> str:
        return base64.a85encode(data.encode()).decode()

    @staticmethod
    def base85_decode(data: str) -> str:
        return base64.a85decode(data).decode()

    # ==================== URL 编码 ====================

    @staticmethod
    def url_encode(data: str) -> str:
        return urllib.parse.quote(data)

    @staticmethod
    def url_decode(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def double_url_encode(data: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(data))

    @staticmethod
    def double_url_decode(data: str) -> str:
        return urllib.parse.unquote(urllib.parse.unquote(data))

    # ==================== HTML 编码 ====================

    @staticmethod
    def html_encode(data: str) -> str:
        return html.escape(data)

    @staticmethod
    def html_decode(data: str) -> str:
        return html.unescape(data)

    @staticmethod
    def html_entity_encode(data: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in data)

    @staticmethod
    def html_entity_decode(data: str) -> str:
        return html.unescape(data)

    # ==================== Unicode 编码 ====================

    @staticmethod
    def unicode_encode(data: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in data)

    @staticmethod
    def unicode_decode(data: str) -> str:
        return codecs.decode(data, 'unicode_escape')

    @staticmethod
    def unicode_escape(data: str) -> str:
        return data.encode('unicode_escape').decode()

    # ==================== Hex 编码 ====================

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        return bytes.fromhex(data).decode()

    @staticmethod
    def hex_with_space(data: str) -> str:
        return ' '.join(f'{b:02x}' for b in data.encode())

    # ==================== 二进制/八进制 ====================

    @staticmethod
    def binary_encode(data: str) -> str:
        return ' '.join(f'{b:08b}' for b in data.encode())

    @staticmethod
    def binary_decode(data: str) -> str:
        bits = data.replace(' ', '')
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()

    @staticmethod
    def octal_encode(data: str) -> str:
        return ' '.join(oct(b)[2:] for b in data.encode())

    @staticmethod
    def octal_decode(data: str) -> str:
        return bytes(int(x, 8) for x in data.split()).decode()

    # ==================== 摩斯密码 ====================

    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
        '9': '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..',
        '/': '-..-.', '@': '.--.-.', '(': '-.--.', ')': '-.--.-',
    }

    @staticmethod
    def morse_encode(data: str) -> str:
        result = []
        for char in data.upper():
            if char == ' ':
                result.append('/')
            elif char in EncodingToolkit.MORSE_CODE:
                result.append(EncodingToolkit.MORSE_CODE[char])
        return ' '.join(result)

    @staticmethod
    def morse_decode(data: str) -> str:
        reverse_morse = {v: k for k, v in EncodingToolkit.MORSE_CODE.items()}
        result = []
        for code in data.split():
            if code == '/':
                result.append(' ')
            elif code in reverse_morse:
                result.append(reverse_morse[code])
        return ''.join(result)

    # ==================== 栅栏密码 ====================

    @staticmethod
    def rail_fence_encode(data: str, rails: int = 2) -> str:
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for char in data:
            fence[rail].append(char)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1
        return ''.join(''.join(r) for r in fence)

    @staticmethod
    def rail_fence_decode(data: str, rails: int = 2) -> str:
        # 计算每个 rail 的长度
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        lengths = [0] * rails
        for i in range(len(data)):
            lengths[pattern[i % len(pattern)]] += 1
        # 分割
        rails_content = []
        idx = 0
        for length in lengths:
            rails_content.append(data[idx:idx + length])
            idx += length
        # 重建
        result = []
        rail_indices = [0] * rails
        for i in range(len(data)):
            rail = pattern[i % len(pattern)]
            result.append(rails_content[rail][rail_indices[rail]])
            rail_indices[rail] += 1
        return ''.join(result)

    # ==================== 凯撒密码 ====================

    @staticmethod
    def caesar_encode(data: str, shift: int = 3) -> str:
        result = []
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def caesar_decode(data: str, shift: int = 3) -> str:
        return EncodingToolkit.caesar_encode(data, -shift)

    @staticmethod
    def caesar_brute_force(data: str) -> list:
        results = []
        for shift in range(26):
            results.append((shift, EncodingToolkit.caesar_decode(data, shift)))
        return results

    # ==================== ROT13 ====================

    @staticmethod
    def rot13(data: str) -> str:
        return codecs.encode(data, 'rot_13')

    # ==================== Vigenere ====================

    @staticmethod
    def vigenere_encode(data: str, key: str) -> str:
        result = []
        key_idx = 0
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                k = key[key_idx % len(key)].upper()
                k_base = ord('A')
                result.append(chr((ord(char) - base + (ord(k) - k_base)) % 26 + base))
                key_idx += 1
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def vigenere_decode(data: str, key: str) -> str:
        result = []
        key_idx = 0
        for char in data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                k = key[key_idx % len(key)].upper()
                k_base = ord('A')
                result.append(chr((ord(char) - base - (ord(k) - k_base)) % 26 + base))
                key_idx += 1
            else:
                result.append(char)
        return ''.join(result)

    # ==================== 自动识别 ====================

    @staticmethod
    def auto_detect(data: str) -> list:
        """自动识别编码类型"""
        results = []

        # Base64 (允许无填充, 接受任意长度)
        if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) > 0:
            try:
                decoded = EncodingToolkit.base64_decode(data)
                if decoded.isprintable():
                    results.append(('Base64', decoded))
            except:
                pass

        # Base32
        if re.match(r'^[A-Z2-7]*={0,6}$', data):
            try:
                decoded = EncodingToolkit.base32_decode(data)
                if decoded.isprintable():
                    results.append(('Base32', decoded))
            except:
                pass

        # Hex
        if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
            try:
                decoded = EncodingToolkit.hex_decode(data)
                if decoded.isprintable():
                    results.append(('Hex', decoded))
            except:
                pass

        # URL 编码
        if '%' in data:
            try:
                decoded = EncodingToolkit.url_decode(data)
                if decoded != data:
                    results.append(('URL', decoded))
            except:
                pass

        # HTML 实体
        if '&#' in data or '&lt;' in data or '&gt;' in data:
            try:
                decoded = EncodingToolkit.html_decode(data)
                if decoded != data:
                    results.append(('HTML', decoded))
            except:
                pass

        # Unicode
        if '\\u' in data:
            try:
                decoded = EncodingToolkit.unicode_decode(data)
                if decoded.isprintable():
                    results.append(('Unicode', decoded))
            except:
                pass

        # 摩斯密码
        if set(data) <= {'.', '-', ' ', '/'}:
            try:
                decoded = EncodingToolkit.morse_decode(data)
                if decoded.strip():
                    results.append(('Morse', decoded))
            except:
                pass

        # 二进制
        if set(data) <= {'0', '1', ' '}:
            try:
                decoded = EncodingToolkit.binary_decode(data)
                if decoded.isprintable():
                    results.append(('Binary', decoded))
            except:
                pass

        return results


def main():
    toolkit = EncodingToolkit()

    print("=" * 60)
    print("CTF 编码工具包")
    print("=" * 60)

    while True:
        print("\n选择功能:")
        print("1. Base 系列 (16/32/58/64/85)")
        print("2. URL 编码")
        print("3. HTML 编码")
        print("4. Unicode 编码")
        print("5. Hex/Binary/Octal")
        print("6. 摩斯密码")
        print("7. 栅栏密码")
        print("8. 凯撒密码")
        print("9. Vigenere 密码")
        print("10. ROT13")
        print("11. 自动识别")
        print("0. 退出")

        choice = input("\n选择: ").strip()

        if choice == "0":
            break

        data = input("输入数据: ").strip()

        if choice == "1":
            print(f"\nBase16: {toolkit.base16_encode(data)}")
            print(f"Base32: {toolkit.base32_encode(data)}")
            print(f"Base58: {toolkit.base58_encode(data)}")
            print(f"Base64: {toolkit.base64_encode(data)}")
            print(f"Base85: {toolkit.base85_encode(data)}")
            print("\n解码:")
            try: print(f"  Base16: {toolkit.base16_decode(data)}")
            except: pass
            try: print(f"  Base32: {toolkit.base32_decode(data)}")
            except: pass
            try: print(f"  Base58: {toolkit.base58_decode(data)}")
            except: pass
            try: print(f"  Base64: {toolkit.base64_decode(data)}")
            except: pass
            try: print(f"  Base85: {toolkit.base85_decode(data)}")
            except: pass
        elif choice == "2":
            print(f"\nURL: {toolkit.url_encode(data)}")
            print(f"双重 URL: {toolkit.double_url_encode(data)}")
            try: print(f"解码: {toolkit.url_decode(data)}")
            except: pass
        elif choice == "3":
            print(f"\nHTML: {toolkit.html_encode(data)}")
            print(f"HTML 实体: {toolkit.html_entity_encode(data)}")
            try: print(f"解码: {toolkit.html_decode(data)}")
            except: pass
        elif choice == "4":
            print(f"\nUnicode: {toolkit.unicode_encode(data)}")
            try: print(f"解码: {toolkit.unicode_decode(data)}")
            except: pass
        elif choice == "5":
            print(f"\nHex: {toolkit.hex_encode(data)}")
            print(f"Binary: {toolkit.binary_encode(data)}")
            print(f"Octal: {toolkit.octal_encode(data)}")
            try: print(f"Hex 解码: {toolkit.hex_decode(data)}")
            except: pass
            try: print(f"Binary 解码: {toolkit.binary_decode(data)}")
            except: pass
        elif choice == "6":
            print(f"\n摩斯编码: {toolkit.morse_encode(data)}")
            try: print(f"摩斯解码: {toolkit.morse_decode(data)}")
            except: pass
        elif choice == "7":
            rails = int(input("栏数 (默认 2): ").strip() or "2")
            print(f"\n栅栏编码: {toolkit.rail_fence_encode(data, rails)}")
            try: print(f"栅栏解码: {toolkit.rail_fence_decode(data, rails)}")
            except: pass
        elif choice == "8":
            shift = int(input("位移 (默认 3): ").strip() or "3")
            print(f"\n凯撒编码: {toolkit.caesar_encode(data, shift)}")
            print(f"凯撒解码: {toolkit.caesar_decode(data, shift)}")
            print("\n爆破:")
            for s, d in toolkit.caesar_brute_force(data):
                print(f"  位移 {s}: {d}")
        elif choice == "9":
            key = input("密钥: ").strip()
            print(f"\nVigenere 编码: {toolkit.vigenere_encode(data, key)}")
            print(f"Vigenere 解码: {toolkit.vigenere_decode(data, key)}")
        elif choice == "10":
            print(f"\nROT13: {toolkit.rot13(data)}")
        elif choice == "11":
            results = toolkit.auto_detect(data)
            if results:
                print("\n识别结果:")
                for enc_type, decoded in results:
                    print(f"  {enc_type}: {decoded}")
            else:
                print("未识别")


if __name__ == "__main__":
    main()
