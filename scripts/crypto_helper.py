#!/usr/bin/env python3
"""
CTF Crypto 辅助工具
提供常用密码学计算功能
"""

import math
import random
from typing import Optional, Tuple, List


class CryptoHelper:
    """CTF 密码学辅助工具"""

    # ==================== 数论基础 ====================

    @staticmethod
    def iroot(n: int, k: int) -> Optional[int]:
        """整数开 k 次方 (Newton 法) — 替代 result**(1/k) 浮点方法, 大数安全"""
        if n < 0 or k <= 0:
            return None
        if k == 1:
            return n
        # Newton iteration
        x = n
        while True:
            y = ((k - 1) * x + n // (x ** (k - 1))) // k
            if y >= x:
                break
            x = y
        return x if pow(x, k) == n else None

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """最大公约数"""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """扩展欧几里得算法"""
        if a == 0:
            return b, 0, 1
        g, x, y = CryptoHelper.extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    @staticmethod
    def mod_inverse(a: int, m: int) -> Optional[int]:
        """模逆"""
        g, x, _ = CryptoHelper.extended_gcd(a, m)
        if g != 1:
            return None
        return x % m

    @staticmethod
    def is_prime(n: int) -> bool:
        """素数检测（Miller-Rabin）"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        # 写成 n-1 = 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        # 测试
        for _ in range(10):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def factor_small(n: int) -> List[int]:
        """小数分解"""
        factors = []
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        if n > 1:
            factors.append(n)
        return factors

    @staticmethod
    def euler_phi(n: int) -> int:
        """欧拉函数"""
        result = n
        p = 2
        while p * p <= n:
            if n % p == 0:
                while n % p == 0:
                    n //= p
                result -= result // p
            p += 1
        if n > 1:
            result -= result // n
        return result

    # ==================== RSA 工具 ====================

    @staticmethod
    def rsa_decrypt(c: int, d: int, n: int) -> int:
        """RSA 解密"""
        return pow(c, d, n)

    @staticmethod
    def rsa_encrypt(m: int, e: int, n: int) -> int:
        """RSA 加密"""
        return pow(m, e, n)

    @staticmethod
    def rsa_recover_d(e: int, p: int, q: int) -> int:
        """从 p, q 恢复 d"""
        phi = (p - 1) * (q - 1)
        return CryptoHelper.mod_inverse(e, phi)

    @staticmethod
    def rsa_common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
        """RSA 共模攻击"""
        g, s, t = CryptoHelper.extended_gcd(e1, e2)
        if s < 0:
            c1 = CryptoHelper.mod_inverse(c1, n)
            s = -s
        if t < 0:
            c2 = CryptoHelper.mod_inverse(c2, n)
            t = -t
        m = (pow(c1, s, n) * pow(c2, t, n)) % n
        return m

    @staticmethod
    def rsa_wiener(e: int, n: int) -> Optional[int]:
        """Wiener 攻击（小 d）"""
        # 连分数展开
        def continued_fraction(a, b):
            cf = []
            while b:
                q = a // b
                cf.append(q)
                a, b = b, a - q * b
            return cf

        def convergents(cf):
            convs = []
            h_prev, h_curr = 0, 1
            k_prev, k_curr = 1, 0
            for a in cf:
                h_prev, h_curr = h_curr, a * h_curr + h_prev
                k_prev, k_curr = k_curr, a * k_curr + k_prev
                convs.append((h_curr, k_curr))
            return convs

        cf = continued_fraction(e, n)
        convs = convergents(cf)

        for k, d in convs:
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            # 检查 phi
            # x^2 - (n - phi + 1)x + n = 0
            b = n - phi + 1
            discriminant = b * b - 4 * n
            if discriminant < 0:
                continue
            sqrt_disc = int(math.isqrt(discriminant))
            if sqrt_disc * sqrt_disc == discriminant:
                if (b + sqrt_disc) % 2 == 0:
                    return d
        return None

    @staticmethod
    def rsa_broadcast(e: int, n_list: List[int], c_list: List[int]) -> int:
        """RSA 广播攻击"""
        # CRT
        from functools import reduce

        N = reduce(lambda a, b: a * b, n_list)
        result = 0
        for i in range(len(n_list)):
            Ni = N // n_list[i]
            Ni_inv = CryptoHelper.mod_inverse(Ni, n_list[i])
            result += c_list[i] * Ni * Ni_inv
        result %= N

        # 整数开 e 次方 (Newton 法, 大数安全)
        m = CryptoHelper.iroot(result, e)
        if m is not None:
            return m
        return None

    # ==================== AES 工具 ====================

    @staticmethod
    def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """AES CBC 解密"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
        """AES ECB 解密"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """PKCS7 去填充 (验证所有填充字节)"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len > len(data) or pad_len == 0:
            return data
        # 验证所有填充字节
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            return data
        return data[:-pad_len]

    # ==================== AES 加密 ====================

    @staticmethod
    def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
        """AES ECB 加密"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)

    @staticmethod
    def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        """AES CTR 加密 (CTR nonce 16 字节, 默认递增 counter)"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(plaintext)

    @staticmethod
    def aes_ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """AES CTR 解密"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """AES GCM 解密 + 认证验证 (tag 校验)"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """AES GCM 加密, 返回 (密文, tag)"""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        tag = cipher.digest()
        return ciphertext, tag

    # ==================== 哈希工具 ====================

    @staticmethod
    def md5(data) -> str:
        import hashlib
        if isinstance(data, str):
            data = data.encode()
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def sha1(data) -> str:
        import hashlib
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha1(data).hexdigest()

    @staticmethod
    def sha256(data) -> str:
        import hashlib
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha512(data) -> str:
        import hashlib
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha512(data).hexdigest()

    # ==================== LCG 工具 ====================

    @staticmethod
    def lcg_next(x: int, a: int, c: int, m: int) -> int:
        """LCG 下一个值"""
        return (a * x + c) % m

    @staticmethod
    def lcg_recover_seed(outputs: List[int], a: int, c: int, m: int) -> Optional[int]:
        """恢复 LCG 种子"""
        inv_a = CryptoHelper.mod_inverse(a, m)
        if inv_a is None:
            return None
        x = (outputs[0] - c) * inv_a % m
        return x

    @staticmethod
    def lcg_recover_params(outputs: List[int], m: int) -> Tuple[int, int]:
        """恢复 LCG 参数（已知 m）"""
        x0, x1, x2 = outputs[0], outputs[1], outputs[2]
        a = (x2 - x1) * CryptoHelper.mod_inverse(x1 - x0, m) % m
        c = (x1 - a * x0) % m
        return a, c

    @staticmethod
    def lcg_recover_m(outputs: List[int]) -> int:
        """恢复 LCG 模数 m"""
        from math import gcd
        diffs = [outputs[i+1] - outputs[i] for i in range(len(outputs)-1)]
        # T_i = X_{i+1} - X_i
        # T_{i+1} * T_{i-1} - T_i^2 ≡ 0 mod m
        m = 0
        for i in range(len(diffs) - 2):
            t = diffs[i+2] * diffs[i] - diffs[i+1] ** 2
            m = gcd(m, abs(t))
        return m

    # ==================== 格工具 ====================

    @staticmethod
    def lattice_lll(basis: List[List[int]]) -> List[List[int]]:
        """LLL 格基规约（需要 SageMath）"""
        try:
            from sage.all import Matrix, ZZ
            M = Matrix(ZZ, basis)
            return M.LLL().rows()
        except ImportError:
            print("需要 SageMath")
            return None

    @staticmethod
    def coppersmith_univariate(f, n: int, X: int, beta: float = 1.0) -> List[int]:
        """Coppersmith 单变量（需要 SageMath）"""
        try:
            return f.small_roots(X=X, beta=beta)
        except:
            print("需要 SageMath")
            return []

    # ==================== ECC 工具 ====================

    @staticmethod
    def ecc_point_add(P: Tuple[int, int], Q: Tuple[int, int],
                      a: int, p: int) -> Tuple[int, int]:
        """椭圆曲线点加"""
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None  # 无穷远点
        if P == Q:
            # 点加倍
            lam = (3 * x1 * x1 + a) * CryptoHelper.mod_inverse(2 * y1, p) % p
        else:
            lam = (y2 - y1) * CryptoHelper.mod_inverse(x2 - x1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    @staticmethod
    def ecc_scalar_mult(k: int, P: Tuple[int, int],
                        a: int, p: int) -> Tuple[int, int]:
        """椭圆曲线标量乘"""
        result = None
        current = P
        while k > 0:
            if k % 2 == 1:
                result = CryptoHelper.ecc_point_add(result, current, a, p)
            current = CryptoHelper.ecc_point_add(current, current, a, p)
            k //= 2
        return result

    # ==================== 工具函数 ====================

    @staticmethod
    def int_to_bytes(n: int) -> bytes:
        """整数转字节"""
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, 'big')

    @staticmethod
    def bytes_to_int(b: bytes) -> int:
        """字节转整数"""
        return int.from_bytes(b, 'big')

    @staticmethod
    def int_to_str(n: int) -> str:
        """整数转字符串"""
        return CryptoHelper.int_to_bytes(n).decode('utf-8', errors='ignore')

    @staticmethod
    def str_to_int(s: str) -> int:
        """字符串转整数"""
        return CryptoHelper.bytes_to_int(s.encode())


def main():
    ch = CryptoHelper()

    print("=" * 60)
    print("CTF Crypto 辅助工具")
    print("=" * 60)

    while True:
        print("\n选择功能:")
        print("1. 数论工具 (gcd/逆元/素数/分解)")
        print("2. RSA 工具")
        print("3. AES 工具")
        print("4. 哈希工具")
        print("5. LCG 工具")
        print("6. ECC 工具")
        print("7. 转换工具")
        print("0. 退出")

        choice = input("\n选择: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            print("\n1. GCD  2. 模逆  3. 素数检测  4. 分解")
            sub = input("选择: ").strip()
            if sub == "1":
                a = int(input("a: "))
                b = int(input("b: "))
                print(f"gcd({a}, {b}) = {ch.gcd(a, b)}")
            elif sub == "2":
                a = int(input("a: "))
                m = int(input("m: "))
                inv = ch.mod_inverse(a, m)
                print(f"{a}^(-1) mod {m} = {inv}")
            elif sub == "3":
                n = int(input("n: "))
                print(f"{n} 是素数: {ch.is_prime(n)}")
            elif sub == "4":
                n = int(input("n: "))
                print(f"因子: {ch.factor_small(n)}")
        elif choice == "2":
            print("\n1. 解密  2. 恢复 d  3. 共模攻击  4. Wiener  5. 广播攻击")
            sub = input("选择: ").strip()
            if sub == "1":
                c = int(input("c: "))
                d = int(input("d: "))
                n = int(input("n: "))
                m = ch.rsa_decrypt(c, d, n)
                print(f"m = {m}")
                try:
                    print(f"明文: {ch.int_to_str(m)}")
                except:
                    pass
            elif sub == "2":
                e = int(input("e: "))
                p = int(input("p: "))
                q = int(input("q: "))
                d = ch.rsa_recover_d(e, p, q)
                print(f"d = {d}")
            elif sub == "3":
                n = int(input("n: "))
                e1 = int(input("e1: "))
                e2 = int(input("e2: "))
                c1 = int(input("c1: "))
                c2 = int(input("c2: "))
                m = ch.rsa_common_modulus(n, e1, e2, c1, c2)
                print(f"m = {m}")
                try:
                    print(f"明文: {ch.int_to_str(m)}")
                except:
                    pass
            elif sub == "4":
                e = int(input("e: "))
                n = int(input("n: "))
                d = ch.rsa_wiener(e, n)
                if d:
                    print(f"d = {d}")
                else:
                    print("Wiener 攻击失败")
            elif sub == "5":
                e = int(input("e: "))
                n_list = [int(x) for x in input("n 列表(逗号分隔): ").split(",")]
                c_list = [int(x) for x in input("c 列表(逗号分隔): ").split(",")]
                m = ch.rsa_broadcast(e, n_list, c_list)
                if m:
                    print(f"m = {m}")
                    try:
                        print(f"明文: {ch.int_to_str(m)}")
                    except:
                        pass
        elif choice == "3":
            print("\n1. CBC 解密  2. ECB 解密")
            sub = input("选择: ").strip()
            if sub == "1":
                key = bytes.fromhex(input("key(hex): "))
                iv = bytes.fromhex(input("iv(hex): "))
                ct = bytes.fromhex(input("ciphertext(hex): "))
                pt = ch.aes_cbc_decrypt(key, iv, ct)
                print(f"明文(hex): {pt.hex()}")
                try:
                    print(f"明文: {ch.pkcs7_unpad(pt).decode()}")
                except:
                    pass
            elif sub == "2":
                key = bytes.fromhex(input("key(hex): "))
                ct = bytes.fromhex(input("ciphertext(hex): "))
                pt = ch.aes_ecb_decrypt(key, ct)
                print(f"明文(hex): {pt.hex()}")
                try:
                    print(f"明文: {ch.pkcs7_unpad(pt).decode()}")
                except:
                    pass
        elif choice == "4":
            data = input("数据: ")
            print(f"MD5: {ch.md5(data)}")
            print(f"SHA1: {ch.sha1(data)}")
            print(f"SHA256: {ch.sha256(data)}")
            print(f"SHA512: {ch.sha512(data)}")
        elif choice == "5":
            print("\n1. 恢复种子  2. 恢复参数  3. 恢复 m")
            sub = input("选择: ").strip()
            if sub == "1":
                outputs = [int(x) for x in input("输出(逗号分隔): ").split(",")]
                a = int(input("a: "))
                c = int(input("c: "))
                m = int(input("m: "))
                seed = ch.lcg_recover_seed(outputs, a, c, m)
                print(f"种子: {seed}")
            elif sub == "2":
                outputs = [int(x) for x in input("输出(逗号分隔): ").split(",")]
                m = int(input("m: "))
                a, c = ch.lcg_recover_params(outputs, m)
                print(f"a = {a}, c = {c}")
            elif sub == "3":
                outputs = [int(x) for x in input("输出(逗号分隔): ").split(",")]
                m = ch.lcg_recover_m(outputs)
                print(f"m = {m}")
        elif choice == "6":
            print("\n1. 点加  2. 标量乘")
            sub = input("选择: ").strip()
            if sub == "1":
                x1 = int(input("x1: "))
                y1 = int(input("y1: "))
                x2 = int(input("x2: "))
                y2 = int(input("y2: "))
                a = int(input("a: "))
                p = int(input("p: "))
                result = ch.ecc_point_add((x1, y1), (x2, y2), a, p)
                print(f"结果: {result}")
            elif sub == "2":
                k = int(input("k: "))
                x = int(input("x: "))
                y = int(input("y: "))
                a = int(input("a: "))
                p = int(input("p: "))
                result = ch.ecc_scalar_mult(k, (x, y), a, p)
                print(f"结果: {result}")
        elif choice == "7":
            print("\n1. int->str  2. str->int  3. int->bytes  4. bytes->int")
            sub = input("选择: ").strip()
            if sub == "1":
                n = int(input("n: "))
                print(f"字符串: {ch.int_to_str(n)}")
            elif sub == "2":
                s = input("字符串: ")
                print(f"整数: {ch.str_to_int(s)}")
            elif sub == "3":
                n = int(input("n: "))
                print(f"字节(hex): {ch.int_to_bytes(n).hex()}")
            elif sub == "4":
                b = bytes.fromhex(input("字节(hex): "))
                print(f"整数: {ch.bytes_to_int(b)}")


if __name__ == "__main__":
    main()
