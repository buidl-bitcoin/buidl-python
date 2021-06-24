from io import BytesIO

import hmac
import hashlib

from buidl.helper import (
    big_endian_to_int,
    encode_base58_checksum,
    hash160,
    hash256,
    int_to_big_endian,
    raw_decode_base58,
)


class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = "Num {} not in field range 0 to {}".format(num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        # this should be the inverse of the == operator
        return not (self == other)

    def __repr__(self):
        return "FieldElement_{}({})".format(self.prime, self.num)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        # self.num and other.num are the actual values
        num = (self.num + other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        # self.num and other.num are the actual values
        num = (self.num - other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        # self.num and other.num are the actual values
        num = (self.num * other.num) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __pow__(self, n):
        # remember Fermat's Little Theorem:
        # self.num**(p-1) % p == 1
        # you might want to use % operator on n
        prime = self.prime
        num = pow(self.num, n % (prime - 1), prime)
        return self.__class__(num, prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")
        # self.num and other.num are the actual values
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        # self.prime is what you'll need to mod against
        prime = self.prime
        # use fermat's little theorem:
        # self.num**(p-1) % p == 1
        # this means:
        # 1/n == pow(n, p-2, p)
        # You need to return an element of the same class
        # use: self.__class__(num, prime)
        return self.__class__(num, prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


class Point:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        # x being None and y being None represents the point at infinity
        # Check for that here since the equation below won't make sense
        # with None values for both.
        if self.x is None and self.y is None:
            return
        # make sure that the elliptic curve equation is satisfied
        # y**2 == x**3 + a*x + b
        if self.y ** 2 != self.x ** 3 + a * x + b:
            # if not, raise a ValueError
            raise ValueError("({}, {}) is not on the curve".format(self.x, self.y))

    def __eq__(self, other):
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other):
        # this should be the inverse of the == operator
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return "Point({},{})_{}".format(self.x.num, self.y.num, self.x.prime)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(
                "Points {}, {} are not on the same curve".format(self, other)
            )
        # Case 0.0: self is the point at infinity, return other
        if self.x is None:
            return other
        # Case 0.1: other is the point at infinity, return self
        if other.x is None:
            return self

        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            # Remember to return an instance of this class:
            # self.__class__(x, y, a, b)
            return self.__class__(None, None, self.a, self.b)

        # Case 2: self.x != other.x
        if self.x != other.x:
            # Formula (x3,y3)==(x1,y1)+(x2,y2)
            # s=(y2-y1)/(x2-x1)
            s = (other.y - self.y) / (other.x - self.x)
            # x3=s**2-x1-x2
            x = s ** 2 - self.x - other.x
            # y3=s*(x1-x3)-y1
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # Case 3: self.x == other.x, self.y == other.y
        else:
            # Formula (x3,y3)=(x1,y1)+(x1,y1)
            # s=(3*x1**2+a)/(2*y1)
            s = (3 * self.x ** 2 + self.a) / (2 * self.y)
            # x3=s**2-2*x1
            x = s ** 2 - 2 * self.x
            # y3=s*(x1-x3)-y1
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        # rmul calculates coefficient * self
        coef = coefficient
        current = self
        # start at 0
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            # if the bit at this binary expansion is 1, add
            if coef & 1:
                result += current
            # double the point
            current += current
            coef >>= 1
        return result


A = 0
B = 7
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def hex(self):
        return "{:x}".format(self.num).zfill(64)

    def __repr__(self):
        return self.hex()

    def sqrt(self):
        return self ** ((P + 1) // 4)


class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.x is None:
            return "S256Point(infinity)"
        else:
            return "S256Point({},{})".format(hex(self.x.num), hex(self.y.num))

    def __rmul__(self, coefficient):
        # we want to mod by N to make this simple
        coef = coefficient % N
        return super().__rmul__(coef)

    def __add__(self, other):
        """If other is an int, multiplies scalar by generator, adds result to current point"""
        if type(other) == int:
            return super().__add__(other * G)
        else:
            return super().__add__(other)

    def sec(self, compressed=True):
        # returns the binary version of the sec format, NOT hex
        # if compressed, starts with b'\x02' if self.y.num is even, b'\x03' if self.y is odd
        # then self.x.num
        # remember, you have to convert self.x.num/self.y.num to binary using int_to_big_endian
        x = int_to_big_endian(self.x.num, 32)
        if compressed:
            if self.y.num % 2 == 0:
                return b"\x02" + x
            else:
                return b"\x03" + x
        else:
            # if non-compressed, starts with b'\x04' followod by self.x and then self.y
            y = int_to_big_endian(self.y.num, 32)
            return b"\x04" + x + y

    def hash160(self, compressed=True):
        # get the sec
        sec = self.sec(compressed)
        # hash160 the sec
        return hash160(sec)

    def p2pkh_script(self, compressed=True):
        """Returns the p2pkh Script object"""
        h160 = self.hash160(compressed)
        # avoid circular dependency
        from buidl.script import P2PKHScriptPubKey

        return P2PKHScriptPubKey(h160)

    def p2wpkh_script(self):
        """Returns the p2wpkh Script object"""
        h160 = self.hash160(True)
        # avoid circular dependency
        from buidl.script import P2WPKHScriptPubKey

        return P2WPKHScriptPubKey(h160)

    def p2sh_p2wpkh_redeem_script(self):
        """Returns the RedeemScript for a p2sh-p2wpkh redemption"""
        return self.p2wpkh_script().redeem_script()

    def address(self, compressed=True, network="mainnet"):
        """Returns the p2pkh address string"""
        return self.p2pkh_script(compressed).address(network)

    def bech32_address(self, network="mainnet"):
        """Returns the p2wpkh bech32 address string"""
        return self.p2wpkh_script().address(network)

    def p2sh_p2wpkh_address(self, network="mainnet"):
        """Returns the p2sh-p2wpkh base58 address string"""
        return self.p2wpkh_script().p2sh_address(network)

    def verify(self, z, sig):
        # remember sig.r and sig.s are the main things we're checking
        # remember 1/s = pow(s, N-2, N)
        s_inv = pow(sig.s, N - 2, N)
        # u = z / s
        u = z * s_inv % N
        # v = r / s
        v = sig.r * s_inv % N
        # u*G + v*P should have as the x coordinate, r
        total = u * G + v * self
        return total.x.num == sig.r

    def verify_message(self, message, sig):
        """Verify a message in the form of bytes. Assumes that the z
        is calculated using hash256 interpreted as a big-endian integer"""
        # calculate the hash256 of the message
        h256 = hash256(message)
        # z is the big-endian interpretation. use big_endian_to_int
        z = big_endian_to_int(h256)
        # verify the message using the self.verify method
        return self.verify(z, sig)

    @classmethod
    def parse(self, sec_bin):
        """returns a Point object from a compressed sec binary (not hex)"""
        if sec_bin[0] == 4:
            x = int(sec_bin[1:33].hex(), 16)
            y = int(sec_bin[33:65].hex(), 16)
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = S256Field(int(sec_bin[1:].hex(), 16))
        # right side of the equation y^2 = x^3 + 7
        alpha = x ** 3 + S256Field(B)
        # solve for left side
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)


G = S256Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return "Signature({:x},{:x})".format(self.r, self.s)

    def der(self):
        # convert the r part to bytes
        rbin = int_to_big_endian(self.r, 32)
        # if rbin has a high bit, add a 00
        if rbin[0] >= 128:
            rbin = b"\x00" + rbin
        while rbin[0] == 0:
            if rbin[1] >= 128:
                break
            else:
                rbin = rbin[1:]
        result = bytes([2, len(rbin)]) + rbin
        sbin = int_to_big_endian(self.s, 32)
        # if sbin has a high bit, add a 00
        if sbin[0] >= 128:
            sbin = b"\x00" + sbin
        while sbin[0] == 0:
            if sbin[1] >= 128:
                break
            else:
                sbin = sbin[1:]
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise RuntimeError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise RuntimeError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        rlength = s.read(1)[0]
        r = int(s.read(rlength).hex(), 16)
        marker = s.read(1)[0]
        if marker != 0x02:
            raise RuntimeError("Bad Signature")
        slength = s.read(1)[0]
        s = int(s.read(slength).hex(), 16)
        if len(signature_bin) != 6 + rlength + slength:
            raise RuntimeError("Signature too long")
        return cls(r, s)


class PrivateKey:
    def __init__(self, secret, network="mainnet", compressed=True):
        self.secret = secret
        self.point = secret * G
        self.network = network
        self.compressed = compressed

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)

    def sign(self, z):
        # we need use deterministic k
        k = self.deterministic_k(z)
        # r is the x coordinate of the resulting point k*G
        r = (k * G).x.num
        # remember 1/k = pow(k, N-2, N)
        k_inv = pow(k, N - 2, N)
        # s = (z+r*secret) / k
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        # return an instance of Signature:
        # Signature(r, s)
        return Signature(r, s)

    def deterministic_k(self, z):
        k = b"\x00" * 32
        v = b"\x01" * 32
        if z > N:
            z -= N
        z_bytes = int_to_big_endian(z, 32)
        secret_bytes = int_to_big_endian(self.secret, 32)
        s256 = hashlib.sha256
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = big_endian_to_int(v)
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b"\x00", s256).digest()
            v = hmac.new(k, v, s256).digest()

    def sign_message(self, message):
        """Sign a message in the form of bytes instead of the z. The z should
        be assumed to be the hash256 of the message interpreted as a big-endian
        integer."""
        # compute the hash256 of the message
        h256 = hash256(message)
        # z is the big-endian interpretation. use big_endian_to_int
        z = big_endian_to_int(h256)
        # sign the message using the self.sign method
        return self.sign(z)

    def wif(self, compressed=True):
        # convert the secret from integer to a 32-bytes in big endian using int_to_big_endian(x, 32)
        secret_bytes = int_to_big_endian(self.secret, 32)
        # prepend b'\xef' on testnet/signet, b'\x80' on mainnet
        if self.network == "mainnet":
            prefix = b"\x80"
        else:
            prefix = b"\xef"
        # append b'\x01' if compressed
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)

    @classmethod
    def parse(cls, wif):
        """Converts WIF to a PrivateKey object"""
        raw = raw_decode_base58(wif)
        if len(raw) == 34:
            compressed = True
            if raw[-1] != 1:
                raise ValueError("Invalid WIF")
            raw = raw[:-1]
        else:
            compressed = False
        secret = big_endian_to_int(raw[1:])
        if raw[0] == 0xEF:
            network = "testnet"
        elif raw[0] == 0x80:
            network = "mainnet"
        else:
            raise ValueError("Invalid WIF")
        return cls(secret, network=network, compressed=compressed)
