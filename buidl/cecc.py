import hashlib
import hmac

from buidl.helper import (
    big_endian_to_int,
    encode_base58_checksum,
    hash160,
    hash256,
    int_to_big_endian,
    raw_decode_base58,
)
from buidl._libsec import ffi, lib


GLOBAL_CTX = ffi.gc(
    lib.secp256k1_context_create(
        lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY
    ),
    lib.secp256k1_context_destroy,
)
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Point:
    def __init__(self, csec=None, usec=None):
        if usec:
            self.usec = usec
            self.csec = None
            sec_cache = usec
        elif csec:
            self.csec = csec
            self.usec = None
            sec_cache = csec
        else:
            raise RuntimeError("need a serialization")
        self.c = ffi.new("secp256k1_pubkey *")
        if not lib.secp256k1_ec_pubkey_parse(
            GLOBAL_CTX, self.c, sec_cache, len(sec_cache)
        ):
            raise ValueError("libsecp256k1 produced error")

    def __eq__(self, other):
        return self.sec() == other.sec()

    def __repr__(self):
        return "S256Point({})".format(self.sec(compressed=False).hex())

    def __rmul__(self, coefficient):
        coef = coefficient % N
        new_key = ffi.new("secp256k1_pubkey *")
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_mul(GLOBAL_CTX, new_key, coef.to_bytes(32, "big"))
        serialized = ffi.new("unsigned char [65]")
        output_len = ffi.new("size_t *", 65)
        lib.secp256k1_ec_pubkey_serialize(
            GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED
        )
        return self.__class__(usec=bytes(serialized))

    def __add__(self, scalar):
        """Multiplies scalar by generator, adds result to current point"""
        coef = scalar % N
        new_key = ffi.new("secp256k1_pubkey *")
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_add(GLOBAL_CTX, new_key, coef.to_bytes(32, "big"))
        serialized = ffi.new("unsigned char [65]")
        output_len = ffi.new("size_t *", 65)
        lib.secp256k1_ec_pubkey_serialize(
            GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED
        )
        return self.__class__(usec=bytes(serialized))

    def verify(self, z, sig):
        msg = z.to_bytes(32, "big")
        sig_data = sig.cdata()
        return lib.secp256k1_ecdsa_verify(GLOBAL_CTX, sig_data, msg, self.c)

    def sec(self, compressed=True):
        """returns the binary version of the SEC format"""
        if compressed:
            if not self.csec:
                serialized = ffi.new("unsigned char [33]")
                output_len = ffi.new("size_t *", 33)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_COMPRESSED,
                )
                self.csec = bytes(ffi.buffer(serialized, 33))
            return self.csec
        else:
            if not self.usec:
                serialized = ffi.new("unsigned char [65]")
                output_len = ffi.new("size_t *", 65)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_UNCOMPRESSED,
                )
                self.usec = bytes(ffi.buffer(serialized, 65))
            return self.usec

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
        """returns a Point object from a SEC binary (not hex)"""
        if sec_bin[0] == 4:
            return S256Point(usec=sec_bin)
        else:
            return S256Point(csec=sec_bin)


G = S256Point(
    usec=bytes.fromhex(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
)


class Signature:
    def __init__(self, der=None, c=None):
        if der:
            self.der_cache = der
            self.c = ffi.new("secp256k1_ecdsa_signature *")
            if not lib.secp256k1_ecdsa_signature_parse_der(
                GLOBAL_CTX, self.c, der, len(der)
            ):
                raise RuntimeError("badly formatted signature {}".format(der.hex()))
        elif c:
            self.c = c
            self.der_cache = None
        else:
            raise RuntimeError("need der or c object")

    def __eq__(self, other):
        return self.der() == other.der()

    def __repr__(self):
        return "Signature{}".format(self.der().hex())

    def der(self):
        if not self.der_cache:
            der = ffi.new("unsigned char[72]")
            der_length = ffi.new("size_t *", 72)
            lib.secp256k1_ecdsa_signature_serialize_der(
                GLOBAL_CTX, der, der_length, self.c
            )
            self.der_cache = bytes(ffi.buffer(der, der_length[0]))
        return self.der_cache

    def cdata(self):
        return self.c

    @classmethod
    def parse(cls, der):
        return cls(der=der)


class PrivateKey:
    def __init__(self, secret, network="mainnet", compressed=True):
        self.secret = secret
        self.point = secret * G
        self.network = network
        self.compressed = compressed

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)

    def sign(self, z):
        secret = self.secret.to_bytes(32, "big")
        msg = z.to_bytes(32, "big")
        csig = ffi.new("secp256k1_ecdsa_signature *")
        if not lib.secp256k1_ecdsa_sign(
            GLOBAL_CTX, csig, msg, secret, ffi.NULL, ffi.NULL
        ):
            raise RuntimeError("something went wrong with c signing")
        sig = Signature(c=csig)
        if not self.point.verify(z, sig):
            raise RuntimeError("something went wrong with signing")
        return sig

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

    def wif(self, compressed=True):
        # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, "big")
        # prepend b'\xef' on testnet, b'\x80' on mainnet
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
