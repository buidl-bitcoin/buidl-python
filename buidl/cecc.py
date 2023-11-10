import hashlib
import hmac
import secrets

from buidl.hash import hash_taptweak
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
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class S256Point:
    def __init__(self, csec=None, usec=None):
        if usec:
            self.usec = usec
            self.csec = None
            sec_cache = usec
            self.parity = usec[-1] & 1
        elif csec:
            self.csec = csec
            self.usec = None
            sec_cache = csec
            self.parity = csec[0] - 2
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
        return f"S256Point({self.sec().hex()})"

    def __rmul__(self, coefficient):
        coef = coefficient % N
        new_key = ffi.new("secp256k1_pubkey *")
        s = self.sec(compressed=False)
        if not lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s)):
            raise RuntimeError("libsecp256k1 parse error")
        if not lib.secp256k1_ec_pubkey_tweak_mul(
            GLOBAL_CTX, new_key, int_to_big_endian(coef, 32)
        ):
            raise RuntimeError("libsecp256k1 multiplication error")
        serialized = ffi.new("unsigned char [65]")
        output_len = ffi.new("size_t *", 65)
        if not lib.secp256k1_ec_pubkey_serialize(
            GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED
        ):
            raise RuntimeError("libsecp256k1 serialization error")
        return self.__class__(usec=bytes(serialized))

    def __add__(self, scalar):
        """Multiplies scalar by generator, adds result to current point"""
        coef = scalar % N
        new_key = ffi.new("secp256k1_pubkey *")
        s = self.sec(compressed=False)
        if not lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s)):
            raise RuntimeError("libsecp256k1 parse error")
        if not lib.secp256k1_ec_pubkey_tweak_add(
            GLOBAL_CTX, new_key, int_to_big_endian(coef, 32)
        ):
            raise RuntimeError("libsecp256k1 add error")
        serialized = ffi.new("unsigned char [65]")
        output_len = ffi.new("size_t *", 65)
        if not lib.secp256k1_ec_pubkey_serialize(
            GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED
        ):
            raise RuntimeError("libsecp256k1 serialize error")
        return self.__class__(usec=bytes(serialized))

    def even_point(self):
        if self.parity:
            return -1 * self
        else:
            return self

    def verify(self, z, sig):
        msg = int_to_big_endian(z, 32)
        sig_data = sig.cdata()
        return lib.secp256k1_ecdsa_verify(GLOBAL_CTX, sig_data, msg, self.c)

    def verify_schnorr(self, msg, sig):
        xonly_key = ffi.new("secp256k1_xonly_pubkey *")
        if not lib.secp256k1_xonly_pubkey_from_pubkey(
            GLOBAL_CTX, xonly_key, ffi.NULL, self.c
        ):
            raise RuntimeError("libsecp256k1 xonly pubkey error")
        return lib.secp256k1_schnorrsig_verify(
            GLOBAL_CTX, sig.raw, msg, len(msg), xonly_key
        )

    def sec(self, compressed=True):
        """returns the binary version of the SEC format"""
        if compressed:
            if not self.csec:
                serialized = ffi.new("unsigned char [33]")
                output_len = ffi.new("size_t *", 33)

                if not lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_COMPRESSED,
                ):
                    raise RuntimeError("libsecp256k1 serialize error")
                self.csec = bytes(ffi.buffer(serialized, 33))
            return self.csec
        else:
            if not self.usec:
                serialized = ffi.new("unsigned char [65]")
                output_len = ffi.new("size_t *", 65)

                if not lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_UNCOMPRESSED,
                ):
                    raise RuntimeError("libsecp256k1 serialize error")
                self.usec = bytes(ffi.buffer(serialized, 65))
            return self.usec

    def xonly(self):
        # returns the binary version of XONLY pubkey
        xonly_key = ffi.new("secp256k1_xonly_pubkey *")
        if not lib.secp256k1_xonly_pubkey_from_pubkey(
            GLOBAL_CTX, xonly_key, ffi.NULL, self.c
        ):
            raise RuntimeError("libsecp256k1 xonly pubkey error")
        output32 = ffi.new("unsigned char [32]")
        if not lib.secp256k1_xonly_pubkey_serialize(GLOBAL_CTX, output32, xonly_key):
            raise RuntimeError("libsecp256k1 xonly serialize error")
        return bytes(ffi.buffer(output32, 32))

    def tweak(self, merkle_root=b""):
        """returns the tweak for use in p2tr"""
        # take the hash_taptweak of the xonly and the merkle root
        tweak = hash_taptweak(self.xonly() + merkle_root)
        return tweak

    def tweaked_key(self, merkle_root=b"", tweak=None):
        """Creates the tweaked external key for a particular merkle root/tweak."""
        # Get the tweak with the merkle root
        if tweak is None:
            tweak = self.tweak(merkle_root)
        # t is the tweak interpreted as a big endian integer
        t = big_endian_to_int(tweak)
        # Q = P + tG
        external_key = self.even_point() + t
        # return the external key
        return external_key

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

    def p2tr_script(self, merkle_root=b"", tweak=None):
        """Returns the p2tr Script object"""
        external_pubkey = self.tweaked_key(merkle_root, tweak)
        # avoid circular dependency
        from buidl.script import P2TRScriptPubKey

        return P2TRScriptPubKey(external_pubkey)

    def p2pk_tap_script(self):
        """Returns the p2tr Script object"""
        # avoid circular dependency
        from buidl.script import P2PKTapScript

        return P2PKTapScript(self)

    def address(self, compressed=True, network="mainnet"):
        """Returns the p2pkh address string"""
        return self.p2pkh_script(compressed).address(network)

    def p2wpkh_address(self, network="mainnet"):
        """Returns the p2wpkh bech32 address string"""
        return self.p2wpkh_script().address(network)

    def p2sh_p2wpkh_address(self, network="mainnet"):
        """Returns the p2sh-p2wpkh base58 address string"""
        return self.p2wpkh_script().p2sh_address(network)

    def p2tr_address(self, merkle_root=b"", tweak=None, network="mainnet"):
        """Returns the p2tr bech32m address string"""
        return self.p2tr_script(merkle_root, tweak).address(network)

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
    def parse(cls, binary):
        """returns a Point object from a SEC or XONLY pubkey"""
        if len(binary) == 32:
            return cls.parse_xonly(binary)
        elif len(binary) in (33, 65):
            return cls.parse_sec(binary)
        else:
            raise ValueError(f"Unknown public key format {binary.hex()}")

    @classmethod
    def parse_sec(cls, sec_bin):
        """returns a Point object from a SEC binary (not hex)"""
        if sec_bin[0] == 4:
            return cls(usec=sec_bin)
        else:
            return cls(csec=sec_bin)

    @classmethod
    def parse_xonly(cls, binary):
        sec_bin = b"\x02" + binary
        return cls(csec=sec_bin)

    @classmethod
    def combine(cls, points):
        c_pubkeys = []
        for point in points:
            new_key = ffi.new("secp256k1_pubkey *")
            s = point.sec(compressed=False)
            if not lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s)):
                raise RuntimeError("libsecp256k1 parse error")
            c_pubkeys.append(new_key)
        sum_pub_key = ffi.new("secp256k1_pubkey *")
        if not lib.secp256k1_ec_pubkey_combine(
            GLOBAL_CTX, sum_pub_key, c_pubkeys, len(c_pubkeys)
        ):
            raise RuntimeError("libsecp256k1 combine error")
        serialized = ffi.new("unsigned char [65]")
        output_len = ffi.new("size_t *", 65)
        if not lib.secp256k1_ec_pubkey_serialize(
            GLOBAL_CTX,
            serialized,
            output_len,
            sum_pub_key,
            lib.SECP256K1_EC_UNCOMPRESSED,
        ):
            raise RuntimeError("libsecp256k1 serialization error")
        return cls(usec=bytes(serialized))


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
                raise RuntimeError(f"badly formatted signature {der.hex()}")
        elif c:
            self.c = c
            self.der_cache = None
        else:
            raise RuntimeError("need der or c object")

    def __eq__(self, other):
        return self.der() == other.der()

    def __repr__(self):
        return f"Signature{self.der().hex()}"

    def der(self):
        if not self.der_cache:
            der = ffi.new("unsigned char[72]")
            der_length = ffi.new("size_t *", 72)
            if not lib.secp256k1_ecdsa_signature_serialize_der(
                GLOBAL_CTX, der, der_length, self.c
            ):
                raise RuntimeError("libsecp256k1 der serialize error")
            self.der_cache = bytes(ffi.buffer(der, der_length[0]))
        return self.der_cache

    def cdata(self):
        return self.c

    @classmethod
    def parse(cls, der):
        return cls(der=der)


class SchnorrSignature:
    def __init__(self, raw):
        self.raw = raw
        if len(raw) != 64:
            raise ValueError("signature should be 64 bytes")
        # check that the sig's R is valid
        if big_endian_to_int(raw[:32]) == 0:
            raise AssertionError("R should not be zero")
        xonly_key = ffi.new("secp256k1_xonly_pubkey *")
        if not lib.secp256k1_xonly_pubkey_parse(GLOBAL_CTX, xonly_key, raw[:32]):
            raise ValueError(f"libsecp256k1 invalid R {raw[:32].hex()}")
        s = big_endian_to_int(raw[32:])
        if s >= N:
            raise ValueError(f"{s:x} is greater than or equal to {N:x}")

    def __repr__(self):
        return f"SchnorrSignature({self.raw[:32].hex()},{self.raw[32:].hex()})"

    def __eq__(self, other):
        return self.raw == other.raw

    def serialize(self):
        return self.raw

    @classmethod
    def parse(cls, raw):
        return cls(raw)


class PrivateKey:
    def __init__(self, secret, network="mainnet", compressed=True):
        self.secret = secret
        self.point = secret * G
        self.network = network
        self.compressed = compressed

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)

    def even_secret(self):
        if self.point.parity:
            return N - self.secret
        else:
            return self.secret

    def sign(self, z):
        # per libsecp256k1 documentation, this helps against side-channel attacks
        if not lib.secp256k1_context_randomize(
            GLOBAL_CTX,
            secrets.token_bytes(32),
        ):
            raise RuntimeError("libsecp256k1 context randomization error")
        secret = int_to_big_endian(self.secret, 32)
        msg = int_to_big_endian(z, 32)
        csig = ffi.new("secp256k1_ecdsa_signature *")
        if not lib.secp256k1_ecdsa_sign(
            GLOBAL_CTX, csig, msg, secret, ffi.NULL, ffi.NULL
        ):
            raise RuntimeError("libsecp256k1 ecdsa signing problem")
        sig = Signature(c=csig)
        if not self.point.verify(z, sig):
            raise RuntimeError("generated signature doesn't verify")
        return sig

    def sign_schnorr(self, msg, aux):
        if len(msg) != 32:
            raise ValueError("msg needs to be 32 bytes")
        if len(aux) != 32:
            raise ValueError("aux needs to be 32 bytes")
        # per libsecp256k1 documentation, this helps against side-channel attacks
        if not lib.secp256k1_context_randomize(
            GLOBAL_CTX,
            secrets.token_bytes(32),
        ):
            raise RuntimeError("libsecp256k1 context randomization error")
        keypair = ffi.new("secp256k1_keypair *")
        if not lib.secp256k1_keypair_create(
            GLOBAL_CTX, keypair, int_to_big_endian(self.secret, 32)
        ):
            raise RuntimeError("libsecp256k1 keypair creation problem")
        raw_sig = ffi.new("unsigned char [64]")
        if not lib.secp256k1_schnorrsig_sign(GLOBAL_CTX, raw_sig, msg, keypair, aux):
            raise RuntimeError("libsecp256k1 schnorr signing problem")
        return SchnorrSignature(bytes(ffi.buffer(raw_sig, 64)))

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
        # convert the secret from integer to a 32-bytes in big endian using int_to_big_endian(num, 32)
        secret_bytes = int_to_big_endian(self.secret, 32)
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

    def tweaked_key(self, merkle_root=b""):
        e = self.even_secret()
        # get the tweak from the point's tweak method
        tweak = self.point.tweak(merkle_root)
        # t is the tweak interpreted as big endian
        t = big_endian_to_int(tweak)
        # new secret is the secret plus t (make sure to mod by N)
        new_secret = (e + t) % N
        # create a new instance of this class using self.__class__
        return self.__class__(new_secret, network=self.network)

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
