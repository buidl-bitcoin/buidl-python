import re

from io import BytesIO

from buidl.helper import int_to_big_endian

BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

BECH32_CHARS_RE = re.compile("^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$")


def uses_only_bech32_chars(string):
    return bool(BECH32_CHARS_RE.match(string.lower()))


# next four functions are straight from BIP0173:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
def bech32_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s):
    b = s.encode("ascii")
    return [x >> 5 for x in b] + [0] + [x & 31 for x in b]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def group_32(s):
    """Convert from 8-bit bytes to 5-bit array of integers"""
    result = []
    unused_bits = 0
    current = 0
    for c in s:
        unused_bits += 8
        current = (current << 8) + c
        while unused_bits > 5:
            unused_bits -= 5
            result.append(current >> unused_bits)
            mask = (1 << unused_bits) - 1
            current &= mask
    result.append(current << (5 - unused_bits))
    return result


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bc32encode(data: bytes) -> str:
    """
    bc32 encoding
    see https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-004-bc32.md
    """
    dd = convertbits(data, 8, 5)
    polymod = bech32_polymod([0] + dd + [0, 0, 0, 0, 0, 0]) ^ 0x3FFFFFFF
    chk = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "".join([BECH32_ALPHABET[d] for d in dd + chk])


def bc32decode(bc32: str) -> bytes:
    """
    bc32 decoding
    see https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-004-bc32.md
    """
    if bc32.lower() != bc32 and bc32.upper() != bc32:
        return None
    bc32 = bc32.lower()
    if not all([x in BECH32_ALPHABET for x in bc32]):
        return None
    res = [BECH32_ALPHABET.find(c) for c in bc32.lower()]
    if bech32_polymod([0] + res) != 0x3FFFFFFF:
        return None
    return bytes(convertbits(res[:-6], 5, 8, False))


def cbor_encode(data):
    length = len(data)
    if length <= 23:
        prefix = bytes([0x40 + length])
    elif length <= 255:
        prefix = bytes([0x58, length])
    elif length <= 65535:
        prefix = b"\x59" + length.to_bytes(2, "big")
    else:
        prefix = b"\x60" + length.to_bytes(4, "big")
    return prefix + data


def cbor_decode(data):
    s = BytesIO(data)
    b = s.read(1)[0]
    if b >= 0x40 and b < 0x58:
        length = b - 0x40
        return s.read(length)
    if b == 0x58:
        length = s.read(1)[0]
        return s.read(length)
    if b == 0x59:
        length = int.from_bytes(s.read(2), "big")
        return s.read(length)
    if b == 0x60:
        length = int.from_bytes(s.read(4), "big")
        return s.read(length)
    return None


def encode_bech32(nums):
    """Convert from 5-bit array of integers to bech32 format"""
    result = ""
    for n in nums:
        result += BECH32_ALPHABET[n]
    return result


def encode_bech32_checksum(s, network="mainnet"):
    """Convert a segwit ScriptPubKey to a bech32 address"""
    if network == "mainnet":
        prefix = "bc"
    else:
        prefix = "tb"
    version = s[0]
    if version > 0:
        version -= 0x50
    length = s[1]
    data = [version] + group_32(s[2 : 2 + length])
    checksum = bech32_create_checksum(prefix, data)
    bech32 = encode_bech32(data + checksum)
    return prefix + "1" + bech32


def decode_bech32(s):
    """Returns network, segwit version and the hash from the bech32 address"""
    hrp, raw_data = s.split("1")
    if hrp == "bc":
        network = "mainnet"
    elif hrp == "tb":
        network = "testnet"
    else:
        raise ValueError("unknown human readable part: {}".format(hrp))
    data = [BECH32_ALPHABET.index(c) for c in raw_data]
    if not bech32_verify_checksum(hrp, data):
        raise ValueError("bad address: {}".format(s))
    version = data[0]
    number = 0
    for digit in data[1:-6]:
        number = (number << 5) + digit
    num_bytes = (len(data) - 7) * 5 // 8
    bits_to_ignore = (len(data) - 7) * 5 % 8
    number >>= bits_to_ignore
    hash = int_to_big_endian(number, num_bytes)
    if num_bytes < 2 or num_bytes > 40:
        raise ValueError("bytes out of range: {}".format(num_bytes))
    return [network, version, hash]
