from io import BytesIO

from buidl.helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    read_varint,
    read_varstr,
)
from buidl.siphash import SipHash_2_4


BASIC_FILTER_TYPE = 0
GOLOMB_P = 19
GOLOMB_M = int(round(1.497137 * 2**GOLOMB_P))


def _siphash(key, value):
    if len(key) != 16:
        raise ValueError("Key should be 16 bytes")
    sip = SipHash_2_4(key)
    sip.update(value)
    return sip.hash()


def hash_to_range(key, value, f):
    """Returns a number between 0 and f-1, uniformly distributed.
    Uses siphash-2-4."""
    return _siphash(key, value) * f >> 64


def hashed_items(key, items):
    n = len(items)
    f = n * GOLOMB_M
    result = []
    for item in items:
        result.append(hash_to_range(key, item, f))
    return sorted(result)


def encode_golomb(x, p):
    """converts a number x to a golomb-encoded array of 0's and 1's"""
    # quotient when dividing x by 2^p
    q = x >> p
    # q 1's and a 0 at the end
    result = [1] * q + [0]
    # the last p bits of x
    result += [x & (1 << (p - i - 1)) > 0 for i in range(p)]
    return result


def decode_golomb(bits, p):
    """converts a golomb-encoded array of 0's and 1's to a number"""
    q = 0
    while bits[0] != 0:
        q += 1
        bits.pop(0)
    bits.pop(0)
    r = 0
    for _ in range(p):
        r <<= 1
        if bits.pop(0) == 1:
            r |= 1
    return (q << p) + r


def pack_bits(bits):
    """converts bits to a byte-string"""
    num_bytes = len(bits)
    bits += [0] * (-num_bytes % 8)
    result = 0
    for bit in bits:
        result <<= 1
        if bit:
            result |= 1
    return result.to_bytes(len(bits) // 8, "big")


def unpack_bits(byte_string):
    bits = []
    for byte in byte_string:
        for _ in range(8):
            if byte & 0x80:
                bits.append(1)
            else:
                bits.append(0)
            byte <<= 1
    return bits


def serialize_gcs(sorted_items):
    last_value = 0
    result = []
    for item in sorted_items:
        delta = item - last_value
        result += encode_golomb(delta, GOLOMB_P)
        last_value = item
    return encode_varint(len(sorted_items)) + pack_bits(result)


def encode_gcs(key, items):
    """Returns the golomb-coded-set byte-string which is the sorted
    hashes of the items"""
    sorted_items = hashed_items(key, items)
    return serialize_gcs(sorted_items)


def decode_gcs(key, gcs):
    """Returns the sorted hashes of the items from the golomb-coded-set"""
    s = BytesIO(gcs)
    num_items = read_varint(s)
    bits = unpack_bits(s.read())
    items = []
    current = 0
    for _ in range(num_items):
        delta = decode_golomb(bits, GOLOMB_P)
        current += delta
        items.append(current)
    return items


class CompactFilter:
    def __init__(self, key, hashes):
        self.key = key
        self.hashes = set(hashes)
        self.f = len(self.hashes) * GOLOMB_M

    def __repr__(self):
        result = f"{self.key.hex()}:\n\n"
        for h in sorted(list(self.hashes)):
            result += f"{h.hex()}\n"
        return result

    def __eq__(self, other):
        return self.key == other.key and sorted(list(self.hashes)) == sorted(
            list(other.hashes)
        )

    @classmethod
    def parse(cls, key, filter_bytes):
        return cls(key, set(decode_gcs(key, filter_bytes)))

    def hash(self):
        return hash256(self.serialize())

    def serialize(self):
        return serialize_gcs(sorted(list(self.hashes)))

    def compute_hash(self, raw_script_pubkey):
        return hash_to_range(self.key, raw_script_pubkey, self.f)

    def __contains__(self, script_pubkey):
        raw_script_pubkey = script_pubkey.raw_serialize()
        return self.compute_hash(raw_script_pubkey) in self.hashes


class GetCFiltersMessage:
    command = b"getcfilters"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=1, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError("A stop hash is required")
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFilterMessage:
    command = b"cfilter"
    define_network = False

    def __init__(self, filter_type, block_hash, filter_bytes):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_bytes = filter_bytes
        self.cf = CompactFilter.parse(block_hash[::-1][:16], filter_bytes)

    def __eq__(self, other):
        return (
            self.filter_type == other.filter_type
            and self.block_hash == other.block_hash
            and self.filter_bytes == other.filter_bytes
        )

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        block_hash = s.read(32)[::-1]
        filter_bytes = read_varstr(s)
        return cls(filter_type, block_hash, filter_bytes)

    def hash(self):
        return hash256(self.filter_bytes)

    def __contains__(self, script_pubkey):
        return script_pubkey in self.cf


class GetCFHeadersMessage:
    command = b"getcfheaders"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=0, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFHeadersMessage:
    command = b"cfheaders"
    define_network = False

    def __init__(self, filter_type, stop_hash, previous_filter_header, filter_hashes):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.previous_filter_header = previous_filter_header
        self.filter_hashes = filter_hashes
        current = self.previous_filter_header
        for filter_hash in self.filter_hashes:
            current = hash256(filter_hash + current)
        self.last_header = current

    def __repr__(self):
        result = f"up to {self.stop_hash.hex()}\nstarting from {self.previous_filter_header.hex()}\n\n"
        for fh in self.filter_hashes:
            result += f"{fh.hex()}\n"
        return result

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        previous_filter_header = s.read(32)
        filter_hashes_length = read_varint(s)
        filter_hashes = []
        for _ in range(filter_hashes_length):
            filter_hashes.append(s.read(32))
        return cls(filter_type, stop_hash, previous_filter_header, filter_hashes)


class GetCFCheckPointMessage:

    command = b"getcfcheckpt"
    define_network = False

    def __init__(self, filter_type=BASIC_FILTER_TYPE, stop_hash=None):
        self.filter_type = filter_type
        if stop_hash is None:
            raise RuntimeError("Need a stop hash")
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += self.stop_hash[::-1]
        return result


class CFCheckPointMessage:
    command = b"cfcheckpt"
    define_network = False

    def __init__(self, filter_type, stop_hash, filter_headers):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.filter_headers = filter_headers

    def __repr__(self):
        result = f"up to {self.stop_hash.hex()}\n\n"
        for fh in self.filter_headers:
            result += f"{fh.hex()}\n"
        return result

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        filter_headers_length = read_varint(s)
        filter_headers = []
        for _ in range(filter_headers_length):
            filter_headers.append(s.read(32))
        return cls(filter_type, stop_hash, filter_headers)
