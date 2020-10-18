from io import BytesIO

import hashlib
import hmac

from base64 import b64decode, b64encode
from buidl.pbkdf2 import PBKDF2


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
PBKDF2_ROUNDS = 2048



def bytes_to_str(b, encoding='ascii'):
    '''Returns a string version of the bytes'''
    # use the bytes.decode(encoding) method
    return b.decode(encoding)


def str_to_bytes(s, encoding='ascii'):
    '''Returns a bytes version of the string'''
    # use the string.encode(encoding) method
    return s.encode(encoding)


def byte_to_int(b):
    '''Returns an integer that corresponds to the byte'''
    return b[0]


def int_to_byte(n):
    '''Returns a single byte that corresponds to the integer'''
    if n > 255 or n < 0:
        raise ValueError('integer greater than 255 or lower than 0 cannot be converted into a byte')
    return bytes([n])


def big_endian_to_int(b):
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the int.from_bytes(b, <endianness>) method
    return int.from_bytes(b, 'big')


def int_to_big_endian(n, length):
    '''int_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the int.to_bytes(length, <endianness>) method
    return n.to_bytes(length, 'big')


def little_endian_to_int(b):
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the int.from_bytes(b, <endianness>) method
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    '''int_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the int.to_bytes(length, <endianness>) method
    return n.to_bytes(length, 'little')


def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def sha256(s):
    return hashlib.sha256(s).digest()


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert from binary to hex, then hex to integer
    num = int(s.hex(), 16)
    result = ''
    prefix = '1' * count
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(raw):
    '''Takes bytes and turns it into base58 encoding with checksum'''
    # checksum is the first 4 bytes of the hash256
    checksum = hash256(raw)[:4]
    # encode_base58 on the raw and the checksum
    return encode_base58(raw + checksum)


def raw_decode_base58(s):
    num = 0
    # see how many leading 0's we are starting with
    prefix = b''
    for c in s:
        if num == 0 and c == '1':
            prefix += b'\x00'
        else:
            num = 58*num + BASE58_ALPHABET.index(c)
    # put everything into base64
    byte_array = []
    while num > 0:
        byte_array.insert(0, num & 255)
        num >>= 8
    combined = prefix + bytes(byte_array)
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise RuntimeError('bad address: {} {}'.format(checksum, hash256(combined)[:4]))
    return combined[:-4]


def decode_base58(s):
    return raw_decode_base58(s)[1:]


# next four functions are straight from BIP0173:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
def bech32_polymod(values):
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s):
    b = s.encode('ascii')
    return [x >> 5 for x in b] + [0] + [x & 31 for x in b]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def group_32(s):
    '''Convert from 8-bit bytes to 5-bit array of integers'''
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


def encode_bech32(nums):
    '''Convert from 5-bit array of integers to bech32 format'''
    result = ''
    for n in nums:
        result += BECH32_ALPHABET[n]
    return result


def encode_bech32_checksum(s, testnet=False):
    '''Convert a segwit ScriptPubKey to a bech32 address'''
    if testnet:
        prefix = 'tb'
    else:
        prefix = 'bc'
    version = s[0]
    if version > 0:
        version -= 0x50
    length = s[1]
    data = [version] + group_32(s[2:2 + length])
    checksum = bech32_create_checksum(prefix, data)
    bech32 = encode_bech32(data + checksum)
    return prefix + '1' + bech32


def decode_bech32(s):
    '''Returns whether it's testnet, segwit version and the hash from the bech32 address'''
    hrp, raw_data = s.split('1')
    if hrp == 'tb':
        testnet = True
    elif hrp == 'bc':
        testnet = False
    else:
        raise ValueError('unknown human readable part: {}'.format(hrp))
    data = [BECH32_ALPHABET.index(c) for c in raw_data]
    if not bech32_verify_checksum(hrp, data):
        raise ValueError('bad address: {}'.format(s))
    version = data[0]
    number = 0
    for digit in data[1:-6]:
        number = (number << 5) + digit
    num_bytes = (len(data) - 7) * 5 // 8
    bits_to_ignore = (len(data) - 7) * 5 % 8
    number >>= bits_to_ignore
    hash = int_to_big_endian(number, num_bytes)
    if num_bytes < 2 or num_bytes > 40:
        raise ValueError('bytes out of range: {}'.format(num_bytes))
    return [testnet, version, hash]


def read_varint(s):
    '''reads a variable integer from a stream'''
    b = s.read(1)
    if len(b) != 1:
        raise IOError('stream has no bytes')
    i = b[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


def read_varstr(s):
    '''reads a variable string from a stream'''
    # remember that s.read(n) will read n bytes from the stream
    # find the length of the string by using read_varint on the string
    item_length = read_varint(s)
    # read that many bytes from the stream
    return s.read(item_length)


def encode_varstr(b):
    '''encodes bytes as a varstr'''
    # encode the length of the string using encode_varint
    result = encode_varint(len(b))
    # add the bytes
    result += b
    # return the whole thing
    return result


def merkle_parent(hash1, hash2):
    '''Takes the binary hashes and calculates the hash256'''
    # return the hash256 of hash1 + hash2
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    '''Takes a list of binary hashes and returns a list that's half
    the length'''
    # if the list has exactly 1 element raise an error
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    # if the list has an odd number of elements, duplicate the last one
    #       and put it at the end so it has an even number of elements
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # initialize parent level
    parent_level = []
    # loop over every pair (use: for i in range(0, len(hashes), 2))
    for i in range(0, len(hashes), 2):
        # get the merkle parent of i and i+1 hashes
        parent = merkle_parent(hashes[i], hashes[i + 1])
        # append parent to parent level
        parent_level.append(parent)
    # return parent level
    return parent_level


def merkle_root(hashes):
    '''Takes a list of binary hashes and returns the merkle root
    '''
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of current_level
    return current_level[0]


def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError('bit_field does not have a length that is divisible by 8')
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def bytes_to_bit_field(some_bytes):
    flag_bits = []
    # iterate over each byte of flags
    for byte in some_bytes:
        # iterate over each bit, right-to-left
        for _ in range(8):
            # add the current bit (byte & 1)
            flag_bits.append(byte & 1)
            # rightshift the byte 1
            byte >>= 1
    return flag_bits


def murmur3(data, seed=0):
    '''from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash'''
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
            ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64
    # tail
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
    # finalization
    h1 ^= length
    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)
    return h1 & 0xffffffff


def number_to_op_code_byte(n):
    '''Returns the OP code for a particular number'''
    if n < -1 or n > 16:
        raise ValueError('Not a valid OP code')
    if n > 0:
        return bytes([0x50 + n])
    elif n == 0:
        return b'\x00'
    elif n == -1:
        return b'\x4f'


def op_code_to_number(op_code):
    '''Returns the n for a particular OP code'''
    if op_code not in (0, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96):
        raise ValueError('Not a valid OP code')
    if op_code == 0:
        return 0
    else:
        return op_code - 80


def hmac_sha512(key, msg):
    return hmac.HMAC(key=key, msg=msg, digestmod=hashlib.sha512).digest()


def hmac_sha512_kdf(msg, salt):
    return PBKDF2(
        msg,
        salt,
        iterations=PBKDF2_ROUNDS,
        macmodule=hmac,
        digestmodule=hashlib.sha512,
    ).read(64)


def base64_encode(b):
    return b64encode(b).decode('ascii')


def base64_decode(s):
    return b64decode(s)


def serialize_key_value(key, value):
    return encode_varstr(key) + encode_varstr(value)


def child_to_path(child_number):
    if child_number >= 0x80000000:
        hardened = "'"
        index = child_number - 0x80000000
    else:
        hardened = ''
        index = child_number
    return '/{}{}'.format(index, hardened)


def path_to_child(path_component):
    if path_component[-1:] == "'":
        child_number = 0x80000000 + int(path_component[:-1])
    else:
        child_number = int(path_component)
    return child_number


def parse_binary_path(bin_path):
    if len(bin_path) % 4 != 0:
        raise ValueError('Not a valid binary path: {}'.format(bin_path.hex()))
    path_data = bin_path
    path = 'm'
    while len(path_data):
        child_number = little_endian_to_int(path_data[:4])
        path += child_to_path(child_number)
        path_data = path_data[4:]
    return path


def serialize_binary_path(path):
    bin_path = b''
    for component in path.split('/')[1:]:
        bin_path += int_to_little_endian(path_to_child(component), 4)
    return bin_path
