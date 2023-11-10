import hashlib

from buidl.ecc import (
    S256Point,
    SchnorrSignature,
    Signature,
)
from buidl.helper import (
    hash160,
    hash256,
)
from buidl.timelock import (
    Locktime,
    Sequence,
    MAX_SEQUENCE,
)


def number_to_op_code_byte(n):
    """Returns the OP code for a particular number"""
    if n < -1 or n > 16:
        raise ValueError("Not a valid OP code")
    if n > 0:
        return bytes([0x50 + n])
    elif n == 0:
        return b"\x00"
    elif n == -1:
        return b"\x4f"


def number_to_op_code(n):
    if n < -1 or n > 16:
        raise ValueError("Not a valid OP code")
    if n == 0:
        return 0
    return n + 80


def op_code_to_number(op_code):
    """Returns the n for a particular OP code"""
    if op_code not in (
        0,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        86,
        87,
        88,
        89,
        90,
        91,
        92,
        93,
        94,
        95,
        96,
    ):
        raise ValueError("Not a valid OP code")
    if op_code == 0:
        return 0
    else:
        return op_code - 80


def encode_minimal_num(n):
    if -1 <= n <= 16:
        return number_to_op_code(n)
    else:
        return encode_num(n)


def encode_num(num):
    if num == 0:
        return b""
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xFF)
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set
    # for positive numbers we ensure that the top bit is not set
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element):
    if element == b"":
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7F
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result


def op_0(stack):
    stack.append(encode_num(0))
    return True


def op_1negate(stack):
    stack.append(encode_num(-1))
    return True


def op_1(stack):
    stack.append(encode_num(1))
    return True


def op_2(stack):
    stack.append(encode_num(2))
    return True


def op_3(stack):
    stack.append(encode_num(3))
    return True


def op_4(stack):
    stack.append(encode_num(4))
    return True


def op_5(stack):
    stack.append(encode_num(5))
    return True


def op_6(stack):
    stack.append(encode_num(6))
    return True


def op_7(stack):
    stack.append(encode_num(7))
    return True


def op_8(stack):
    stack.append(encode_num(8))
    return True


def op_9(stack):
    stack.append(encode_num(9))
    return True


def op_10(stack):
    stack.append(encode_num(10))
    return True


def op_11(stack):
    stack.append(encode_num(11))
    return True


def op_12(stack):
    stack.append(encode_num(12))
    return True


def op_13(stack):
    stack.append(encode_num(13))
    return True


def op_14(stack):
    stack.append(encode_num(14))
    return True


def op_15(stack):
    stack.append(encode_num(15))
    return True


def op_16(stack):
    stack.append(encode_num(16))
    return True


def op_nop(stack):
    return True


def op_if(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True


def op_notif(stack, items):
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_verify(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_return(stack):
    return False


def op_toaltstack(stack, altstack):
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack, altstack):
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True


def op_2drop(stack):
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True


def op_2dup(stack):
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_3dup(stack):
    if len(stack) < 3:
        return False
    stack.extend(stack[-3:])
    return True


def op_2over(stack):
    if len(stack) < 4:
        return False
    stack.extend(stack[-4:-2])
    return True


def op_2rot(stack):
    if len(stack) < 6:
        return False
    stack.extend(stack[-6:-4])
    return True


def op_2swap(stack):
    if len(stack) < 4:
        return False
    stack[-4:] = stack[-2:] + stack[-4:-2]
    return True


def op_ifdup(stack):
    if len(stack) < 1:
        return False
    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])
    return True


def op_depth(stack):
    stack.append(encode_num(len(stack)))
    return True


def op_drop(stack):
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_nip(stack):
    if len(stack) < 2:
        return False
    stack[-2:] = stack[-1:]
    return True


def op_over(stack):
    if len(stack) < 2:
        return False
    stack.append(stack[-2])
    return True


def op_pick(stack):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    stack.append(stack[-n - 1])
    return True


def op_roll(stack):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    if n == 0:
        return True
    stack.append(stack.pop(-n - 1))
    return True


def op_rot(stack):
    if len(stack) < 3:
        return False
    stack.append(stack.pop(-3))
    return True


def op_swap(stack):
    if len(stack) < 2:
        return False
    stack.append(stack.pop(-2))
    return True


def op_tuck(stack):
    if len(stack) < 2:
        return False
    stack.insert(-2, stack[-1])
    return True


def op_size(stack):
    if len(stack) < 1:
        return False
    stack.append(encode_num(len(stack[-1])))
    return True


def op_equal(stack):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)


def op_1add(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))
    return True


def op_1sub(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))
    return True


def op_negate(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(-element))
    return True


def op_abs(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    if element < 0:
        stack.append(encode_num(-element))
    else:
        stack.append(encode_num(element))
    return True


def op_not(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_0notequal(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_add(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_booland(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 and element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_boolor(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 or element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequalverify(stack):
    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_lessthan(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 < element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthan(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 > element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_lessthanorequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 <= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthanorequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 >= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_min(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 < element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_max(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 > element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_within(stack):
    if len(stack) < 3:
        return False
    maximum = decode_num(stack.pop())
    minimum = decode_num(stack.pop())
    element = decode_num(stack.pop())
    if element >= minimum and element < maximum:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_ripemd160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new("ripemd160", element).digest())
    return True


def op_sha1(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack):
    # check to see if there's at least 1 element
    if len(stack) < 1:
        return False
    # get the element on the top with stack.pop()
    element = stack.pop()
    # add the hash160 of the element to the end of the stack
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_hash256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack, tx_obj, input_index):
    # check to see if there's at least 2 elements
    if len(stack) < 2:
        return False
    # get the sec_pubkey with stack.pop()
    sec_pubkey = stack.pop()
    # get the der_signature with stack.pop()[:-1] (last byte is removed)
    tmp = stack.pop()
    der_signature, hash_type = tmp[:-1], tmp[-1]
    # parse the sec format pubkey with S256Point
    point = S256Point.parse(sec_pubkey)
    # parse the der format signature with Signature
    sig = Signature.parse(der_signature)
    z = tx_obj.sig_hash(input_index, hash_type)
    # verify using the point, z and signature
    # if verified add encode_num(1) to the end, otherwise encode_num(0)
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_checksigverify(stack, tx_obj, input_index):
    return op_checksig(stack, tx_obj, input_index) and op_verify(stack)


def op_checksig_schnorr(stack, tx_obj, input_index):
    # check to see if there's at least 2 elements
    if len(stack) < 2:
        return False
    pubkey = stack.pop()
    signature = stack.pop()
    point = S256Point.parse_xonly(pubkey)
    if len(signature) == 65:
        hash_type = signature[-1]
        signature = signature[:-1]
    elif len(signature) == 0:
        stack.append(encode_num(0))
        return True
    else:
        hash_type = 0
    sig = SchnorrSignature.parse(signature)
    msg = tx_obj.sig_hash(input_index, hash_type)
    if point.verify_schnorr(msg, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_checksigverify_schnorr(stack, tx_obj, input_index):
    return op_checksig_schnorr(stack, tx_obj, input_index) and op_verify(stack)


def op_checksigadd_schnorr(stack, tx_obj, input_index):
    # check to see if there's at least 3 elements
    if len(stack) < 3:
        return False
    pubkey = stack.pop()
    n = decode_num(stack.pop())
    signature = stack.pop()
    point = S256Point.parse_xonly(pubkey)
    if len(signature) == 65:
        hash_type = signature[-1]
        signature = signature[:-1]
    elif len(signature) == 0:
        stack.append(encode_num(n))
        return True
    else:
        hash_type = 0
    sig = SchnorrSignature.parse(signature)
    msg = tx_obj.sig_hash(input_index, hash_type)
    if point.verify_schnorr(msg, sig):
        stack.append(encode_num(n + 1))
    else:
        stack.append(encode_num(n))
    return True


def op_checkmultisig(stack, tx_obj, input_index):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        tmp = stack.pop()
        der, hash_type = tmp[:-1], tmp[-1]
        der_signatures.append((der, hash_type))
    # OP_CHECKMULTISIG bug
    stack.pop()
    try:
        # parse the sec pubkeys into an array of points
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        # loop through the signatures
        for der_signature, hash_type in der_signatures:
            sig = Signature.parse(der_signature)
            z = tx_obj.sig_hash(input_index, hash_type)
            # bail early if we don't have any points left
            if len(points) == 0:
                print("signatures no good or not in right order")
                return False
            # while we have points
            while points:
                # get the point at the front (points.pop(0))
                point = points.pop(0)
                # see if this point can verify this sig with this z
                if point.verify(z, sig):
                    # break if so, this sig is valid!
                    break
        # if we made it this far, we have to add a 1 to the stack
        # use encode_num(1)
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def op_checkmultisigverify(stack, tx_obj, input_index):
    return op_checkmultisig(stack, tx_obj, input_index) and op_verify(stack)


def op_checklocktimeverify(stack, tx_obj, input_index):
    sequence = tx_obj.tx_ins[input_index].sequence
    locktime = tx_obj.locktime
    if sequence == MAX_SEQUENCE:
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    stack_locktime = Locktime(element)
    if not locktime.is_comparable(stack_locktime):
        return False
    if locktime < stack_locktime:
        return False
    return True


def op_checksequenceverify(stack, tx_obj, input_index):
    sequence = tx_obj.tx_ins[input_index].sequence
    if not sequence.is_relative():
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if tx_obj.version < 2:
        return False
    stack_sequence = Sequence(element)
    if not sequence.is_comparable(stack_sequence):
        return False
    if sequence < stack_sequence:
        return False
    return True


def op_success(stack):
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    79: op_1negate,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    99: op_if,
    100: op_notif,
    105: op_verify,
    106: op_return,
    107: op_toaltstack,
    108: op_fromaltstack,
    109: op_2drop,
    110: op_2dup,
    111: op_3dup,
    112: op_2over,
    113: op_2rot,
    114: op_2swap,
    115: op_ifdup,
    116: op_depth,
    117: op_drop,
    118: op_dup,
    119: op_nip,
    120: op_over,
    121: op_pick,
    122: op_roll,
    123: op_rot,
    124: op_swap,
    125: op_tuck,
    130: op_size,
    135: op_equal,
    136: op_equalverify,
    139: op_1add,
    140: op_1sub,
    143: op_negate,
    144: op_abs,
    145: op_not,
    146: op_0notequal,
    147: op_add,
    148: op_sub,
    154: op_booland,
    155: op_boolor,
    156: op_numequal,
    157: op_numequalverify,
    158: op_numnotequal,
    159: op_lessthan,
    160: op_greaterthan,
    161: op_lessthanorequal,
    162: op_greaterthanorequal,
    163: op_min,
    164: op_max,
    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig,
    173: op_checksigverify,
    174: op_checkmultisig,
    175: op_checkmultisigverify,
    176: op_nop,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    179: op_nop,
    180: op_nop,
    181: op_nop,
    182: op_nop,
    183: op_nop,
    184: op_nop,
    185: op_nop,
}

TAPROOT_OP_CODE_FUNCTIONS = {
    0: op_0,
    79: op_1negate,
    80: op_success,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    98: op_success,
    99: op_if,
    100: op_notif,
    105: op_verify,
    106: op_return,
    107: op_toaltstack,
    108: op_fromaltstack,
    109: op_2drop,
    110: op_2dup,
    111: op_3dup,
    112: op_2over,
    113: op_2rot,
    114: op_2swap,
    115: op_ifdup,
    116: op_depth,
    117: op_drop,
    118: op_dup,
    119: op_nip,
    120: op_over,
    121: op_pick,
    122: op_roll,
    123: op_rot,
    124: op_swap,
    125: op_tuck,
    126: op_success,
    127: op_success,
    128: op_success,
    129: op_success,
    130: op_size,
    131: op_success,
    132: op_success,
    133: op_success,
    134: op_success,
    135: op_equal,
    136: op_equalverify,
    137: op_success,
    138: op_success,
    139: op_1add,
    140: op_1sub,
    141: op_success,
    142: op_success,
    143: op_negate,
    144: op_abs,
    145: op_not,
    146: op_0notequal,
    147: op_add,
    148: op_sub,
    149: op_success,
    150: op_success,
    151: op_success,
    152: op_success,
    153: op_success,
    154: op_booland,
    155: op_boolor,
    156: op_numequal,
    157: op_numequalverify,
    158: op_numnotequal,
    159: op_lessthan,
    160: op_greaterthan,
    161: op_lessthanorequal,
    162: op_greaterthanorequal,
    163: op_min,
    164: op_max,
    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig_schnorr,
    173: op_checksigverify_schnorr,
    174: op_return,
    175: op_return,
    176: op_nop,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    179: op_nop,
    180: op_nop,
    181: op_nop,
    182: op_nop,
    183: op_nop,
    184: op_nop,
    185: op_nop,
    186: op_checksigadd_schnorr,
    187: op_success,
    188: op_success,
    189: op_success,
    190: op_success,
    191: op_success,
    192: op_success,
    193: op_success,
    194: op_success,
    195: op_success,
    196: op_success,
    197: op_success,
    198: op_success,
    199: op_success,
    200: op_success,
    201: op_success,
    202: op_success,
    203: op_success,
    204: op_success,
    205: op_success,
    206: op_success,
    207: op_success,
    208: op_success,
    209: op_success,
    210: op_success,
    211: op_success,
    212: op_success,
    213: op_success,
    214: op_success,
    215: op_success,
    216: op_success,
    217: op_success,
    218: op_success,
    219: op_success,
    220: op_success,
    221: op_success,
    222: op_success,
    223: op_success,
    224: op_success,
    225: op_success,
    226: op_success,
    227: op_success,
    228: op_success,
    229: op_success,
    230: op_success,
    231: op_success,
    232: op_success,
    233: op_success,
    234: op_success,
    235: op_success,
    236: op_success,
    237: op_success,
    238: op_success,
    239: op_success,
    240: op_success,
    241: op_success,
    242: op_success,
    243: op_success,
    244: op_success,
    245: op_success,
    246: op_success,
    247: op_success,
    248: op_success,
    249: op_success,
    250: op_success,
    251: op_success,
    252: op_success,
    253: op_success,
    254: op_success,
}

OP_CODE_NAMES = {
    0: "OP_0",
    76: "OP_PUSHDATA1",
    77: "OP_PUSHDATA2",
    78: "OP_PUSHDATA4",
    79: "OP_1NEGATE",
    81: "OP_1",
    82: "OP_2",
    83: "OP_3",
    84: "OP_4",
    85: "OP_5",
    86: "OP_6",
    87: "OP_7",
    88: "OP_8",
    89: "OP_9",
    90: "OP_10",
    91: "OP_11",
    92: "OP_12",
    93: "OP_13",
    94: "OP_14",
    95: "OP_15",
    96: "OP_16",
    97: "OP_NOP",
    99: "OP_IF",
    100: "OP_NOTIF",
    103: "OP_ELSE",
    104: "OP_ENDIF",
    105: "OP_VERIFY",
    106: "OP_RETURN",
    107: "OP_TOALTSTACK",
    108: "OP_FROMALTSTACK",
    109: "OP_2DROP",
    110: "OP_2DUP",
    111: "OP_3DUP",
    112: "OP_2OVER",
    113: "OP_2ROT",
    114: "OP_2SWAP",
    115: "OP_IFDUP",
    116: "OP_DEPTH",
    117: "OP_DROP",
    118: "OP_DUP",
    119: "OP_NIP",
    120: "OP_OVER",
    121: "OP_PICK",
    122: "OP_ROLL",
    123: "OP_ROT",
    124: "OP_SWAP",
    125: "OP_TUCK",
    130: "OP_SIZE",
    135: "OP_EQUAL",
    136: "OP_EQUALVERIFY",
    139: "OP_1ADD",
    140: "OP_1SUB",
    143: "OP_NEGATE",
    144: "OP_ABS",
    145: "OP_NOT",
    146: "OP_0NOTEQUAL",
    147: "OP_ADD",
    148: "OP_SUB",
    154: "OP_BOOLAND",
    155: "OP_BOOLOR",
    156: "OP_NUMEQUAL",
    157: "OP_NUMEQUALVERIFY",
    158: "OP_NUMNOTEQUAL",
    159: "OP_LESSTHAN",
    160: "OP_GREATERTHAN",
    161: "OP_LESSTHANOREQUAL",
    162: "OP_GREATERTHANOREQUAL",
    163: "OP_MIN",
    164: "OP_MAX",
    165: "OP_WITHIN",
    166: "OP_RIPEMD160",
    167: "OP_SHA1",
    168: "OP_SHA256",
    169: "OP_HASH160",
    170: "OP_HASH256",
    171: "OP_CODESEPARATOR",
    172: "OP_CHECKSIG",
    173: "OP_CHECKSIGVERIFY",
    174: "OP_CHECKMULTISIG",
    175: "OP_CHECKMULTISIGVERIFY",
    176: "OP_NOP1",
    177: "OP_CHECKLOCKTIMEVERIFY",
    178: "OP_CHECKSEQUENCEVERIFY",
    179: "OP_NOP4",
    180: "OP_NOP5",
    181: "OP_NOP6",
    182: "OP_NOP7",
    183: "OP_NOP8",
    184: "OP_NOP9",
    185: "OP_NOP10",
    186: "OP_CHECKSIGADD",
}
