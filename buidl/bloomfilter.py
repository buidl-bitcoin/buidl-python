from buidl.helper import (
    bit_field_to_bytes,
    encode_varint,
    int_to_byte,
    int_to_little_endian,
    murmur3,
)
from buidl.network import GenericMessage


BIP37_CONSTANT = 0xFBA4C795


class BloomFilter:
    def __init__(self, size, function_count, tweak):
        self.size = size
        self.bit_field = [0] * (size * 8)
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item):
        """Add an item to the filter"""
        # iterate self.function_count number of times
        for i in range(self.function_count):
            # BIP0037 spec seed is i*BIP37_CONSTANT + self.tweak
            seed = i * BIP37_CONSTANT + self.tweak
            # get the murmur3 hash given that seed
            h = murmur3(item, seed=seed)
            # set the bit at the hash mod the bitfield size (self.size*8)
            bit = h % (self.size * 8)
            # set the bit field at bit to be 1
            self.bit_field[bit] = 1

    def filter_bytes(self):
        return bit_field_to_bytes(self.bit_field)

    def filterload(self, flag=1):
        """Return a network message whose command is filterload"""
        # encode_varint self.size
        payload = encode_varint(self.size)
        # next is the self.filter_bytes()
        payload += self.filter_bytes()
        # function count is 4 bytes little endian
        payload += int_to_little_endian(self.function_count, 4)
        # tweak is 4 bytes little endian
        payload += int_to_little_endian(self.tweak, 4)
        # flag is 1 byte little endian
        payload += int_to_byte(flag)
        # return a GenericMessage with b'filterload' as the command
        return GenericMessage(b"filterload", payload)
