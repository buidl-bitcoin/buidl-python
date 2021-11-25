from buidl.helper import (
    int_to_little_endian,
    little_endian_to_int,
)

MAX_LOCKTIME = (1 << 32) - 1
MAX_SEQUENCE = (1 << 32) - 1
BLOCK_LIMIT = 500000000
SEQUENCE_DISABLE_RELATIVE_FLAG = 1 << 31
SEQUENCE_RELATIVE_TIME_FLAG = 1 << 22
SEQUENCE_MASK = (1 << 16) - 1


class Locktime(int):
    def __new__(cls, n=0):
        if n < 0 or n > MAX_LOCKTIME:
            raise ValueError(f"Locktime must be between 0 and 2^32 - 1: {n}")
        return super().__new__(cls, n)

    @classmethod
    def parse(cls, s):
        return cls(little_endian_to_int(s.read(4)))

    def serialize(self):
        return int_to_little_endian(self, 4)

    def block_height(self):
        if self < BLOCK_LIMIT:
            return self
        else:
            return None

    def mtp(self):
        if self >= BLOCK_LIMIT:
            return self
        else:
            return None

    def is_comparable(self, other):
        return (self < BLOCK_LIMIT and other < BLOCK_LIMIT) or (
            self >= BLOCK_LIMIT and other >= BLOCK_LIMIT
        )

    def __lt__(self, other):
        if type(other) == int:
            return super().__lt__(other)
        if self.is_comparable(other):
            return super().__lt__(other)
        else:
            raise ValueError(
                "locktimes where one is a block height and the other a unix time cannot be compared"
            )


class Sequence(int):
    def __new__(cls, n=MAX_SEQUENCE):
        if n < 0 or n > MAX_SEQUENCE:
            raise ValueError(f"Sequence must be between 0 and 2^32 - 1: {n}")
        return super().__new__(cls, n)

    @classmethod
    def parse(cls, s):
        return cls(little_endian_to_int(s.read(4)))

    @classmethod
    def from_relative_time(cls, num_seconds):
        return cls(SEQUENCE_RELATIVE_TIME_FLAG | (num_seconds // 512))

    @classmethod
    def from_relative_blocks(cls, num_blocks):
        return cls(num_blocks)

    def serialize(self):
        return int_to_little_endian(self, 4)

    def is_rbf_able(self):
        return self < MAX_SEQUENCE

    def is_max(self):
        return self == MAX_SEQUENCE

    def is_relative(self):
        return self & SEQUENCE_DISABLE_RELATIVE_FLAG == 0

    def is_relative_time(self):
        return self.is_relative() and self & SEQUENCE_RELATIVE_TIME_FLAG

    def is_relative_block(self):
        return self.is_relative() and not self.is_relative_time()

    def relative_blocks(self):
        """Returns the number of blocks that need to age"""
        if self.is_relative_block():
            return self & SEQUENCE_MASK
        else:
            return None

    def relative_time(self):
        """Returns the number of seconds that need to age"""
        if self.is_relative_time():
            return (self & SEQUENCE_MASK) << 9
        else:
            return None

    def is_comparable(self, other):
        return (self.is_relative_block() and other.is_relative_block()) or (
            self.is_relative_time() and other.is_relative_time()
        )

    def __lt__(self, other):
        if type(other) == int:
            return super().__lt__(other)
        if self.is_comparable(other):
            return self & SEQUENCE_MASK < other & SEQUENCE_MASK
        else:
            raise ValueError(
                "sequences where one is a relative block height and the other a relative unix time cannot be compared"
            )
