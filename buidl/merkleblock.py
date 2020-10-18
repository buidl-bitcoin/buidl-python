import math

from buidl.block import Block

from buidl.helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)


class MerkleTree:
    def __init__(self, total):
        self.total = total
        # compute max depth math.ceil(math.log(self.total, 2))
        self.max_depth = math.ceil(math.log(self.total, 2))
        # initialize the nodes property to hold the actual tree
        self.nodes = []
        # loop over the number of levels (max_depth+1)
        for depth in range(self.max_depth + 1):
            # the number of items at this depth is
            # math.ceil(self.total / 2**(self.max_depth - depth))
            num_items = math.ceil(self.total / 2 ** (self.max_depth - depth))
            # create this level's hashes list with the right number of items
            level_hashes = [None] * num_items
            # append this level's hashes to the merkle tree
            self.nodes.append(level_hashes)
        # set the pointer to the root (depth=0, index=0)
        self.current_depth = 0
        self.current_index = 0
        self.proved_txs = []

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = "None"
                else:
                    short = "{}...".format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    items.append("*{}*".format(short[:-2]))
                else:
                    items.append("{}".format(short))
            result.append(", ".join(items))
        return "\n".join(result)

    def up(self):
        # reduce depth by 1 and halve the index
        self.current_depth -= 1
        self.current_index //= 2

    def left(self):
        # increase depth by 1 and double the index
        self.current_depth += 1
        self.current_index *= 2

    def right(self):
        # increase depth by 1 and double the index + 1
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_index]

    def get_left_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self):
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1

    def populate_tree(self, flag_bits, hashes):
        # populate until we have the root
        while self.root() is None:
            # if we are a leaf, we know this position's hash
            if self.is_leaf():
                # get the next bit from flag_bits: flag_bits.pop(0)
                flag_bit = flag_bits.pop(0)
                # get the current hash from hashes: hashes.pop(0)
                current_hash = hashes.pop(0)
                # set the current node in the merkle tree to the current hash
                self.set_current_node(current_hash)
                # if our flag bit is 1, add to the self.proved_txs array
                if flag_bit == 1:
                    self.proved_txs.append(current_hash[::-1])
                # go up a level
                self.up()
            # else
            else:
                # get the left hash
                left_hash = self.get_left_node()
                # if we don't have the left hash
                if left_hash is None:
                    # if the next flag bit is 0, the next hash is our current node
                    if flag_bits.pop(0) == 0:
                        # set the current node to be the next hash
                        self.set_current_node(hashes.pop(0))
                        # sub-tree doesn't need calculation, go up
                        self.up()
                    # else
                    else:
                        # go to the left node
                        self.left()
                elif self.right_exists():
                    # get the right hash
                    right_hash = self.get_right_node()
                    # if we don't have the right hash
                    if right_hash is None:
                        # go to the right node
                        self.right()
                    # else
                    else:
                        # combine the left and right hashes
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        # we've completed this sub-tree, go up
                        self.up()
                # else
                else:
                    # combine the left hash twice
                    self.set_current_node(merkle_parent(left_hash, left_hash))
                    # we've completed this sub-tree, go up
                    self.up()
        if len(hashes) != 0:
            raise RuntimeError("hashes not all consumed {}".format(len(hashes)))
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError("flag bits not all consumed")


class MerkleBlock:
    command = b"merkleblock"

    def __init__(self, header, total, hashes, flags):
        self.header = header
        self.total = total
        self.hashes = hashes
        self.flags = flags
        self.merkle_tree = None

    def __repr__(self):
        result = "{}\n".format(self.total)
        for h in self.hashes:
            result += "\t{}\n".format(h.hex())
        result += "{}".format(self.flags.hex())

    def hash(self):
        return self.header.hash()

    def id(self):
        return self.header.id()

    @classmethod
    def parse(cls, s):
        """Takes a byte stream and parses a merkle block. Returns a Merkle Block object"""
        # s.read(n) will read n bytes from the stream
        # header - use Block.parse_header with the stream
        header = Block.parse_header(s)
        # total number of transactions (4 bytes, little endian)
        total = little_endian_to_int(s.read(4))
        # number of hashes is a varint
        num_txs = read_varint(s)
        # initialize the hashes array
        hashes = []
        # loop through the number of hashes times
        for _ in range(num_txs):
            # each hash is 32 bytes, little endian
            hashes.append(s.read(32)[::-1])
        # get the length of the flags field as a varint
        flags_length = read_varint(s)
        # read the flags field
        flags = s.read(flags_length)
        # initialize class
        return cls(header, total, hashes, flags)

    def is_valid(self):
        """Verifies whether the merkle tree information validates to the merkle root"""
        # use bytes_to_bit_field on self.flags to get the flag_bits
        flag_bits = bytes_to_bit_field(self.flags)
        # set hashes to be the reversed hashes of everything in self.hashes
        hashes = [h[::-1] for h in self.hashes]
        # initialize the merkle tree with self.total
        self.merkle_tree = MerkleTree(self.total)
        # populate_tree with flag_bits and hashes
        self.merkle_tree.populate_tree(flag_bits, hashes)
        # check if the computed root [::-1] is the same as the merkle root
        return self.merkle_tree.root()[::-1] == self.header.merkle_root

    def proved_txs(self):
        """Returns the list of proven transactions from the Merkle block"""
        if self.merkle_tree is None:
            return []
        else:
            return self.merkle_tree.proved_txs
