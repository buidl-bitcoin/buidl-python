from io import BytesIO

from buidl.helper import (
    encode_varint,
    encode_varstr,
    read_varint,
    read_varstr,
)
from buidl.script import Script
from buidl.taproot import ControlBlock, TapLeaf


class Witness:
    def __init__(self, items=None):
        self.items = items or []

    def __repr__(self):
        result = ""
        for item in self.items:
            if item == b"":
                result += "<null> "
            else:
                result += "{} ".format(item.hex())
        return result

    def __getitem__(self, key):
        return self.items[key]

    def __len__(self):
        return len(self.items)

    def clone(self):
        return self.__class__(self.items[:])

    def serialize(self):
        result = encode_varint(len(self))
        for item in self.items:
            if len(item) == 1:
                result += item
            else:
                result += encode_varstr(item)
        return result

    def has_annex(self):
        return len(self.items) and self.items[-1][0] == 0x50

    def control_block(self):
        if self.has_annex():
            return ControlBlock.parse(self.items[-2])
        else:
            return ControlBlock.parse(self.items[-1])

    def tap_script(self):
        if self.has_annex():
            raw_tap_script = self.items[-3]
        else:
            raw_tap_script = self.items[-2]
        return Script.parse(BytesIO(encode_varstr(raw_tap_script)))

    def tap_leaf(self):
        leaf_version = self.control_block().tapleaf_version
        return TapLeaf(self.tap_script(), leaf_version)

    @classmethod
    def parse(cls, s):
        num_items = read_varint(s)
        items = []
        for _ in range(num_items):
            items.append(read_varstr(s))
        return cls(items)
