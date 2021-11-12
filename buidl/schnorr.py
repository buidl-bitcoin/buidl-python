from buidl.helper import sha256


TAGS = {
    "aux": sha256(b"BIP0340/aux") + sha256(b"BIP0340/aux"),
    "nonce": sha256(b"BIP0340/nonce") + sha256(b"BIP0340/nonce"),
    "challenge": sha256(b"BIP0340/challenge") + sha256(b"BIP0340/challenge"),
}


def tagged_hash(tag, msg):
    return sha256(TAGS[tag] + msg)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
