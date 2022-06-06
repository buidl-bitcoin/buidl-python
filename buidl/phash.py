import hashlib


TAG_HASH_CACHE = {}


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    if TAG_HASH_CACHE.get(tag) is None:
        TAG_HASH_CACHE[tag] = hashlib.sha256(tag).digest() * 2
    return hashlib.sha256(TAG_HASH_CACHE[tag] + msg).digest()


def hash_aux(msg):
    return tagged_hash(b"BIP0340/aux", msg)


def hash_challenge(msg):
    return tagged_hash(b"BIP0340/challenge", msg)


def hash_keyaggcoef(msg):
    return tagged_hash(b"KeyAgg coefficient", msg)


def hash_keyagglist(msg):
    return tagged_hash(b"KeyAgg list", msg)


def hash_musignonce(msg):
    return tagged_hash(b"MuSig/noncecoef", msg)


def hash_nonce(msg):
    return tagged_hash(b"BIP0340/nonce", msg)


def hash_tapbranch(msg):
    return tagged_hash(b"TapBranch", msg)


def hash_tapleaf(msg):
    return tagged_hash(b"TapLeaf", msg)


def hash_tapsighash(msg):
    return tagged_hash(b"TapSighash", msg)


def hash_taptweak(msg):
    return tagged_hash(b"TapTweak", msg)


def hash_bip322message(msg):
    return tagged_hash(b"BIP0322-signed-message",msg)