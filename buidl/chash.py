from buidl._libsec import ffi, lib


GLOBAL_CTX = ffi.gc(
    lib.secp256k1_context_create(
        lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY
    ),
    lib.secp256k1_context_destroy,
)


def tagged_hash(tag, msg):
    result = ffi.new("unsigned char [32]")
    tag_length = len(tag)
    msg_length = len(msg)
    if not lib.secp256k1_tagged_sha256(
        GLOBAL_CTX,
        result,
        tag,
        tag_length,
        msg,
        msg_length,
    ):
        raise RuntimeError("libsecp256k1 tagged hash problem")
    return bytes(ffi.buffer(result, 32))


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

def hash_bip322message(msg: bytes):
    return tagged_hash(b"BIP0322-signed-message",msg)
