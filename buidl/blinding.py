from buidl.hd import HDPublicKey, is_valid_bip32_path
from secrets import randbelow


def secure_secret_path(depth=4):
    """
    Generate a secure_secret_path for blinding an xpub.

    Approx entropy by depth:

        for depth in range(1, 10): print(f"{depth}: {31*depth}")
        1: 31
        2: 62
        3: 93
        4: 124
        5: 155
        6: 186
        7: 217
        8: 248
        9: 279
    """
    if type(depth) != int:
        raise ValueError(f"depth must be an int: {depth}")
    if depth >= 32:
        raise ValueError(
            f"BIP32 requries depth < 256, but this function will not allow you to go anywhere near this high: {depth}"
        )
    if depth < 1:
        raise ValueError(f"Depth must be > 0: {depth}")
    to_return = ["m"]
    for _ in range(depth):
        # https://bitcoin.stackexchange.com/questions/92056/what-is-the-max-allowed-depth-for-bip32-derivation-paths#comment105756_92057
        rand_int = randbelow(2 ** 31 - 1)
        to_return.append(str(rand_int))
    return "/".join(to_return)


def blind_xpub(starting_xpub, starting_path, secret_path):
    """
    Blind a starting_xpub with a given (and unverifiable) path, using a secret path.

    Return the complete (combined) bip32 path, and
    """

    starting_xpub_obj = HDPublicKey.parse(starting_xpub)
    # Note that we cannot verify the starting path, so it is essential that at least this safety check is accurate
    if starting_xpub_obj.depth != starting_path.count("/"):
        raise ValueError(
            f"starting_xpub_obj.depth {starting_xpub_obj.depth} != starting_path depth {starting_path.count('/')}"
        )

    # This will automatically use the version byte that was parsed in the previous step
    blinded_child_xpub = starting_xpub_obj.traverse(secret_path).xpub()
    blinded_full_path = combine_bip32_paths(
        first_path=starting_path, second_path=secret_path
    )
    return {
        "blinded_child_xpub": blinded_child_xpub,
        "blinded_full_path": blinded_full_path,
    }


def combine_bip32_paths(first_path, second_path):
    for bip32_path in (first_path, second_path):
        if not is_valid_bip32_path(bip32_path):
            raise ValueError(f"Invalid bip32 path: {bip32_path}")

    # be forgiving
    first_path = first_path.lower().strip().replace("'", "h").replace("//", "/")
    second_path = second_path.lower().strip().replace("'", "h").replace("//", "/")

    if first_path == "m":
        return second_path

    if second_path == "m":
        return first_path

    # Trim of leading "m/" from second path:
    return f"{first_path}/{second_path[2:]}"
