from os import path
from secrets import randbits
from time import time

from buidl.helper import big_endian_to_int, int_to_big_endian, sha256


class InvalidBIP39Length(Exception):
    pass


class InvalidChecksumWordsError(Exception):
    pass


def secure_mnemonic(num_bits=256, extra_entropy=0):
    """
    Generates a mnemonic phrase using num_bits of entropy
    extra_entropy is optional and should not be saved as it is NOT SUFFICIENT to recover your mnemonic.
    extra_entropy exists only to prevent 100% reliance on your random number generator.
    """
    if num_bits not in (128, 160, 192, 224, 256):
        raise ValueError(f"Invalid num_bits: {num_bits}")
    if type(extra_entropy) is not int:
        raise TypeError(f"extra_entropy must be an int: {extra_entropy}")
    if extra_entropy < 0:
        raise ValueError(f"extra_entropy cannot be negative: {extra_entropy}")

    # if we have more bits than needed, mask so we get what we need
    if len(bin(extra_entropy)) > num_bits + 2:
        extra_entropy &= (1 << num_bits) - 1

    # For added paranoia, xor current epoch to extra_entropy
    # Would use time.time_ns() but that requires python3.7
    extra_entropy ^= int(time() * 1_000_000)

    # xor some random bits with the extra_entropy that was passed in
    preseed = randbits(num_bits) ^ extra_entropy
    # convert the number to big-endian
    s = int_to_big_endian(preseed, num_bits // 8)
    # convert to mnemonic
    mnemonic = bytes_to_mnemonic(s, num_bits)
    # sanity check
    if mnemonic_to_bytes(mnemonic) != s:
        raise RuntimeError("Generated mnemonic does not correspond to random bits")
    return mnemonic


def mnemonic_to_bytes(mnemonic):
    """returns a byte representation of the mnemonic"""
    all_bits = 0
    words = mnemonic.split()
    # check that there are 12, 15, 18, 21 or 24 words
    # if not, raise a ValueError
    if len(words) not in (12, 15, 18, 21, 24):
        raise InvalidBIP39Length(
            f"{len(words)} words (you need 12, 15, 18, 21, or 24 words)"
        )
    num_words = len(words)
    for word in words:
        all_bits <<= 11
        all_bits += BIP39[word]
    num_checksum_bits = num_words // 3
    checksum = all_bits & ((1 << num_checksum_bits) - 1)
    all_bits >>= num_checksum_bits
    num_bytes = (num_words * 11 - num_checksum_bits) // 8
    s = int_to_big_endian(all_bits, num_bytes)
    computed_checksum = sha256(s)[0] >> (8 - num_checksum_bits)
    if checksum != computed_checksum:
        raise InvalidChecksumWordsError("Checksum is wrong")
    return s


def bytes_to_mnemonic(b, num_bits):
    """returns a mnemonic given a byte representation"""
    if num_bits not in (128, 160, 192, 224, 256):
        raise InvalidBIP39Length(
            f"{num_bits} bits (you need 128, 160, 192, 224 or 256 bits)"
        )
    preseed = big_endian_to_int(b)
    # 1 extra bit for checksum is needed per 32 bits
    num_checksum_bits = num_bits // 32
    # the checksum is the sha256's first n bits. At most this is 8
    checksum = sha256(b)[0] >> (8 - num_checksum_bits)
    # we concatenate the checksum to the preseed
    all_bits = (preseed << num_checksum_bits) | checksum
    # now we get the mnemonic passphrase
    mnemonic = []
    # now group into groups of 11 bits
    for _ in range((num_bits + num_checksum_bits) // 11):
        # grab the last 11 bits
        current = all_bits & ((1 << 11) - 1)
        # insert the correct word at the front
        mnemonic.insert(0, BIP39[current])
        # shift by 11 bits so we can move to the next set
        all_bits >>= 11
    # return the mnemonic phrase by putting spaces between
    return " ".join(mnemonic)


class WordList:
    def __init__(self, filename, num_words):
        word_file = path.join(path.dirname(__file__), filename)
        with open(word_file, "r") as f:
            self.words = f.read().split()
        if len(self.words) != num_words:
            raise ValueError(f"Expected {num_words} but got {len(self.words)}")
        self.lookup = {}
        for i, word in enumerate(self.words):
            # add the word's index in the dict lookup
            self.lookup[word] = i
            # if the word is more than 4 characters, also keep
            #  a lookup of just the first 4 characters
            if len(word) > 4:
                self.lookup[word[:4]] = i

    def __getitem__(self, key):
        if type(key) == str:
            return self.lookup[key]
        elif type(key) == int:
            return self.words[key]
        else:
            raise KeyError("key needs to be a str or int")

    def __iter__(self):
        for word in self.words:
            yield word

    def __contains__(self, key):
        return key in self.words

    def normalize(self, word):
        return self[self[word.lower()]]


BIP39 = WordList("bip39_words.txt", 2048)
