from buidl.hd import HDPrivateKey
from buidl.mnemonic import WORD_LIST


FIRST_WORDS = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo"
PATH = "m/48'/0'/0'/2'"
VERSION_BYTES = "02aa7ed3"


def get_all_valid_checksum_words(first_words):
    to_return = []
    for word in WORD_LIST:
        try:
            HDPrivateKey.from_mnemonic(first_words + " " + word)
            to_return.append(word)
        except KeyError:
            # We have words in first_words that are not in WORD_LIST
            return []
        except ValueError:
            pass

    return to_return

valid_checksum_words = get_all_valid_checksum_words(FIRST_WORDS)

print("valid_checksum_words", valid_checksum_words)

result = HDPrivateKey.from_mnemonic(FIRST_WORDS + " " + valid_checksum_words[0])

xfp = result.fingerprint().hex()
print("xfp", xfp)

print("path", PATH)

child_slip132_pubkey = result.traverse(PATH).xpub(version=bytes.fromhex(VERSION_BYTES))
print("child_slip132_pubkey", child_slip132_pubkey)
