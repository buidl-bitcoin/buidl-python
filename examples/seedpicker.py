import argparse, sys

from buidl.hd import HDPrivateKey
from buidl.mnemonic import WORD_LIST


def get_all_valid_checksum_words(first_words):
    to_return = []
    for word in WORD_LIST:
        try:
            HDPrivateKey.from_mnemonic(first_words + " " + word)
            to_return.append(word)
        except KeyError as e:
            # We have a word in first_words that is not in WORD_LIST
            return [], "Invalid BIP39 Word: {}".format(e.args[0])
        except ValueError:
            pass

    return to_return, ""


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Calculate checksum word and display multisig extended pubkey information for your seed phrase"
    )
    parser.add_argument(
        "--firstWords",
        help="First words of your seed phrase that you want to find the appropriate final (checksum) word to append",
        required=True,
    )
    parser.add_argument(
        "--testnet",
        action="store_true",
        help="Generate extended pubkey info and BIP32 paths for testnet.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print out extra debugging info (experts only).",
    )

    args = parser.parse_args()

    FIRST_WORDS = args.firstWords.strip()

    if len(FIRST_WORDS.split()) not in (11, 14, 17, 20, 23):
        print(
            "Invalid firstWords length of {} words, must be 11, 14, 17, 20, or 23 words before appending a checksum.".format(
                len(FIRST_WORDS.split())
            )
        )
        sys.exit(1)

    if args.testnet:
        PATH = "m/48'/1'/0'/2'"
        SLIP132_VERSION_BYTES = "02575483"
    else:
        PATH = "m/48'/0'/0'/2'"
        SLIP132_VERSION_BYTES = "02aa7ed3"

    valid_checksum_words, err_str = get_all_valid_checksum_words(FIRST_WORDS)
    if err_str:
        print("Error calculating checksum:")
        print("  ", err_str)
        sys.exit(1)

    if not valid_checksum_words:
        print("No valid checksum word found")
        sys.exit(1)

    if args.verbose:
        print(
            "{} valid_checksum_words".format(len(valid_checksum_words)),
            valid_checksum_words,
        )

    result = HDPrivateKey.from_mnemonic(FIRST_WORDS + " " + valid_checksum_words[0])

    xfp = result.fingerprint().hex()

    print("SECRET INFO")
    print(
        "Full mnemonic (with checksum word):",
        FIRST_WORDS + " " + valid_checksum_words[0],
    )
    print("Full mnemonic length (# words):", len(FIRST_WORDS.split()) + 1)

    print("")
    print("PUBLIC KEY INFO")
    print("Network:", "Testnet" if args.testnet else "Mainnet")

    child_slip132_pubkey = result.traverse(PATH).xpub(
        version=bytes.fromhex(SLIP132_VERSION_BYTES)
    )
    if args.verbose:
        print("xfp:", xfp)
        print("path:", PATH)
        print("child_slip132_pubkey:", child_slip132_pubkey)

    print("Specter-Desktop Input Format:")
    print(
        "  [{}{}]{}".format(
            xfp, PATH.replace("m", "").replace("'", "h"), child_slip132_pubkey
        ),
    )
