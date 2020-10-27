import readline

from cmd import Cmd

from buidl.hd import HDPrivateKey
from buidl.mnemonic import WORD_LIST, WORD_LOOKUP

# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python


class colors:
    """Colors class:
    reset all colors with colors.reset
    two subclasses fg for foreground and bg for background.
    use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.green
    also, the generic bold, disable, underline, reverse, strikethrough,
    and invisible work with the main class
    i.e. colors.bold
    """

    reset = "\033[0m"
    bold = "\033[01m"
    disable = "\033[02m"
    underline = "\033[04m"
    reverse = "\033[07m"
    strikethrough = "\033[09m"
    invisible = "\033[08m"

    class fg:
        black = "\033[30m"
        red = "\033[31m"
        green = "\033[32m"
        orange = "\033[33m"
        blue = "\033[34m"
        purple = "\033[35m"
        cyan = "\033[36m"
        lightgrey = "\033[37m"
        darkgrey = "\033[90m"
        lightred = "\033[91m"
        lightgreen = "\033[92m"
        yellow = "\033[93m"
        lightblue = "\033[94m"
        pink = "\033[95m"
        lightcyan = "\033[96m"

    class bg:
        black = "\033[40m"
        red = "\033[41m"
        green = "\033[42m"
        orange = "\033[43m"
        blue = "\033[44m"
        purple = "\033[45m"
        cyan = "\033[46m"
        lightgrey = "\033[47m"


def yellow_fg(string):
    return f"{colors.fg.yellow}{string}{colors.reset}"


def green_fg(string):
    return f"{colors.fg.green}{string}{colors.reset}"


def red_fg(string):
    return f"{colors.fg.red}{string}{colors.reset}"


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


class WordCompleter:
    def __init__(self, wordlist):
        self.wordlist = wordlist

    def complete(self, text, state):
        results = [x for x in self.wordlist if x.startswith(text)] + [None]
        return results[state] + " "


readline.parse_and_bind("tab: complete")


def _get_bip39_firstwords():
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    fw = input("Enter your 23 word BIP39 seed phrase: ").strip()
    fw_num = len(fw.split())
    if fw_num not in (11, 14, 17, 20, 23):
        # TODO: 11, 14, 17, or 20 word seed phrases also work but this is not documented as it's for advanced users
        print(red_fg(f"Enter 23 word seed-phrase (you entered {fw_num} words)"))
        return _get_bip39_firstwords()
    for cnt, word in enumerate(fw.split()):
        if word not in WORD_LOOKUP:
            print(red_fg(f"Word #{cnt+1} ({word} is not a valid BIP39 word"))
            return _get_bip39_firstwords()
    valid_checksum_words, err_str = get_all_valid_checksum_words(fw)
    if err_str:
        print(red_fg(f"Error calculating checksum word: {err_str}"))
        return _get_bip39_firstwords()

    readline.set_completer(old_completer)
    return fw, valid_checksum_words


def _is_testnet():
    network = input("Network [Test/main]: ")
    if network.strip() == "" or network.strip().lower() in ("test", "testnet"):
        return True
    if network.strip().lower() in ("main", "mainet", "mainnet"):
        return False

    # Bad input, ask again
    print(red_fg("Please choose either test or main"))
    return _is_testnet()


class MyPrompt(Cmd):
    def __init__(self):
        super().__init__()

    def do_seedpicker(self, arg):
        """Calculate bitcoin public and private key information from BIP39 words drawn out of a hat"""
        is_testnet = _is_testnet()
        print("is_testnet", yellow_fg(is_testnet))
        first_words, valid_checksum_words = _get_bip39_firstwords()
        print("words entered: ", first_words)

        print(f"Last word: {valid_checksum_words[0]}")

        if is_testnet:
            PATH = "m/48'/1'/0'/2'"
            SLIP132_VERSION_BYTES = "02575483"
        else:
            PATH = "m/48'/0'/0'/2'"
            SLIP132_VERSION_BYTES = "02aa7ed3"

        hd_priv = HDPrivateKey.from_mnemonic(
            first_words + " " + valid_checksum_words[0]
        )
        xfp = hd_priv.fingerprint().hex()

        print("SECRET INFO")
        print(
            "Full mnemonic (with checksum word):",
            first_words + " " + valid_checksum_words[0],
        )
        print("Full mnemonic length (# words):", len(first_words.split()) + 1)

        print("")
        print("PUBLIC KEY INFO")
        print("Network:", "Testnet" if is_testnet else "Mainnet")

        child_slip132_pubkey = hd_priv.traverse(PATH).xpub(
            version=bytes.fromhex(SLIP132_VERSION_BYTES)
        )
        if False:
            # TODO: add verbosity flag
            print("xfp:", xfp)
            print("path:", PATH)
            print("child_slip132_pubkey:", child_slip132_pubkey)

        print("Specter-Desktop Input Format:")
        print(
            "  [{}{}]{}".format(
                xfp, PATH.replace("m", "").replace("'", "h"), child_slip132_pubkey
            ),
        )

    def do_exit(self, arg):
        """Exit Program"""
        print("Quitting multiwallet, no data saved")
        return True


if __name__ == "__main__":
    MyPrompt().cmdloop()
