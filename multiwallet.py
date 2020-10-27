import re
import readline

from cmd import Cmd

from buidl.hd import HDPrivateKey, HDPublicKey
from buidl.helper import sha256
from buidl.mnemonic import WORD_LIST, WORD_LOOKUP
from buidl.script import P2WSHScriptPubKey, WitnessScript
from buidl.op import OP_CODE_NAMES_LOOKUP

readline.parse_and_bind("tab: complete")


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


def blue_fg(string):
    return f"{colors.fg.blue}{string}{colors.reset}"


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


def _re_pubkey_info_from_descriptor_fragment(fragment):
    xfp, path, xpub, idx = re.match(
        "\[([0-9a-f]+)\*?(.*?)\]([0-9A-Za-z]+).*([0-9]+?)",  # noqa: W605
        fragment,
    ).groups()
    return {
        "xfp": xfp,
        "path": path.replace("\\/", "/").lstrip("/"),
        "xpub": xpub,
        "idx": int(idx),
    }


def _get_pubkeys_info_from_descriptor(descriptor):
    re_results = re.findall("wsh\(sortedmulti\((.*)\)\)", descriptor)  # noqa: W605
    parts = re_results[0].split(",")
    quorum_m = int(parts.pop(0))
    quorum_n = len(parts)  # remaining entries are pubkeys with fingerprint/path
    assert 0 < quorum_m <= quorum_n

    pubkey_dicts = []
    for fragment in parts:
        pubkey_info = _re_pubkey_info_from_descriptor_fragment(fragment=fragment)
        parent_pubkey_obj = HDPublicKey.parse(pubkey_info["xpub"])
        pubkey_info["parent_pubkey_obj"] = parent_pubkey_obj
        pubkey_info["child_pubkey_obj"] = parent_pubkey_obj.child(
            index=pubkey_info["idx"]
        )
        pubkey_dicts.append(pubkey_info)

    # safety check
    all_pubkeys = [x["xpub"] for x in pubkey_dicts]
    assert (
        len(set([x[:4] for x in all_pubkeys])) == 1
    ), "ERROR: multiple conflicting networks in pubkeys: {}".format(all_pubkeys)

    return {
        "quorum_m": quorum_m,
        "quorum_n": quorum_n,
        "pubkey_dicts": pubkey_dicts,
    }


def _get_bip39_checksumwords():
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    fw = input(blue_fg("Enter your 23 word BIP39 seed phrase: ")).strip()
    fw_num = len(fw.split())
    if fw_num not in (11, 14, 17, 20, 23):
        # TODO: 11, 14, 17, or 20 word seed phrases also work but this is not documented as it's for advanced users
        print(red_fg(f"Enter 23 word seed-phrase (you entered {fw_num} words)"))
        return _get_bip39_checksumwords()
    for cnt, word in enumerate(fw.split()):
        if word not in WORD_LOOKUP:
            print(red_fg(f"Word #{cnt+1} ({word} is not a valid BIP39 word"))
            return _get_bip39_checksumwords()
    valid_checksum_words, err_str = get_all_valid_checksum_words(fw)
    if err_str:
        print(red_fg(f"Error calculating checksum word: {err_str}"))
        return _get_bip39_checksumwords()

    readline.set_completer(old_completer)
    return fw, valid_checksum_words


def _get_network():
    network = input(blue_fg("Network [Test/main]: ")).strip().lower()
    if network == "" or network in ("test", "testnet"):
        return "Testnet"
    if network in ("main", "mainet", "mainnet"):
        return "Mainnet"

    # Bad input, ask again
    print(red_fg("Please choose either test or main"))
    return _get_network()


def _get_int(prompt, default=20, minimum=0, maximum=20):
    res = input(blue_fg(f"{prompt} [{default}]: ")).strip()
    if not res:
        res = str(default)
    try:
        res_int = int(res)
    except ValueError:
        print(red_fg(f"{res} is not an integer"))
        return _get_int(
            prompt=prompt, default=default, minimum=minimum, maximum=maximum
        )
    if not minimum <= res_int <= maximum:
        print(red_fg(f"{res_int} must be between {minimum} and {maximum}"))
        return _get_int(
            prompt=prompt, default=default, minimum=minimum, maximum=maximum
        )
    return res_int


class MyPrompt(Cmd):
    def __init__(self):
        super().__init__()

    def do_seedpicker(self, arg):
        """Calculate bitcoin public and private key information from BIP39 words drawn out of a hat"""
        network = _get_network()
        first_words, valid_checksum_words = _get_bip39_checksumwords()

        if network == "Mainnet":
            PATH = "m/48'/0'/0'/2'"
            SLIP132_VERSION_BYTES = "02aa7ed3"
        elif network == "Testnet":
            PATH = "m/48'/1'/0'/2'"
            SLIP132_VERSION_BYTES = "02575483"

        hd_priv = HDPrivateKey.from_mnemonic(
            first_words + " " + valid_checksum_words[0]
        )

        print(green_fg("SECRET INFO") + red_fg(" guard this very carefully"))
        print(green_fg(f"Calculated last word: {valid_checksum_words[0]}"))
        print(
            green_fg(
                f"Full ({len(first_words.split()) + 1} word) mnemonic with last word: {first_words + ' ' + valid_checksum_words[0]}"
            )
        )

        print("")
        print(green_fg("PUBLIC KEY INFO"))
        print(green_fg(f"Network: {network}"))

        print(green_fg("Specter-Desktop Input Format:"))
        print(
            green_fg(
                "  [{}{}]{}".format(
                    hd_priv.fingerprint().hex(),
                    PATH.replace("m", "").replace("'", "h"),
                    hd_priv.traverse(PATH).xpub(
                        version=bytes.fromhex(SLIP132_VERSION_BYTES)
                    ),
                ),
            )
        )

    def do_verify_receive_address(self, arg):
        """Verify receive addresses for a multisig wallet (using output descriptors from Specter-Desktop)"""
        output_descriptor = input(
            blue_fg("Paste in your output descriptor from Specter-Desktop: ")
        ).strip()
        pubkeys_info = _get_pubkeys_info_from_descriptor(descriptor=output_descriptor)
        limit = _get_int(
            prompt="Limit of addresses to generate",
            default=20,
            minimum=1,
            maximum=10 ** 10,
        )
        offset = _get_int(
            prompt="Offset of addresses to generate - EXPERTS ONLY",
            default=0,
            minimum=0,
            maximum=10 ** 10,
        )

        for cnt in range(limit):
            sec_hexes_to_use = []
            for pubkey_info in pubkeys_info["pubkey_dicts"]:
                # import pdb; pdb.set_trace()
                leaf_xpub = pubkey_info["child_pubkey_obj"].child(index=cnt + offset)
                sec_hexes_to_use.append(leaf_xpub.sec().hex())

            commands = [OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_m"])]]
            commands.extend(
                [bytes.fromhex(x) for x in sorted(sec_hexes_to_use)]
            )  # BIP67
            commands.append(
                OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_n"])]
            )
            commands.append(OP_CODE_NAMES_LOOKUP["OP_CHECKMULTISIG"])
            witness_script = WitnessScript(commands)
            redeem_script = P2WSHScriptPubKey(sha256(witness_script.raw_serialize()))
            print(f"Address #{cnt + offset}: {redeem_script.address(testnet=True)}")

    def do_sign_psbt(self, arg):
        """Sign a PSBT from Specter-Desktop using one of your mnemonics"""
        pass

    def do_exit(self, arg):
        """Exit Program"""
        print("Quitting multiwallet, no data saved")
        return True


if __name__ == "__main__":
    MyPrompt().cmdloop()
