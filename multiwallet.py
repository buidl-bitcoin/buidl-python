import re
import readline
import sys

from cmd import Cmd

from buidl.hd import HDPrivateKey, HDPublicKey
from buidl.helper import sha256, hash256
from buidl.mnemonic import WORD_LIST, WORD_LOOKUP
from buidl.psbt import PSBT
from buidl.script import P2WSHScriptPubKey, WitnessScript
from buidl.op import OP_CODE_NAMES, OP_CODE_NAMES_LOOKUP

readline.parse_and_bind("tab: complete")


# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
RESET_TERMINAL_COLOR = "\033[0m"
BLUE_FOREGOUND_COLOR = "\033[34m"
YELLOW_FOREGOUND_COLOR = "\033[93m"
GREEN_FOREGOUND_COLOR = "\033[32m"
RED_FOREGOUND_COLOR = "\033[31m"


def blue_fg(string):
    return f"{BLUE_FOREGOUND_COLOR}{string}{RESET_TERMINAL_COLOR}"


def yellow_fg(string):
    return f"{YELLOW_FOREGOUND_COLOR}{string}{RESET_TERMINAL_COLOR}"


def green_fg(string):
    return f"{GREEN_FOREGOUND_COLOR}{string}{RESET_TERMINAL_COLOR}"


def red_fg(string):
    return f"{RED_FOREGOUND_COLOR}{string}{RESET_TERMINAL_COLOR}"


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

    xpub_prefix = all_pubkeys[0][:4]
    if xpub_prefix == 'tpub':
        is_testnet = True
    elif xpub_prefix == 'xpub':
        is_testnet = False
    else:
        raise Exception(f"Invalid xpub prefix: {xpub_prefix}")

    return {
        "is_testnet": is_testnet,
        "quorum_m": quorum_m,
        "quorum_n": quorum_n,
        "pubkey_dicts": pubkey_dicts,
    }


def _get_bip39_seed_from_firstwords():
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    fw = input(blue_fg("Enter your 23 word BIP39 seed phrase: ")).strip()
    fw_num = len(fw.split())
    if fw_num not in (11, 14, 17, 20, 23):
        # TODO: 11, 14, 17, or 20 word seed phrases also work but this is not documented as it's for advanced users
        print(red_fg(f"Enter 23 word seed-phrase (you entered {fw_num} words)"))
        return _get_bip39_seed_from_firstwords()
    for cnt, word in enumerate(fw.split()):
        if word not in WORD_LOOKUP:
            print(red_fg(f"Word #{cnt+1} ({word} is not a valid BIP39 word"))
            return _get_bip39_seed_from_firstwords()
    valid_checksum_words, err_str = get_all_valid_checksum_words(fw)
    if err_str:
        print(red_fg(f"Error calculating checksum word: {err_str}"))
        return _get_bip39_seed_from_firstwords()

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


def _get_int(prompt, default=20, minimum=0):
    res = input(blue_fg(f"{prompt} [{default}]: ")).strip()
    if not res:
        res = str(default)
    try:
        res_int = int(res)
    except ValueError:
        print(red_fg(f"{res} is not an integer"))
        return _get_int(prompt=prompt, default=default, minimum=minimum)
    if minimum > res_int:
        print(red_fg(f"{res_int} must be < {minimum}"))
        return _get_int(prompt=prompt, default=default, minimum=minimum)
    return res_int


def _get_output_descriptor():
    output_descriptor = input(
        blue_fg("Paste in your output descriptor from Specter-Desktop: ")
    ).strip()
    try:
        return _get_pubkeys_info_from_descriptor(descriptor=output_descriptor)
    except Exception as e:
        print(red_fg(f"Could not parse output descriptor: {e}"))
        return _get_output_descriptor()


def _get_psbt_obj():
    psbt_b64 = input(
        blue_fg(f"Paste partially signed bitcoin transaction (PSBT) in base64 form: ")
    ).strip()
    try:
        psbt_obj = PSBT.parse_base64(psbt_b64)
        # redundant but explicit
        if psbt_obj.validate() is not True:
            raise Exception("PSBT does not validate")
    except Exception as e:
        print(red_fg(f"Could not parse PSBT: {e}"))
        return _get_psbt_obj()
    return psbt_obj


def _abort(msg):
    " Used because TX signing is complicated and we might bail after intial pasting of PSBT "
    print(red_fg("ABORTING WITHOUT SIGNING:\n"))
    print(red_fg(msg))
    return True


def _get_bool(prompt, default=True):
    if default is True:
        yn = "[Y/n]"
    else:
        yn = "[y/N]"
    response_str = input(blue_fg(f"{prompt} {yn}: ")).strip().lower()
    if response_str == "":
        return default
    if response_str in ("n", "no"):
        return False
    if response_str in ("y", "yes"):
        return True
    print(red_fg("Please choose either y or n"))
    return _get_bool(prompt=prompt, default=default)


def _get_detailed_summary():
    detailed_str = input(blue_fg(f"In Depth Transaction View? [y/N]: ")).strip().lower()
    if detailed_str in ("", "n", "no"):
        return False
    if detailed_str in ("y", "yes"):
        return True
    print(red_fg("Please choose either y or n"))
    return _get_detailed_summary()


def _get_hd_priv_from_bip39_seed(is_testnet):
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    seed_phrase = input(blue_fg("Enter your 24 word BIP39 seed phrase: ")).strip()
    seed_phrase_num = len(seed_phrase.split())
    if seed_phrase_num not in (12, 15, 18, 21, 24):
        print(
            red_fg(f"Enter 24 word seed-phrase (you entered {seed_phrase_num} words)")
        )
        # Other length seed phrases also work but this is not documented as it's for advanced users
        return _get_hd_priv_from_bip39_seed(is_testnet=is_testnet)
    for cnt, word in enumerate(seed_phrase.split()):
        if word not in WORD_LOOKUP:
            print(red_fg(f"Word #{cnt+1} ({word}) is not a valid BIP39 word"))
            return _get_hd_priv_from_bip39_seed(is_testnet=is_testnet)
    try:
        hd_priv = HDPrivateKey.from_mnemonic(seed_phrase, testnet=is_testnet)
    except Exception as e:
        print(red_fg(f"Invalid mnemonic: {e}"))
        return _get_hd_priv_from_bip39_seed(is_testnet=is_testnet)

    readline.set_completer(old_completer)
    return hd_priv


def _get_units():
    units = input(blue_fg(f"Units to diplay [BTC/sats]: ")).strip().lower()
    if units in ("", "btc", "btcs", "bitcoin", "bitcoins"):
        return "btc"
    if units in ("sat", "satoshis", "sats"):
        return "sats"
    print(red_fg("Please choose either BTC or sats"))
    return units


def _format_satoshis(sats, in_btc=False):
    if in_btc:
        btc = sats / 10 ** 8
        return f"{btc:,.8f} BTC"
    return f"{sats:,} sats"


# TODO: is there a standard to use here?
# Inspired by https://github.com/trezor/trezor-firmware/blob/e23bb10ec49710cc2b2b993db9c907d3c7becf2c/core/src/apps/wallet/sign_tx/multisig.py#L37
def calculate_msig_digest(quorum_m, root_xfp_hexes):
    fingerprints_to_hash = "-".join(sorted(root_xfp_hexes))
    return hash256(f"{quorum_m}:{fingerprints_to_hash}".encode()).hex()


def _is_libsec_enabled():
    try:
        from buidl import cecc

        return True
    except ModuleNotFoundError:
        return False


class MyPrompt(Cmd):
    intro = "Welcome to multiwallet, a stateless multisig ONLY wallet. Type help or ? to list commands.\n"
    prompt = "(₿) "  # the bitcoin symbol :)

    def __init__(self):
        super().__init__()

    def do_seedpicker(self, arg):
        """Calculate bitcoin public and private key information from BIP39 words you draw out of a hat"""
        network = _get_network()
        first_words, valid_checksum_words = _get_bip39_seed_from_firstwords()

        if network == "Mainnet":
            PATH = "m/48'/0'/0'/2'"
            SLIP132_VERSION_BYTES = "02aa7ed3"
        elif network == "Testnet":
            PATH = "m/48'/1'/0'/2'"
            SLIP132_VERSION_BYTES = "02575483"

        hd_priv = HDPrivateKey.from_mnemonic(
            first_words + " " + valid_checksum_words[0]
        )

        print(green_fg("SECRET INFO") + yellow_fg("( guard this VERY carefully)"))
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
        pubkeys_info = _get_output_descriptor()
        limit = _get_int(
            prompt="Limit of addresses to display",
            default=20,  # This is slow without libsecp256k1 :(
            minimum=1,
        )
        offset = _get_int(
            prompt="Offset of addresses to display",
            default=0,
            minimum=0,
        )

        print(
            green_fg(
                f"Multisig Addresses:{'(this would be 100x faster with libsec bindings)' if not _is_libsec_enabled() else ''}"
            )
        )
        for cnt in range(limit):
            sec_hexes_to_use = []
            for pubkey_info in pubkeys_info["pubkey_dicts"]:
                # import pdb; pdb.set_trace()
                leaf_xpub = pubkey_info["child_pubkey_obj"].child(index=cnt + offset)
                sec_hexes_to_use.append(leaf_xpub.sec().hex())

            commands = [OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_m"])]]
            commands.extend(
                [bytes.fromhex(x) for x in sorted(sec_hexes_to_use)]  # BIP67
            )
            commands.append(
                OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_n"])]
            )
            commands.append(OP_CODE_NAMES_LOOKUP["OP_CHECKMULTISIG"])
            witness_script = WitnessScript(commands)
            redeem_script = P2WSHScriptPubKey(sha256(witness_script.raw_serialize()))
            print(
                green_fg(
                    f"#{cnt + offset}: {redeem_script.address(testnet=pubkeys_info['is_testnet'])}"
                )
            )

    def do_psbt_signer(self, arg):
        """Sign a multisig PSBT from using 1 of your BIP39 seed phrases"""
        psbt_obj = _get_psbt_obj()
        TX_FEE_SATS = psbt_obj.tx_obj.fee()
        IS_TESTNET = psbt_obj.tx_obj.testnet

        hd_priv = _get_hd_priv_from_bip39_seed(is_testnet=IS_TESTNET)

        # Validate multisig transaction
        # TODO: abstract some of this into buidl library?
        # Below is confusing because we perform both validation and coordinate signing.

        # This tool only supports a TX with the following constraints:
        #   We sign ALL inputs and they have the same multisig wallet (quorum + pubkeys)
        #   There can only be 1 output (sweep transaction) or 2 outputs (spend + change).
        #   If there is change, we validate it has the same multisig wallet as the inputs we sign.

        # Gather TX info and validate
        inputs_desc = []
        for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):
            psbt_in.validate()  # redundant but explicit

            if type(psbt_in.witness_script) != WitnessScript:
                return _abort(
                    f"Input #{cnt} does not contain a witness script, this tool can only sign p2wsh transactions."
                )

            # Determine quroum_m (and that it hasn't changed between inputs)
            try:
                quorum_m = OP_CODE_NAMES[psbt_in.witness_script.commands[0]].split(
                    "OP_"
                )[1]
            except Exception:
                return _abort(
                    f"Witness script for input #{cnt} is not p2wsh:\n{psbt_in})"
                )

            root_path_used = None
            root_xfp_hexes = []  # for calculating msig fingerprint
            for _, details in psbt_in.named_pubs.items():
                root_xfp_hexes.append(details.root_fingerprint.hex())
                if details.root_fingerprint.hex() == hd_priv.fingerprint().hex():
                    root_path_used = details.root_path

            input_desc = {
                "quorum": f"{quorum_m}-of-{len(root_xfp_hexes)}",
                "root_xfp_hexes": root_xfp_hexes,
                "root_path_used": root_path_used,
                "prev_txhash": psbt_in.tx_in.prev_tx.hex(),
                "prev_idx": psbt_in.tx_in.prev_index,
                "n_sequence": psbt_in.tx_in.sequence,
                "sats": psbt_in.tx_in.value(),
                # TODO: would be possible for transaction to be p2sh-wrapped p2wsh (can we tell?)
                "addr": psbt_in.witness_script.address(testnet=IS_TESTNET),
                # "p2sh_addr": psbt_in.witness_script.p2sh_address(testnet=IS_TESTNET),
                "witness_script": str(psbt_in.witness_script),
                "msig_digest": calculate_msig_digest(
                    quorum_m=quorum_m, root_xfp_hexes=root_xfp_hexes
                ),
            }
            if not root_path_used:
                return _abort(
                    f"This key is not a participant in input #{cnt}:\n{input_desc}"
                )

            inputs_desc.append(input_desc)

        if not all(
            x["msig_digest"] == inputs_desc[0]["msig_digest"] for x in inputs_desc
        ):
            return _abort(
                "Multiple different multisig quorums in inputs. Construct a transaction with one input to continue."
            )

        TOTAL_INPUT_SATS = sum([x["sats"] for x in inputs_desc])

        # This too only supports TXs with 1-2 outputs (sweep TX OR spend+change TX):
        if len(psbt_obj.psbt_outs) > 2:
            return _abort(
                f"This tool does not support batching, your transaction has {len(psbt_obj.psbt_outs)} outputs. Please construct a transaction with <= 2 outputs."
            )

        spend_addr, change_addr = "", ""
        output_spend_sats, output_change_sats = 0, 0
        outputs_desc = []
        for cnt, psbt_out in enumerate(psbt_obj.psbt_outs):
            psbt_out.validate()  # redundant but explicit

            output_desc = {
                "sats": psbt_out.tx_out.amount,
                "addr_type": psbt_out.tx_out.script_pubkey.__class__.__name__.rstrip(
                    "ScriptPubKey"
                ),
                "is_change": False,
            }

            if psbt_out.witness_script:
                output_desc["addr"] = psbt_out.witness_script.address(
                    testnet=IS_TESTNET
                )
            else:
                output_desc["addr"] = psbt_out.tx_out.script_pubkey.address(
                    testnet=IS_TESTNET
                )

            if psbt_out.named_pubs:
                # Validate below that this is correct and abort otherwise
                output_desc["is_change"] = True
                change_addr = output_desc["addr"]
                output_change_sats = output_desc["sats"]

                root_xfp_hexes = []  # for calculating msig fingerprint
                for _, details in psbt_out.named_pubs.items():
                    root_xfp_hexes.append(details.root_fingerprint.hex())

                # Determine quroum_m (and that it hasn't changed between inputs)
                try:
                    quorum_m = OP_CODE_NAMES[psbt_out.witness_script.commands[0]].split(
                        "OP_"
                    )[1]
                except Exception:
                    return _abort(
                        f"Witness script for input #{cnt} is not p2wsh:\n{psbt_in})"
                    )

                output_msig_digest = calculate_msig_digest(
                    quorum_m=quorum_m, root_xfp_hexes=root_xfp_hexes
                )
                if (
                    output_msig_digest != inputs_desc[0]["msig_digest"]
                ):  # ALL inputs have the same msig_digest
                    return _abort(
                        f"Output #{cnt} is claiming to be change but has different multisig wallet(s)! Do a sweep transaction (1-output) if you want this wallet to cosign."
                    )
            else:
                output_desc["is_change"] = False
                spend_addr = output_desc["addr"]
                output_spend_sats = output_desc["sats"]

            outputs_desc.append(output_desc)

        # Sanity check
        if len(outputs_desc) != len(psbt_obj.psbt_outs):
            return _abort(
                f"{len(outputs_desc)} outputs in summary doesn't match {len(psbt_obj.psbt_outs)} outputs in PSBT"
            )

        # Confirm if 2 outputs we only have 1 change and 1 spend (can't be 2 changes or 2 spends)
        if len(outputs_desc) == 2:
            if all(
                x["is_change"] == outputs_desc[0]["is_change"] for x in outputs_desc
            ):
                return _abort(
                    f"Cannot have both outputs be change or spend, must be 1-and-1. {outputs_desc}"
                )

        # Derive list of child private keys we'll use to sign the TX
        private_keys = []
        for root_path in set([x["root_path_used"] for x in inputs_desc]):
            private_keys.append(hd_priv.traverse(root_path).private_key)

        UNITS = _get_units()
        TX_SUMMARY = " ".join(
            [
                "send",
                _format_satoshis(output_spend_sats, in_btc=UNITS == "btc"),
                "to",
                spend_addr,
                "with a fee of",
                _format_satoshis(TX_FEE_SATS, in_btc=UNITS == "btc"),
                f"({round(TX_FEE_SATS / TOTAL_INPUT_SATS * 100, 2)}% of spend)",
            ]
        )
        print(green_fg(f"Transaction Summary: {TX_SUMMARY}"))

        if _get_bool("In Depth Transaction View?", default=False):
            print(green_fg("-" * 80))
            print(green_fg("DETAILED VIEW"))
            print(green_fg(f"TXID: {psbt_obj.tx_obj.id()}"))
            print(green_fg(f"{len(inputs_desc)} input(s):"))
            for cnt, input_desc in enumerate(inputs_desc):
                print(green_fg(f"  Input #{cnt}"))
                for (
                    k,
                    v,
                ) in input_desc.items():
                    print(green_fg(f"    {k}: {v}"))
            print(green_fg(f"{len(outputs_desc)} output(s):"))
            for cnt, output_desc in enumerate(outputs_desc):
                print(green_fg(f"  Output #{cnt}"))
                for (
                    k,
                    v,
                ) in output_desc.items():
                    print(green_fg(f"    {k}: {v}"))
            print("-" * 80)

        if not _get_bool("Sign this transaction?", default=True):
            return

        if psbt_obj.sign_with_private_keys(private_keys) is True:
            print()
            print(green_fg(f"Signed PSBT to broadcast:\n"))
            print(green_fg(psbt_obj.serialize_base64()))
        else:
            return _abort("PSBT wasn't signed")

    def do_exit(self, arg):
        """Exit Program"""
        print(yellow_fg("Quitting multiwallet, "))
        return True


if __name__ == "__main__":
    try:
        MyPrompt().cmdloop()
    except KeyboardInterrupt:
        print(yellow_fg("\nNo data saved\n"))
        sys.exit(0)
