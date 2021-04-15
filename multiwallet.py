#!/usr/bin/env python3
import readline
import sys
from cmd import Cmd
from getpass import getpass
from os import environ
from platform import platform
from pkg_resources import DistributionNotFound, get_distribution

import buidl  # noqa: F401 (used below with pkg_resources for versioning)
from buidl.hd import (
    calc_num_valid_seedpicker_checksums,
    calc_valid_seedpicker_checksums,
    HDPrivateKey,
    HDPublicKey,
    parse_wshsortedmulti,
)
from buidl.helper import sha256, hash256
from buidl.libsec_status import is_libsec_enabled
from buidl.mnemonic import WORD_LIST, WORD_LOOKUP
from buidl.psbt import MixedNetwork, PSBT
from buidl.script import P2WSHScriptPubKey, WitnessScript
from buidl.op import OP_CODE_NAMES, OP_CODE_NAMES_LOOKUP

readline.parse_and_bind("tab: complete")  # TODO: can this be moved inside a method?


#####################################################################
# CLI UX
#####################################################################


# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
RESET_TERMINAL_COLOR = "\033[0m"


DEFAULT_TESTNET_PATH = "m/48'/1'/0'/2'"
DEFAULT_MAINNET_PATH = "m/48'/0'/0'/2'"


def blue_fg(string):
    return f"\033[34m{string}{RESET_TERMINAL_COLOR}"


def yellow_fg(string):
    return f"\033[93m{string}{RESET_TERMINAL_COLOR}"


def green_fg(string):
    return f"\033[32m{string}{RESET_TERMINAL_COLOR}"


def red_fg(string):
    return f"\033[31m{string}{RESET_TERMINAL_COLOR}"


def print_blue(string):
    print(blue_fg(string))


def print_yellow(string):
    print(yellow_fg(string))


def print_green(string):
    print(green_fg(string))


def print_red(string):
    print(red_fg(string))


def _get_buidl_version():
    try:
        return get_distribution("buidl").version
    except DistributionNotFound:
        return "Unknown"


def _get_int(prompt, default=20, minimum=0, maximum=None):
    res = input(blue_fg(f"{prompt} [{default}]: ")).strip()
    if not res:
        res = str(default)
    try:
        res_int = int(res)
    except ValueError:
        print_red(f"{res} is not an integer")
        return _get_int(
            prompt=prompt,
            default=default,
            minimum=minimum,
            maximum=maximum,
        )

    if maximum is not None:
        if not minimum <= res_int <= maximum:
            print_red(
                f"Please pick a number between {minimum} and {maximum} (inclusive)"
            )
            return _get_int(
                prompt=prompt, default=default, minimum=minimum, maximum=maximum
            )
    elif res_int < minimum:
        print_red(f"Please pick a number >= {minimum}")
        return _get_int(
            prompt=prompt, default=default, minimum=minimum, maximum=maximum
        )

    return res_int


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
    print_red("Please choose either y or n")
    return _get_bool(prompt=prompt, default=default)


def _get_path_string():
    res = input(blue_fg('Path to use (should start with "m/"): ')).strip().lower()
    if not res.startswith("m/"):
        print_red(f'Invalid path "{res}" must start with "m/")')
        return _get_path_string()
    if res == "m/":
        # TODO: support this?
        print_red("Empty path (must have a depth of > 0): m/somenumberhere")
        return _get_path_string()
    for sub_path in res.split("/")[1:]:
        if sub_path.endswith("'") or sub_path.endswith("h"):
            # Trim trailing hardening indicator
            sub_path_cleaned = sub_path[:-1]
        else:
            sub_path_cleaned = sub_path
        try:
            int(sub_path_cleaned)
        except Exception:
            print_red(f"Invalid Path Section: {sub_path}")
            return _get_path_string()
    return res.replace("h", "'")


def _get_path(is_testnet):
    if is_testnet:
        network_string = "Testnet"
        default_path = DEFAULT_TESTNET_PATH
    else:
        network_string = "Mainnet"
        default_path = DEFAULT_MAINNET_PATH

    if _get_bool(
        prompt=f"Use default path ({default_path} for {network_string})",
        default=True,
    ):
        return default_path
    else:
        return _get_path_string()


def _get_confirmed_pw():
    first = getpass(prompt=blue_fg("Enter custom passphrase: "))
    if first.strip() != first:
        print_red(
            "Leading/trailing spaces in passphrases are not supported. "
            "Please use an unambiguous passphrase."
        )
        return _get_confirmed_pw()
    second = getpass(prompt=blue_fg("Confirm custom passphrase: "))
    if first != second:
        print_red("Passphrases don't match, please try again.")
        return _get_confirmed_pw()
    return first


def _get_password():
    if _get_bool(
        prompt="Use a passphrase (advanced users only)?",
        default=False,
    ):
        return _get_confirmed_pw()
    else:
        return ""


class WordCompleter:
    def __init__(self, wordlist):
        self.wordlist = wordlist

    def complete(self, text, state):
        results = [x for x in self.wordlist if x.startswith(text)] + [None]
        return results[state] + " "


#####################################################################
# Verify Receive Address
#####################################################################


def _get_output_record():
    output_record = input(
        blue_fg("Paste in your output record (collection of output descriptors): ")
    ).strip()
    try:
        return parse_wshsortedmulti(output_record=output_record)
    except Exception as e:
        print_red(f"Could not parse output descriptor: {e}")
        return _get_output_record()


#####################################################################
# Seedpicker
#####################################################################


def _get_bip39_firstwords():
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    fw = input(blue_fg("Enter the first 23 words of your BIP39 seed phrase: ")).strip()
    fw_num = len(fw.split())
    if fw_num not in (11, 14, 17, 20, 23):
        # TODO: 11, 14, 17, or 20 word seed phrases also work but this is not documented as it's for advanced users
        print_red(
            f"You entered {fw_num} words. "
            "We recommend 23 words, but advanced users may enter 11, 14, 17 or 20 words."
        )
        return _get_bip39_firstwords()
    for cnt, word in enumerate(fw.split()):
        if word not in WORD_LOOKUP:
            print_red(f"Word #{cnt+1} ({word} is not a valid BIP39 word")
            return _get_bip39_firstwords()

    readline.set_completer(old_completer)
    return fw


#####################################################################
# PSBT Signer
#####################################################################


def _get_psbt_obj():
    psbt_b64 = input(
        blue_fg("Paste partially signed bitcoin transaction (PSBT) in base64 form: ")
    ).strip()
    if not psbt_b64:
        return _get_psbt_obj()

    try:
        # Attempt to infer network from BIP32 paths
        psbt_obj = PSBT.parse_base64(psbt_b64, testnet=None)
        if psbt_obj.testnet:
            use_testnet = _get_bool(
                prompt="Transaction appears to be a testnet transaction. Display as testnet?",
                default=True,
            )
        else:
            use_testnet = not _get_bool(
                prompt="Transaction appears to be a mainnet transaction. Display as mainnet?",
                default=True,
            )
        if psbt_obj.testnet != use_testnet:
            psbt_obj = PSBT.parse_base64(psbt_b64, testnet=use_testnet)

    except MixedNetwork:
        use_testnet = not _get_bool(
            prompt="Cannot infer PSBT network from BIP32 paths. Use Mainnet?",
            default=True,
        )
        psbt_obj = PSBT.parse_base64(psbt_b64, testnet=use_testnet)

    except Exception as e:
        print_red(f"Could not parse PSBT: {e}")
        return _get_psbt_obj()

    # redundant but explicit
    if psbt_obj.validate() is not True:
        print_red("PSBT does not validate")
        return _get_psbt_obj()

    return psbt_obj


def _abort(msg):
    " Used because TX signing is complicated and we might bail after intial pasting of PSBT "
    print_red("ABORTING WITHOUT SIGNING:\n")
    print_red(msg)
    return True


def _get_bip39_seed(is_testnet):
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=WORD_LIST)

    readline.set_completer(completer.complete)
    seed_phrase = input(blue_fg("Enter your full BIP39 seed phrase: ")).strip()
    seed_phrase_num = len(seed_phrase.split())
    if seed_phrase_num not in (12, 15, 18, 21, 24):
        print_red(
            f"You entered {seed_phrase_num} words. "
            "By default seed phrases are 24 words long, but advanced users may have seed phrases that are 12, 15, 18 or 21 words long."
        )
        # Other length seed phrases also work but this is not documented as it's for advanced users
        return _get_bip39_seed(is_testnet=is_testnet)
    for cnt, word in enumerate(seed_phrase.split()):
        if word not in WORD_LOOKUP:
            print_red(f"Word #{cnt+1} ({word}) is not a valid BIP39 word")
            return _get_bip39_seed(is_testnet=is_testnet)
    try:
        _ = HDPrivateKey.from_mnemonic(mnemonic=seed_phrase, testnet=is_testnet)

        password = _get_password()
        hd_priv = HDPrivateKey.from_mnemonic(
            mnemonic=seed_phrase, testnet=is_testnet, password=password.encode()
        )
    except Exception as e:
        print_red(f"Invalid mnemonic: {e}")
        return _get_bip39_seed(is_testnet=is_testnet)

    readline.set_completer(old_completer)
    return hd_priv


def _get_units():
    units = input(blue_fg("Units to diplay [BTC/sats]: ")).strip().lower()
    if units in ("", "btc", "btcs", "bitcoin", "bitcoins"):
        return "btc"
    if units in ("sat", "satoshis", "sats"):
        return "sats"
    print_red("Please choose either BTC or sats")
    return units


def _format_satoshis(sats, in_btc=False):
    if in_btc:
        btc = sats / 10 ** 8
        return f"{btc:,.8f} BTC"
    return f"{sats:,} sats"


# TODO: is there a standard to use here?
# Inspired by https://github.com/trezor/trezor-firmware/blob/e23bb10ec49710cc2b2b993db9c907d3c7becf2c/core/src/apps/wallet/sign_tx/multisig.py#L37
def _calculate_msig_digest(quorum_m, root_xfp_hexes):
    fingerprints_to_hash = "-".join(sorted(root_xfp_hexes))
    return hash256(f"{quorum_m}:{fingerprints_to_hash}".encode()).hex()


#####################################################################
# Command Line App Code Starts Here
#####################################################################


class MyPrompt(Cmd):
    ADVANCED_MODE = environ.get("ADVANCED_MODE", "").lower() in (
        "1",
        "t",
        "true",
        "y",
        "yes",
        "on",
    )
    intro = (
        "Welcome to multiwallet, the stateless multisig bitcoin wallet.\n"
        f"You are currently in {'ADVANCED' if ADVANCED_MODE else 'SAFE'} mode.\n"
        "Type help or ? to list commands.\n"
    )
    prompt = "(₿) "  # the bitcoin symbol :)

    def __init__(self):
        super().__init__()

    def do_generate_seed(self, arg):
        """Seedpicker implementation: calculate bitcoin public and private key information from BIP39 words you draw out of a hat"""

        if not self.ADVANCED_MODE:
            print_blue(
                "Running in SAFE mode.\n"
                f"For advanced features like passphrases, different checksum indices, and custom paths, first run  `{self.prompt} advanced_mode true` in the main menu.\n"
            )

        first_words = _get_bip39_firstwords()
        valid_checksums_generator = calc_valid_seedpicker_checksums(
            first_words=first_words
        )

        if self.ADVANCED_MODE:
            use_default_checksum = _get_bool(
                prompt="Use the default checksum index?", default=True
            )
        else:
            use_default_checksum = True

        if use_default_checksum:
            # This will be VERY fast
            last_word = next(valid_checksums_generator)
        else:
            num_valid_seedpicker_checksums = calc_num_valid_seedpicker_checksums(
                num_first_words=len(first_words.split())
            )

            to_print = f"Generating the {num_valid_seedpicker_checksums} valid checksum words for this seed phrase"
            if not is_libsec_enabled():
                to_print += " (this is ~10x faster if you install libsec)"
            to_print += ":\n"
            print_yellow(to_print)

            # This is slow, but will display progress in a UX-friendly way
            valid_checksum_words = []
            line = ""
            for i, word in enumerate(valid_checksums_generator):
                valid_checksum_words.append(word)
                current = f"{i}. {word}"
                if len(current) < 8:
                    current += "\t"
                line += f"{current}\t"
                if i % 4 == 3:
                    print_yellow("\t" + line)
                    line = ""
            print()
            index = _get_int(
                prompt="Choose one of the possible last words from above",
                default=0,
                minimum=0,
                maximum=len(valid_checksum_words) - 1,
            )
            last_word = valid_checksum_words[index]

        if self.ADVANCED_MODE:
            password = _get_password()
        else:
            password = ""

        is_testnet = not _get_bool(prompt="Use Mainnet?", default=False)

        if self.ADVANCED_MODE:
            path_to_use = _get_path(is_testnet=is_testnet)
        else:
            path_to_use = DEFAULT_TESTNET_PATH if is_testnet else DEFAULT_MAINNET_PATH

        # TODO: migrate away from SLIP132 bytes?
        # https://github.com/cryptoadvance/specter-desktop/issues/628
        if is_testnet:
            SLIP132_VERSION_BYTES = "02575483"
        else:
            SLIP132_VERSION_BYTES = "02aa7ed3"

        hd_priv = HDPrivateKey.from_mnemonic(
            mnemonic=f"{first_words} {last_word}",
            password=password.encode(),
            testnet=is_testnet,
        )
        print(yellow_fg("SECRET INFO") + red_fg(" (guard this VERY carefully)"))
        print_green(f"Last word: {last_word}")
        print_green(
            f"Full ({len(first_words.split()) + 1} word) mnemonic (including last word): {first_words + ' ' + last_word}"
        )
        if password:
            print_green(f"Passphrase: {password}")

        print_yellow(f"\nPUBLIC KEY INFO ({'testnet' if is_testnet else 'mainnet'})")
        print_yellow("Copy-paste this into Specter-Desktop:")
        print_green(
            "  [{}{}]{}".format(
                hd_priv.fingerprint().hex(),
                path_to_use.replace("m", "").replace("'", "h"),
                hd_priv.traverse(path_to_use).xpub(
                    version=bytes.fromhex(SLIP132_VERSION_BYTES)
                ),
            ),
        )

    def do_receive(self, arg):
        """Verify receive addresses for a multisig wallet using output descriptors (from Specter-Desktop)"""
        pubkeys_info = _get_output_record()
        limit = _get_int(
            prompt="Limit of addresses to display",
            # This is slow without libsecp256k1:
            default=25 if is_libsec_enabled() else 5,
            minimum=1,
        )
        offset = _get_int(
            prompt="Offset of addresses to display",
            default=0,
            minimum=0,
        )

        quorum_display = f"{pubkeys_info['quorum_m']}-of-{pubkeys_info['quorum_n']}"
        to_print = f"{quorum_display} Multisig Receive Addresses"
        if not is_libsec_enabled:
            to_print += " (this is ~100x faster if you install libsec)"
        print_yellow(to_print + ":")
        for cnt in range(limit):
            sec_hexes_to_use = []
            for key_record in pubkeys_info["key_records"]:
                hdpubkey = HDPublicKey.parse(key_record["xpub_parent"])
                leaf_xpub = hdpubkey.child(key_record["index"]).child(
                    index=cnt + offset
                )
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
            print_green(
                f"#{cnt + offset}: {redeem_script.address(testnet=pubkeys_info['is_testnet'])}"
            )

    def do_send(self, arg):
        """Sign a multisig PSBT using 1 of your BIP39 seed phrases. Can also be used to just inspect a TX and not sign it."""

        psbt_obj = _get_psbt_obj()
        TX_FEE_SATS = psbt_obj.tx_obj.fee()

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

            # for calculating msig fingerprint
            root_xfp_hexes = []
            for _, details in psbt_in.named_pubs.items():
                root_xfp_hexes.append(details.root_fingerprint.hex())

            input_desc = {
                "quorum": f"{quorum_m}-of-{len(root_xfp_hexes)}",
                "root_xfp_hexes": root_xfp_hexes,
                "prev_txhash": psbt_in.tx_in.prev_tx.hex(),
                "prev_idx": psbt_in.tx_in.prev_index,
                "n_sequence": psbt_in.tx_in.sequence,
                "sats": psbt_in.tx_in.value(),
                # TODO: would be possible for transaction to be p2sh-wrapped p2wsh (can we tell?)
                "addr": psbt_in.witness_script.address(testnet=psbt_obj.testnet),
                # "p2sh_addr": psbt_in.witness_script.p2sh_address(testnet=psbt_obj.testnet),
                "witness_script": str(psbt_in.witness_script),
                "msig_digest": _calculate_msig_digest(
                    quorum_m=quorum_m, root_xfp_hexes=root_xfp_hexes
                ),
            }
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

        spend_addr, output_spend_sats = "", 0
        outputs_desc = []
        for cnt, psbt_out in enumerate(psbt_obj.psbt_outs):
            psbt_out.validate()  # redundant but explicit

            output_desc = {
                "sats": psbt_out.tx_out.amount,
                "addr_type": psbt_out.tx_out.script_pubkey.__class__.__name__.rstrip(
                    "ScriptPubKey"
                ),
            }

            output_desc["addr"] = psbt_out.tx_out.script_pubkey.address(
                testnet=psbt_obj.testnet
            )

            if psbt_out.named_pubs:
                # Validate below that this is correct and abort otherwise
                output_desc["is_change"] = True

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

                output_msig_digest = _calculate_msig_digest(
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

        UNITS = _get_units()  # TODO: move this to an internal setting somewhere
        TX_SUMMARY = " ".join(
            [
                "PSBT sends",
                _format_satoshis(output_spend_sats, in_btc=UNITS == "btc"),
                "to",
                spend_addr,
                "with a fee of",
                _format_satoshis(TX_FEE_SATS, in_btc=UNITS == "btc"),
                f"({round(TX_FEE_SATS / TOTAL_INPUT_SATS * 100, 2)}% of spend)",
            ]
        )
        print_yellow(TX_SUMMARY)

        if _get_bool(prompt="In Depth Transaction View?", default=False):
            to_print = []
            to_print.append("DETAILED VIEW")
            to_print.append(f"TXID: {psbt_obj.tx_obj.id()}")
            to_print.append("-" * 80)
            to_print.append(f"{len(inputs_desc)} Input(s):")
            for cnt, input_desc in enumerate(inputs_desc):
                to_print.append(f"  input #{cnt}")
                for k in input_desc:
                    to_print.append(f"    {k}: {input_desc[k]}")
            to_print.append("-" * 80)
            to_print.append(f"{len(outputs_desc)} Output(s):")
            for cnt, output_desc in enumerate(outputs_desc):
                to_print.append(f"  output #{cnt}")
                for k in output_desc:
                    to_print.append(f"    {k}: {output_desc[k]}")
            print_yellow("\n".join(to_print))

        if not _get_bool(prompt="Sign this transaction?", default=True):
            print_yellow(f"Transaction {psbt_obj.tx_obj.id()} NOT signed")
            return

        hd_priv = _get_bip39_seed(is_testnet=psbt_obj.testnet)
        xfp_hex = hd_priv.fingerprint().hex()

        # Derive list of child private keys we'll use to sign the TX
        root_paths = set()
        for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):
            # Safety check
            if inputs_desc[cnt]["prev_txhash"] != psbt_in.tx_in.prev_tx.hex():
                _abort("Script error")
            if inputs_desc[cnt]["prev_idx"] != psbt_in.tx_in.prev_index:
                _abort("Script error")

            for _, details in psbt_in.named_pubs.items():
                if details.root_fingerprint.hex() == xfp_hex:
                    root_paths.add(details.root_path)

        if not root_paths:
            # We confirmed above that all inputs have identical encumberance so we choose the first one as representative
            err = [
                "Did you enter a seed for another wallet?",
                f"The seed supplied (fingerprint {xfp_hex}) does not correspond to the transaction inputs, which are {inputs_desc[0]['quorum']} of the following:",
            ]
            for xfp in sorted(inputs_desc[0]["root_xfp_hexes"]):
                err.append("  " + xfp)
            return _abort("\n".join(err))

        private_keys = [
            hd_priv.traverse(root_path).private_key for root_path in root_paths
        ]

        if psbt_obj.sign_with_private_keys(private_keys) is True:
            print()
            print_yellow("Signed PSBT to broadcast:\n")
            print_green(psbt_obj.serialize_base64())
        else:
            return _abort("PSBT wasn't signed")

    def do_advanced_mode(self, arg):
        """
        Toggle advanced mode features like passphrases, different BIP39 seed checksums, and non-standard BIP32 paths.
        WARNING: these features are for advanced users and could lead to loss of funds.
        """
        if arg.lower() in ("1", "t", "true", "y", "yes", "on", "enable", "enabled"):
            if self.ADVANCED_MODE:
                print_red("ADVANCED mode already set, no changes")
            else:
                print_yellow("ADVANCED mode set, don't mess up!")
                self.ADVANCED_MODE = True
        else:
            if self.ADVANCED_MODE:
                print_yellow("SAFE mode set, your training wheels have been restored!")
                self.ADVANCED_MODE = False
            else:
                print_red("SAFE mode already set, no changes")

    def do_debug(self, arg):
        """Print program settings for debug purposes"""

        to_print = [
            f"buidl Version: {_get_buidl_version()}",
            f"Multiwallet Mode: {'Advanced' if self.ADVANCED_MODE else 'Basic'}",
            f"Python Version: {sys.version_info}",
            f"Platform: {platform()}",
            f"libsecp256k1 Configured: {is_libsec_enabled()}",
        ]
        print_yellow("\n".join(to_print))

    def do_exit(self, arg):
        """Exit Program"""
        print_yellow("\nNo data saved")
        return True


if __name__ == "__main__":
    try:
        MyPrompt().cmdloop()
    except KeyboardInterrupt:
        print_yellow("\nNo data saved")
