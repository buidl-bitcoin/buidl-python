#!/usr/bin/env python3
# coding: utf-8

import readline
import sys
from cmd import Cmd
from getpass import getpass
from itertools import combinations
from os import environ
from platform import platform
from pkg_resources import DistributionNotFound, get_distribution

import buidl  # noqa: F401 (used below with pkg_resources for versioning)
from buidl.blinding import blind_xpub, secure_secret_path
from buidl.hd import (
    calc_num_valid_seedpicker_checksums,
    calc_valid_seedpicker_checksums,
    generate_wshsortedmulti_address,
    HDPrivateKey,
    HDPublicKey,
    parse_partial_key_record,
    parse_wshsortedmulti,
)
from buidl.libsec_status import is_libsec_enabled
from buidl.mnemonic import BIP39
from buidl.shamir import ShareSet
from buidl.psbt import MixedNetwork, PSBT

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
    completer = WordCompleter(wordlist=BIP39)

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
        if word not in BIP39:
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
    completer = WordCompleter(wordlist=BIP39)

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
        if word not in BIP39:
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


def _get_key_record():
    key_record_str = input(
        blue_fg(
            "Enter an xpub key record to blind in the format [deadbeef/path]xpub (any path will do): "
        )
    ).strip()
    try:
        return parse_partial_key_record(key_record_str=key_record_str)
    except ValueError as e:
        print_red(f"Could not parse entry: {e}")
        return _get_key_record()


def _get_units():
    # TODO: re-incorporate this into TX summary
    units = input(blue_fg("Units to diplay [BTC/sats]: ")).strip().lower()
    if units in ("", "btc", "btcs", "bitcoin", "bitcoins"):
        return "btc"
    if units in ("sat", "satoshis", "sats"):
        return "sats"
    print_red("Please choose either BTC or sats")
    return units


def _print_footgun_warning(custom_str=""):
    to_print = [
        "Running in SAFE mode.",
        "If you want to live dangerously, enter `(₿) advanced_mode` in the main menu.",
    ]
    if custom_str:
        to_print.append(custom_str)
    print_blue("\n".join(to_print) + "\n")


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
        "This tool is free and there is NO WARRANTY OF ANY KIND.\n"
        f"You are currently in {'ADVANCED' if ADVANCED_MODE else 'SAFE'} mode.\n"
        "Type help or ? to list commands.\n"
    )
    prompt = "(₿) "  # the bitcoin symbol :)

    def __init__(self):
        super().__init__()

    def do_generate_seed(self, arg):
        """Seedpicker implementation: calculate bitcoin public and private key information from BIP39 words you draw out of a hat"""

        if not self.ADVANCED_MODE:
            _print_footgun_warning(
                "This will enable passphrases, custom paths, and different checksum indices."
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

    def do_blind_xpub(self, arg):
        """Blind an XPUB using a random BIP32 path. Experts only!"""

        # Prevent footgun-ing
        if not self.ADVANCED_MODE:
            warning_msg = (
                "Blinding an xpub must be performed correctly or you could lose funds!\n"
                "Multiwallet supports the custom BIP32 paths needed, but few HWWs can sign on these paths.\n"
                "Some can't even co-sign a multisig transaction with nonstandard BIP32 paths (even if their path is standard)"
            )
            _print_footgun_warning(warning_msg)
            return

        key_record_dict = _get_key_record()
        xfp_hex = key_record_dict["xfp"]
        starting_xpub = key_record_dict["xpub"]
        starting_path = key_record_dict["path"]

        depth = 4
        if not _get_bool("Use standard entropy parameters for blinding?", default=True):
            depth = _get_int(
                "EXPERTS ONLY: How deep of a BIP32 path do you want to blind this xpub with?",
                default=4,
                minimum=1,
                maximum=16,
            )
        # Get secret BIP32 path:
        secret_bip32_path = secure_secret_path(depth=depth)

        print_blue(f"Generating BIP32 path with {31*depth} bits of good entropy...")
        blinded_xpub_dict = blind_xpub(
            starting_xpub=starting_xpub,
            starting_path=starting_path,
            secret_path=secret_bip32_path,
        )
        blinded_full_path = blinded_xpub_dict["blinded_full_path"]
        blinded_child_xpub = blinded_xpub_dict["blinded_child_xpub"]
        blinded_key_record = f"[{xfp_hex}/{blinded_full_path[2:]}]{blinded_child_xpub}"

        explanation_msg = (
            "Here is a blinded xpub key record to upload to your Coordinator.\n"
            "Create a multisig wallet with this blinded xpub and it will become a part of your account map (output descriptors).\n"
        )
        print_yellow(explanation_msg)

        print_green(blinded_key_record)

        warning_msg = (
            "\nImportant notes:",
            "  - Do NOT share this record with the holder of the seed phrase, or they will be able to unblind their key (potentially leaking privacy info about what it controls).",
            "  - Possesion of this blinded xpub key record has privacy implications, but it CANNOT alone be used to sign bitcoin transactions.",
            "  - Possesion of the original seed phrase (used to create the original xpub key record), CANNOT alone be used to sign bitcoin transactions.",
            "  - In order to spend from this blinded xpub, you must have BOTH the seed phrase AND the blinded xpub key record (which will be included in your account map before you can receive funds).\n",
        )
        print_yellow("\n".join(warning_msg))

    def do_recover_seed(self, arg):
        """Recover a seed from Shamir shares per SLIP39"""
        share_mnemonics = []
        while True:
            share_phrase = input(
                blue_fg("Enter a SLIP39 Shamir share (blank to end): ")
            ).strip()
            if share_phrase == "":
                break
            share_mnemonics.append(share_phrase)
        passphrase = b""
        if self.ADVANCED_MODE:
            has_passphrase = _get_bool("Is there a passphrase?", default=False)
            if has_passphrase:
                passphrase = _get_confirmed_pw().encode("ascii")
        try:
            mnemonic = ShareSet.recover_mnemonic(share_mnemonics, passphrase=passphrase)
            print_green(f"Here is your recovered mnemonic:\n\n{mnemonic}")
        except (TypeError, ValueError, SyntaxError) as e:
            print_red(e)

    def do_split_seed(self, arg):
        """Split a seed to Shamir shares per SLIP39"""
        mnemonic = input(blue_fg("Enter a BIP39 seed phrase: ")).strip()
        k = _get_int(
            "How many Shamir shares should be required to recover the seed phrase?",
            default=2,
            minimum=1,
            maximum=16,
        )
        default_n = 2 * k - 1 if 2 * k - 1 < 16 else 16
        n = _get_int(
            "How many Shamir shares do you want to generate?",
            default=default_n,
            minimum=k,
            maximum=16,
        )
        passphrase = b""
        # Max possible combos is 12,870 (with 8-of-16)
        testing_limit = 12870
        if self.ADVANCED_MODE:
            add_passphrase = _get_bool(
                "Do you want to add a passphrase?", default=False
            )
            if add_passphrase:
                passphrase = _get_confirmed_pw().encode("ascii")
            if _get_bool(
                "Do you want to limit how many of these shares you test (for faster results)?",
                default=False,
            ):
                testing_limit = _get_int(
                    "How many combinations would you like to test?",
                    default=1000,
                    minimum=k,
                    maximum=testing_limit,
                )
        shares = ShareSet.generate_shares(mnemonic, k, n, passphrase=passphrase)
        # test the shares (cap at 1000 combinations)
        print_yellow(
            "Testing share combinations to be certain they will recover your seed phrase"
        )
        for cnt, combo in enumerate(combinations(shares, k)):
            if cnt > testing_limit:
                break
            calculated = ShareSet.recover_mnemonic(combo, passphrase)
            if calculated != mnemonic:
                # we should never reach this line
                raise RuntimeError(f"Bad shares {calculated} for mnemonic {mnemonic}")
            if cnt % 10 == 0:
                print(".", end="", flush=True)

        print_yellow(
            f"\nSuccesfully tested {'ALL ' if testing_limit == 12870 else ''}{cnt} combinations"
        )

        print("\n")
        share_mnemonics = "\n\n".join(shares)
        if passphrase:
            additional = " AND your passphrase"
        else:
            additional = ""
        prompt = f"You will need {k} of these {n} share phrases{additional} to recover your seed phrase:\n\n{share_mnemonics}"
        print_green(prompt)

    def do_receive(self, arg):
        """Verify receive addresses for a multisig wallet using output descriptors (from Specter-Desktop)"""
        output_record = _get_output_record()
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

        # Only advanced users should consider seeing change addresses
        is_change = False
        if self.ADVANCED_MODE:
            is_change = not _get_bool(
                prompt="Display receive addresses? `N` to display change addresses instead.",
                default=True,
            )

        to_print = f"{output_record['quorum_m']}-of-{output_record['quorum_n']} Multisig {'Change' if is_change else 'Receive'} Addresses"
        if not is_libsec_enabled():
            to_print += "\n(this is ~100x faster if you install libsec)"
        print_yellow(to_print + ":")
        generator = generate_wshsortedmulti_address(
            quorum_m=output_record["quorum_m"],
            key_records=output_record["key_records"],
            is_testnet=output_record["is_testnet"],
            is_change=is_change,
            offset=offset,
            limit=limit,
        )
        cnt = 0
        for cnt, address in enumerate(generator):
            print_green(f"#{cnt + offset}: {address}")

    def do_send(self, arg):
        """Sign a multisig PSBT using 1 of your BIP39 seed phrases. Can also be used to just inspect a TX and not sign it."""
        # This tool only supports a TX with the following constraints:
        #   We sign ALL inputs and they have the same multisig wallet (quorum + pubkeys)
        #   There can only be 1 output (sweep transaction) or 2 outputs (spend + change).
        #   If there is change, we validate it has the same multisig wallet as the inputs we sign.

        # Unfortunately, there is no way to validate change without having the hdpubkey_map
        # TODO: make version where users can enter this later (after manually approving the transaction)?
        output_record = _get_output_record()
        psbt_obj = _get_psbt_obj()

        hdpubkey_map = {}
        for key_record in output_record["key_records"]:
            hdpubkey_map[key_record["xfp"]] = HDPublicKey.parse(
                key_record["xpub_parent"]
            )

        psbt_described = psbt_obj.describe_basic_multisig_tx(
            hdpubkey_map=hdpubkey_map, xfp_for_signing=None
        )

        # Gather TX info and validate
        print_yellow(psbt_described["tx_summary_text"])

        if _get_bool(prompt="In Depth Transaction View?", default=False):
            to_print = []
            to_print.append("DETAILED VIEW")
            to_print.append(f"TXID: {psbt_obj.tx_obj.id()}")
            to_print.append("-" * 80)
            to_print.append(f"{len(psbt_described['inputs_desc'])} Input(s):")
            for cnt, input_desc in enumerate(psbt_described["inputs_desc"]):
                to_print.append(f"  Input #{cnt}")
                for k, v in input_desc.items():
                    if k == "sats":
                        # Comma separate ints
                        val = f"{v:,}"
                    else:
                        val = v
                    to_print.append(f"    {k}: {val}")
            to_print.append("-" * 80)
            to_print.append(f"{len(psbt_described['outputs_desc'])} Output(s):")
            for cnt, output_desc in enumerate(psbt_described["outputs_desc"]):
                to_print.append(f"  Output #{cnt}")
                for k, v in output_desc.items():
                    if k == "sats":
                        # Comma separate ints
                        val = f"{v:,}"
                    else:
                        val = v
                    to_print.append(f"    {k}: {val}")
            print_yellow("\n".join(to_print))

        if not _get_bool(prompt="Sign this transaction?", default=True):
            print_yellow(f"Transaction {psbt_obj.tx_obj.id()} NOT signed")
            return

        hd_priv = _get_bip39_seed(is_testnet=psbt_obj.testnet)
        xfp_hex = hd_priv.fingerprint().hex()

        # Derive list of child private keys we'll use to sign the TX
        root_paths = set()
        for cnt, input_desc in enumerate(psbt_described["inputs_desc"]):
            for bip32_deriv in input_desc["bip32_derivs"]:
                if bip32_deriv["master_fingerprint"] == xfp_hex:
                    root_paths.add(bip32_deriv["path"])

        if not root_paths:
            # We confirmed above that all inputs have identical encumberance so we choose the first one as representative
            err = [
                "Did you enter a seed for another wallet?",
                f"The seed supplied (fingerprint {xfp_hex}) does not correspond to the transaction inputs, which are {psbt_described['inputs_desc'][0]['quorum']} of the following:",
            ]
            for xfp in sorted(psbt_described["inputs_desc"][0]["root_xfp_hexes"]):
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
            return _abort("PSBT was NOT signed")

    def do_advanced_mode(self, arg):
        """
        Toggle advanced mode features like passphrases, different BIP39 seed checksums, and non-standard BIP32 paths.
        WARNING: these features are for advanced users and could lead to loss of funds.
        """
        if self.ADVANCED_MODE:
            self.ADVANCED_MODE = False
            print_yellow("SAFE mode set, your training wheels have been restored!")
        else:
            self.ADVANCED_MODE = True
            print_yellow("ADVANCED mode set, don't mess up!")

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
