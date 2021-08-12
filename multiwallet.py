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
from buidl.descriptor import P2WSHSortedMulti, parse_any_key_record
from buidl.hd import (
    calc_num_valid_seedpicker_checksums,
    calc_valid_seedpicker_checksums,
    HDPrivateKey,
    HDPublicKey,
    DEFAULT_P2WSH_PATH,
)
from buidl.libsec_status import is_libsec_enabled
from buidl.mnemonic import BIP39
from buidl.shamir import ShareSet
from buidl.psbt import MixedNetwork, PSBT


#####################################################################
# CLI UX
#####################################################################


# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
RESET_TERMINAL_COLOR = "\033[0m"


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
    while True:
        res = input(blue_fg(f"{prompt} [{default}]: ")).strip()
        if not res:
            res = str(default)
        try:
            res_int = int(res)
        except ValueError:
            print_red(f"{res} is not an integer")
            continue

        if maximum is not None:
            if not minimum <= res_int <= maximum:
                print_red(
                    f"Please pick a number between {minimum} and {maximum} (inclusive)"
                )
                continue

        if res_int < minimum:
            print_red(f"Please pick an integer >= {minimum}")
            continue

        return res_int


def _get_bool(prompt, default=True):
    if default is True:
        yn = "[Y/n]"
    else:
        yn = "[y/N]"

    while True:
        response_str = input(blue_fg(f"{prompt} {yn}: ")).strip().lower()
        if response_str == "":
            return default
        if response_str in ("n", "no"):
            return False
        if response_str in ("y", "yes"):
            return True
        print_red("Please choose either y or n")


def _get_string(prompt, default=""):
    return input(blue_fg(f"{prompt} [{default}]: ")).strip().lower() or default


def _get_path_string():
    while True:
        res = input(blue_fg('Path to use (should start with "m/"): ')).strip().lower()
        if not res.startswith("m/"):
            print_red(f'Invalid path "{res}" must start with "m/")')
            continue
        if res == "m/":
            # TODO: support this?
            print_red("Empty path (must have a depth of > 0): m/somenumberhere")
            continue
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
                continue
        return res.replace("h", "'")


def _get_path(network):
    network_string = network.capitalize()
    default_path = DEFAULT_P2WSH_PATH[network]

    if _get_bool(
        prompt=f"Use default path ({default_path} for {network_string})",
        default=True,
    ):
        return default_path
    else:
        return _get_path_string()


def _get_confirmed_pw():
    while True:
        first = getpass(prompt=blue_fg("Enter custom passphrase: "))
        if first.strip() != first:
            print_red(
                "Leading/trailing spaces in passphrases are not supported. "
                "Please use an unambiguous passphrase."
            )
            continue
        second = getpass(prompt=blue_fg("Confirm custom passphrase: "))
        if first != second:
            print_red("Passphrases don't match, please try again.")
            continue
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
# Output Descriptors
#####################################################################


def _get_p2wsh_sortedmulti():
    while True:
        output_record = input(
            blue_fg("Paste in your p2wsh output descriptors (account map): ")
        ).strip()
        try:
            return P2WSHSortedMulti.parse(output_record=output_record)
        except Exception as e:
            print_red(f"Could not parse output descriptor: {e}")
            if "wsh(sortedmulti(" not in output_record.lower():
                print_red("It should start with wsh(sortedmulti(... ")


#####################################################################
# Seedpicker
#####################################################################


def _get_bip39_firstwords():
    readline.parse_and_bind("tab: complete")
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=BIP39)
    readline.set_completer(completer.complete)
    while True:
        fw = input(
            blue_fg("Enter the first 23 words of your BIP39 seed phrase: ")
        ).strip()
        fw_num = len(fw.split())

        if fw_num not in (11, 14, 17, 20, 23):
            # TODO: 11, 14, 17, or 20 word seed phrases also work but this is not documented as it's for advanced users
            print_red(
                f"You entered {fw_num} words. "
                "We recommend 23 words, but advanced users may enter 11, 14, 17 or 20 words."
            )
            continue

        all_words_valid = True
        for cnt, word in enumerate(fw.split()):
            if word not in BIP39:
                print_red(f"Word #{cnt+1} `{word}` is not a valid BIP39 word")
                all_words_valid = False
        if all_words_valid is False:
            continue

        readline.set_completer(old_completer)
        return fw


#####################################################################
# PSBT Signer
#####################################################################


def _get_psbt_obj():
    psbt_prompt = blue_fg(
        "Paste partially signed bitcoin transaction (PSBT) in base64 form: "
    )
    while True:
        psbt_b64 = input(psbt_prompt).strip()

        if not psbt_b64:
            continue

        try:
            # Attempt to infer network from BIP32 paths
            psbt_obj = PSBT.parse_base64(psbt_b64, network=None)
            if _get_bool(
                prompt=f"Transaction appears to be a {psbt_obj.network} transaction. Display as {psbt_obj.network}?",
                default=True,
            ):
                network = psbt_obj.network
            elif psbt_obj.network == "mainnet":
                network = "testnet"
            else:
                network = "mainnet"
            if psbt_obj.network != network:
                psbt_obj = PSBT.parse_base64(psbt_b64, network=network)

        except MixedNetwork:
            if _get_bool(
                prompt="Cannot infer PSBT network from BIP32 paths. Use Mainnet?",
                default=True,
            ):
                network = "mainnet"
            else:
                network = "testnet"
            psbt_obj = PSBT.parse_base64(psbt_b64, network=network)

        except Exception as e:
            print_red(f"Could not parse PSBT: {e}")
            continue

        # redundant but explicit
        if psbt_obj.validate() is not True:
            print_red("PSBT does not validate")
            continue

        return psbt_obj


def _get_bip39_seed(network):
    readline.parse_and_bind("tab: complete")
    old_completer = readline.get_completer()
    completer = WordCompleter(wordlist=BIP39)
    readline.set_completer(completer.complete)

    bip39_prompt = blue_fg("Enter your full BIP39 seed phrase: ")
    while True:
        seed_phrase = input(bip39_prompt).strip()
        seed_phrase_num = len(seed_phrase.split())

        if seed_phrase_num not in (12, 15, 18, 21, 24):
            # Other length seed phrases also work but this is not documented as it's for advanced users
            print_red(
                f"You entered {seed_phrase_num} words. "
                "By default seed phrases should be 24 words long (advanced users may enter seed phrases that are 12, 15, 18 or 21 words long)."
            )
            continue

        for cnt, word in enumerate(seed_phrase.split()):
            if word not in BIP39:
                print_red(f"Word #{cnt+1} ({word}) is not a valid BIP39 word")
                continue
        try:
            HDPrivateKey.from_mnemonic(mnemonic=seed_phrase, network=network)

            password = _get_password()
            hd_priv = HDPrivateKey.from_mnemonic(
                mnemonic=seed_phrase, network=network, password=password.encode()
            )
        except Exception as e:
            print_red(f"Invalid mnemonic: {e}")
            continue

        readline.set_completer(old_completer)
        return hd_priv


def _get_key_record(prompt):
    key_record_prompt = blue_fg(prompt)
    while True:
        key_record_str = input(key_record_prompt).strip()
        try:
            return parse_any_key_record(key_record_str=key_record_str)
        except ValueError as e:
            print_red(f"Could not parse entry: {e}")
            continue


def _get_units():
    # TODO: re-incorporate this into TX summary
    prompt = blue_fg("Units to diplay [BTC/sats]: ")
    while True:
        units = input(prompt).strip().lower()
        if units in ("", "btc", "btcs", "bitcoin", "bitcoins"):
            return "btc"
        if units in ("sat", "satoshis", "sats"):
            return "sats"


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


class MultiWallet(Cmd):
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

    def __init__(self, stdin=sys.stdin, stdout=sys.stdout):
        Cmd.__init__(self, stdin=stdin, stdout=stdout)

    def do_generate_seed(self, arg):
        """Calculate bitcoin public and private key information from BIP39 words you draw out of a hat (using the seedpicker implementation)"""

        if not self.ADVANCED_MODE:
            _print_footgun_warning(
                "This will enable passphrases, custom paths, slip132 version bytes, and different checksum indices."
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

        if _get_bool(prompt="Use Mainnet?", default=False):
            network = "mainnet"
        else:
            network = "testnet"

        if self.ADVANCED_MODE:
            path_to_use = _get_path(network=network)
            use_slip132_version_byte = _get_bool(
                prompt="Encode with SLIP132 version byte?", default=True
            )
        else:
            path_to_use = None  # buidl will use default path
            use_slip132_version_byte = True

        hd_priv = HDPrivateKey.from_mnemonic(
            mnemonic=f"{first_words} {last_word}",
            password=password.encode(),
            network=network,
        )
        key_record = hd_priv.generate_p2wsh_key_record(
            bip32_path=path_to_use, use_slip132_version_byte=use_slip132_version_byte
        )
        print(yellow_fg("SECRET INFO") + red_fg(" (guard this VERY carefully)"))
        print_green(f"Last word: {last_word}")
        print_green(
            f"Full ({len(first_words.split()) + 1} word) mnemonic (including last word): {first_words + ' ' + last_word}"
        )
        if password:
            print_green(f"Passphrase: {password}")

        print_yellow(f"\nPUBLIC KEY INFO ({network})")
        print_yellow("Copy-paste this into Specter-Desktop:")
        print_green(key_record)

    def do_create_output_descriptors(self, arg):
        """Combine m-of-n public key records into a multisig output descriptor (account map)"""

        m_int = _get_int(
            prompt="How many signatures will be required to spend from this wallet?",
            default=2,
            minimum=1,
            maximum=15,
        )
        n_int = _get_int(
            prompt="How many total keys will be able to sign transaction from this wallet?",
            default=min(m_int + 1, 15),
            minimum=m_int,
            maximum=15,
        )
        key_records = []
        for cnt in range(n_int):
            prompt = f"Enter xpub key record #{cnt+1} (of {n_int}) in the format [deadbeef/path]xpub: "
            key_record_dict = _get_key_record(prompt)
            if key_record_dict.get("account_index") is None:
                # we have a partial dict
                key_record_dict["account_index"] = 0
                key_record_dict["xpub_parent"] = key_record_dict.pop("xpub")
            # Safety check
            if key_record_dict in key_records:
                # TODO: make this more performant
                print_red(
                    "ABORTING! Cannot use the same xpub key record twice in the same output descriptor."
                )
                return
            key_records.append(key_record_dict)

        sort_key_records = True
        if self.ADVANCED_MODE:
            sort_key_records = _get_bool(
                "Sort parent xpubs? This does not affect child addresses for sortedmulti, but alters bitcoin core descriptor checksum.",
                default=True,
            )

        p2wsh_sortedmulti_obj = P2WSHSortedMulti(
            quorum_m=m_int,
            key_records=key_records,
            sort_key_records=sort_key_records,
        )
        print_yellow("Your output descriptors are:\n")
        print_green(str(p2wsh_sortedmulti_obj))

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

        key_record_dict = _get_key_record(
            "Enter an xpub key record to blind in the format [deadbeef/path]xpub (any path will do): "
        )
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
            "  - Possession of this blinded xpub key record has privacy implications, but it CANNOT alone be used to sign bitcoin transactions.",
            "  - Possession of the original seed phrase (used to create the original xpub key record), CANNOT alone be used to sign bitcoin transactions.",
            "  - In order to spend from this blinded xpub, you must have BOTH the seed phrase AND the blinded xpub key record (which will be included in your account map before you can receive funds).\n",
        )
        print_yellow("\n".join(warning_msg))

    def do_shamir_recover_seed(self, arg):
        """Recover a seed from Shamir shares using a SLIP39-like standard"""
        # Prevent footgun-ing
        if not self.ADVANCED_MODE:
            warning_msg = (
                "This shamir share implementation is non-standard!\n"
                "If you're trying to recover from SLIP39 seed generated elsewhere, it probably won't work."
            )
            _print_footgun_warning(warning_msg)
            return

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

    def do_shamir_split_seed(self, arg):
        """Split a seed to Shamir shares using a SLIP39-like standard"""
        # Prevent footgun-ing
        if not self.ADVANCED_MODE:
            warning_msg = (
                "This shamir share implementation is non-standard!\n"
                "It has the benefit of being reversible, meaning it accepts standard BIP39 seeds and can recreate them later from Shamir Shares, the SSSS protocol is not compatible with SLIP39."
                "However, once you recover your original BIP39 seed phrase (not possible with SLIP39), you can put that into any hardware wallet."
            )
            _print_footgun_warning(warning_msg)
            return

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

    def do_validate_address(self, arg):
        """Verify receive addresses for a multisig wallet using output descriptors (from Specter-Desktop)"""
        p2wsh_sortedmulti_obj = _get_p2wsh_sortedmulti()
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

        to_print = f"{p2wsh_sortedmulti_obj.m_of_n} Multisig {'Change' if is_change else 'Receive'} Addresses"
        if not is_libsec_enabled():
            to_print += "\n(this is ~100x faster if you install libsec)"
        print_yellow(to_print + ":")
        for cnt in range(limit):
            offset_to_use = offset + cnt
            address = p2wsh_sortedmulti_obj.get_address(
                is_change=is_change,
                offset=offset_to_use,
            )
            print_green(f"#{offset_to_use}: {address}")

    def do_sign_transaction(self, arg):
        """
        (Co)sign a multisig PSBT using 1 of your BIP39 seed phrases.
        Can also be used to just inspect a PSBT and not sign it.

        Note: This tool ONLY supports transactions with the following constraints:
          - We sign ALL inputs and they belong to the same multisig wallet (quorum + pubkeys).
          - There can only be 1 output (sweep transaction) or 2 outputs (spend + change).
          - If there is change, we validate it belongs to the same multisig wallet as all inputs.
        """

        psbt_obj = _get_psbt_obj()

        if psbt_obj.hd_pubs:
            # if the PSBT included hd_pubs, then buidl will build the hdpubkey_map automatically from that
            hdpubkey_map = {}
        else:
            # ask for output descriptors to use to build hdpubkey_map
            print_blue(
                "PSBT doesn't include enough info to guess your account map (for validation)."
            )
            p2wsh_sortedmulti_obj = _get_p2wsh_sortedmulti()

            hdpubkey_map = {}
            for key_record in p2wsh_sortedmulti_obj.key_records:
                hdpubkey_map[key_record["xfp"]] = HDPublicKey.parse(
                    key_record["xpub_parent"]
                )

        psbt_described = psbt_obj.describe_basic_p2wsh_multisig_tx(
            hdpubkey_map=hdpubkey_map
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

        hd_priv = _get_bip39_seed(network=psbt_obj.network)
        root_paths_for_seed = psbt_described["root_paths"][hd_priv.fingerprint().hex()]
        private_keys = [
            hd_priv.traverse(root_path).private_key for root_path in root_paths_for_seed
        ]

        if psbt_obj.sign_with_private_keys(private_keys) is True:
            print()
            print_yellow("Signed PSBT to broadcast:\n")
            print_green(psbt_obj.serialize_base64())
        else:
            print_red("ERROR: Could NOT sign PSBT!")
            return

    def do_convert_descriptors_to_caravan(self, arg):
        """
        Convert bitcoin core output descriptors to caravan import
        """
        p2wsh_sortedmulti_obj = _get_p2wsh_sortedmulti()

        wallet_name = _get_string("Enter wallet name", default="p2wsh wallet")

        key_record_names = []
        if _get_bool("Give human name to each key record?", default=False):
            for cnt, kr in enumerate(p2wsh_sortedmulti_obj.key_records):
                kr_name = _get_string(
                    f"Enter key record name for {kr['xfp']}", default=f"Seed #{cnt+1}"
                )
                key_record_names.append(kr_name)

        caravan_json = p2wsh_sortedmulti_obj.caravan_export(
            wallet_name=wallet_name, key_record_names=key_record_names
        )
        print_yellow("Output descriptor as Caravan import (save this to a file):")
        print_green(caravan_json)

    def do_toggle_advanced_mode(self, arg):
        """
        Toggle advanced mode features like passphrases, different BIP39 seed checksums, non-standard BIP32 paths, xpub blinding, shamir's secret sharing scheme, etc.
        WARNING: these features are for advanced users and could lead to loss of funds.
        """
        if self.ADVANCED_MODE:
            self.ADVANCED_MODE = False
            print_yellow("SAFE mode set, your training wheels have been restored!")
        else:
            self.ADVANCED_MODE = True
            print_yellow("ADVANCED mode set, don't mess up!")

    def do_version_info(self, arg):
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
        MultiWallet().cmdloop()
    except KeyboardInterrupt:
        print_yellow("\nNo data saved")
