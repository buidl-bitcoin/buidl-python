#!/usr/bin/env python3
# coding: utf-8

import sys
from cmd import Cmd
from getpass import getpass
from platform import platform
from pkg_resources import DistributionNotFound, get_distribution

import buidl  # noqa: F401 (used below with pkg_resources for versioning)
from buidl.ecc import PrivateKey
from buidl.libsec_status import is_libsec_enabled
from buidl.psbt import PSBT


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


def _get_wif():
    prompt = blue_fg("Enter WIF (Wallet Import Format) to use for signing: ")
    while True:
        wif = getpass(prompt=prompt).strip()
        try:
            return PrivateKey.parse(wif)
        except Exception as e:
            print_red(f"Could not parse WIF: {e}")


def _get_psbt_obj(network):
    psbt_prompt = blue_fg(
        "Paste partially signed bitcoin transaction (PSBT) in base64 form: "
    )
    while True:
        psbt_b64 = input(psbt_prompt).strip()

        if not psbt_b64:
            continue

        try:
            psbt_obj = PSBT.parse_base64(psbt_b64, network=network)
        except Exception as e:
            print_red(f"Could not parse PSBT: {e}")
            continue

        # redundant but explicit
        if psbt_obj.validate() is not True:
            print_red("PSBT does not validate")
            continue

        return psbt_obj


#####################################################################
# Command Line App Code Starts Here
#####################################################################


class MyPrompt(Cmd):
    intro = (
        "Welcome to singlesweep, a stateless single sig sweeper that works with WIF and PSBTs.\n"
        "Single sig is DANGEROUS, this is an emergency recovery tool with NO WARRANTY OF ANY KIND.\n"
        "It is often used for collecting funds from old paper wallets.\n"
        "Type help or ? to list commands.\n"
    )
    prompt = "(₿) "  # the bitcoin symbol :)

    def __init__(self):
        super().__init__()

    def do_sweep(self, arg):
        """Sign a single-sig PSBT sweep transaction (1 output) using 1 WIF."""

        # We ask for this upfront so we can infer the network from it (PSBT doesn't have network info)
        # Users SHOULD only run this code on an airgap machine
        privkey_obj = _get_wif()
        network = privkey_obj.network

        # TODO: create a new helper method in pecc.py/cecc.py?
        expected_utxo_addr = privkey_obj.point.address(
            compressed=privkey_obj.compressed, network=network
        )
        print_yellow(
            f"Will attempt to spend from {network.upper()} {expected_utxo_addr}"
        )

        psbt_obj = _get_psbt_obj(network=network)
        tx_obj = psbt_obj.tx_obj

        try:
            psbt_described = psbt_obj.describe_p2pkh_sweep(privkey_obj=privkey_obj)
        except Exception as e:
            print_red(f"ABORTING WITHOUT SIGNING, could not describe PSBT:\n{e}")
            return

        # Gather TX info and validate
        print_yellow(psbt_described["tx_summary_text"])

        if _get_bool(prompt="In Depth Transaction View?", default=True):
            to_print = []
            to_print.append("DETAILED VIEW")
            to_print.append(f"Fee: {psbt_described['tx_fee_sats']:,} (unverified)")
            to_print.append(
                f"Total Input Sats Consumed: {psbt_described['total_input_sats']:,} (unverified)"
            )
            to_print.append(
                f"Total Output Sats Created: {psbt_described['output_spend_sats']:,}"
            )
            to_print.append(f"Lock Time: {psbt_described['locktime']:,}")
            to_print.append(
                f"RBF: {'Enabled' if psbt_described['is_rbf_able'] else 'DISABLED'}"
            )
            to_print.append(
                f"Size: {psbt_described['tx_size_bytes']} bytes (will increase after signing)"
            )
            to_print.append("-" * 80)
            to_print.append(f"{len(psbt_described['inputs_desc'])} Input(s):")
            for cnt, input_desc in enumerate(psbt_described["inputs_desc"]):
                to_print.append(f"  Input #{cnt}")
                for k, v in input_desc.items():
                    if k == "sats":
                        # Comma separate ints
                        val = f"{v:,} (unverified)"
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
            print_yellow(f"Transaction {tx_obj.id()} NOT signed")
            return

        # Sign the TX
        # TODO: would prefer to use psbt_obj.sign_with_private_keys(), but that requires NamedPublicKeys that we don't have (no paths in PSBT)
        for cnt, _ in enumerate(tx_obj.tx_ins):
            was_signed = tx_obj.sign_p2pkh(input_index=cnt, private_key=privkey_obj)
            if was_signed is not True:
                print_red("PSBT was NOT signed")

        print_yellow(f"SIGNED TX {tx_obj.hash().hex()} has the following hex:\n")
        print_green(tx_obj.serialize().hex())
        print_yellow("\nYou can be broadcast this hex via:")
        print_yellow(" - Your bitcoin core node")
        print_yellow(
            ' - "pushtx" block explorers (Blockstream, BlockCypher, Blockchain.com, etc), mining pools, Electrum SPV network, etc'
        )
        print_yellow(
            ' - Electrum signing of a previously unsigned transaction: "Combine" > "Merge Signatures From"\n'
        )

    def do_version_info(self, arg):
        """Print program settings for debug purposes"""

        to_print = [
            f"buidl Version: {_get_buidl_version()}",
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
