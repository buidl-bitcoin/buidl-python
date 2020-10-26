import argparse, sys
from io import BytesIO
from pathlib import Path

from buidl.psbt import PSBT
from buidl.hd import HDPrivateKey
from buidl.helper import hash256
from buidl.script import WitnessScript, OP_CODE_NAMES


# TODO: is there a standard to use here?
# Inspired by https://github.com/trezor/trezor-firmware/blob/e23bb10ec49710cc2b2b993db9c907d3c7becf2c/core/src/apps/wallet/sign_tx/multisig.py#L37
def calculate_msig_digest(quorum_m, root_xfp_hexes):
    fingerprints_to_hash = "-".join(sorted(root_xfp_hexes))
    return hash256(f"{quorum_m}:{fingerprints_to_hash}".encode()).hex()


def _abort(msg):
    print("ABORTING WITHOUT SIGNING:\n")
    print(msg)
    sys.exit(1)


def _format_satoshis(sats, in_btc=False):
    if in_btc:
        btc = sats / 10 ** 8
        return f"{btc:,.8f} BTC"
    return f"{sats:,} sats"


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Sign a multisig transaction via PSBT."
    )
    parser.add_argument(
        "--psbt-file",
        help="Partially Signed Bitcoin Transaction (PSBT) file to sign. /path/to/file.psbt",
        required=True,
    )
    parser.add_argument(
        "--mnemonic",
        help="Full BIP39 mnemonic",
        required=True,
    )
    parser.add_argument(
        "--verbose",
        help="Print out more info",
        action="store_true",
    )
    parser.add_argument(
        "--display-btc",
        action="store_true",
        help="Display BTC as unit instead of satoshis",
    )
    # TODO: add flag for saving output to file

    args = parser.parse_args()

    psbt_b64 = Path(args.psbt_file).read_text()

    psbt_obj = PSBT.parse_base64(psbt_b64)
    psbt_obj.validate()  # redundant but explicit
    TX_FEE_SATS = psbt_obj.tx_obj.fee()
    IS_TESTNET = True  # TODO

    hd_priv = HDPrivateKey.from_mnemonic(
        mnemonic=args.mnemonic.strip(), testnet=psbt_obj.tx_obj.testnet
    )

    # Validate multisig transaction
    # TODO: abstract some of this into buidl library?
    # Below is confusing because we perform both validation and coordinate signing.

    # This tool only supports a TX with the following constraints:
    #   We sign ALL inputs and they have the same multisig wallet (quorum + pubkeys)
    #   There can only be 1 output (sweep transaction) or 2 outputs (spend + change).
    #   If there is change, we validate it has the same multiisg wallet as the inputs we sign.

    # Gather TX info and validate
    inputs_desc = []
    for cnt, psbt_in in enumerate(psbt_obj.psbt_ins):
        psbt_in.validate()  # redundant but explicit

        if type(psbt_in.witness_script) != WitnessScript:
            _abort(
                f"Input #{cnt} does not contain a witness script, this tool can only sign p2wsh transactions."
            )

        # Determine quroum_m (and that it hasn't changed between inputs)
        try:
            quorum_m = OP_CODE_NAMES[psbt_in.witness_script.commands[0]].split("OP_")[1]
        except:
            _abort(f"Witness script for input #{cnt} is not p2wsh:\n{psbt_in})")

        root_path_used = None
        root_xfp_hexes = []  # for calculating msig fingerprint
        for _, details in psbt_in.named_pubs.items():
            root_xfp_hexes.append(details.root_fingerprint.hex())
            if details.root_fingerprint.hex() == hd_priv.fingerprint().hex():
                root_path_used = details.root_path

        if not root_path_used:
            _abort(f"Your key is not a participant in input #{cnt}")

        inputs_desc.append(
            {
                "quorum": f"{quorum_m}-of-{len(root_xfp_hexes)}",
                "root_xfp_hexes": root_xfp_hexes,
                "root_path_used": root_path_used,
                "prev_txhash": psbt_in.tx_in.prev_tx.hex(),
                "prev_idx": psbt_in.tx_in.prev_index,
                "n_sequence": psbt_in.tx_in.sequence,
                "sats": psbt_in.tx_in.value(),
                # TODO: would be possible for transaction to be p2sh-wrapped p2wsh (can we tell?)
                "addr": psbt_in.witness_script.address(testnet=IS_TESTNET),
                # "p2sh_addr": psbt_in.witness_script.p2sh_address(testnet=psbt_obj.tx_obj.testnet),
                "witness_script": str(psbt_in.witness_script),
                "msig_digest": calculate_msig_digest(
                    quorum_m=quorum_m, root_xfp_hexes=root_xfp_hexes
                ),
            }
        )

    if not all(x["msig_digest"] == inputs_desc[0]["msig_digest"] for x in inputs_desc):
        _abort(
            "Multiple different multisig quorums in inputs. Construct a transaction with one input to continue."
        )

    TOTAL_INPUT_SATS = sum([x["sats"] for x in inputs_desc])

    # Currently only supporting TXs with 1-2 outputs (sweep TX OR spend+change TX):
    if len(psbt_obj.psbt_outs) > 2:
        _abort(
            f"This tool does not support batching, your transaction has {len(psbt_obj.psbt_outs)} outputs, which is >2."
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
            output_desc["addr"] = psbt_out.witness_script.address(testnet=IS_TESTNET)
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
            except:
                _abort(f"Witness script for input #{cnt} is not p2wsh:\n{psbt_in})")

            output_msig_digest = calculate_msig_digest(
                quorum_m=quorum_m, root_xfp_hexes=root_xfp_hexes
            )
            if (
                output_msig_digest != inputs_desc[0]["msig_digest"]
            ):  # ALL inputs have the same msig_digest
                _abort(
                    f"Output #{cnt} is claiming to be change but has different multisig wallet(s)! Do a sweep transaction (1-output) if you want this wallet to cosign."
                )
        else:
            output_desc["is_change"] = False
            spend_addr = output_desc["addr"]
            output_spend_sats = output_desc["sats"]

        outputs_desc.append(output_desc)

    # Sanity check
    if len(outputs_desc) != len(psbt_obj.psbt_outs):
        _abort(
            f"{len(outputs_desc)} outputs in summary doesn't match {len(psbt_obj.psbt_outs)} outputs in PSBT"
        )

    # Confirm if 2 outputs we only have 1 change and 1 spend (can't be 2 changes or 2 spends)
    if len(outputs_desc) == 2:
        if all(x["is_change"] == outputs_desc[0]["is_change"] for x in outputs_desc):
            _abort(
                f"Cannot have both outputs be change or spend, must be 1-and-1. {outputs_desc}"
            )

    # Derive list of child private keys we'll use to sign the TX
    private_keys = []
    for root_path in set([x["root_path_used"] for x in inputs_desc]):
        private_keys.append(hd_priv.traverse(root_path).private_key)

    if args.verbose:
        print("Signing...")

    was_signed = psbt_obj.sign_with_private_keys(private_keys)

    TO_DISPLAY = " ".join(
        [
            "Send",
            _format_satoshis(output_spend_sats, in_btc=args.display_btc),
            "to",
            spend_addr,
            "with a fee of",
            _format_satoshis(TX_FEE_SATS, in_btc=args.display_btc),
            f"({round(TX_FEE_SATS / TOTAL_INPUT_SATS * 100, 2)}% of spend)",
        ]
    )

    if args.verbose:
        print("-" * 80)
        print("DETAILED VIEW")
        print("TXID:", psbt_obj.tx_obj.id())
        print(len(inputs_desc), "input(s):")
        for cnt, input_desc in enumerate(inputs_desc):
            print(f"  Input #{cnt}")
            for (
                k,
                v,
            ) in input_desc.items():
                print(f"    {k}: {v}")
        print(len(outputs_desc), "output(s):")
        for cnt, output_desc in enumerate(outputs_desc):
            print(f"  Output #{cnt}")
            for (
                k,
                v,
            ) in output_desc.items():
                print(f"    {k}: {v}")
        print("-" * 80)

    if was_signed is True:
        print()
        print(TO_DISPLAY, "by using this SIGNED PSBT:\n")
        print(psbt_obj.serialize_base64())
    else:
        _abort("PSBT wasn't signed: \n\n{TO_DISPLAY}")
