import argparse, sys
from io import BytesIO
from pathlib import Path

from buidl.psbt import PSBT
from buidl.hd import HDPrivateKey
from buidl.helper import hash256
from buidl.script import WitnessScript, OP_CODE_NAMES

# MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract"

# PSBT_B64 = """cHNidP8BAFICAAAAATmuiNDMoIDFGkbzmjO4o5XFcIa/suq0dPzwSXYEX7OTAQAAAAD/////AYcmAAAAAAAAFgAUIt/omUxFi3UfZe3udmqf+kfJo3oAAAAAAAEBKxAnAAAAAAAAIgAgV8V9KO3ZPhSVAz6L9BAFTjBTA6v3Jh5ue9zpMN9Vr7EBBYtRIQKsgw1c0nvywMceF18zkBpGWthmBrhvdtTaKOLekS85WCEDMubsh2ALyRkMDvmQ0/G3P7/BMztnPFpI2WR1hEj2y74hA2Odq3jSQaa+iGPkhTaIH1z7T9X4BBngghbQTdquJpDCIQOds1UQ8tnzBZxIT2itonCSaoro4gSIm+TU0VUGONpgIlSuIgYCrIMNXNJ78sDHHhdfM5AaRlrYZga4b3bU2iji3pEvOVgcOlK1zTAAAIABAACAAAAAgAIAAIAAAAAAAgAAACIGAzLm7IdgC8kZDA75kNPxtz+/wTM7ZzxaSNlkdYRI9su+HMfQZIowAACAAQAAgAAAAIACAACAAAAAAAIAAAAiBgNjnat40kGmvohj5IU2iB9c+0/V+AQZ4IIW0E3ariaQwhwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAACAAAAIgYDnbNVEPLZ8wWcSE9oraJwkmqK6OIEiJvk1NFVBjjaYCIc99BAkDAAAIABAACAAAAAgAIAAIAAAAAAAgAAAAAA"""


# FIXME:
# Add TX fee to confirmation
# Add summary view (x BTC to Y address)
# Add flag/method for saving to file


# TODO: is there a standard to use here?
# Inspired by https://github.com/trezor/trezor-firmware/blob/e23bb10ec49710cc2b2b993db9c907d3c7becf2c/core/src/apps/wallet/sign_tx/multisig.py#L37
def calculate_msig_digest(quorum_m, root_xfp_hexes):
    fingerprints_to_hash = "-".join(sorted(root_xfp_hexes))
    return hash256(f"{quorum_m}:{fingerprints_to_hash}".encode())


def _abort(msg):
    print("ABORTING WITHOUT SIGNING:")
    print(msg)
    sys.exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Sign a multisig transaction via PSBT."
    )
    parser.add_argument(
        "--psbt-file",
        help="PSBT (Partially Signed Bitcoin Transaction) file to sign. /path/to/file.psbt",
        required=True,
    )
    parser.add_argument(
        "--mnemonic",
        help="Full BIP39 mnemonic",
        required=True,
    )
    # parser.add_argument("--testnet", action="store_true")
    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args()

    psbt_b64 = Path(args.psbt_file).read_text()

    psbt_obj = PSBT.parse_base64(psbt_b64)
    psbt_obj.validate()  # redundant but explicit
    IS_TESTNET = not psbt_obj.tx_obj.testnet  # FIXME, yikes!

    hd_priv = HDPrivateKey.from_mnemonic(
        mnemonic=args.mnemonic.strip(), testnet=psbt_obj.tx_obj.testnet
    )

    # Validate multisig transaction
    # TODO: abstract some of this into buidl library?
    # Below is confusing because we perform both validation and coordinate signing.

    # This tool only supports a TX with the following constraints:
    # 1. We sign ALL inputs with the same multisig wallet (quorum/pubkeys)
    # 2. There can only be 1 output (sweep transaction) or 2 outputs (spend + change). If there is change, we validate that it matches the inputs.

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
                "quorum_m": quorum_m,
                "quroum_n": len(root_xfp_hexes),
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
            # TODO: add nsequence!
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

    # Confirm we only have 1 change and 1 spend (can't be 2 changes or 2 spends)
    if len(outputs_desc) != len(psbt_obj.psbt_outs):
        _abort(
            f"{len(outputs_desc)} outputs in summary doesn't match {len(psbt_obj.psbt_outs)} outputs in PSBT"
        )

    if len(outputs_desc) == 2:
        if all(x["is_change"] == outputs_desc[0]["is_change"] for x in outputs_desc):
            _abort(
                f"Cannot have both outputs be change or spend, must be 1-and-1. {outputs_desc}"
            )

    if not args.quiet:
        print("-" * 80)
        print("DETAILED VIEW")
        print(len(inputs_desc), "input(s):")
        for input_desc in inputs_desc:
            print("", input_desc)
        print(len(outputs_desc), "output(s):")
        for output_desc in outputs_desc:
            print("", output_desc)
        print("-" * 80)

    # Derive list of child private keys we'll use to sign the TX
    private_keys = []
    for root_path in set([x["root_path_used"] for x in inputs_desc]):
        private_keys.append(hd_priv.traverse(root_path).private_key)

    print("Signing...")
    was_signed = psbt_obj.sign_with_private_keys(private_keys)
    if was_signed is True:
        print("Signed Transaction to Broadcast:\n")
        print(psbt_obj.serialize_base64())
    else:
        _abort("TRANSACTION WASN'T SIGNED!")
