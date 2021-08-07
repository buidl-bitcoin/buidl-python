from collections import defaultdict

from buidl.hd import get_unhardened_child_path, HDPublicKey
from buidl.psbt import MixedNetwork, NamedHDPublicKey, PSBT
from buidl.tx import Tx, TxIn, TxOut
from buidl.script import RedeemScript, address_to_script_pubkey


def _safe_get_child_hdpubkey(xfp_dict, xfp_hex, root_path, cnt):
    """
    Given an xfp_dict, inteligently traverse all the xpubs until you find one that can traverse to the given root_path
    """
    for base_path, xpub_obj in xfp_dict.get(xfp_hex, {}).items():
        child_path = get_unhardened_child_path(
            root_path=root_path,
            base_path=base_path,
        )
        if child_path:
            if base_path.count("/") != xpub_obj.depth:
                msg = f"xfp_hex {xfp_hex} for in/output #{cnt} base_path mismatch: {base_path} depth != {xpub_obj.depth} for {xpub_obj}"
                raise ValueError(msg)
            return xpub_obj.traverse(child_path)
    raise ValueError(
        f"xfp_hex {xfp_hex} with {root_path} for in/output #{cnt} not supplied in xpub_dict"
    )


def create_p2sh_multisig_psbt(
    public_key_records,
    input_dicts,
    output_dicts,
    fee_sats,
):
    """
    Helper method to create a p2sh multisig PSBT.

    network (testnet/mainnet) will be inferred from xpubs/tpubs.

    public_key_records are a list of entries that loom like this: [xfp_hex, xpub_b58, base_path]
    # TODO: turn this into a new object?
    """

    # initialize variables
    network = None
    tx_lookup, pubkey_lookup, redeem_lookup, hd_pubs = {}, {}, {}, {}

    # Use a nested default dict for increased readability
    # It's possible (though nonstandard) for one xfp to have multiple public_key_records in a multisig wallet
    # https://stackoverflow.com/a/19189356
    recursive_defaultdict = lambda: defaultdict(recursive_defaultdict)  # noqa: E731
    xfp_dict = recursive_defaultdict()

    # This at the child pubkey lookup that each input will traverse off of
    for xfp_hex, xpub_b58, base_path in public_key_records:
        hd_pubkey_obj = HDPublicKey.parse(xpub_b58)

        # We will use this dict/list structure for each input/ouput in the for-loops below
        xfp_dict[xfp_hex][base_path] = hd_pubkey_obj

        named_global_hd_pubkey_obj = NamedHDPublicKey.from_hd_pub(
            child_hd_pub=hd_pubkey_obj,
            xfp_hex=xfp_hex,
            # we're only going to base path level
            path=base_path,
        )
        hd_pubs[named_global_hd_pubkey_obj.serialize()] = named_global_hd_pubkey_obj

        if network is None:
            # Set the initial value
            network = hd_pubkey_obj.network
        else:
            # Confirm it hasn't changed
            if network != hd_pubkey_obj.network:
                raise MixedNetwork(
                    f"Mixed networks in public key records: {public_key_records}"
                )

    tx_ins = []
    for cnt, input_dict in enumerate(input_dicts):

        # Prev tx stuff
        prev_tx_dict = input_dict["prev_tx_dict"]
        prev_tx_obj = Tx.parse_hex(prev_tx_dict["hex"])
        tx_lookup[prev_tx_obj.hash()] = prev_tx_obj

        if prev_tx_dict["hash_hex"] != prev_tx_obj.hash().hex():
            raise ValueError(
                f"Hash digest mismatch for input #{cnt}: {prev_tx_dict['hash_hex']} != {prev_tx_obj.hash().hex()}"
            )

        # pubkey lookups needed for validation
        input_pubkey_hexes, total_input_sats = [], 0
        for xfp_hex, root_path in input_dict["path_dict"].items():
            # Get the correct xpub/path
            child_hd_pubkey = _safe_get_child_hdpubkey(
                xfp_dict=xfp_dict,
                xfp_hex=xfp_hex,
                root_path=root_path,
                cnt=cnt,
            )
            input_pubkey_hexes.append(child_hd_pubkey.sec().hex())

            # Enhance the PSBT
            named_hd_pubkey_obj = NamedHDPublicKey.from_hd_pub(
                child_hd_pub=child_hd_pubkey,
                xfp_hex=xfp_hex,
                path=root_path,
            )
            pubkey_lookup[named_hd_pubkey_obj.sec()] = named_hd_pubkey_obj

        utxo = prev_tx_obj.tx_outs[prev_tx_dict["output_idx"]]

        # Grab amount as developer safety check
        if prev_tx_dict["output_sats"] != utxo.amount:
            raise ValueError(
                f"Wrong number of sats for input #{cnt}! Expecting {prev_tx_dict['output_sats']} but got {utxo.amount}"
            )
        total_input_sats += utxo.amount

        redeem_script = RedeemScript.create_p2sh_multisig(
            quorum_m=input_dict["quorum_m"],
            pubkey_hexes=input_pubkey_hexes,
            sort_keys=True,  # TODO: allow legacy users to customize this?
            expected_addr=utxo.script_pubkey.address(network=network),
            expected_addr_network=network,
        )

        # Confirm address matches previous ouput
        if redeem_script.address(network=network) != utxo.script_pubkey.address(
            network=network
        ):
            raise ValueError(
                f"Invalid redeem script for input #{cnt}. Expecting {redeem_script.address(network=network)} but got {utxo.script_pubkey.address(network=network)}"
            )

        tx_in = TxIn(prev_tx=prev_tx_obj.hash(), prev_index=prev_tx_dict["output_idx"])
        tx_ins.append(tx_in)

        # For enhancing the PSBT for HWWs:
        redeem_lookup[redeem_script.hash160()] = redeem_script

    tx_outs = []
    for cnt, output_dict in enumerate(output_dicts):
        tx_out = TxOut(
            amount=output_dict["sats"],
            script_pubkey=address_to_script_pubkey(output_dict["address"]),
        )
        tx_outs.append(tx_out)

        if output_dict.get("path_dict"):
            # This output claims to be change, so we must validate it here
            output_pubkey_hexes = []
            for xfp_hex, root_path in output_dict["path_dict"].items():
                child_hd_pubkey = _safe_get_child_hdpubkey(
                    xfp_dict=xfp_dict,
                    xfp_hex=xfp_hex,
                    root_path=root_path,
                    cnt=cnt,
                )
                output_pubkey_hexes.append(child_hd_pubkey.sec().hex())

                # Enhance the PSBT
                named_hd_pubkey_obj = NamedHDPublicKey.from_hd_pub(
                    child_hd_pub=child_hd_pubkey,
                    xfp_hex=xfp_hex,
                    path=root_path,
                )
                pubkey_lookup[named_hd_pubkey_obj.sec()] = named_hd_pubkey_obj

            redeem_script = RedeemScript.create_p2sh_multisig(
                quorum_m=output_dict["quorum_m"],
                pubkey_hexes=output_pubkey_hexes,
                # We intentionally only allow change addresses to be lexicographically sorted
                sort_keys=True,
            )
            # Confirm address matches previous ouput
            if redeem_script.address(network=network) != output_dict["address"]:
                raise ValueError(
                    f"Invalid redeem script for output #{cnt}. Expecting {redeem_script.address(network=network)} but got {output_dict['address']}"
                )

    tx_obj = Tx(
        version=1,
        tx_ins=tx_ins,
        tx_outs=tx_outs,
        locktime=0,
        network=network,
        segwit=False,
    )

    # Safety check to try and prevent footgun

    calculated_fee_sats = total_input_sats - sum([tx_out.amount for tx_out in tx_outs])
    if fee_sats != calculated_fee_sats:
        raise ValueError(
            f"TX fee of {fee_sats} sats supplied != {calculated_fee_sats} sats calculated"
        )

    return PSBT.create(
        tx_obj=tx_obj,
        validate=True,
        tx_lookup=tx_lookup,
        pubkey_lookup=pubkey_lookup,
        redeem_lookup=redeem_lookup,
        witness_lookup=None,
        hd_pubs=hd_pubs,
    )
