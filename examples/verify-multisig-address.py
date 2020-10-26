import argparse, re, sys
from pathlib import Path

from buidl.hd import HDPublicKey
from buidl.helper import sha256
from buidl.script import Script, P2WSHScriptPubKey, WitnessScript
from buidl.op import OP_CODE_NAMES_LOOKUP


def re_pubkey_info_from_descriptor_fragment(fragment):
    xfp, path, xpub, idx = re.match(
        "\[([0-9a-f]+)\*?(.*?)\]([0-9A-Za-z]+).*([0-9]+?)", fragment
    ).groups()
    return {
        "xfp": xfp,
        "path": path.replace("\\/", "/").lstrip("/"),
        "xpub": xpub,
        "idx": int(idx),
    }


def get_pubkeys_info_from_descriptor(descriptor):
    re_results = re.findall("wsh\(sortedmulti\((.*)\)\)", descriptor)
    parts = re_results[0].split(",")
    quorum_m = int(parts.pop(0))
    quorum_n = len(parts)  # remaining entries are pubkeys with fingerprint/path
    assert 0 < quorum_m <= quorum_n

    pubkey_dicts = []
    for fragment in parts:
        pubkey_info = re_pubkey_info_from_descriptor_fragment(fragment=fragment)
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
    ), "ERROR: multiple networks in pubkeys: {}".format(all_pubkeys)

    return {
        "quorum_m": quorum_m,
        "quorum_n": quorum_n,
        "pubkey_dicts": pubkey_dicts,
    }


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Derive bitcoin addresses from your multisig wallet public key information."
    )
    parser.add_argument(
        "--descriptor",
        help="Bitcoin core script descriptor /path/to/file.json",
        required=True,
    )
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--offset", type=int, default=0)

    args = parser.parse_args()

    contents = Path(args.descriptor).read_text()
    pubkeys_info = get_pubkeys_info_from_descriptor(contents)

    for cnt in range(args.limit):
        sec_hexes_to_use = []
        for pubkey_info in pubkeys_info["pubkey_dicts"]:
            # import pdb; pdb.set_trace()
            leaf_xpub = pubkey_info["child_pubkey_obj"].child(index=cnt + args.offset)
            sec_hexes_to_use.append(leaf_xpub.sec().hex())

        commands = [OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_m"])]]
        commands.extend([bytes.fromhex(x) for x in sorted(sec_hexes_to_use)])  # BIP67
        commands.append(OP_CODE_NAMES_LOOKUP["OP_{}".format(pubkeys_info["quorum_n"])])
        commands.append(OP_CODE_NAMES_LOOKUP["OP_CHECKMULTISIG"])
        witness_script = WitnessScript(commands)
        redeem_script = P2WSHScriptPubKey(sha256(witness_script.raw_serialize()))
        print(f"Address #{cnt + args.offset}: {redeem_script.address(testnet=True)}")
