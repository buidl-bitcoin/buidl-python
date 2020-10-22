import argparse, re, sys
from pathlib import Path

from buidl.hd import HDPublicKey
from buidl.helper import sha256
from buidl.script import Script, P2WSHScriptPubKey, WitnessScript
from buidl.op import OP_CODE_NAMES_LOOKUP


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Calculate your checksum word and display your multisig extended pubkey information"
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

    re_results = re.findall("wsh\(sortedmulti\((.*)\)\)", contents)

    parts = re_results[0].split(",")
    quorum_m = int(parts.pop(0))
    quorum_n = len(parts)  # remaining entries are pubkeys with fingerprint/path
    assert 0 < quorum_m <= quorum_n

    sec_hex_lists, networks = [], set({})
    for pubkey in parts:
        # import pdb; pdb.set_trace()
        print("PUBKEY", pubkey)
        xfp, path, xpub, idx = re.match(
            "\[([0-9a-f]+)\*?(.*?)]([0-9A-Za-z]+).*([0-9]+?)", pubkey
        ).groups()
        print("xfp", xfp)
        print("path", path)
        print("xpub", xpub)
        print("idx", idx)
        pubkey_obj = HDPublicKey.parse(xpub)
        networks.add(pubkey_obj.testnet)
        child_obj = pubkey_obj.child(int(idx))

        sec_hex_list = []
        for cnt in range(args.limit):
            sec_hex_list.append(
                [
                    xfp,
                    "{}/{}/{}".format(path, idx, cnt + args.offset),
                    child_obj.child(cnt + args.offset).sec().hex(),
                ]
            )
        sec_hex_lists.append(sec_hex_list)

    assert len(networks) == 1, "ERROR: multiple networks in descriptor: {}".format(
        contents
    )

    for i in range(args.limit):
        sec_hexes_to_use = []
        for j in range(quorum_n):
            sec_hexes_to_use.append(sec_hex_lists[j][i][2])

        commands = [OP_CODE_NAMES_LOOKUP["OP_{}".format(quorum_m)]]
        commands.extend([bytes.fromhex(x) for x in sorted(sec_hexes_to_use)])  # BIP67
        commands.append(OP_CODE_NAMES_LOOKUP["OP_{}".format(quorum_n)])
        commands.append(OP_CODE_NAMES_LOOKUP["OP_CHECKMULTISIG"])
        witness_script = WitnessScript(commands)
        redeem_script = P2WSHScriptPubKey(sha256(witness_script.raw_serialize()))
        print(i + args.offset, redeem_script.address(testnet=True))
