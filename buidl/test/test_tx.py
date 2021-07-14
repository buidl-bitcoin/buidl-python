from os.path import dirname, realpath, sep
from unittest import TestCase

from buidl.ecc import PrivateKey, Signature
from buidl.helper import decode_base58
from buidl.script import P2PKHScriptPubKey, RedeemScript, WitnessScript
from buidl.tx import Tx, TxIn, TxOut, TxFetcher


class TxTest(TestCase):
    cache_file = dirname(realpath(__file__)) + sep + "tx.cache"

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    def test_parse_version(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(len(tx.tx_ins), 1)
        want = bytes.fromhex(
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        )
        self.assertEqual(tx.tx_ins[0].prev_tx, want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = bytes.fromhex(
            "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a"
        )
        self.assertEqual(tx.tx_ins[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xFFFFFFFE)

    def test_parse_outputs(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = bytes.fromhex("1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac")
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = bytes.fromhex("1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac")
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.locktime, 410393)

    def test_parse_segwit(self):
        raw_tx = "01000000000101c70c4ede5731f1b47a89d133be9244927fa12e15778ec78a7e071273c0c58a870400000000ffffffff02809698000000000017a9144f34d55c56f827169921df008e8dfdc23678fc1787d464da1f00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d0400473044022050a5a50e78e6f9c65b5d94c78f8e4b339848456ff7c2231702b4a37439e2a3bd02201569cbf1c672bbb1608d6e9feea28705d8d6e54aa51d9fa396469be6ffc83c2d0147304402200b69a83cc3e3e1694037ef639049b0ece00f15718a03e9038aa42ac9d1bd0ea50220780c510821cd5205e5d178e6277005f4dd61a7fcccd4f8fae9e2d2adc355e728016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
        tx = Tx.parse_hex(raw_tx)
        self.assertTrue(tx.segwit)
        self.assertEqual(tx.version, 1)
        self.assertEqual(tx.tx_ins[0].prev_index, 4)
        self.assertEqual(tx.tx_outs[0].amount, 10000000)
        self.assertEqual(tx.locktime, 0)

    def test_serialize(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.serialize().hex(), raw_tx)

    def test_serialize_segwit(self):
        raw_tx = "01000000000101c70c4ede5731f1b47a89d133be9244927fa12e15778ec78a7e071273c0c58a870400000000ffffffff02809698000000000017a9144f34d55c56f827169921df008e8dfdc23678fc1787d464da1f00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d0400473044022050a5a50e78e6f9c65b5d94c78f8e4b339848456ff7c2231702b4a37439e2a3bd02201569cbf1c672bbb1608d6e9feea28705d8d6e54aa51d9fa396469be6ffc83c2d0147304402200b69a83cc3e3e1694037ef639049b0ece00f15718a03e9038aa42ac9d1bd0ea50220780c510821cd5205e5d178e6277005f4dd61a7fcccd4f8fae9e2d2adc355e728016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.serialize().hex(), raw_tx)

    def test_input_value(self):
        tx_hash = "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_hash = "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_hash), index)
        want = bytes.fromhex("1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac")
        self.assertEqual(tx_in.script_pubkey().serialize(), want)

    def test_fee(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        want = int(
            "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6", 16
        )
        self.assertEqual(tx.sig_hash(0), want)

    def test_sig_hash_bip143(self):
        raw_tx = "0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000"
        tx = Tx.parse_hex(raw_tx, network="testnet")
        want = int(
            "12bb9e0988736b8d1c3a180acd828b8a7eddae923a6a4bf0b4c14c40cd7327d1", 16
        )
        self.assertEqual(tx.sig_hash(0), want)
        tx = Tx.parse_hex(raw_tx, network="signet")
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_p2pkh(self):
        tx = TxFetcher.fetch(
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03"
        )
        self.assertTrue(tx.verify())
        tx = TxFetcher.fetch(
            "5418099cc755cb9dd3ebc6cf1a7888ad53a1a3beb5a025bce89eb1bf7f1650a2",
            network="testnet",
        )
        self.assertTrue(tx.verify())

    def test_verify_p2sh(self):
        tx = TxFetcher.fetch(
            "46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b"
        )
        self.assertTrue(tx.verify())

    def test_verify_p2wpkh(self):
        tx = TxFetcher.fetch(
            "d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c",
            network="testnet",
        )
        self.assertTrue(tx.verify())

    def test_verify_p2sh_p2wpkh(self):
        tx = TxFetcher.fetch(
            "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a"
        )
        self.assertTrue(tx.verify())

    def test_verify_p2wsh(self):
        tx = TxFetcher.fetch(
            "78457666f82c28aa37b74b506745a7c7684dc7842a52a457b09f09446721e11c",
            network="testnet",
        )
        self.assertTrue(tx.verify())

    def test_sign_p2pkh(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex(
            "0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8"
        )
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2")
        tx_outs.append(
            TxOut(amount=int(0.99 * 100000000), script_pubkey=P2PKHScriptPubKey(h160))
        )
        h160 = decode_base58("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf")
        tx_outs.append(
            TxOut(amount=int(0.1 * 100000000), script_pubkey=P2PKHScriptPubKey(h160))
        )
        tx = Tx(1, tx_ins, tx_outs, 0, network="testnet")
        self.assertTrue(tx.sign_p2pkh(0, private_key))

    def test_sign_p2wpkh(self):
        private_key = PrivateKey(secret=8675309)
        prev_tx = bytes.fromhex(
            "6bfa079532dd9fad6cfbf218edc294fdfa7dd0cb3956375bc864577fb36fad97"
        )
        prev_index = 0
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(network="testnet") - fee
        h160 = decode_base58("mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv")
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, network="testnet", segwit=True)
        self.assertTrue(t.sign_input(0, private_key))
        want = "0100000000010197ad6fb37f5764c85b375639cbd07dfafd94c2ed18f2fb6cad9fdd329507fa6b0000000000ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac02483045022100feab5b8feefd5e774bdfdc1dc23525b40f1ffaa25a376f8453158614f00fa6cb02204456493d0bc606ebeb3fa008e056bbc96a67cb0c11abcc871bfc2bec60206bf0012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b6700000000"
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2sh_p2wpkh(self):
        private_key = PrivateKey(secret=8675309)
        redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
        prev_tx = bytes.fromhex(
            "2e19b463bd5c8a3e0f10ae827f5a670f6794fca96394ecf8488321291d1c2ee9"
        )
        prev_index = 1
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(network="testnet") - fee
        h160 = decode_base58("mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv")
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, network="testnet", segwit=True)
        self.assertTrue(t.sign_input(0, private_key, redeem_script=redeem_script))
        want = "01000000000101e92e1c1d29218348f8ec9463a9fc94670f675a7f82ae100f3e8a5cbd63b4192e0100000017160014d52ad7ca9b3d096a38e752c2018e6fbc40cdf26fffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0247304402205e3ae5ac9a0e0a16ae04b0678c5732973ce31051ba9f42193e69843e600d84f2022060a91cbd48899b1bf5d1ffb7532f69ab74bc1701a253a415196b38feb599163b012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b6700000000"
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_input(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex(
            "0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8"
        )
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58("mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2")
        tx_outs.append(
            TxOut(amount=int(0.99 * 100000000), script_pubkey=P2PKHScriptPubKey(h160))
        )
        h160 = decode_base58("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf")
        tx_outs.append(
            TxOut(amount=int(0.1 * 100000000), script_pubkey=P2PKHScriptPubKey(h160))
        )
        tx = Tx(1, tx_ins, tx_outs, 0, network="testnet")
        self.assertTrue(tx.sign_input(0, private_key))

    def test_sign_p2sh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)

        redeem_script = RedeemScript.create_p2sh_multisig(
            quorum_m=2,
            pubkey_hexes=[
                private_key1.point.sec().hex(),
                private_key2.point.sec().hex(),
            ],
            sort_keys=False,
        )

        prev_tx = bytes.fromhex(
            "ded9b3c8b71032d42ea3b2fd5211d75b39a90637f967e637b64dfdb887dd11d7"
        )
        prev_index = 1
        fee_sats = 500
        tx_in = TxIn(prev_tx, prev_index)
        tx_in_sats = 1000000
        amount = tx_in_sats - fee_sats
        h160 = decode_base58("mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv")
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, network="testnet", segwit=True)
        sig1 = t.get_sig_legacy(0, private_key1, redeem_script=redeem_script)
        sig2 = t.get_sig_legacy(0, private_key2, redeem_script=redeem_script)
        self.assertTrue(
            t.check_sig_legacy(
                0,
                private_key1.point,
                Signature.parse(sig1[:-1]),
                redeem_script=redeem_script,
            )
        )
        self.assertTrue(
            t.check_sig_legacy(
                0,
                private_key2.point,
                Signature.parse(sig2[:-1]),
                redeem_script=redeem_script,
            )
        )
        tx_in.finalize_p2sh_multisig([sig1, sig2], redeem_script)
        want = "01000000000101d711dd87b8fd4db637e667f93706a9395bd71152fdb2a32ed43210b7c8b3d9de01000000da00483045022100c457fa45f63636eb2552cef642116a8363469d60b99dcda19686d30ed2a539bb0220222c7617e3dd9aef37095df52047e9a6bf11254a88eab521aec1b8b4e7913b3401473044022003d3d6a1b232b42d9fb961b42ab6854077a1e195473d952d54e6dcf22ef6dede02206f62a44b65e1dbccbdd54a3fd6f87c05a8d8da39c70e06f5ee07d469e1155e020147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452aeffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0000000000"
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2wsh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)
        witness_script = WitnessScript(
            [0x52, private_key1.point.sec(), private_key2.point.sec(), 0x52, 0xAE]
        )
        prev_tx = bytes.fromhex(
            "61cd20e3ffdf9216cee9cd607e1a65d3096513c4df3a63d410c047379b54a94a"
        )
        prev_index = 1
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(network="testnet") - fee
        h160 = decode_base58("mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv")
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, network="testnet", segwit=True)
        sig1 = t.get_sig_segwit(0, private_key1, witness_script=witness_script)
        sig2 = t.get_sig_segwit(0, private_key2, witness_script=witness_script)
        self.assertTrue(
            t.check_sig_segwit(
                0,
                private_key1.point,
                Signature.parse(sig1[:-1]),
                witness_script=witness_script,
            )
        )
        self.assertTrue(
            t.check_sig_segwit(
                0,
                private_key2.point,
                Signature.parse(sig2[:-1]),
                witness_script=witness_script,
            )
        )
        tx_in.finalize_p2wsh_multisig([sig1, sig2], witness_script)
        want = "010000000001014aa9549b3747c010d4633adfc4136509d3651a7e60cde9ce1692dfffe320cd610100000000ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac04004730440220325e9f389c4835dab74d644e8c8e295535d9b082d28aefc3fa127e23538051bd022050d68dcecda660d4c01a8443c2b30bd0b3e4b1a405b0f352dcb068210862f6810147304402201abceabfc94903644cf7be836876eaa418cb226e03554c17a71c65b232f4507302202105a8344abae9632d1bc8249a52cf651c4ea02ca5259e20b50d8169c949f5a20147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452ae00000000"
        self.assertEqual(t.serialize().hex(), want)

    def test_sign_p2sh_p2wsh_multisig(self):
        private_key1 = PrivateKey(secret=8675309)
        private_key2 = PrivateKey(secret=8675310)
        witness_script = WitnessScript(
            [0x52, private_key1.point.sec(), private_key2.point.sec(), 0x52, 0xAE]
        )
        prev_tx = bytes.fromhex(
            "f92c8c8e40296c6a94539b6d22d8994a56dd8ff2d6018d07a8371fef1f66efee"
        )
        prev_index = 0
        fee = 500
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(network="testnet") - fee
        h160 = decode_base58("mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv")
        tx_out = TxOut(amount=amount, script_pubkey=P2PKHScriptPubKey(h160))
        t = Tx(1, [tx_in], [tx_out], 0, network="testnet", segwit=True)
        sig1 = t.get_sig_segwit(0, private_key1, witness_script=witness_script)
        sig2 = t.get_sig_segwit(0, private_key2, witness_script=witness_script)
        self.assertTrue(
            t.check_sig_segwit(
                0,
                private_key1.point,
                Signature.parse(sig1[:-1]),
                witness_script=witness_script,
            )
        )
        self.assertTrue(
            t.check_sig_segwit(
                0,
                private_key2.point,
                Signature.parse(sig2[:-1]),
                witness_script=witness_script,
            )
        )
        tx_in.finalize_p2sh_p2wsh_multisig([sig1, sig2], witness_script)
        want = "01000000000101eeef661fef1f37a8078d01d6f28fdd564a99d8226d9b53946a6c29408e8c2cf900000000232200206ddafd1089f07a2ba9868df71f622801fe11f5452c6ff1f8f51573133828b437ffffffff014c400f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac0400483045022100d31433973b7f8014a4e17d46c4720c6c9bed1ee720dc1f0839dd847fa6972553022039278e98a3c18f4748a2727b99acd41eb1534dcf041a3abefd0c7546c868f55801473044022027be7d616b0930c1edf7ed39cc99edf5975e7b859d3224fe340d55c595c2798f02206c05662d39e5b05cc13f936360d62a482b122ad9791074bbdafec3ddc221b8c00147522103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b672103674944c63d8dc3373a88cd1f8403b39b48be07bdb83d51dbbaa34be070c72e1452ae00000000"
        self.assertEqual(t.serialize().hex(), want)

    def test_is_coinbase(self):
        raw_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        tx = Tx.parse_hex(raw_tx)
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        raw_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000"
        tx = Tx.parse_hex(raw_tx)
        self.assertEqual(tx.coinbase_height(), 465879)
        raw_tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
        tx = Tx.parse_hex(raw_tx)
        self.assertIsNone(tx.coinbase_height())
