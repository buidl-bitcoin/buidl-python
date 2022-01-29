from itertools import combinations
from unittest import TestCase

from buidl.ecc import S256Point
from buidl.hd import HDPrivateKey
from buidl.helper import SIGHASH_DEFAULT
from buidl.script import address_to_script_pubkey
from buidl.taproot import MultiSigTapScript, MuSigTapScript, TapRootMultiSig
from buidl.timelock import Locktime, Sequence
from buidl.tx import Tx, TxIn, TxOut
from buidl.witness import Witness


class MuSigTest(TestCase):
    def test_musig2_compute_r(self):
        tests = [
            [
                "a807726c871dbf39f521add8f4f3ec12481c72f3eaf34c3817e0700d962f5dcb",
                "02033723cd84ff7862203f6414a2cf91af15860e1af59cb90c81b351a613e8a10a02addb1c18ccf16d7339cd9913221ba9bf652589d867a147cc922efbba7ce9521b",
                "02e4112326a722f4284ede04eb1ce790dc033e6848060552f3f672f0d9a6dba1af02fc61d2981bd01b607055a4b277241c996f231a4b7a76a4ab2f63e686a482dc06",
                "02ad57546657c85ecf573bfa9f4b7cecd082e891c8275f19367a81a0b906f247c802b9a3c5e431967c4a876d71610e2cd9e045ff719f883f181d155f722c5e6be6da",
                "02b570933248f11e96a2817a4c7a25d9d207f491c225735b2ec62564e4c477ca930226687bf51b1c4c793735be5ff0025413786a935239d503c1f89a009e969c51de",
                "02cd8c1671c5c747db87251f2eea9c798791cd8a48e3040affb20d3304ca649b560256de137cdd0102bf513d7eccd36ac8f9600bedf19a81ceb00beccebf2b3805ea",
                "03b2b2a479a72a73be4e5f1b2c971206626551fe0f5af51641f952bedc87f0329f02854f12c8b1d6f1a6799f772790551774337df481fe46bcec6080319e88505a6f",
                0x485032E1B095FD8CF1078D57FA5082A70133CD434940B01CD8C4EB1A5E0C4847,
                "5bca13eda91a22384935345b98cc9ccddfd0cb8a70dec437dd166e1d6bae2ec7",
            ],
            [
                "5892104fe51ecaf6947ea7fb34570e2644445a8730e1a0e0a97f8cf41a6998d5",
                "021170a2d066f039d23e4290d6363f85f54d8083f9f35563573d4200f3b13545f002931d05af6b03f220b4f9d5071bca3a19eefc8ff6d6ef98dfe4f13a4e967da5ab",
                "023ecdd0ec0529bbbd48b33e23fadb151a27d159334697e1b45355c9bdeb63a69002168a7172e135aee5528c670bdb2c55d7ef3b58183b9b7769a640a4400411b181",
                "029d203eda048363e8966deeffc4172026886551e3a453e999e36d62719b92988f0245f6e60814b697df5c2854190666cb911bbc55855b95116d2110a5d54c4d2dd0",
                "02a3c615001bf3fcf7dd75b0ccfebbe64153ebc616430c3d8edd5b0a5960ad9c8302d48cd72069474c246646095ff0bce07b98efe01cd1631e4e19fb1dcaa93f2472",
                "0264bc34dd34b2db1c6dcddc2dd02ab98af9b4eff610860738387837ccd2cd6b19027b673907b6ccd139d1a642d2c2a3473fb95d66f92713cf1973dd3295f803c840",
                "035c43ee76251eaaccdfcb6eb778688b41a8e25748d3bb23ee1a8ad549a0a42b6803cd922f35f041ac5916f8a5027dc2a9c31b480a8943cb88ab6149f96cb60b41a9",
                0x85AA1A22A7DA77B9E845B7E64306B6E1EB54476BB0C6D6E5FCE1C541D0B1EBF4,
                "9f4997a17b6af65fa0e519a0df3afe7dfbda5d1e6574f29fcbb313d7724dbe9d",
            ],
            [
                "d7bfbe8f3f48c6e898a00ffac11d789b8d6101f611c18697fc041e84d51dc419",
                "029d88be466076f1a0ae94b9ede9fa87992e0c1273f052a5297b36539bea51af6802cbb8bb5adbcbfe2293f9587c754ab23a092415acf040e5c9581d9a1941d86418",
                "0261bc725160ad35a4188358c1d92a5d68d918dc505647b41972ea25e774a51d5002710415f2b065988ecd9d3662e4198d6651d1a667a0e368110d1d0477dfd56f99",
                "0218499b0cd51edd722d74063f60c655a77e50f6a313772323aa4e75f9898b2a26023beaa481b75a982b320c5e9f3353fe7035ec19f77142fd707359e9e8255ff13a",
                "0293ff85af58daa9e3abd3ee77f931f40968cce06aa3b086a7bd433d2c3d929b92024f33b3ce19b12d17a50edb5eea4e1a0ddb46cbf8589bad2ab7ae0b801a18ec06",
                "02b364a6aececa595b1c1345469fc4afc9256610e94bccd3c54ca6c03d8c185ed302a4a884453a098bd29e6901e7068eadd6b3803b2ed3280323de69dc5dd1dd87d2",
                "03c33ad8a2c54cd5a9e4ec0428125fa37e0a6af211648ae9ee5ed64a0c3a1710260242843c43948786fb1ca4ce01d4abb1ea45f2fe8b522b2accca70edba572c8555",
                0x48E2AAD2090D1B7D4F9D641FDB4E1280723D13565CA816D2C3A532A655B2B9AF,
                "9b01366803d78b50822b9b6bf29f5cca8b6de2a5c14a1da14df578b9c2026634",
            ],
            [
                "d8a29f297b924870a943266ed06d4a56f4fbeb57820202421bf48e814a889e79",
                "021b2c92221b3561e9e900f82b46d7ba87983406e93806206c338a30c69e49192702c0c19e45e83b3526f7bd081ac34a263c8c4a5ae032acd61a828fe510c352994d",
                "02c97fb7c9ad42c0f83b9cee839ada9d448d8c8af2d413ea6c3bca76b043c9ad2902f83b7d6b7e5b67d42467122c9654c901dadc1149291300e53eeca7695d86a0d5",
                "02fd811fecf9c7c253e2d7bc7c372a39f2292cd0f92a8b25bdb94592db3254593602d5586bcef60ab3e7497dbd448a4a621b9b9a4c2171b5f75c0e678f9928570623",
                "0276b7f238b4727e631b91a789e5510aa2cf6ec50d9a8b742e20cf97a781347c12021ae0461b198dffa38244eef86a3831e7dab78a430f307e572e404bbefb525e7a",
                "02c47af19a3a2ffeccbc60c90c5474faea051ebcec39160c571c257da1c5dbe21b02f7ebf2dd8e23c383680f6f98cf5f0eda0548493a2073a2b0770c7336cd7c7e86",
                "02bf559c4ca6a6bb9f1e1fa6722b5d4cef7505ca8d22a2ba00b311ba44c510c769025f31b61f1342e106ba26f270d0aa322c615b83b5456e6a00ba5a730a391d3468",
                0xD87547E3BE133CA41A6899D0A61B6F4B0B5693CAFF66B3DAEAC35485676A350F,
                "1809e4aad196c7b78842da227f3c0cd9b5ada55d92937e07c6abbee7947ff5df",
            ],
            [
                "f9ddddfd6d2e6de9740786fe0fab265eefc96048505338015af110fa784f74c1",
                "023e0ae0b9fea2777a9a15889717ea0b38f79297ecc0c356a9506740be872c8979026d2cf16d5f28c4d58212d96f956090700b2a66b4ba3f19d8103ad9712e9afa8c",
                "02b1dbc9b4edfe1176276212a232845855c404b459174ee8de7fb34526f38b81a40239c92970413a9648229452c5ad07d37dac2cd523e4bbed4a5e824a45afaad28d",
                "021d60c18d8122664b928f37542913d98c22db61149580188440f3555afde22d7a02eeb3abb06c37d16e2a6ed394adef9c4cc725d92620791662bf090dfdec729eea",
                "02a2bc659e1c9931bcf033c940317ffbc194858b82d4706ee903efbf93c33fda73027bc2a03cce254742bb19ecf78827b03c35f09c7dffbe11774b145519c934591b",
                "02e604e14ec0050ee8d32592862b97093cd7b7f2378ceeea7304cc41d53fdb354c020433725dcabd8300a1101da1ebc3e62ac770436328f37716b62dd65e3a531bf1",
                "03170563b7ecc5623b43c0453902a18e4232b947771063d437501c22c38a2cd55c02068dd4ad13180a96eae7e45b77ba1b07763262fe2b3facc2576f04e4b8fa7827",
                0x577DBD5E86F697C7FE9DDD1A651DACD7BD872F9482DE345C3FF2367BBD7128D7,
                "dd76a3dc69856cab7fc846fed66570d9abe08c20c6933fa5137366a085a342c1",
            ],
        ]
        msg = b"hello world"
        for i, test in enumerate(tests):
            p = S256Point.parse(bytes.fromhex(test[0]))
            nonce_point_pairs = []
            for raw in test[1:6]:
                r_1 = S256Point.parse(bytes.fromhex(raw[:66]))
                r_2 = S256Point.parse(bytes.fromhex(raw[66:]))
                nonce_point_pairs.append((r_1, r_2))
            want = test[-1]
            # Hack to create the musig object
            musig = MuSigTapScript([p, p])
            musig.point = p
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r_1_sum = S256Point.parse(bytes.fromhex(test[6][:66]))
            r_2_sum = S256Point.parse(bytes.fromhex(test[6][66:]))
            self.assertEqual(nonce_sums[0], r_1_sum)
            self.assertEqual(nonce_sums[1], r_2_sum)
            self.assertEqual(musig.compute_coefficient(nonce_sums, msg), test[-2])
            r = musig.compute_r(nonce_sums, msg)
            self.assertEqual(r.bip340().hex(), want)

    def test_musig2_point_aggregation(self):
        tests = [
            [
                "346b16bbd0034f1c22fca23aa3aee0629b6b36fd504c617277bc245dfc71158b",
                "a805b4af00a0e3e522bb11eb46240f21f5fbce133bf34b0386b5fece4e8e93cb",
                "002c57fabe0d3401c9226de176ed25842d8d906a134c71806e0eb065dd5d2493",
                "cd71e04348b4f118d6f3efd6bbfef377a0ebabfc03a8fb564a4c1887fc322463",
                "75d0edbd30cee22cc424963cdbb1146b83baec5e27d2c2200663e1b44c909dec",
                "9e10adc2253f8699868a456b79059dcad028f8252057f1dcde68cf9ae8c5eeca",
            ],
            [
                "7eb3fd1c4d3f0c541b4260d673f51beba62b15aafe9cbad311ecc2a94eb20b2f",
                "d86e713462f55d13e8d0ff9a74c5523ca0ce8baaa339c75d59c91549b3aacd89",
                "c0361dc4b1f78a4f52cc431dde2467205544918ddc350b911c094ca78af5c194",
                "14a9f3a1730874d86afbc50a82297970714d332100a82e89b86f6185f16c24aa",
                "4eb803c43cb72e5fba9f255261452eb62e3fc798159082fedf3bbadd9a081794",
                "d0f19e0c0a13a1e05b25b679fe62b9f32794cc7729e39f8c9a880b5bb76e4072",
            ],
            [
                "332f121ff348c45b917d429985cbacf6a02d29ddeb940006c78eb620c92e6e17",
                "a6993d21fb59bdbd5d440d91ef63a6efddc23afc8fe378e8ab302de5a02ea6db",
                "c1040a3e8557900d4ac0d39bd13d3e118d949ddc6d887af332c274d355abee0b",
                "23befb7cef7a0f6780df8068538a1a0318c79c6ae9929f2ac151788b90381621",
                "bcbc1fdfa3c994601a12c4903b7c13126770c91b764a2ae9665e1d5108b87cbe",
                "2975571d6f7eeb695b31a9f362d938ca7cd6adc9f88ca16b8530d029c5c6b77e",
            ],
            [
                "147760f9692a4ac0b6f3620a1a78439513747d80db0740257aeb629f53a0f020",
                "a635e81e738bb6c82b86cf99bb1e66b67d66bef15127f1458e011853773d6134",
                "3cbde74f668afc7770d3ea4ed105f578d8fa17676796c950001f9e81f61d8df0",
                "deb885f923049d858f2f777fcbc0259449744214de7312ae952ea80fa8d0fed3",
                "771f2f656e3e03c35b7fd5271eefaf07f2cf839db6aa5756dabb270417b6b75f",
                "03e89d0c9c4374872b31e638a529088a810d0dbab4268d4438105e5ed6c0627a",
            ],
            [
                "0d0ac5169c2949584546ee723bbd9d968957f2ae2c6c81831d49037e06f64cc9",
                "cc402bb99c35310e635a5e62e1906dba5fb644a97c4d5774f7f683c2d786a772",
                "12e0e04f53c38290c191841c1e86980f91babc53c806375512f23cd1a39af109",
                "2b4a3f84469e280594c694a9d26e0fd108ef8a8dce8189a4efb0369f3e9c6dbd",
                "ef33036853535ecf3b42ca7339028d8233dbe7f7eff1ece81e206db433f0f35c",
                "942732e83fda0f976b2ed2bf63c9526c30089326a19792a1fb65a1a742d411c4",
            ],
            [
                "13733d0dea513fa3e68579a478670400891b48ecec10eac48de621a632a9fa84",
                "663bfccfa355c03e6d59da97618e19f86025b8feb3d18b9233ed66c4dae1407c",
                "bed92b873b26573a665a53ada307331122d929b16592c679bcbe17c7d3e345d0",
                "3ebb43e8f32a388c5fce9ca37b497b93565a8de3036b1a5a7530b78982abf9d2",
                "ea7b73b9e415416e8784c2e2e1d9727446ba38e1bfafa3618b3c20cbb4102300",
                "e148b34e6d2bb76c2da7efb63b91b69b6bd274aa734a7c837f07a285bce512bb",
            ],
        ]
        for test in tests:
            want = bytes.fromhex(test[-1])
            points = [S256Point.parse_bip340(bytes.fromhex(h)) for h in test[:-1]]
            tap_script = MuSigTapScript(points)
            self.assertEqual(tap_script.point.bip340(), want)

    def test_single_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.single_leaf_tap_root()
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1ppjjz7akunmrldfsldkhe5m7vhyx58g85pv7pw79jcere9tl4huqqdqezny",
        )
        prev_tx = bytes.fromhex(
            "cb476b747ee965bb4b34a739d7c07e42c074f23d566674fcc80c426db1bd9dfb"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1522
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_single_leaf_multisig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(1643332867)
        tap_root_input = tr_multisig.single_leaf_tap_root(locktime=current_locktime)
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pg67krjn69exwkdam3um0w5devyk4qs7eetzkm3twzfnqrk58xdlsyd62rg",
        )
        prev_tx = bytes.fromhex(
            "e1652728c24b904a7f8852445b6d952cb8270b944b67091b427d5154939a2494"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=0xFFFFFFFE)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1539
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(
            1, tx_ins, [tx_out], current_locktime, network="signet", segwit=True
        )
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        tx_obj.locktime = Locktime(current_locktime - 1)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_single_leaf_multisig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_time(3000)
        tap_root_input = tr_multisig.single_leaf_tap_root(sequence=current_sequence)
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p64cjudufu6699ddtw767zwjepl3ktaax8mgkgrpc9trclghtv9dqmazesf",
        )
        prev_tx = bytes.fromhex(
            "04449d63dd175dc09dfa143cdf4763594ba015f7596cf60d378e9a029ed7085c"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=current_sequence)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1537
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(2, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.sequence = Sequence(tx_in.sequence - 1)
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                tap_root_input.tap_node.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_multi_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        multisig = TapRootMultiSig(points, 3)
        tap_root_input = multisig.multi_leaf_tap_root()
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pkyedped6jxzamm88nmf4wc22jaz4rqxnsh8h2kjz7t6fnjl87q5qdfjmwf",
        )
        prev_tx = bytes.fromhex(
            "53ff5cf85de15a4083b01fe4ba1948d2a0cfe7975cd656887da7c6c9bbfd011e"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1619
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_obj.initialize_p2tr_multisig(
                input_index, tap_root_input.control_block(leaf), leaf.tap_script
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                    sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_multi_leaf_multisig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(74930)
        tap_root_input = tr_multisig.multi_leaf_tap_root(locktime=current_locktime)
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p7glmm24y2gqsf58emquv6mzy9m6msnwtenj5s77df33t3cal3wkssw5320",
        )
        prev_tx = bytes.fromhex(
            "03be9cbe084ef9deb54befac24381459ee89fbc9fc46079b9bde71451be95219"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=0xFFFFFFFE)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1634
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(
            1, tx_ins, [tx_out], current_locktime, network="signet", segwit=True
        )
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3, locktime=current_locktime).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        tx_obj.locktime = Locktime(current_locktime - 1)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3, locktime=current_locktime).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_multi_leaf_multisig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_blocks(50)
        tap_root_input = tr_multisig.multi_leaf_tap_root(sequence=current_sequence)
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p2qgnkwl2ny40d0xcy0fldljzmsk5vpj8navrhh5y2vsvle6xnj5ssvzrck",
        )
        prev_tx = bytes.fromhex(
            "40a61c5dd4a8c84e52563e5a47c6f962fa423b07785a1b412174eaef4df64b7b"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=current_sequence)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1629
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(2, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3, sequence=current_sequence).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3, sequence=current_sequence).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.sequence = Sequence(current_sequence - 1)
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address_num=i))
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.musig_tap_root()
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pd4rlyggzaj902pa92awwdrryftmyjeyd0unmuqf2atsg09jdv90qrp7pzs",
        )
        prev_tx = bytes.fromhex(
            "8072bb61c5f632171d5f5456d05e1beda10e5351cec755b63afe1aee3986ec71"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1119
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            musig = MuSigTapScript(pubkeys)
            leaf = musig.tap_leaf()
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_musig_locktime(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 musig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_locktime = Locktime(1643332867)
        tap_root_input = tr_multisig.musig_tap_root(locktime=current_locktime)
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pc357vk4y2qadgtkdfy3xqtmf5hfqh9apdqs3ajaw7kwspthtjt5sj8l4rh",
        )
        prev_tx = bytes.fromhex(
            "05362b7bf1d9d4e22f59fe5b6f019bc029a033bbf382a3bad5e7c68fa35d909d"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=0xFFFFFFFE)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1136
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(
            1, tx_ins, [tx_out], current_locktime, network="signet", segwit=True
        )
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            musig = MuSigTapScript(pubkeys, locktime=current_locktime)
            leaf = musig.tap_leaf()
            tx_in = tx_ins[input_index]
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        tx_obj.locktime = Locktime(current_locktime - 1)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            musig = MuSigTapScript(pubkeys, locktime=current_locktime)
            leaf = musig.tap_leaf()
            tx_in = tx_ins[input_index]
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_musig_sequence(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        current_sequence = Sequence.from_relative_time(3000)
        tap_root_input = tr_multisig.musig_tap_root(sequence=current_sequence)
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1ppqsvmxljh0e6tjaedamk52ft5k549nxd5wcgzc0luh6rxgwf7djs8s6h0p",
        )
        prev_tx = bytes.fromhex(
            "4421233e822da7e2eff98b439027cab0ef848f7904b1280bb3db6cd51cfa4dd0"
        )
        tx_ins = []
        for prev_index in range(11):
            tx_in = TxIn(prev_tx, prev_index, sequence=current_sequence)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 1134
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(2, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            musig = MuSigTapScript(pubkeys, sequence=current_sequence)
            leaf = musig.tap_leaf()
            tx_in = tx_ins[input_index]
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            musig = MuSigTapScript(pubkeys, sequence=current_sequence)
            leaf = musig.tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.sequence = Sequence(current_sequence - 1)
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_internal_pubkey_musig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf musig
        private_keys = []
        for i in range(5):
            private_keys.append(hd_priv_key.get_p2tr_receiving_privkey(address_num=i))
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        musig = MuSigTapScript(points)
        tap_root_input = tr_multisig.musig_tap_root()
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pd4rlyggzaj902pa92awwdrryftmyjeyd0unmuqf2atsg09jdv90qrp7pzs",
        )
        prev_tx = bytes.fromhex(
            "0e20a7fa2da856f82c3c0d35c99f456e953050ff8cdaad7147b391b2aaa0160c"
        )
        tx_ins = []
        for prev_index in range(3):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 214
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, tx_in in enumerate(tx_ins):
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in points:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
            schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
            tx_in.witness = Witness([schnorr.serialize()])
            self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_musig_and_single_leaf_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.musig_and_single_leaf_tap_root()
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pxspe3588dj53da5krsln9uszhudprt4qcc7srahn583j3q34cnts7pazqd",
        )
        prev_tx = bytes.fromhex(
            "9b630900da01a255f31d67e2157c2c382833c49d89c7291c6ead19fbcf0205d3"
        )
        tx_ins = []
        for prev_index in range(21):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 2701
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            tx_in.witness.items = []
            leaf = tr_multisig.single_leaf()
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
            tx_in = tx_obj.tx_ins[input_index + 10]
            musig = MuSigTapScript(pubkeys)
            leaf = musig.tap_leaf()
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index + 10, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index + 10))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_everything_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 single-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.everything_tap_root()
        leaf = tap_root_input.tap_node
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1pttvce83hlk5ktd248tj5dw0xtge9qfcnkhlfs86p4wzvtzzt79hq2h0p77",
        )
        prev_tx = bytes.fromhex(
            "7ccc9e42c4d7a12dbc5cb63158fd1f729f627e4f2fb89a2d474210eec22e43c6"
        )
        tx_ins = []
        for prev_index in range(31):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 4461
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(1, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            tx_in = tx_obj.tx_ins[input_index]
            tx_in.witness.items = []
            leaf = tr_multisig.single_leaf()
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 3)):
            input_index = i + 10
            tx_in = tx_obj.tx_ins[input_index]
            tx_in.witness.items = []
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_obj.initialize_p2tr_multisig(
                input_index, tap_root_input.control_block(leaf), leaf.tap_script
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                    sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 3)):
            input_index = i + 20
            tx_in = tx_obj.tx_ins[input_index]
            musig = MuSigTapScript(pubkeys)
            leaf = musig.tap_leaf()
            cb = tap_root_input.control_block(leaf)
            self.assertTrue(cb)
            tx_in.witness.items = [leaf.tap_script.raw_serialize(), cb.serialize()]
            sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
            nonce_secret_pairs = []
            nonce_point_pairs = []
            for _ in pubkeys:
                nonce_secrets, nonce_points = musig.generate_nonces()
                nonce_secret_pairs.append(nonce_secrets)
                nonce_point_pairs.append(nonce_points)
            nonce_sums = musig.nonce_sums(nonce_point_pairs)
            r = musig.compute_r(nonce_sums, sig_hash)
            s_sum = 0
            privs = [p for p in private_keys if p.point in pubkeys]
            for nonce_secrets, priv in zip(nonce_secret_pairs, privs):
                k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
                s_sum += musig.sign(priv, k, r, sig_hash)
            schnorr = musig.get_signature(s_sum, r, sig_hash)
            self.assertTrue(musig.point.verify_schnorr(sig_hash, schnorr))
            tx_in.witness.items.insert(0, schnorr.serialize())
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())

    def test_degrading_multisig(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.degrading_multisig_tap_root(
            sequence_time_interval=18 * 512
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1p80glz296ahqunke7tzp7d3s5swjfa5c8ff4vs5xqymee02gs9dkqs27p8u",
        )
        prev_tx = bytes.fromhex(
            "549d4f18a5c031f0ddc0040381d3914921f64b5e2b904cbfa5d57c89ac8f37c5"
        )
        tx_ins = []
        for prev_index in range(26):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        sequence_1 = Sequence.from_relative_time(18 * 512)
        sequence_2 = Sequence.from_relative_time(18 * 512 * 2)
        for tx_in in tx_ins[10:20]:
            tx_in.sequence = sequence_1
        for tx_in in tx_ins[20:25]:
            tx_in.sequence = sequence_2
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 3687
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(2, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 2)):
            input_index = i + 10
            leaf = MultiSigTapScript(pubkeys, 2, sequence=sequence_1).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 1)):
            input_index = i + 20
            leaf = MultiSigTapScript(pubkeys, 1, sequence=sequence_2).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        for tx_in in tx_ins[10:20]:
            tx_in.sequence = Sequence(sequence_1 - 1)
        for tx_in in tx_ins[20:25]:
            tx_in.sequence = Sequence(sequence_2 - 1)
        for i, pubkeys in enumerate(combinations(points, 2)):
            input_index = i + 10
            leaf = MultiSigTapScript(pubkeys, 2, sequence=sequence_1).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 1)):
            input_index = i + 20
            leaf = MultiSigTapScript(pubkeys, 1, sequence=sequence_2).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))

    def test_degrading_multisig_2(self):
        hd_priv_key = HDPrivateKey.from_mnemonic(
            "oil oil oil oil oil oil oil oil oil oil oil oil", network="signet"
        )
        # create a 3-of-5 multi-leaf multisig
        private_keys = [
            hd_priv_key.get_p2tr_receiving_privkey(address_num=i) for i in range(5)
        ]
        points = [priv.point for priv in private_keys]
        tr_multisig = TapRootMultiSig(points, 3)
        tap_root_input = tr_multisig.degrading_multisig_tap_root(
            sequence_block_interval=18
        )
        self.assertEqual(
            tap_root_input.address(network="signet"),
            "tb1ps00xd4jzdw982gjmmjgxzrhsca8ez5yfu6p4l6rt83ueqzlfns2qxf3qat",
        )
        prev_tx = bytes.fromhex(
            "f97d1c01fe613ed8357c9ab557e7cf55c7086ba5da299cd97819d1081494cebe"
        )
        tx_ins = []
        for prev_index in range(26):
            tx_in = TxIn(prev_tx, prev_index)
            tx_in._value = 1000000
            tx_in._script_pubkey = tap_root_input.script_pubkey()
            tx_ins.append(tx_in)
        sequence_1 = Sequence.from_relative_blocks(18)
        sequence_2 = Sequence.from_relative_blocks(18 * 2)
        for tx_in in tx_ins[10:20]:
            tx_in.sequence = sequence_1
        for tx_in in tx_ins[20:25]:
            tx_in.sequence = sequence_2
        change_script = address_to_script_pubkey(
            "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
        )
        fee = 3680
        tx_out = TxOut(1000000 * len(tx_ins) - fee, change_script)
        tx_obj = Tx(2, tx_ins, [tx_out], 0, network="signet", segwit=True)
        for input_index, pubkeys in enumerate(combinations(points, 3)):
            leaf = MultiSigTapScript(pubkeys, 3).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 2)):
            input_index = 10 + i
            leaf = MultiSigTapScript(pubkeys, 2, sequence=sequence_1).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 1)):
            input_index = 20 + i
            leaf = MultiSigTapScript(pubkeys, 1, sequence=sequence_2).tap_leaf()
            self.assertTrue(tap_root_input.control_block(leaf))
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertTrue(tx_obj.verify_input(input_index))
        input_index = len(tx_ins) - 1
        tx_in = tx_ins[input_index]
        musig = MuSigTapScript(points)
        self.assertEqual(tr_multisig.default_internal_pubkey, musig.point)
        nonce_secret_pairs = []
        nonce_point_pairs = []
        for _ in points:
            nonce_secrets, nonce_points = musig.generate_nonces()
            nonce_secret_pairs.append(nonce_secrets)
            nonce_point_pairs.append(nonce_points)
        sig_hash = tx_obj.sig_hash(input_index, SIGHASH_DEFAULT)
        nonce_sums = musig.nonce_sums(nonce_point_pairs)
        r = musig.compute_r(nonce_sums, sig_hash)
        s_sum = 0
        for nonce_secrets, priv in zip(nonce_secret_pairs, private_keys):
            k = musig.compute_k(nonce_secrets, nonce_sums, sig_hash)
            s_sum += musig.sign(priv, k, r, sig_hash, tweak=tap_root_input.tweak)
        schnorr = musig.get_signature(s_sum, r, sig_hash, tap_root_input.tweak)
        tx_in.finalize_p2tr_keypath(schnorr.serialize())
        self.assertTrue(tx_obj.verify_input(input_index))
        self.assertEqual(tx_obj.vbytes(), tx_obj.fee())
        self.assertTrue(tx_obj.verify())
        for tx_in in tx_ins[10:20]:
            tx_in.sequence = Sequence(sequence_1 - 1)
        for tx_in in tx_ins[20:25]:
            tx_in.sequence = Sequence(sequence_2 - 1)
        for i, pubkeys in enumerate(combinations(points, 2)):
            input_index = i + 10
            leaf = MultiSigTapScript(pubkeys, 2, sequence=sequence_1).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))
        for i, pubkeys in enumerate(combinations(points, 1)):
            input_index = i + 20
            leaf = MultiSigTapScript(pubkeys, 1, sequence=sequence_2).tap_leaf()
            tx_in = tx_ins[input_index]
            tx_in.witness.items = []
            tx_obj.initialize_p2tr_multisig(
                input_index,
                tap_root_input.control_block(leaf),
                leaf.tap_script,
            )
            sigs = []
            for priv in private_keys:
                if priv.point in pubkeys:
                    sig = tx_obj.get_sig_taproot(input_index, priv, ext_flag=1)
                else:
                    sig = b""
                sigs.append(sig)
            tx_obj.finalize_p2tr_multisig(input_index, sigs)
            self.assertFalse(tx_obj.verify_input(input_index))
