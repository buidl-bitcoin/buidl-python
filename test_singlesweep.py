import unittest

import pexpect

from buidl import PrivateKey


class SinglesweepTest(unittest.TestCase):
    def expect_b(self, text):
        """
        Expect a string of text reading one byte at a time (not waiting on a newline)
        """
        buffer = ""
        while True:
            # This will error out at the end of the buffer
            latest_char = self.child.read(1)
            try:
                buffer += latest_char.decode()
            except UnicodeDecodeError:
                buffer += str(latest_char)
            if text in buffer:
                return True

        # this line should never be reached, the script would timeout first
        assert f"`{text}` not in buffer: {buffer}"

    def setUp(self):
        self.child = pexpect.spawn("python3 singlesweep.py", timeout=2)
        self.child.expect(
            "Welcome to singlesweep, a stateless single sig sweeper that works with WIF and PSBTs."
        )

    def test_debug(self):
        self.child.sendline("debug")
        self.expect_b("buidl Version: ")
        self.expect_b("Python Version: ")
        self.expect_b("Platform: ")
        self.expect_b("libsecp256k1 Configured: ")

    def test_send_compressed(self):
        # This isn't strictly neccesary, just shows how this was generated
        privkey_obj = PrivateKey(
            secret=314159265358979323846, testnet=True, compressed=True
        )
        self.assertEqual(
            privkey_obj.point.address(compressed=True, testnet=True),
            "mxgA6BsDLcv4vooLx4j6MfHQRihbrdwV5P",
        )
        self.assertEqual(
            privkey_obj.wif(compressed=True),
            "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuh9HqjiLNWDVQudB7k4E",
        )

        self.child.sendline("sweep")
        self.expect_b("Enter WIF (Wallet Import Format) to use for signing:")

        self.child.sendline("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuh9HqjiLNWDVQudB7k4E")
        self.child.expect(
            "Will attempt to spend from TESTNET mxgA6BsDLcv4vooLx4j6MfHQRihbrdwV5P"
        )
        self.expect_b("Paste partially signed bitcoin transaction (PSBT) in base64 form")

        psbt_to_sign = "cHNidP8BAFUCAAAAAVRZh97dheVJzHkcaznyZCtSunoNJgnNGBRKGYw5nBSQAQAAAAD9////ASCFAQAAAAAAGXapFJ+aer1gDAyqA5g6d8jD344GLLL6iKxZiR4AAAEA4gIAAAAAAQEy/IizvbchxG0F6yLb/g0qEa9HidaAzlDzGCUMNgwZTQAAAAAA/v///wKEOaMAAAAAABepFOpylCCZWu7JekQ9p98RPeFn3kRoh6CGAQAAAAAAGXapFLw3unG6dBaKPCHEL+A8dYsff8aRiKwCRzBEAiBanqsb6aKeGstvedoheUCnr7buvdOHz58/J803NfsOkAIgOIpcQ+OGZEzFo7E3FBvUHagLZJLik8vf9KqnfVwfn9MBIQO3M5Kw2cHk3i3s1FpZK69B/oUOubZhv6e/GU7n6RVAeViJHgAAAA=="
        self.child.sendline(psbt_to_sign)
        self.expect_b("PSBT sends 99,616 sats to mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB with an UNVERIFIED fee of 384 sats (0.38% of spend)")
        self.expect_b("In Depth Transaction View? [Y/n]")

        self.child.sendline("Y")
        self.child.expect("DETAILED VIEW")
        self.expect_b("Sign this transaction?")

        self.child.sendline("Y")
        self.child.expect(
            "SIGNED TX 0dfc0c3b8e0e87b6321a75fca542c22f792b2d6f519720e0a974976c646b7d5e"
        )
        self.child.expect(
            "0200000001545987dedd85e549cc791c6b39f2642b52ba7a0d2609cd18144a198c399c1490010000006a473044022076ce7079425632ca3d355d33c9f8d5152bdfef87e7ef4a8be3792f3cbc4c7f4702201da9fd053b42c4ea2b57717d8b4995caf6f3d47cf7572f54122f158c208c4d3c012102f64b30341c33fb908144acb898781e1cf011bae3e44489864a6c621ded2a29aafdffffff0120850100000000001976a9149f9a7abd600c0caa03983a77c8c3df8e062cb2fa88ac59891e00"
        )

    def test_send_uncompressed(self):
        # This isn't strictly neccesary, just shows how this was generated
        privkey_obj = PrivateKey(
            secret=314159265358979323846, testnet=True, compressed=False
        )
        self.assertEqual(
            privkey_obj.point.address(compressed=False, testnet=True),
            "mzJtwV9LL6B3Nvm1uc1Z5NK3mqqaZyn9w1",
        )
        self.assertEqual(
            privkey_obj.wif(compressed=False),
            "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4nM1C3RmiaMW6WFGmDS",
        )

        self.child.sendline("sweep")
        self.expect_b("Enter WIF (Wallet Import Format) to use for signing:")

        self.child.sendline("91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4nM1C3RmiaMW6WFGmDS")
        self.child.expect(
            "Will attempt to spend from TESTNET mzJtwV9LL6B3Nvm1uc1Z5NK3mqqaZyn9w1"
        )
        self.expect_b("Paste partially signed bitcoin transaction (PSBT) in base64 form")
        psbt_to_sign = "cHNidP8BAFUCAAAAAaASEHE91UJrrmU5FMjXIVUV5HF91EGzcaktfooEUPBFAAAAAAD9////AWPhFwAAAAAAGXapFJ+aer1gDAyqA5g6d8jD344GLLL6iKxniR4AAAEA4gIAAAAAAQH96ccGxhmgYfsrP9xnIUl2WJxnE+Jz2iAH08QAkPiSiQAAAAAA/v///wLj4hcAAAAAABl2qRTOIpkaGEnqK3MB5zwY6WWk/ZKiRoisAWO7XQAAAAAXqRT2kti1/KAVtU90LS4zl1LNGa3NtocCRzBEAiAnsPi908ar1ROFyTWV4TlqlKHijNRbOuolJILCG2G6ywIgCPZLYkWebvcTOztJj3I+D6CX/y9DCZRRhrD9QJtdR80BIQPLHa2FJlrG7KzxKA6ZVJfJ2P3xGp/88a65XIkCNK6Xk1iJHgAAAA=="
        self.child.sendline(psbt_to_sign)
        self.child.readline()
        res = str(self.child.readline())
        want = "PSBT sends 1,565,027 sats to mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB with an UNVERIFIED fee of 384 sats (0.02% of spend)"
        self.assertIn(want, res)
        res = str(self.child.read(40))
        self.assertIn("In Depth Transaction View?", res)
        self.child.sendline("Y")
        self.child.expect("DETAILED VIEW")
        for _ in range(21):
            self.child.readline()
        res = str(self.child.read(35))
        self.assertIn("Sign this transaction?", res)
        self.child.sendline("Y")
        self.child.expect(
            "SIGNED TX f3271bbac2b66d83379de855a79cead9d0e5210b857bee5c22462635033861c4"
        )
        self.child.expect(
            "0200000001a01210713dd5426bae653914c8d7215515e4717dd441b371a92d7e8a0450f045000000008b4830450221008123f3ce37457a8c61709d873bddf3fc93e46f684749956571d59acbd00087c002202346068137f144df11d92fa185640c848dd89c22552803b502e34be56e9da6de014104f64b30341c33fb908144acb898781e1cf011bae3e44489864a6c621ded2a29aaee264a64a924c505d1e66bc7308b2d87806813ad203725d7a9548c9d79017d36fdffffff0163e11700000000001976a9149f9a7abd600c0caa03983a77c8c3df8e062cb2fa88ac67891e00"
        )

    def test_fail(self):
        # This has to take some seconds to fail
        # TODO: find a way to make this optional (default to no because slow)
        mw = pexpect.spawn("python3 singlesweep.py", timeout=2)
        with self.assertRaises(pexpect.exceptions.TIMEOUT):
            mw.expect("this text should not match")
