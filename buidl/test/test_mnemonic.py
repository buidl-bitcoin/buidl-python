from unittest import TestCase

from buidl.mnemonic import (
    secure_mnemonic,
    dice_rolls_to_mnemonic,
    InvalidBIP39Length,
)
from buidl.hd import HDPrivateKey


class MnemonicTest(TestCase):
    def test_secure_mnemonic_bits(self):
        tests = (
            # num_bits, num_words
            (128, 12),
            (160, 15),
            (192, 18),
            (224, 21),
            (256, 24),
        )

        for num_bits, num_words in tests:
            mnemonic = secure_mnemonic(num_bits=num_bits)
            self.assertEqual(num_words, len(mnemonic.split(" ")))
            # This is inherently non-deterministic, so we can't check the specific output
            HDPrivateKey.from_mnemonic(mnemonic, network="testnet")

        for invalid_num_bits in (-1, 1, 127, 129, 257, "notanint"):
            with self.assertRaises(ValueError):
                secure_mnemonic(num_bits=invalid_num_bits)

    def test_secure_mnemonic_extra_entropy(self):
        tests = (
            # num_bits, num_words, extra_entropy
            (128, 12, 0),
            (160, 15, 1),
            (192, 18, 2**128),
            (224, 21, 2**256),
            (256, 24, 2**512),
        )

        for num_bits, num_words, extra_entropy in tests:
            mnemonic = secure_mnemonic(num_bits=num_bits, extra_entropy=extra_entropy)
            self.assertEqual(num_words, len(mnemonic.split(" ")))
            # This is inherently non-deterministic, so we can't check the specific output
            HDPrivateKey.from_mnemonic(mnemonic, network="testnet")

        with self.assertRaises(TypeError):
            secure_mnemonic(extra_entropy="not an int")
        with self.assertRaises(ValueError):
            secure_mnemonic(extra_entropy=-1)

    def test_dice_to_mnemonic(self):
        tests = [  # dice_rolls, num_words, allow_low_entropy, expected_mnemonic, expected_exception
            [
                "",
                24,
                True,
                "together mail awful cradle scrub apart hip leader silk slice unusual embark kit can muscle nature nation gown century cram resource citizen throw produce",
                None,
            ],
            [
                "123456",
                24,
                True,
                "mirror reject rookie talk pudding throw happy era myth already payment own sentence push head sting video explain letter bomb casual hotel rather garment",
                None,
            ],
            [
                "123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456",
                24,
                False,
                "more matter caught bind tip twin indicate visa rifle angle defense lizard stock cave cradle injury always mule photo horse range opinion affair garlic",
                None,
            ],
            [
                "523365252662366",
                24,
                True,
                "dilemma rural physical exhaust divorce escape nut umbrella lawn midnight prosper prevent employ caught mercy student arctic umbrella feed super mad magic crawl fiscal",
                None,
            ],
            [
                "",
                12,
                True,
                "together mail awful cradle scrub apart hip leader silk slice unusual embark",
                None,
            ],
            [
                "123456",
                12,
                True,
                "mirror reject rookie talk pudding throw happy era myth already payment owner",
                None,
            ],
            [
                "12345612345612345612345612345612345612345612345612",
                12,
                False,
                "unveil nice picture region tragic fault cream strike tourist control recipe tourist",
                None,
            ],
            [
                "12345612345612345612345612345612345612345612345612345612345612",
                15,
                False,
                "end spider topple cliff tomorrow process dismiss produce athlete film monster team vacant ill silk",
                None,
            ],
            [
                "123456123456123456123456123456123456123456123456123456123456123456123456123",
                18,
                False,
                "melt churn alley retreat flip once enough gather project prosper cannon nasty furnace isolate cost laundry lottery slice",
                None,
            ],
            [
                "123456123456123456123456123456123456123456123456123456123456123456123456123456123456123",
                21,
                False,
                "start insane amazing fall kite punch owner refuse bone trigger spirit luggage slide sound reopen broom remember nose limb swallow kitten",
                None,
            ],
            [  # low entropy not allowed
                "123456",
                24,
                False,
                "",
                ValueError(
                    "Received 6 rolls but need at least 100 rolls (for 256 bits of entropy)"
                ),
            ],
            [  # Invalid num_words
                "123456",
                23,
                False,
                "",
                InvalidBIP39Length(
                    "23 words requested (must be 12, 15, 18, 21, or 24 words)"
                ),
            ],
            [  # non-string dice rolls
                b"123456",
                24,
                False,
                "",
                ValueError("Dice rolls must be provided as a string"),
            ],
            [  # string containing non-dice values
                "1234567",
                24,
                False,
                "",
                ValueError("Dice roll string contained invalid dice numbers"),
            ],
        ]

        for (
            dice_rolls,
            num_words,
            allow_low_entropy,
            expected_mnemonic,
            expected_exception,
        ) in tests:
            if expected_exception is None:
                received_mnemonic = dice_rolls_to_mnemonic(
                    dice_rolls, num_words, allow_low_entropy
                )
                self.assertEqual(received_mnemonic, expected_mnemonic)
            else:
                with self.assertRaises(type(expected_exception)) as exception_context:
                    dice_rolls_to_mnemonic(dice_rolls, num_words, allow_low_entropy)
                self.assertEqual(
                    str(exception_context.exception), str(expected_exception)
                )
