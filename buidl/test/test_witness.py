from io import BytesIO
from unittest import TestCase

from buidl.witness import Witness


class WitnessTest(TestCase):
    def test_parse_serialize_roundtrip(self):
        w = Witness([b"\x01\x02\x03", b"\x04\x05"])
        serialized = w.serialize()
        self.assertEqual(serialized.hex(), "0203010203020405")
        w2 = Witness.parse(BytesIO(serialized))
        self.assertEqual(w2.items, w.items)

    def test_empty_witness(self):
        w = Witness()
        self.assertEqual(len(w), 0)
        self.assertEqual(w.serialize().hex(), "00")
        w2 = Witness.parse(BytesIO(w.serialize()))
        self.assertEqual(len(w2), 0)

    def test_single_item(self):
        w = Witness([b"\xde\xad\xbe\xef"])
        self.assertEqual(len(w), 1)
        serialized = w.serialize()
        w2 = Witness.parse(BytesIO(serialized))
        self.assertEqual(w2.items, [b"\xde\xad\xbe\xef"])

    def test_getitem(self):
        w = Witness([b"\x01", b"\x02", b"\x03"])
        self.assertEqual(w[0], b"\x01")
        self.assertEqual(w[1], b"\x02")
        self.assertEqual(w[2], b"\x03")
        self.assertEqual(w[-1], b"\x03")

    def test_len(self):
        self.assertEqual(len(Witness()), 0)
        self.assertEqual(len(Witness([b"\x01"])), 1)
        self.assertEqual(len(Witness([b"\x01", b"\x02", b"\x03"])), 3)

    def test_repr(self):
        w = Witness([b"\x01\x02", b""])
        result = repr(w)
        self.assertIn("0102", result)
        self.assertIn("<null>", result)

    def test_clone(self):
        w = Witness([b"\x01", b"\x02"])
        c = w.clone()
        self.assertEqual(c.items, w.items)
        # clone should be independent
        c.items.append(b"\x03")
        self.assertNotEqual(len(c), len(w))

    def test_has_annex(self):
        # Annex starts with 0x50
        w_annex = Witness([b"sig", b"\x50\x01\x02"])
        self.assertTrue(w_annex.has_annex())
        # No annex
        w_no_annex = Witness([b"sig", b"\x30\x01\x02"])
        self.assertFalse(w_no_annex.has_annex())

    def test_with_empty_items(self):
        """Witness with empty byte strings (used in multisig for OP_0 bug)."""
        w = Witness([b"", b"\x01\x02"])
        self.assertEqual(len(w), 2)
        serialized = w.serialize()
        w2 = Witness.parse(BytesIO(serialized))
        self.assertEqual(w2.items, w.items)
