from unittest import TestCase

from buidl import BloomFilter


class BloomFilterTest(TestCase):
    def test_add(self):
        bf = BloomFilter(10, 5, 99)
        item = b"Hello World"
        bf.add(item)
        expected = "0000000a080000000140"
        self.assertEqual(bf.filter_bytes().hex(), expected)
        item = b"Goodbye!"
        bf.add(item)
        expected = "4000600a080000010940"
        self.assertEqual(bf.filter_bytes().hex(), expected)

    def test_filterload(self):
        bf = BloomFilter(10, 5, 99)
        item = b"Hello World"
        bf.add(item)
        item = b"Goodbye!"
        bf.add(item)
        expected = "0a4000600a080000010940050000006300000001"
        self.assertEqual(bf.filterload().payload.hex(), expected)
