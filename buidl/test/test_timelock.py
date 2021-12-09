from io import BytesIO
from time import time
from unittest import TestCase

from buidl.timelock import Locktime, Sequence, MAX_SEQUENCE


class LocktimeTest(TestCase):
    def test_locktime(self):
        locktime_0 = Locktime()
        self.assertEqual(locktime_0, 0)
        self.assertEqual(locktime_0.block_height(), 0)
        self.assertIsNone(locktime_0.mtp())
        self.assertEqual(Locktime.parse(BytesIO(locktime_0.serialize())), 0)
        current_time = int(time())
        locktime_1 = Locktime(current_time)
        self.assertIsNone(locktime_1.block_height())
        self.assertEqual(locktime_1.mtp(), current_time)
        self.assertEqual(Locktime.parse(BytesIO(locktime_1.serialize())), locktime_1)
        locktime_2 = Locktime(current_time - 1000000)
        self.assertTrue(locktime_2 < locktime_1)
        with self.assertRaises(ValueError):
            locktime_2 < locktime_0
        with self.assertRaises(ValueError):
            Locktime(-1)
        with self.assertRaises(ValueError):
            Locktime(1 << 32)


class SequenceTest(TestCase):
    def test_sequence(self):
        sequence_0 = Sequence()
        self.assertEqual(sequence_0, MAX_SEQUENCE)
        self.assertTrue(sequence_0.is_max())
        self.assertFalse(sequence_0.is_relative())
        self.assertIsNone(sequence_0.relative_blocks())
        self.assertIsNone(sequence_0.relative_time())
        self.assertEqual(Sequence.parse(BytesIO(sequence_0.serialize())), sequence_0)
        time_amount = 512 * 1000
        sequence_1 = Sequence.from_relative_time(time_amount)
        self.assertFalse(sequence_1.is_comparable(sequence_0))
        self.assertIsNone(sequence_1.relative_blocks())
        self.assertEqual(sequence_1.relative_time(), time_amount)
        self.assertEqual(Sequence.parse(BytesIO(sequence_1.serialize())), sequence_1)
        blocks_amount = 144
        sequence_2 = Sequence.from_relative_blocks(blocks_amount)
        self.assertIsNone(sequence_2.relative_time())
        self.assertEqual(sequence_2.relative_blocks(), blocks_amount)
        self.assertFalse(sequence_1.is_comparable(sequence_2))
        sequence_3 = Sequence.from_relative_time(512 * 100)
        self.assertTrue(sequence_3 < sequence_1)
        with self.assertRaises(ValueError):
            sequence_2 < sequence_0
        with self.assertRaises(ValueError):
            sequence_2 < sequence_1
        with self.assertRaises(ValueError):
            Sequence(-1)
        with self.assertRaises(ValueError):
            Sequence(1 << 32)
