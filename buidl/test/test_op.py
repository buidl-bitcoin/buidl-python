from unittest import TestCase

from buidl.op import decode_num, op_checkmultisig, op_checksig, op_hash160


class OpTest(TestCase):
    def test_op_hash160(self):
        stack = [b"hello world"]
        self.assertTrue(op_hash160(stack))
        self.assertEqual(stack[0].hex(), "d7d5ee7824ff93f94c3055af9382c86c68b5ca92")

    def test_op_checksig(self):
        z = 0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D
        sec = bytes.fromhex(
            "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
        )
        sig = bytes.fromhex(
            "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
        )
        stack = [sig, sec]
        self.assertTrue(op_checksig(stack, z))
        self.assertEqual(decode_num(stack[0]), 1)

    def test_op_checkmultisig(self):
        z = 0xE71BFA115715D6FD33796948126F40A8CDD39F187E4AFB03896795189FE1423C
        sig1 = bytes.fromhex(
            "3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701"
        )
        sig2 = bytes.fromhex(
            "3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201"
        )
        sec1 = bytes.fromhex(
            "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70"
        )
        sec2 = bytes.fromhex(
            "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71"
        )
        stack = [b"", sig1, sig2, b"\x02", sec1, sec2, b"\x02"]
        self.assertTrue(op_checkmultisig(stack, z))
        self.assertEqual(decode_num(stack[0]), 1)
