from unittest import TestCase

from buidl.op import decode_num, op_checkmultisig, op_checksig, op_hash160


class OpTest(TestCase):
    def test_op_hash160(self):
        stack = [b"hello world"]
        self.assertTrue(op_hash160(stack))
        self.assertEqual(stack[0].hex(), "d7d5ee7824ff93f94c3055af9382c86c68b5ca92")

    def test_op_checksig(self):
        tests = (
            (
                0xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60,
                "3045022100ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a3950220068342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
                "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            ),
            (
                0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D,
                "3044022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022038df8011e682d839e75159debf909408cb3f12ae472b1d88cf6280cf01c6568b",
                "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            ),
            (
                0x2270CB0316E68389A3A23DE16023A03B8FC271A21B467B1DC97E0FC0E2CE97F7,
                "3045022100ea6d640d5275d091607e1f4ad5cdb214e45f8d17cca1095074894dde347605ba022029062e1ff0d9eee52da1f3621caf92436877d7076720e2b3d9f226bf853e2b75",
                "04f47dc2ac0ecaadda5ee2b3ab9bc4e02c3eafb2abcc426643686ad95f6d4e8c44e33fa47d96fc2dace0ef2f583965cf6a0f8faa7a070c0f8ee986d192e2d21835",
            ),
        )
        for z, der_hex, sec_hex in tests:
            sec = bytes.fromhex(sec_hex)
            sig = bytes.fromhex(der_hex) + b"\x01"
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
