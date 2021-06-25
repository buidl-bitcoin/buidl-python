from unittest import TestCase
import unittest  # for skipunless

from io import BytesIO
from os import getenv

from buidl.block import Block
from buidl.helper import decode_base58, decode_gcs
from buidl.network import (
    BASIC_FILTER_TYPE,
    CFCheckPointMessage,
    CFHeadersMessage,
    CFilterMessage,
    FILTERED_BLOCK_DATA_TYPE,
    GetDataMessage,
    GetHeadersMessage,
    GetCFCheckPointMessage,
    GetCFHeadersMessage,
    GetCFiltersMessage,
    HeadersMessage,
    NetworkEnvelope,
    SimpleNode,
    VersionMessage,
)


class NetworkEnvelopeTest(TestCase):
    def test_parse(self):
        msg = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b"verack")
        self.assertEqual(envelope.payload, b"")
        msg = bytes.fromhex(
            "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
        )
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b"version")
        self.assertEqual(envelope.payload, msg[24:])

    def test_serialize(self):
        msg = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
        msg = bytes.fromhex(
            "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
        )
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)


class VersionMessageTest(TestCase):
    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b"\x00" * 8)
        self.assertEqual(
            v.serialize().hex(),
            "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff000000008d20000000000000000000000000000000000000ffff000000008d2000000000000000001b2f70726f6772616d6d696e67626c6f636b636861696e3a302e312f0000000001",
        )


class GetHeadersMessageTest(TestCase):
    def test_serialize(self):
        block_hex = "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3"
        gh = GetHeadersMessage(start_block=bytes.fromhex(block_hex))
        self.assertEqual(
            gh.serialize().hex(),
            "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )


class HeadersMessageTest(TestCase):
    def test_parse(self):
        hex_msg = "0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600"
        stream = BytesIO(bytes.fromhex(hex_msg))
        headers = HeadersMessage.parse(stream)
        self.assertEqual(len(headers.headers), 2)
        for b in headers.headers:
            self.assertEqual(b.__class__, Block)


class GetDataMessageTest(TestCase):
    def test_serialize(self):
        hex_msg = "020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000"
        get_data = GetDataMessage()
        block1 = bytes.fromhex(
            "00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30"
        )
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block1)
        block2 = bytes.fromhex(
            "00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910"
        )
        get_data.add_data(FILTERED_BLOCK_DATA_TYPE, block2)
        self.assertEqual(get_data.serialize().hex(), hex_msg)


@unittest.skipUnless(
    getenv("INCLUDE_NETWORK_TESTS"),
    reason="Requires network connection, so may not be unreliable",
)
class SimpleNodeTest(TestCase):
    def test_handshake(self):
        node = SimpleNode("testnet.programmingbitcoin.com", network="testnet")
        node.handshake()

    def test_handshake_signet(self):
        node = SimpleNode("signet.programmingbitcoin.com", network="signet")
        node.handshake()

    def test_get_filtered_txs(self):
        from buidl.bloomfilter import BloomFilter

        bf = BloomFilter(30, 5, 90210)
        h160 = decode_base58("mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5")
        bf.add(h160)
        node = SimpleNode("testnet.programmingbitcoin.com", network="testnet")
        node.handshake()
        node.send(bf.filterload())
        block_hash = bytes.fromhex(
            "00000000000377db7fde98411876c53e318a395af7304de298fd47b7c549d125"
        )
        txs = node.get_filtered_txs([block_hash])
        self.assertEqual(
            txs[0].id(),
            "0c024b9d3aa2ae8faae96603b8d40c88df2fc6bf50b3f446295206f70f3cf6ad",
        )
        self.assertEqual(
            txs[1].id(),
            "0886537e27969a12478e0d33707bf6b9fe4fdaec8d5d471b5304453b04135e7e",
        )
        self.assertEqual(
            txs[2].id(),
            "23d4effc88b80fb7dbcc2e6a0b0af9821c6fe3bb4c8dc3b61bcab7c45f0f6888",
        )


class CFilterTest(TestCase):
    def test_cfilter(self):
        stop_hash = bytes.fromhex(
            "000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33"
        )
        getcfilters = GetCFiltersMessage(stop_hash=stop_hash)
        expected = b"\x00\x01\x00\x00\x00" + stop_hash[::-1]
        self.assertEqual(getcfilters.serialize(), expected)
        expected = (
            b"\x00" + stop_hash[::-1] + b"\x09" + bytes.fromhex("0385acb4f0fe889ef0")
        )
        cfilter = CFilterMessage.parse(BytesIO(expected))
        self.assertEqual(cfilter.filter_type, 0)
        self.assertEqual(cfilter.block_hash, stop_hash)
        self.assertEqual(cfilter.hashes, {1341840, 1483084, 570774})
        self.assertEqual(cfilter.hash(b"\x00"), 1322199)
        included = bytes.fromhex(
            "002027a5000c7917f785d8fc6e5a55adfca8717ecb973ebb7743849ff956d896a7ed"
        )
        self.assertTrue([included] in cfilter)
        self.assertFalse([b"\x00"] in cfilter)
        with self.assertRaises(RuntimeError):
            GetCFiltersMessage()

    def test_cfilter_without_network(self):
        # Example from Trezor Blog Post (https://blog.trezor.io/bip158-compact-block-filters-9b813b07a878)
        block_hash_hex = (
            "000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313"
        )
        filter_hex = "09027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800"
        key = bytes.fromhex(block_hash_hex)[::-1][:16]
        filter_bytes = bytes.fromhex(filter_hex)
        cfilter = CFilterMessage(
            filter_type=BASIC_FILTER_TYPE,
            block_hash=bytes.fromhex(block_hash_hex),
            filter_bytes=filter_bytes,
            hashes=decode_gcs(key, filter_bytes),
        )
        for script, want in (
            ("76a9143ebc40e411ed3c76f86711507ab952300890397288ac", True),
            ("76a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac", True),
            ("76a914000000000000000000000000000000000000000088ac", False),  # made up
        ):
            self.assertEqual(bytes.fromhex(script) in cfilter, want)


class CFHeaderTest(TestCase):
    def test_cfheader(self):
        stop_hash = bytes.fromhex(
            "000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33"
        )
        getcfheaders = GetCFHeadersMessage(stop_hash=stop_hash)
        self.assertEqual(
            getcfheaders.serialize(), b"\x00\x00\x00\x00\x00" + stop_hash[::-1]
        )
        hash2 = b"\x00" * 32
        stream = BytesIO(
            bytes.fromhex(
                "00335fbc2314a20d310b6f9eba7ed4be418f54344a0480d61dfedd276f000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
            )
        )
        cfheaders = CFHeadersMessage.parse(stream)
        self.assertEqual(cfheaders.filter_type, 0)
        self.assertEqual(cfheaders.stop_hash, stop_hash)
        self.assertEqual(cfheaders.previous_filter_header, hash2)
        self.assertEqual(cfheaders.filter_hashes, [hash2])
        with self.assertRaises(RuntimeError):
            GetCFHeadersMessage()


class CFCheckPointTest(TestCase):
    def test_cfcheckpoint(self):
        stop_hash = bytes.fromhex(
            "000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33"
        )
        getcfcheckpoints = GetCFCheckPointMessage(stop_hash=stop_hash)
        self.assertEqual(getcfcheckpoints.serialize(), b"\x00" + stop_hash[::-1])
        hash2 = b"\x00" * 32
        stream = BytesIO(
            bytes.fromhex(
                "00335fbc2314a20d310b6f9eba7ed4be418f54344a0480d61dfedd276f00000000010000000000000000000000000000000000000000000000000000000000000000000000"
            )
        )
        cfcheckpoints = CFCheckPointMessage.parse(stream)
        self.assertEqual(cfcheckpoints.filter_type, 0)
        self.assertEqual(cfcheckpoints.stop_hash, stop_hash)
        self.assertEqual(cfcheckpoints.filter_headers, [hash2])
        with self.assertRaises(RuntimeError):
            GetCFCheckPointMessage()
