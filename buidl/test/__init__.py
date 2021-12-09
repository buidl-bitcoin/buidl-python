from os.path import dirname, realpath, sep
from os import getenv
from unittest import TestCase

from buidl.tx import TxFetcher


class OfflineTestCase(TestCase):
    cache_file = dirname(realpath(__file__)) + sep + "tx.cache"

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    def test_socket_guard(self):
        if getenv("INCLUDE_NETWORK_TESTS"):
            return

        with self.assertRaises(Exception) as cm:
            TxFetcher.fetch(tx_id="0" * 32)

        self.assertIn("Unit test requires internet", str(cm.exception))
