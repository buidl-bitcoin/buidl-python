import getpass

from Crypto.Cipher import AES
from io import BytesIO
from mock import patch
from secrets import token_bytes
from time import time, sleep
from unittest import TestCase

from hd import HDPrivateKey, MAINNET_XPRV, TESTNET_XPRV
from helper import sha256
from tx import Tx, TxIn, TxOut


KEY_ITERATIONS = 10000
MAX_TRIES = 5


class EncryptedPrivateKey:

    def __init__(self, salt, iv, encrypted_data):
        self.salt = salt
        self.iv = iv
        self.encrypted_data = encrypted_data
        self.expires = 0
        self.private_key = None

    @classmethod
    def parse(cls, s):
        # 32 byte salt
        salt = s.read(32)
        # 16 byte initialization vector
        iv = s.read(AES.block_size)
        # 78 byte x/y/zprv and 2 byte padding all encrypted
        encrypted_data = s.read(80)
        return cls(salt, iv, encrypted_data)

    def serialize(self):
        return self.salt + self.iv + self.encrypted_data

    @classmethod
    def cipher(cls, salt, iv, password):
        key = password + salt
        for _ in range(KEY_ITERATIONS):
            key = sha256(key)
        return AES.new(key, AES.MODE_CBC, iv)

    def unlock(self):
        if not self.locked():
            return
        for i in range(MAX_TRIES):
            # prompt for a password
            password = getpass.getpass(prompt='Password: ').encode('utf-8')
            cipher = self.cipher(self.salt, self.iv, password)
            prv = cipher.decrypt(self.encrypted_data)
            try:
                self.private_key = HDPrivateKey.raw_parse(BytesIO(prv))
                break
            except ValueError:
                print('wrong password, you have {} more tries'.format(MAX_TRIES - i))
#                sleep(1 << i)
        else:
            return False
        self.expires = int(time()) + 300
        return True

    def locked(self):
        if time() > self.expires:
            self.private_key = None
        return self.private_key is None

    def get_private_key(self):
        self.unlock()
        return self.private_key

    @classmethod
    def generate(cls, testnet=False):
        password = getpass.getpass(prompt='New Password: ').encode('utf-8')
        salt = token_bytes(32)
        iv = token_bytes(AES.block_size)
        cipher = cls.cipher(salt, iv, password)
        mnemonic, private_key = HDPrivateKey.generate(testnet=testnet)
        # pad the xprv by 2 bytes as the length needs to be a multiple of 16
        if testnet:
            version = TESTNET_XPRV
        else:
            version = MAINNET_XPRV
        unencrypted = private_key.raw_serialize(version) + b'\x00\x00'
        encrypted_private = cls(salt, iv, cipher.encrypt(unencrypted))
        encrypted_private.private_key = private_key
        encrypted_private.expires = int(time()) + 300
        return mnemonic, encrypted_private

    @classmethod
    def from_mnemonic(cls, mnemonic, testnet=False):
        private_key = HDPrivateKey.from_mnemonic(mnemonic, testnet=testnet)
        password = getpass.getpass(prompt='New Password: ').encode('utf-8')
        salt = token_bytes(32)
        iv = token_bytes(AES.block_size)
        cipher = cls.cipher(salt, iv, password)
        if testnet:
            version = TESTNET_XPRV
        else:
            version = MAINNET_XPRV
        unencrypted = private_key.raw_serialize(version) + b'\x00\x00'
        encrypted_private = cls(salt, iv, cipher.encrypt(unencrypted))
        encrypted_private.private_key = private_key
        encrypted_private.expires = int(time()) + 300
        return encrypted_private


class EncryptedPrivateTest(TestCase):

    @patch('getpass.getpass')
    def test_generate(self, gp):
        gp.return_value = 'password'
        mnemonic, enc = EncryptedPrivateKey.generate(testnet=True)
        self.assertTrue(mnemonic)
        serialized = enc.serialize()
        self.assertEqual(len(serialized), 32 + 16 + 80)
        stream = BytesIO(serialized)
        parsed = EncryptedPrivateKey.parse(stream)
        self.assertEqual(enc.salt, parsed.salt)
        self.assertEqual(enc.iv, parsed.iv)
        self.assertEqual(enc.encrypted_data, parsed.encrypted_data)
        self.assertFalse(enc.locked())
        self.assertTrue(enc.expires > 0)
        self.assertFalse(enc.locked())
        enc.expires = 0
        self.assertTrue(enc.locked())
        self.assertTrue(enc.unlock())
        self.assertFalse(enc.locked())
        enc.expires = 0
        gp.return_value = 'wrong'
        self.assertFalse(enc.unlock())

    @patch('getpass.getpass')
    def test_recover(self, gp):
        gp.return_value = 'password'
        mnemonic = 'method wire potato cotton fame can repair mother elder festival hurry trophy'
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic)
        private_key = enc.get_private_key()
        path = "m/84'/0'/0'/0/0"
        pub_key = private_key.traverse(path).pub
        addr = 'bc1qq5qrkcc5d0f3chmmwsc50ap8l8ukjjyc8je2wg'
        self.assertEqual(pub_key.bech32_address(), addr)
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet=True)
        private_key = enc.get_private_key()
        path = "m/84'/1'/0'/0/0"
        pub_key = private_key.traverse(path).pub
        addr = 'tb1qtvaq0px8vaxlxez4gx3e78gqv8a06ysnp6me4x'
        self.assertEqual(pub_key.bech32_address(), addr)

    @patch('getpass.getpass')
    def test_sign(self, gp):
        gp.return_value = 'password'
        mnemonic = 'method wire potato cotton fame can repair mother elder festival hurry trophy'
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet=True)
        path = "m/84'/1'/0'/0/0"
        hd_priv = enc.get_private_key().traverse(path)
        tx_id = bytes.fromhex('07affe8b0ef5f009eef5399c20586b3181103564e8ffe444631dcae20389738c')
        tx_index = 0
        amount = 12753130
        tx_in = TxIn(tx_id, tx_index)
        tx_out = TxOut(amount - 5000, hd_priv.p2wpkh_script())
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        self.assertTrue(tx_obj.sign_p2wpkh(0, hd_priv.private_key))
        want = '010000000001018c738903e2ca1d6344e4ffe864351081316b58209c39f5ee09f0f50e8bfeaf070000000000ffffffff016285c200000000001600145b3a0784c7674df3645541a39f1d0061fafd121302483045022100ed55340424848ac402279a703440c3e64234cda15693b155e23daddea8e3ea75022018af9c2df35393e168980b835d1c08318e5417647522fb3c71c936fa20a416ae012102221f70f0e3f9cb3e164a45e7994e6e83816c76dc122d0987e4559536b888530b00000000'
        self.assertEqual(want, tx_obj.serialize().hex())


class Wallet:

    def __init__(self, filename='main.wallet'):
        self.filename = filename
        self._load()

    def _load(self):
        with open(self.filename, 'br') as stream:
            self.encrypted = EncryptedPrivateKey.parse(stream)
            self.testnet = self.encrypted.testnet

    @classmethod
    def create(cls, filename='main.wallet', testnet=False):
        '''Creates a wallet and returns the generated mnemonic'''
        if exists(filename):
            raise IOError('File already exists: {}'.format(filename))
        mnemonic, encrypted = EncryptedPrivateKey.generate(testnet=testnet)
        with open(filename, 'bw') as stream:
            stream.write(encrypted.serialize())
        return mnemonic, cls(filename)

    @classmethod
    def restore(cls, mnemonic, filename='main.wallet', testnet=False):
        '''Restores a wallet given a mnemonic'''
        if exists(filename):
            raise IOError('File already exists: {}'.format(filename))
        encrypted = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet=testnet)
        with open(filename, 'bw') as stream:
            stream.write(encrypted.serialize())
        return cls(filename)
