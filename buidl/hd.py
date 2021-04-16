import re

from io import BytesIO

from buidl.ecc import N, PrivateKey, S256Point
from buidl.helper import (
    big_endian_to_int,
    byte_to_int,
    encode_base58_checksum,
    hmac_sha512,
    hmac_sha512_kdf,
    int_to_big_endian,
    int_to_byte,
    is_intable,
    raw_decode_base58,
    sha256,
)
from buidl.mnemonic import secure_mnemonic, WORD_LOOKUP, WORD_LIST


MAINNET_XPRV = bytes.fromhex("0488ade4")
MAINNET_XPUB = bytes.fromhex("0488b21e")
MAINNET_YPRV = bytes.fromhex("049d7878")
MAINNET_YPUB = bytes.fromhex("049d7cb2")
MAINNET_ZPRV = bytes.fromhex("04b2430c")
MAINNET_ZPUB = bytes.fromhex("04b24746")
TESTNET_XPRV = bytes.fromhex("04358394")
TESTNET_XPUB = bytes.fromhex("043587cf")
TESTNET_YPRV = bytes.fromhex("044a4e28")
TESTNET_YPUB = bytes.fromhex("044a5262")
TESTNET_ZPRV = bytes.fromhex("045f18bc")
TESTNET_ZPUB = bytes.fromhex("045f1cf6")


class InvalidBIP39Length(Exception):
    pass


class InvalidChecksumWordsError(Exception):
    pass


class HDPrivateKey:
    def __init__(
        self,
        private_key,
        chain_code,
        depth=0,
        parent_fingerprint=b"\x00\x00\x00\x00",
        child_number=0,
        testnet=False,
    ):
        # the main secret, should be a PrivateKey object
        self.private_key = private_key
        self.private_key.testnet = testnet
        # the code to make derivation deterministic
        self.chain_code = chain_code
        # level the current key is at in the heirarchy
        self.depth = depth
        # fingerprint of the parent key
        self.parent_fingerprint = parent_fingerprint
        # what order child this is
        self.child_number = child_number
        self.testnet = testnet
        # keep a copy of the corresponding public key
        self.pub = HDPublicKey(
            point=private_key.point,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            testnet=testnet,
        )

    def wif(self):
        return self.private_key.wif()

    def sec(self):
        return self.pub.sec()

    def hash160(self):
        return self.pub.hash160()

    def p2pkh_script(self):
        return self.pub.p2pkh_script()

    def p2wpkh_script(self):
        return self.pub.p2wpkh_script()

    def p2sh_p2wpkh_script(self):
        return self.pub.p2sh_p2wpkh_script()

    def address(self):
        return self.pub.address()

    def bech32_address(self):
        return self.pub.bech32_address()

    def p2sh_p2wpkh_address(self):
        return self.pub.p2sh_p2wpkh_address()

    def __repr__(self):
        return self.xprv()

    @classmethod
    def from_seed(cls, seed, testnet=False):
        # get hmac_sha512 with b'Bitcoin seed' and seed
        h = hmac_sha512(b"Bitcoin seed", seed)
        # create the private key using the first 32 bytes in big endian
        private_key = PrivateKey(secret=big_endian_to_int(h[:32]))
        # chaincode is the last 32 bytes
        chain_code = h[32:]
        # return an instance of the class
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            testnet=testnet,
        )

    def child(self, index):
        """Returns the child HDPrivateKey at a particular index.
        Hardened children return for indices >= 0x8000000.
        """
        # if index >= 0x80000000
        if index >= 0x80000000:
            # the message data is the private key secret in 33 bytes in
            #  big-endian and the index in 4 bytes big-endian.
            data = int_to_big_endian(self.private_key.secret, 33) + int_to_big_endian(
                index, 4
            )
        else:
            # the message data is the public key compressed SEC
            #  and the index in 4 bytes big-endian.
            data = self.private_key.point.sec() + int_to_big_endian(index, 4)
        # get the hmac_sha512 with chain code and data
        h = hmac_sha512(self.chain_code, data)
        # the new secret is the first 32 bytes as a big-endian integer
        #  plus the secret mod N
        secret = (big_endian_to_int(h[:32]) + self.private_key.secret) % N
        # create the PrivateKey object
        private_key = PrivateKey(secret=secret)
        # the chain code is the last 32 bytes
        chain_code = h[32:]
        # depth is whatever the current depth + 1
        depth = self.depth + 1
        # parent_fingerprint is the fingerprint of this node
        parent_fingerprint = self.fingerprint()
        # child number is the index
        child_number = index
        # return a new HDPrivateKey instance
        return HDPrivateKey(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            testnet=self.testnet,
        )

    def traverse(self, path):
        """Returns the HDPrivateKey at the path indicated.
        Path should be in the form of m/x/y/z where x' means
        hardened"""

        # accept path in uppercase and/or using h instead of '
        path = path.lower().replace("h", "'")

        # keep track of the current node starting with self
        current = self
        # split up the path by the '/' splitter, ignore the first
        components = path.split("/")[1:]
        # iterate through the path components
        for child in components:
            # if the child ends with a ', we have a hardened child
            if child.endswith("'"):
                # index is the integer representation + 0x80000000
                index = int(child[:-1]) + 0x80000000
            # else the index is the integer representation
            else:
                index = int(child)
            # grab the child at the index calculated
            current = current.child(index)
        # return the current child
        return current

    def raw_serialize(self, version):
        # version + depth + parent_fingerprint + child number + chain code + private key
        # start with version, which should be a constant depending on testnet
        raw = version
        # add depth, which is 1 byte using int_to_byte
        raw += int_to_byte(self.depth)
        # add the parent_fingerprint
        raw += self.parent_fingerprint
        # add the child number 4 bytes using int_to_big_endian
        raw += int_to_big_endian(self.child_number, 4)
        # add the chain code
        raw += self.chain_code
        # add the 0 byte and the private key's secret in big endian, 33 bytes
        raw += int_to_big_endian(self.private_key.secret, 33)
        return raw

    def _prv(self, version):
        """Returns the base58-encoded x/y/z prv.
        Expects a 4-byte version."""
        raw = self.raw_serialize(version)
        # return the whole thing base58-encoded
        return encode_base58_checksum(raw)

    def xprv(self):
        # from BIP0032:
        if self.testnet:
            version = TESTNET_XPRV
        else:
            version = MAINNET_XPRV
        return self._prv(version)

    def yprv(self):
        # from BIP0049:
        if self.testnet:
            version = TESTNET_YPRV
        else:
            version = MAINNET_YPRV
        return self._prv(version)

    def zprv(self):
        # from BIP0084:
        if self.testnet:
            version = TESTNET_ZPRV
        else:
            version = MAINNET_ZPRV
        return self._prv(version)

    # passthrough methods
    def fingerprint(self):
        return self.pub.fingerprint()

    def xpub(self, version=None):
        if version is None:
            if self.testnet:
                version = TESTNET_XPUB
            else:
                version = MAINNET_XPUB
        return self.pub.xpub(version=version)

    def ypub(self):
        return self.pub.ypub()

    def zpub(self):
        return self.pub.zpub()

    @classmethod
    def parse(cls, s):
        """Returns a HDPrivateKey from an extended key string"""
        # get the bytes from the base58 using raw_decode_base58
        raw = raw_decode_base58(s)
        # check that the length of the raw is 78 bytes, otherwise raise ValueError
        if len(raw) != 78:
            raise ValueError("Not a proper extended key")
        # create a stream
        stream = BytesIO(raw)
        # return the raw parsing of the stream
        return cls.raw_parse(stream)

    @classmethod
    def raw_parse(cls, s):
        """Returns a HDPrivateKey from a stream"""
        # first 4 bytes are the version
        version = s.read(4)
        # check that the version is one of the TESTNET or MAINNET
        #  private keys, if not raise a ValueError
        if version in (TESTNET_XPRV, TESTNET_YPRV, TESTNET_ZPRV):
            testnet = True
        elif version in (MAINNET_XPRV, MAINNET_YPRV, MAINNET_ZPRV):
            testnet = False
        else:
            raise ValueError("not an xprv, yprv or zprv: {}".format(version))
        # the next byte is depth
        depth = byte_to_int(s.read(1))
        # next 4 bytes are the parent_fingerprint
        parent_fingerprint = s.read(4)
        # next 4 bytes is the child number in big-endian
        child_number = big_endian_to_int(s.read(4))
        # next 32 bytes are the chain code
        chain_code = s.read(32)
        # the next byte should be b'\x00'
        if byte_to_int(s.read(1)) != 0:
            raise ValueError("private key should be preceded by a zero byte")
        # last 32 bytes should be the private key in big endian
        private_key = PrivateKey(secret=big_endian_to_int(s.read(32)))
        # return an instance of the class
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            testnet=testnet,
        )

    def _get_address(self, purpose, account=0, external=True, address=0):
        """Returns the proper address among purposes 44', 49' and 84'.
        p2pkh for 44', p2sh-p2wpkh for 49' and p2wpkh for 84'."""
        # if purpose is not one of 44', 49' or 84', raise ValueError
        if purpose not in ("44'", "49'", "84'"):
            raise ValueError(
                "Cannot create an address without a proper purpose: {}".format(purpose)
            )
        # if testnet, coin is 1', otherwise 0'
        if self.testnet:
            coin = "1'"
        else:
            coin = "0'"
        # if external, chain is 0, otherwise 1
        if external:
            chain = "0"
        else:
            chain = "1"
        # create the path m/purpose'/coin'/account'/chain/address
        path = "m/{}/{}/{}'/{}/{}".format(purpose, coin, account, chain, address)
        # get the HDPrivateKey at that location
        hd_priv = self.traverse(path)
        # if 44', return the address
        if purpose == "44'":
            return hd_priv.address()
        # if 49', return the p2sh_p2wpkh_address
        elif purpose == "49'":
            return hd_priv.p2sh_p2wpkh_address()
        # if 84', return the bech32_address
        elif purpose == "84'":
            return hd_priv.bech32_address()

    def get_p2pkh_receiving_address(self, account=0, address=0):
        return self._get_address("44'", account, True, address)

    def get_p2pkh_change_address(self, account=0, address=0):
        return self._get_address("44'", account, False, address)

    def get_p2sh_p2wpkh_receiving_address(self, account=0, address=0):
        return self._get_address("49'", account, True, address)

    def get_p2sh_p2wpkh_change_address(self, account=0, address=0):
        return self._get_address("49'", account, False, address)

    def get_p2wpkh_receiving_address(self, account=0, address=0):
        return self._get_address("84'", account, True, address)

    def get_p2wpkh_change_address(self, account=0, address=0):
        return self._get_address("84'", account, False, address)

    @classmethod
    def generate(cls, password=b"", extra_entropy=0, testnet=False):
        mnemonic = secure_mnemonic(extra_entropy=extra_entropy)
        return mnemonic, cls.from_mnemonic(mnemonic, password=password, testnet=testnet)

    @classmethod
    def from_mnemonic(cls, mnemonic, password=b"", path="m", testnet=False):
        """Returns a HDPrivateKey object from the mnemonic."""
        # split the mnemonic into words with .split()
        words = mnemonic.split()
        # check that there are 12, 15, 18, 21 or 24 words
        # if not, raise a ValueError
        if len(words) not in (12, 15, 18, 21, 24):
            raise InvalidBIP39Length(
                f"{len(words)} words (you need 12, 15, 18, 21, or 24 words)"
            )
        # calculate the number
        number = 0
        # each word is 11 bits
        for word in words:
            # get the number that the word represents using WORD_LOOKUP
            index = WORD_LOOKUP[word]
            # left-shift the number by 11 bits and bitwise-or the index
            number = (number << 11) | index
        # checksum is the last n bits where n = (# of words / 3)
        checksum_bits_length = len(words) // 3
        # grab the checksum bits
        checksum = number & ((1 << checksum_bits_length) - 1)
        # get the actual number by right-shifting by the checksum bits length
        data_num = number >> checksum_bits_length
        # convert the number to big-endian
        data = int_to_big_endian(data_num, checksum_bits_length * 4)
        # the one byte we get is from sha256 of the data, shifted by
        #  8 - the number of bits we need for the checksum
        computed_checksum = sha256(data)[0] >> (8 - checksum_bits_length)
        # check that the checksum is correct or raise ValueError
        if checksum != computed_checksum:
            raise InvalidChecksumWordsError(words)
        # normalize in case we got a mnemonic that's just the first 4 letters
        normalized_words = []
        for word in words:
            normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
        normalized_mnemonic = " ".join(normalized_words)
        # salt is b'mnemonic' + password
        salt = b"mnemonic" + password
        # the seed is the hmac_sha512_kdf with normalized mnemonic and salt
        seed = hmac_sha512_kdf(normalized_mnemonic, salt)
        # return the HDPrivateKey at the path specified
        return cls.from_seed(seed, testnet=testnet).traverse(path)


class HDPublicKey:
    def __init__(
        self, point, chain_code, depth, parent_fingerprint, child_number, testnet=False
    ):
        self.point = point
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.testnet = testnet
        self._raw = None

    def __repr__(self):
        return self.xpub()

    def sec(self):
        return self.point.sec()

    def hash160(self):
        return self.point.hash160()

    def p2pkh_script(self):
        return self.point.p2pkh_script()

    def p2wpkh_script(self):
        return self.point.p2wpkh_script()

    def p2sh_p2wpkh_script(self):
        return self.point.p2sh_p2wpkh_script()

    def address(self):
        return self.point.address(testnet=self.testnet)

    def bech32_address(self):
        return self.point.bech32_address(testnet=self.testnet)

    def p2sh_p2wpkh_address(self):
        return self.point.p2sh_p2wpkh_address(testnet=self.testnet)

    def fingerprint(self):
        """Fingerprint is the hash160's first 4 bytes"""
        return self.hash160()[:4]

    def child(self, index):
        """Returns the child HDPrivateKey at a particular index.
        Raises ValueError for indices >= 0x8000000.
        """
        # if index >= 0x80000000, raise a ValueError
        if index >= 0x80000000:
            raise ValueError("child number should always be less than 2^31")
        # data is the SEC compressed and the index in 4 bytes big-endian
        data = self.point.sec() + int_to_big_endian(index, 4)
        # get hmac_sha512 with chain code, data
        h = hmac_sha512(self.chain_code, data)
        # the new public point is the current point +
        #  the first 32 bytes in big endian * G
        point = self.point + big_endian_to_int(h[:32])
        # chain code is the last 32 bytes
        chain_code = h[32:]
        # depth is current depth + 1
        depth = self.depth + 1
        # parent_fingerprint is the fingerprint of this node
        parent_fingerprint = self.fingerprint()
        # child number is the index
        child_number = index
        # return the HDPublicKey instance
        return HDPublicKey(
            point=point,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            testnet=self.testnet,
        )

    def traverse(self, path):
        """Returns the HDPublicKey at the path indicated.
        Path should be in the form of m/x/y/z."""

        # accept path in uppercase and/or using h instead of '
        path = path.lower().replace("h", "'")

        # start current node at self
        current = self
        # get components of the path split at '/', ignoring the first
        components = path.split("/")[1:]
        # iterate through the components
        for child in components:
            # raise a ValueError if the path ends with a '
            if child[-1:] == "'":
                raise ValueError("HDPublicKey cannot get hardened child")
            # traverse the next child at the index
            current = current.child(int(child))
        # return the current node
        return current

    def raw_serialize(self):
        if self._raw is None:
            if self.testnet:
                version = TESTNET_XPUB
            else:
                version = MAINNET_XPUB
            self._raw = self._serialize(version)
        return self._raw

    def _serialize(self, version):
        # start with the version
        raw = version
        # add the depth using int_to_byte
        raw += int_to_byte(self.depth)
        # add the parent_fingerprint
        raw += self.parent_fingerprint
        # add the child number in 4 bytes using int_to_big_endian
        raw += int_to_big_endian(self.child_number, 4)
        # add the chain code
        raw += self.chain_code
        # add the SEC pubkey
        raw += self.point.sec()
        return raw

    def _pub(self, version):
        """Returns the base58-encoded x/y/z pub.
        Expects a 4-byte version."""
        # get the serialization
        raw = self._serialize(version)
        # base58-encode the whole thing
        return encode_base58_checksum(raw)

    def xpub(self, version=None):

        # Allow for SLIP132 encoding (or other version bytes)
        if version is not None:
            return self._pub(version=version)

        if self.testnet:
            version = TESTNET_XPUB
        else:
            version = MAINNET_XPUB
        return self._pub(version)

    def ypub(self):
        if self.testnet:
            version = TESTNET_YPUB
        else:
            version = MAINNET_YPUB
        return self._pub(version)

    def zpub(self):
        if self.testnet:
            version = TESTNET_ZPUB
        else:
            version = MAINNET_ZPUB
        return self._pub(version)

    @classmethod
    def parse(cls, s):
        """Returns a HDPublicKey from an extended key string"""
        # get the bytes from the base58 using raw_decode_base58
        raw = raw_decode_base58(s)
        # check that the length of the raw is 78 bytes, otherwise raise ValueError
        if len(raw) != 78:
            raise ValueError("Not a proper extended key")
        # create a stream
        stream = BytesIO(raw)
        # return the raw parsing of the stream
        return cls.raw_parse(stream)

    @classmethod
    def raw_parse(cls, s):
        """Returns a HDPublicKey from a stream"""
        # first 4 bytes are the version
        version = s.read(4)
        # check that the version is one of the TESTNET or MAINNET
        #  public keys, if not raise a ValueError
        if version in (TESTNET_XPUB, TESTNET_YPUB, TESTNET_ZPUB):
            testnet = True
        elif version in (MAINNET_XPUB, MAINNET_YPUB, MAINNET_ZPUB):
            testnet = False
        else:
            raise ValueError("not an xpub, ypub or zpub: {} {}".format(s, version))
        # the next byte is depth
        depth = byte_to_int(s.read(1))
        # next 4 bytes are the parent_fingerprint
        parent_fingerprint = s.read(4)
        # next 4 bytes is the child number in big-endian
        child_number = big_endian_to_int(s.read(4))
        # next 32 bytes are the chain code
        chain_code = s.read(32)
        # last 33 bytes should be the SEC
        point = S256Point.parse(s.read(33))
        # return an instance of the class
        return cls(
            point=point,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            testnet=testnet,
        )


def calc_valid_seedpicker_checksums(first_words):
    """
    Generator to return all valid seedpicker checksums.

    For normal useage, just grab the first one only
    """
    for word in WORD_LIST:
        try:
            HDPrivateKey.from_mnemonic(first_words + " " + word)
            yield (word)
        except InvalidChecksumWordsError:
            pass


def calc_num_valid_seedpicker_checksums(num_first_words):
    """
    If you have K firstwords, you will have V valid checksum words to choose from
    This convenience method is used for displaying progress to the user.
    """
    return {
        11: 128,
        14: 64,
        17: 32,
        20: 16,
        23: 8,
    }[num_first_words]


def is_valid_bip32_path(path):
    path = path.lower().strip().replace("'", "h").replace("//", "/")  # be forgiving

    if path == "m":
        # Not really a path, but since this is valid in the library (traverses to itself) we're counting it as valid
        return True

    if not path.startswith("m/"):
        return False

    sub_paths = path[2:].split("/")
    if len(sub_paths) >= 256:
        # https://bitcoin.stackexchange.com/a/92057
        return False

    for sub_path in sub_paths:
        if sub_path.endswith("h"):
            sub_path = sub_path[:-1]
        if not is_intable(sub_path):
            return False
        if int(sub_path) < 0:
            return False
        if int(sub_path) >= 2 ** 31:
            # https://bitcoin.stackexchange.com/a/92057
            return False

    return True


def ltrim_path(bip32_path, depth):
    """
    Left trim off a path by a given depth
    """
    if not is_valid_bip32_path(bip32_path):
        raise ValueError(f"Invalid bip32 path: {bip32_path}")

    # be forgiving
    path = bip32_path.lower().strip().replace("'", "h").replace("//", "/")

    if path.count("/") < depth:
        raise ValueError(
            f"Cannot left trim off a depth of {depth} from a path this short: {bip32_path}"
        )

    to_return = path.split("/")[depth + 1 :]
    return "m/" + "/".join(to_return)


def parse_key_record(key_record_str):
    """
    A key record will look something like this:
    [c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*'
    """

    key_record_re = re.match(
        r"\[([0-9a-f]{8})\*?(.*?)\]([0-9A-Za-z]+).*([0-9]+?)", key_record_str
    )
    if key_record_re is None:
        raise ValueError(f"Invalid key record: {key_record_str}")

    xfp, path, xpub, index_str = key_record_re.groups()

    # Note that we don't validate xfp because the regex already tells us it's good

    if not is_intable(index_str):
        raise ValueError(f"Invalid index {index_str} in key record: {key_record_str}")

    index_int = int(index_str)

    path = "m" + path
    if not is_valid_bip32_path(path):
        raise ValueError(f"Invalid BIP32 path {path} in key record: {key_record_str}")

    xpub_prefix = xpub[:4]
    if xpub_prefix == "tpub":
        is_testnet = True
    elif xpub_prefix == "xpub":
        is_testnet = False
    else:
        raise ValueError(f"Invalid xpub prefix {xpub_prefix} in {xpub}")

    try:
        parent_pubkey_obj = HDPublicKey.parse(s=xpub)
        xpub_child = parent_pubkey_obj.child(index=index_int).xpub()
    except ValueError:
        raise ValueError(f"Invalid xpub {xpub} in key record: {key_record_str}")

    return {
        "xfp": xfp,
        "path": path,
        "xpub_parent": xpub,
        "index": index_int,
        "xpub_child": xpub_child,
        "is_testnet": is_testnet,
    }


def parse_wshsortedmulti(output_record):
    """
    TODO: generalize this to all output records and not just wsh sortedmulti?
    """
    # Fix strange slashes that some software (Specter-Desktop) may use
    output_record = output_record.strip().replace(r"\/", "/")

    # Regex match the string
    re_output_results = re.match(
        r".*wsh\(sortedmulti\(([0-9]*),(.*)\)\)\#([qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}).*",
        output_record,
    )
    if re_output_results is None:
        raise ValueError(f"Not a valid wsh sortedmulti: {output_record}")

    quorum_m_str, key_records_str, checksum = re_output_results.groups()

    if not is_intable(quorum_m_str):
        raise ValueError(f"m in m-of-n must be an int: {quorum_m_str}")
    quorum_m_int = int(quorum_m_str)

    key_records = []
    for key_record_str in key_records_str.split(","):
        # A key record will look something like this:
        # [c7d0648a/48h/1h/0h/2h]tpubDEpefcgzY6ZyEV2uF4xcW2z8bZ3DNeWx9h2BcwcX973BHrmkQxJhpAXoSWZeHkmkiTtnUjfERsTDTVCcifW6po3PFR1JRjUUTJHvPpDqJhr/0/*'
        key_records.append(parse_key_record(key_record_str))

    quorum_n_int = len(key_records)

    if quorum_m_int > quorum_n_int:
        raise ValueError(
            f"Malformed threshold {quorum_m_int}-of-{quorum_n_int} (m must be less than n) in {output_record}"
        )

    # Remove testnet from key records (can just return it once at the parent output record level)
    # Confirm all key records are on the same network
    output_is_testnet = key_records[0]["is_testnet"]
    if not all(x.pop("is_testnet") for x in key_records):
        raise ValueError(f"Multiple (conflicting) networks in pubkeys: {key_records}")

    return {
        "quorum_m": quorum_m_int,
        "quorum_n": quorum_n_int,
        "key_records": key_records,
        "is_testnet": output_is_testnet,
    }
