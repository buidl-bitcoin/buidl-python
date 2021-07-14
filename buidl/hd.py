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
)
from buidl.mnemonic import (
    BIP39,
    InvalidChecksumWordsError,
    secure_mnemonic,
    mnemonic_to_bytes,
)
from buidl.shamir import ShareSet

# https://github.com/satoshilabs/slips/blob/master/slip-0132.md
# Make default xpub/xpriv, but allow for other version bytes

XPRV = {
    "mainnet": bytes.fromhex("0488ade4"),
    "testnet": bytes.fromhex("04358394"),
    "signet": bytes.fromhex("04358394"),
}

XPUB = {
    "mainnet": bytes.fromhex("0488b21e"),
    "testnet": bytes.fromhex("043587cf"),
    "signet": bytes.fromhex("043587cf"),
}

# P2PKH or P2SH, P2WPKH in P2SH, P2WPKH, Multi-signature P2WSH in P2SH, Multi-signature P2WSH
ALL_MAINNET_XPRVS = {
    bytes.fromhex(x)
    for x in ["0488ade4", "049d7878", "04b2430c", "0295b005", "02aa7a99"]
}
ALL_MAINNET_XPUBS = {
    bytes.fromhex(x)
    for x in ["0488b21e", "049d7cb2", "04b24746", "0295b43f", "02aa7ed3"]
}
ALL_TESTNET_XPRVS = {
    bytes.fromhex(x)
    for x in ["04358394", "044a4e28", "045f18bc", "024285b5", "02575048"]
}
ALL_TESTNET_XPUBS = {
    bytes.fromhex(x)
    for x in ["043587cf", "044a5262", "045f1cf6", "024289ef", "02575483"]
}

DEFAULT_P2WSH_PATH = {
    "mainnet": "m/48h/0h/0h/2h",
    "testnet": "m/48h/1h/0h/2h",
    "signet": "m/48h/1h/0h/2h",
}


class HDPrivateKey:
    def __init__(
        self,
        private_key,
        chain_code,
        depth=0,
        parent_fingerprint=b"\x00\x00\x00\x00",
        child_number=0,
        network="mainnet",
        priv_version=None,
        pub_version=None,
    ):
        # the main secret, should be a PrivateKey object
        self.private_key = private_key
        self.private_key.network = network
        # the code to make derivation deterministic
        self.chain_code = chain_code
        # level the current key is at in the heirarchy
        self.depth = depth
        # fingerprint of the parent key
        self.parent_fingerprint = parent_fingerprint
        # what order child this is
        self.child_number = child_number
        self.network = network

        if priv_version is None:
            # Set priv_version based on whether or not we are testnet
            priv_version = XPRV[self.network]
        self.priv_version = priv_version

        # keep a copy of the corresponding public key
        self.pub = HDPublicKey(
            point=private_key.point,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            network=network,
            pub_version=pub_version,  # HDPublicKey handles the case where pub_version is None
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
    def from_seed(cls, seed, network="mainnet", priv_version=None, pub_version=None):
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
            network=network,
            priv_version=priv_version,
            pub_version=pub_version,
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
            network=self.network,
            priv_version=self.priv_version,
            pub_version=self.pub.pub_version,
        )

    def traverse(self, path):
        """Returns the HDPrivateKey at the path indicated.
        Path should be in the form of m/x/y/z where x' means
        hardened"""

        # accept path in uppercase and/or using h instead of '
        path = path.lower().replace("h", "'")

        if not path.startswith("m"):
            raise ValueError(f"Invalid Path: {path}")

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

    def raw_serialize(self, priv_version):
        # version + depth + parent_fingerprint + child number + chain code + private key
        # start with priv_version, which should be a constant
        raw = priv_version
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

    def xprv(self, version=None):
        """Returns the base58-encoded x/y/z prv."""
        if version is None:
            version = self.priv_version
        raw = self.raw_serialize(version)
        return encode_base58_checksum(raw)

    def xpub(self, version=None):
        return self.pub.xpub(version=version)

    # passthrough methods
    def fingerprint(self):
        return self.pub.fingerprint()

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
        # first 4 bytes are the priv_version
        priv_version = s.read(4)
        # check that the priv_version is one of the TESTNET or MAINNET
        #  private keys, if not raise a ValueError
        if priv_version in ALL_TESTNET_XPRVS:
            network = "testnet"
        elif priv_version in ALL_MAINNET_XPRVS:
            network = "mainnet"
        else:
            raise ValueError(f"not a valid [t-z]prv: {priv_version}")
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
            network=network,
            priv_version=priv_version,
            # HDPublicKey will handle its own versioning:
            pub_version=None,
        )

    def _get_address(self, purpose, account=0, external=True, address=0):
        """Returns the proper address among purposes 44', 49' and 84'.
        p2pkh for 44', p2sh-p2wpkh for 49' and p2wpkh for 84'."""
        # if purpose is not one of 44', 49' or 84', raise ValueError
        if purpose not in ("44'", "49'", "84'"):
            raise ValueError(
                "Cannot create an address without a proper purpose: {}".format(purpose)
            )
        # if testnet/signet, coin is 1', otherwise 0'
        if self.network == "mainnet":
            coin = "0'"
        else:
            coin = "1'"
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
    def generate(
        cls,
        password=b"",
        extra_entropy=0,
        network="mainnet",
        priv_version=None,
        pub_version=None,
    ):
        mnemonic = secure_mnemonic(extra_entropy=extra_entropy)
        return mnemonic, cls.from_mnemonic(
            mnemonic,
            password=password,
            network=network,
            priv_version=priv_version,
            pub_version=pub_version,
        )

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic,
        password=b"",
        path="m",
        network="mainnet",
        priv_version=None,
        pub_version=None,
    ):
        """Returns a HDPrivateKey object from the mnemonic."""
        # this will check that the mnemonic is valid
        mnemonic_to_bytes(mnemonic)
        # normalize in case we got a mnemonic that's just the first 4 letters
        normalized = " ".join([BIP39.normalize(word) for word in mnemonic.split()])
        # salt is b'mnemonic' + password
        salt = b"mnemonic" + password
        # the seed is the hmac_sha512_kdf with normalized mnemonic and salt
        seed = hmac_sha512_kdf(normalized, salt)
        # return the HDPrivateKey at the path specified
        return cls.from_seed(
            seed, network=network, priv_version=priv_version, pub_version=pub_version
        ).traverse(path)

    @classmethod
    def from_shares(
        cls, share_mnemonics, passphrase=b"", password=b"", path="m", network="mainnet"
    ):
        """Returns a HDPrivateKey object from SLIP39 mnemonics.
        Note passphrase is for the shares and
        password is for the mnemonic."""
        mnemonic = ShareSet.recover_mnemonic(share_mnemonics, passphrase)
        return cls.from_mnemonic(mnemonic, password, path, network)

    def generate_p2wsh_key_record(
        self, bip32_path=None, use_slip132_version_byte=False
    ):
        """
        Convenience method for generating a public key_record to supply to your Coordinator software.
        """
        # Check that we're using the root HDPrivateKey
        if self.depth != 0:
            raise ValueError(
                "Key depth != 0. Please supply the root HDPrivateKey to use this method."
            )
        if self.parent_fingerprint != b"\x00\x00\x00\x00":
            raise ValueError(
                "Parent fingerprint != the zero byte. Please supply the root HDPrivateKey to use this method."
            )
        if self.child_number != 0:
            raise ValueError(
                "child_number != 0. Please supply the root HDPrivateKey to use this method."
            )
        if bip32_path is not None and not is_valid_bip32_path(bip32_path):
            raise ValueError(f"bip32_path {bip32_path} is not valid")

        if use_slip132_version_byte:
            # https://github.com/satoshilabs/slips/blob/master/slip-0132.md
            if self.network == "mainnet":
                version_byte = bytes.fromhex("02aa7ed3")
            else:
                version_byte = bytes.fromhex("02575483")
        else:
            version_byte = None  # buidl will automatically pick between xpub/tpub

        if bip32_path is None:
            bip32_path = DEFAULT_P2WSH_PATH[self.network]
        else:
            # make the standard h instead of ' for consistency
            bip32_path = bip32_path.replace("'", "h")

        xpub = self.traverse(bip32_path).xpub(version=version_byte)
        return f"[{self.fingerprint().hex()}/{bip32_path[2:]}]{xpub}"


class HDPublicKey:
    def __init__(
        self,
        point,
        chain_code,
        depth,
        parent_fingerprint,
        child_number,
        network="mainnet",
        pub_version=None,
    ):
        self.point = point
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.network = network
        if pub_version is None:
            # Set pub_version based on whether or not we are testnet
            pub_version = XPUB[network]
        self.pub_version = pub_version
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
        return self.point.address(network=self.network)

    def bech32_address(self):
        return self.point.bech32_address(network=self.network)

    def p2sh_p2wpkh_address(self):
        return self.point.p2sh_p2wpkh_address(network=self.network)

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
            network=self.network,
            pub_version=self.pub_version,
        )

    def traverse(self, path):
        """Returns the HDPublicKey at the path indicated.
        Path should be in the form of m/x/y/z."""

        if not path.startswith("m"):
            raise ValueError(f"Invalid Path: {path}")

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
        # start with pub_version, which should be a constant depending on network
        if self._raw is None:
            pub_version = XPUB[self.network]
            self._raw = self._serialize(pub_version)
        return self._raw

    def _serialize(self, pub_version):
        # start with the pub_version
        raw = pub_version
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

    def xpub(self, version=None):
        """Returns the base58-encoded x/y/z pub."""
        if version is None:
            version = self.pub_version
        # get the serialization
        raw = self._serialize(version)
        # base58-encode the whole thing
        return encode_base58_checksum(raw)

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
        # first 4 bytes are the pub_version
        pub_version = s.read(4)
        # check that the pub_version is one of the TESTNET or MAINNET
        #  public keys, if not raise a ValueError
        if pub_version in ALL_TESTNET_XPUBS:
            network = "testnet"
        elif pub_version in ALL_MAINNET_XPUBS:
            network = "mainnet"
        else:
            raise ValueError("not a valid [t-z]pub pub_version: {pub_version}")
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
            network=network,
            pub_version=pub_version,
        )


def calc_valid_seedpicker_checksums(first_words):
    """
    Generator to return all valid seedpicker checksums.

    For normal useage, just grab the first one only
    """
    for word in BIP39:
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


def get_unhardened_child_path(base_path, root_path):
    """
    Return the difference between the base_path and root_path.

    Return None if there is no child_path (or it require hardened derivation).
    """
    if not is_valid_bip32_path(root_path):
        raise ValueError(f"Invalid bip32_path: {root_path}")

    base_path = base_path.strip().lower().replace("h", "'")
    root_path = root_path.strip().lower().replace("h", "'")

    if root_path.startswith(base_path):
        child_path = root_path[len(base_path) :]
        if "'" not in child_path:
            return f"m{child_path}"
