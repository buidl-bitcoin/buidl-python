from buidl.bech32 import (
    cbor_encode,
    cbor_decode,
    bc32encode,
    bc32decode,
    uses_only_bech32_chars,
)
from buidl.helper import is_intable

from binascii import a2b_base64, b2a_base64
from math import ceil

import hashlib


# BCUR Exceptions


class INCONSISTENT_BCUR_STRING(RuntimeError):
    pass


class INVALID_CHECKSUM(RuntimeError):
    pass


class INVALID_ENCODING(RuntimeError):
    pass


class INVALID_BCUR_STRING(RuntimeError):
    pass


def bcur_encode(data):
    """Returns bcur encoded string and hash digest"""
    cbor = cbor_encode(data)
    enc = bc32encode(cbor)
    h = hashlib.sha256(cbor).digest()
    enc_hash = bc32encode(h)
    return enc, enc_hash


def bcur_decode(data, checksum=None):
    """Returns decoded data, verifies hash digest if provided"""
    cbor = bc32decode(data)
    if checksum is not None:
        h = bc32decode(checksum)
        calculated_digest = hashlib.sha256(cbor).digest()
        if h != calculated_digest:
            raise INVALID_CHECKSUM(f"Calculated digest {calculated_digest} != {h}")
    return cbor_decode(cbor)


def _parse_bcur_helper(bcur_string):
    """
    This parses a bcur string and returns the following (or raises an error):

        payload, checksum, x, y

    Notes:
    - Works for both BCURSingle and BCURMulti.
    - All entries may be empty except for payload.
    - Checksums are not validated here, as checksum validation is different for single vs multi.
    """

    if type(bcur_string) is not str:
        raise INVALID_BCUR_STRING(
            f"{bcur_string} is of type {type(bcur_string)}, not a string"
        )

    string = bcur_string.lower().strip()

    if not string.startswith("ur:bytes/"):
        raise INVALID_BCUR_STRING(f"String {string} doesn't start with ur:bytes/")

    bcur_parts = string.split("/")
    if len(bcur_parts) == 2:
        # Non-animated QR code (just 1 qr, doesn't display 1of1 nor checksum)
        _, payload = bcur_parts
        checksum, x_int, y_int = None, 1, 1
    elif len(bcur_parts) == 3:
        # Non-animated QR code (just 1 qr, doesn't display 1of1 but does have checksum)
        _, checksum, payload = bcur_parts
        x_int, y_int = 1, 1
    elif len(bcur_parts) == 4:
        # Animated QR code
        _, xofy, checksum, payload = bcur_parts

        xofy_parts = xofy.split("of")
        if len(xofy_parts) != 2:
            raise INVALID_BCUR_STRING(f"x-of-y section malformed: {xofy_parts}")

        if not is_intable(xofy_parts[0]) or not is_intable(xofy_parts[1]):
            raise INVALID_BCUR_STRING(
                f"x and y (in x-of-y) must both be integers: {xofy_parts}"
            )

        x_int = int(xofy_parts[0])
        y_int = int(xofy_parts[1])

        if x_int > y_int:
            raise INVALID_BCUR_STRING("x must be >= y (in x-of-y): {xofy_parts}")

    else:
        raise INVALID_BCUR_STRING(f"{string} doesn't have 2-4 slashes")

    if checksum:
        if len(checksum) != 58:
            raise INVALID_CHECKSUM("checksum must be 58 chars")
        if not uses_only_bech32_chars(checksum):
            raise INVALID_CHECKSUM(
                f"checksum can only contain bech32 characters: {checksum}"
            )

    if not uses_only_bech32_chars(payload):
        raise INVALID_ENCODING(f"payload can only contain bech32 characters: {payload}")

    return payload, checksum, x_int, y_int


class BCURSingle:
    def __init__(self, text_b64, encoded=None, digest=None):
        binary_b64 = a2b_base64(text_b64)
        enc, enc_hash = bcur_encode(data=binary_b64)
        if encoded and enc != encoded:
            raise INVALID_ENCODING(f"Calculated encoding {enc} != {encoded}")

        if digest and enc_hash != digest:
            # For y>1, we want to ignore the digest on instantiation (digest applies to BCURMulti, not BCURSingle)
            raise INVALID_CHECKSUM(f"Calculated digest {enc_hash} != {digest}")

        self.encoded = enc
        self.text_b64 = text_b64
        self.enc_hash = enc_hash

    def __repr__(self):
        return self.encode()

    def encode(self, use_checksum=True):
        # Single QR, no x-of-y
        if use_checksum:
            return f"ur:bytes/{self.enc_hash}/{self.encoded}"
        else:
            return f"ur:bytes/{self.encoded}"

    @classmethod
    def parse(cls, to_parse):
        """Parses (decodes) a BCURSingle from a single BCUR string"""

        payload, checksum, _, _ = _parse_bcur_helper(bcur_string=to_parse)

        enc = bcur_decode(
            data=payload, checksum=checksum
        )  # will throw an error if digest is incorrect
        text_b64 = b2a_base64(enc).strip().decode()
        return cls(text_b64=text_b64, encoded=payload, digest=checksum)


class BCURMulti:
    def __init__(self, text_b64, encoded=None, digest=None):
        self.checksum = digest
        binary_b64 = a2b_base64(text_b64)
        enc, enc_hash = bcur_encode(data=binary_b64)
        if encoded and enc != encoded:
            raise INVALID_ENCODING(f"Calculated encoding {enc} != {encoded}")

        if digest and enc_hash != digest:
            # For y>1, we want to ignore the digest on instantiation (digest applies to BCURMulti, not BCURSingle)
            raise INVALID_CHECKSUM(f"Calculated digest {enc_hash} != {digest}")

        self.encoded = enc
        self.text_b64 = text_b64
        self.enc_hash = enc_hash

    def __repr__(self):
        # TODO: divide into chunks?
        return f"BCUR: {self.text_b64}"

    def encode(self, max_size_per_chunk=300, animate=True):
        """
        Take some base64 text (i.e. a PSBT string) and encode it into multiple QR codes using Blockchain Commons Uniform Resources.

        If animate=False, then max_size_per_chunk is ignored and this returns a 1of1 with checksum.

        Use parse to return the original result.

        This algorithm makes all the chunks of about equal length.
        This makes sure that the last chunk is not (too) different in size which is visually noticeable when animation occurs
        Inspired by this JS implementation:
        https://github.com/cryptoadvance/specter-desktop/blob/da35e7d88072475746077432710c77f799017eb0/src/cryptoadvance/specter/templates/includes/qr-code.html
        """

        if animate is False:
            number_of_chunks = 1
        else:
            number_of_chunks = ceil(len(self.encoded) / max_size_per_chunk)

        chunk_length = ceil(len(self.encoded) / number_of_chunks)

        # For number_of_chunks == 1 (with no checksum) use BCURSingle

        resulting_chunks = []
        for cnt in range(number_of_chunks):
            start_idx = cnt * chunk_length
            finish_idx = (cnt + 1) * chunk_length
            resulting_chunks.append(
                f"ur:bytes/{cnt+1}of{number_of_chunks}/{self.enc_hash}/{self.encoded[start_idx:finish_idx]}"
            )

        return resulting_chunks

    @classmethod
    def parse(cls, to_parse):
        """Parses a BCURMulti from a list of BCUR strings"""
        if type(to_parse) not in (list, tuple):
            raise INVALID_BCUR_STRING(
                f"{to_parse} is of type {type(to_parse)}, not a list/tuple"
            )

        payloads = []
        multi_checksum, multi_y = "", 0
        for cnt, bcur_string in enumerate(to_parse):
            entry_payload, entry_checksum, entry_x, entry_y = _parse_bcur_helper(
                bcur_string=bcur_string
            )
            if cnt + 1 != entry_x:
                raise INCONSISTENT_BCUR_STRING(
                    f"BCUR strings not in order: got {entry_x} and was expecting {cnt+1}"
                )

            # Initialize checksum and y (as in x-of-y) on first loop
            if cnt == 0:
                multi_checksum = entry_checksum
                multi_y = entry_y

            elif entry_checksum != multi_checksum:
                raise INCONSISTENT_BCUR_STRING(
                    f"Entry {bcur_string} has checksum {entry_checksum} but we're expecting {multi_checksum}"
                )
            elif entry_y != multi_y:
                raise INCONSISTENT_BCUR_STRING(
                    f"Entry {bcur_string} has y {entry_y} but we're expecting {multi_y}"
                )
            # All checks pass
            payloads.append(entry_payload)

        enc = bcur_decode(
            data="".join(payloads), checksum=multi_checksum
        )  # will throw an error if digest is incorrect
        text_b64 = b2a_base64(enc).strip().decode()

        return cls(text_b64=text_b64, digest=multi_checksum)
