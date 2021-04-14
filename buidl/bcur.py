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


class BCURStringFormatError(RuntimeError):
    pass


def bcur_encode(data):
    """Returns bcur encoded string and checksum"""
    cbor = cbor_encode(data)
    enc = bc32encode(cbor)
    h = hashlib.sha256(cbor).digest()
    enc_hash = bc32encode(h)
    return enc, enc_hash


def bcur_decode(data, checksum=None):
    """Returns decoded data, verifies checksum if provided"""
    cbor = bc32decode(data)
    if checksum is not None:
        h = bc32decode(checksum)
        calculated_digest = hashlib.sha256(cbor).digest()
        if h != calculated_digest:
            raise ValueError(f"Calculated digest {calculated_digest} != {h}")
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
        raise BCURStringFormatError(
            f"{bcur_string} is of type {type(bcur_string)}, not a string"
        )

    string = bcur_string.lower().strip()

    if not string.startswith("ur:bytes/"):
        raise BCURStringFormatError(f"String {string} doesn't start with ur:bytes/")

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
            raise BCURStringFormatError(f"x-of-y section malformed: {xofy_parts}")

        if not is_intable(xofy_parts[0]) or not is_intable(xofy_parts[1]):
            raise BCURStringFormatError(
                f"x and y (in x-of-y) must both be integers: {xofy_parts}"
            )

        x_int = int(xofy_parts[0])
        y_int = int(xofy_parts[1])

        if x_int > y_int:
            raise BCURStringFormatError("x must be >= y (in x-of-y): {xofy_parts}")

    else:
        raise BCURStringFormatError(f"{string} doesn't have 2-4 slashes")

    if checksum:
        if len(checksum) != 58:
            raise BCURStringFormatError("Checksum must be 58 chars")
        if not uses_only_bech32_chars(checksum):
            raise BCURStringFormatError(
                f"checksum can only contain bech32 characters: {checksum}"
            )

    if not uses_only_bech32_chars(payload):
        raise BCURStringFormatError(
            f"Payload can only contain bech32 characters: {payload}"
        )

    return payload, checksum, x_int, y_int


class BCURSingle:
    def __init__(self, text_b64, encoded=None, checksum=None):
        binary_b64 = a2b_base64(text_b64)
        enc, enc_hash = bcur_encode(data=binary_b64)
        if encoded and encoded != enc:
            raise ValueError(f"Calculated encoding {enc} != {encoded}")

        if checksum and checksum != enc_hash:
            raise ValueError(f"Calculated checksum {enc_hash} != {checksum}")

        self.text_b64 = text_b64
        self.encoded = enc
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

        payload, checksum, x, y = _parse_bcur_helper(bcur_string=to_parse)

        if x != 1 or y != 1:
            raise BCURStringFormatError(
                f"BCURSingle must have x=1 and y=1, instead got x={x} and y={y}"
            )

        # will throw an error if checksum is incorrect
        enc = bcur_decode(data=payload, checksum=checksum)
        return cls(
            text_b64=b2a_base64(enc).strip().decode(),
            encoded=payload,
            checksum=checksum,
        )


class BCURMulti:
    def __init__(self, text_b64, encoded=None, checksum=None):
        binary_b64 = a2b_base64(text_b64)
        enc, enc_hash = bcur_encode(data=binary_b64)
        if encoded and encoded != enc:
            raise ValueError(f"Calculated encoding {enc} != {encoded}")

        if checksum and checksum != enc_hash:
            raise ValueError(f"Calculated checksum {enc_hash} != {checksum}")

        self.checksum = checksum
        self.encoded = enc
        self.text_b64 = text_b64
        self.enc_hash = enc_hash

    def __repr__(self):
        return f"bcur: {self.checksum}\n{self.text_b64}\n"

    def encode(self, max_size_per_chunk=300, animate=True):
        """
        Take some base64 text (i.e. a PSBT string) and encode it into multiple QR codes using Blockchain Commons Uniform Resources.

        If animate=False, then max_size_per_chunk is ignored and this returns a 1of1 with checksum.

        Use parse() to return a BCURMulti object from this encoded result.

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
            raise BCURStringFormatError(
                f"{to_parse} is of type {type(to_parse)}, not a list/tuple"
            )

        payloads = []
        global_checksum, global_y = "", 0
        for cnt, bcur_string in enumerate(to_parse):
            entry_payload, entry_checksum, entry_x, entry_y = _parse_bcur_helper(
                bcur_string=bcur_string
            )
            if cnt + 1 != entry_x:
                raise ValueError(
                    f"BCUR strings not in order: got {entry_x} and was expecting {cnt+1}"
                )

            # Initialize checksum and y (as in x-of-y) on first loop
            if cnt == 0:
                global_checksum = entry_checksum
                global_y = entry_y

            elif entry_checksum != global_checksum:
                raise ValueError(
                    f"Entry {bcur_string} has checksum {entry_checksum} but we're expecting {global_checksum}"
                )
            elif entry_y != global_y:
                raise ValueError(
                    f"Entry {bcur_string} wants {entry_y} parts but we're expecting {global_y} parts"
                )
            # All checks pass
            payloads.append(entry_payload)

        # will throw an error if checksum is incorrect
        enc = bcur_decode(data="".join(payloads), checksum=global_checksum)

        return cls(text_b64=b2a_base64(enc).strip().decode(), checksum=global_checksum)
