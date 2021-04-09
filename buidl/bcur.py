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
        assert h == hashlib.sha256(cbor).digest()
    return cbor_decode(cbor)


def encode_to_bcur_single(text_b64):
    """
    Take some text (i.e. a base64 PSBT string) and prepare it for encoding as a single QR code (using Blockchain Commons Uniform Resources)

    See encode_to_bcur_qrgif for animation

    Resulting string does NOT contain 1of1
    """
    enc, enc_hash = bcur_encode(a2b_base64(text_b64))
    return f"ur:bytes/{enc_hash}/{enc}"


def decode_single_qr_to_payload(bcur_string):
    """
    Take a Blockchain Commons Uniform Resource (from a QR code) and decode it to base64.
    """
    # TODO: support animation
    x, y, checksum, payload, err_msg = parse_bcur(string=bcur_string)
    if err_msg:
        raise Exception(err_msg)

    enc = bcur_decode(payload)
    decoded = b2a_base64(enc).strip().decode()

    # Note that checksum is NOT validated (would require all QRs to combine all payloads and calculate shared checksum)
    return x, y, checksum, decoded


def decode_multi_qrgif_to_payload(qr_payloads, require_checksum=True):
    """
    Take a Blockchain Commons Uniform Resource (from a QR code) and decode it to base64.

    Returns decoded_text, checksum, and err_msg
    """
    # Initialize values
    y, checksum = None, None
    encoded_payloads = []
    for cnt, qr_payload in enumerate(qr_payloads):
        x_res, y_res, checksum_res, encoded_payload, err_msg = parse_bcur(
            string=qr_payload
        )
        if err_msg:
            return None, None, f"Parse error: {err_msg}"

        # Set values if unset, check unchanged if already set
        if x_res != cnt + 1:
            return None, None, f"X value error: expected {cnt+1} but got {x_res}"
        if y is None:
            y = y_res
        else:
            if y_res != y:
                return (
                    None,
                    None,
                    f"Inconsistent Y value error: expected {y} but got {y_res}",
                )
        if checksum is None:
            checksum = checksum_res
        else:
            if checksum_res != checksum:
                return (
                    None,
                    None,
                    f"Inconsistent checksum across qr payloads: {checksum_res} != {checksum}",
                )

        # checks all pass
        encoded_payloads.append(encoded_payload)

    encoded_full_payload = "".join(encoded_payloads)

    if require_checksum and not checksum:
        return None, None, "QR GIF lacks checksum"

    try:
        decoded_full_payload = bcur_decode(data=encoded_full_payload, checksum=checksum)
    except AssertionError:
        return None, None, "Checksum doesn't match"

    return b2a_base64(decoded_full_payload).strip().decode(), checksum, ""


def parse_bcur(string):
    """
    Returns x, y, checksum, payload, err_msg
    """

    string = string.lower().strip()
    if not string.startswith("ur:bytes/"):
        return None, None, None, None, "Doesn't start with ur:bytes/"

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
            return None, None, None, None, f"xOFy section malformed: {xofy_parts}"

        if not is_intable(xofy_parts[0]) or not is_intable(xofy_parts[1]):
            return None, None, None, None, f"y in xOFy must be an integer: {xofy_parts}"

        x_int = int(xofy_parts[0])
        y_int = int(xofy_parts[1])

        if x_int > y_int:
            return None, None, None, None, "x must be >= y (in xOFy)"
    else:
        return None, None, None, None, "Doesn't have 2-4 slashes"

    if checksum and len(checksum) != 58:
        return None, None, None, None, "checksum must be 58 chars"

    if checksum and not uses_only_bech32_chars(checksum):
        return (
            None,
            None,
            None,
            None,
            f"checksum can only contain bech32 characters: {checksum}",
        )

    if not uses_only_bech32_chars(payload):
        return (
            None,
            None,
            None,
            None,
            f"payload can only contain bech32 characters: {payload}",
        )

    return x_int, y_int, checksum, payload.strip(), ""


def encode_to_bcur_qrgif(text_b64, max_size_per_chunk=300, animate=True):
    """
    This algorithm makes all the chunks of about equal length.
    This makes sure that the last chunk is not (too) different in size which is visually noticeable when animation occurs
    Inspired by https://github.com/cryptoadvance/specter-desktop/blob/da35e7d88072475746077432710c77f799017eb0/src/cryptoadvance/specter/templates/includes/qr-code.html

    If animate=False, then max_size_per_chunk is ignored
    """

    # Calculate values to chunk
    enc, enc_hash = bcur_encode(a2b_base64(text_b64))

    if animate is False:
        number_of_chunks = 1
    else:
        number_of_chunks = ceil(len(enc) / max_size_per_chunk)

    chunk_length = ceil(len(enc) / number_of_chunks)

    # It would be possible to create a unique code-path for number_of_chunks == 1 (with no longer needs a checksum)
    # Including the checksum seems harmless (maybe beneficial) and improves readability

    resulting_chunks = []
    for cnt in range(number_of_chunks):
        start_idx = cnt * chunk_length
        finish_idx = (cnt + 1) * chunk_length
        resulting_chunks.append(
            f"ur:bytes/{cnt+1}of{number_of_chunks}/{enc_hash}/{enc[start_idx:finish_idx]}"
        )

    return resulting_chunks
