import socket
import time

from io import BytesIO
from random import randint
from time import sleep

from buidl.block import Block
from buidl.helper import (
    GOLOMB_M,
    GOLOMB_P,
    decode_golomb,
    encode_varint,
    hash256,
    hash_to_range,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    unpack_bits,
)
from buidl.tx import Tx

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4
WITNESS_TX_DATA_TYPE = (1 << 30) + TX_DATA_TYPE
WITNESS_BLOCK_DATA_TYPE = (1 << 30) + BLOCK_DATA_TYPE

MAGIC = {
    "mainnet": b"\xf9\xbe\xb4\xd9",
    "testnet": b"\x0b\x11\x09\x07",
    "signet": b"\x0a\x03\xcf\x40",
}
PORT = {
    "mainnet": 8333,
    "testnet": 18333,
    "signet": 38333,
}


BASIC_FILTER_TYPE = 0


class NetworkEnvelope:
    def __init__(self, command, payload, network="mainnet"):
        self.command = command
        self.payload = payload
        self.magic = MAGIC[network]

    def __repr__(self):
        return "{}: {}".format(
            self.command.decode("ascii"),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, network="mainnet"):
        """Takes a stream and creates a NetworkEnvelope"""
        # check the network magic
        magic = s.read(4)
        if magic == b"":
            raise RuntimeError("Connection reset!")
        expected_magic = MAGIC[network]
        if magic != expected_magic:
            raise RuntimeError(
                "magic is not right {} vs {}".format(magic.hex(), expected_magic.hex())
            )
        # command 12 bytes, strip the trailing 0's using .strip(b'\x00')
        command = s.read(12).strip(b"\x00")
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of hash256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError("checksum does not match")
        return cls(command, payload, network=network)

    def serialize(self):
        """Returns the byte serialization of the entire network message"""
        # add the network magic using self.magic
        result = self.magic
        # command 12 bytes, fill leftover with b'\x00' * (12 - len(self.command))
        result += self.command + b"\x00" * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += hash256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def stream(self):
        """Returns a stream for parsing the payload"""
        return BytesIO(self.payload)


class VersionMessage:
    command = b"version"

    def __init__(
        self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b"\x00\x00\x00\x00",
        receiver_port=8333,
        sender_services=0,
        sender_ip=b"\x00\x00\x00\x00",
        sender_port=8333,
        nonce=None,
        user_agent=b"/programmingblockchain:0.1/",
        latest_block=0,
        relay=True,
    ):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2 ** 64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        """Serialize this message to send over the network"""
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b"\x00" * 10 + b"\xff\xff" + self.receiver_ip
        # receiver port is 2 bytes, little endian
        result += int_to_little_endian(self.receiver_port, 2)
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b"\x00" * 10 + b"\xff\xff" + self.sender_ip
        # sender port is 2 bytes, little endian
        result += int_to_little_endian(self.sender_port, 2)
        # nonce
        result += self.nonce
        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b"\x01"
        else:
            result += b"\x00"
        return result


class VerAckMessage:
    command = b"verack"

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""


class PingMessage:
    command = b"ping"

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b"pong"

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class GetHeadersMessage:
    command = b"getheaders"

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError("a start block is required")
        self.start_block = start_block
        if end_block is None:
            self.end_block = b"\x00" * 32
        else:
            self.end_block = end_block

    def serialize(self):
        """Serialize this message to send over the network"""
        # protocol version is 4 bytes little-endian
        result = int_to_little_endian(self.version, 4)
        # number of hashes is a varint
        result += encode_varint(self.num_hashes)
        # start block is in little-endian
        result += self.start_block[::-1]
        # end block is also in little-endian
        result += self.end_block[::-1]
        return result


class HeadersMessage:
    command = b"headers"

    def __init__(self, headers):
        self.headers = headers

    @classmethod
    def parse(cls, s):
        # number of headers is in a varint
        num_headers = read_varint(s)
        # initialize the headers array
        headers = []
        # loop through number of headers times
        for _ in range(num_headers):
            # add a header to the headers array by using Block.parse_header(s)
            headers.append(Block.parse_header(s))
            # read the next varint (num_txs)
            num_txs = read_varint(s)
            # num_txs should be 0 or raise a RuntimeError
            if num_txs != 0:
                raise RuntimeError("number of txs not 0")
        # return a class instance
        return cls(headers)

    def is_valid(self):
        """Return whether the headers satisfy proof-of-work and are sequential"""
        last_block = None
        for h in self.headers:
            if not h.check_pow():
                return False
            if last_block and h.prev_block != last_block:
                return False
            last_block = h.hash()
        return True


class GetDataMessage:
    command = b"getdata"

    def __init__(self):
        self.data = []

    def add_data(self, data_type, identifier):
        self.data.append((data_type, identifier))

    def serialize(self):
        # start with the number of items as a varint
        result = encode_varint(len(self.data))
        for data_type, identifier in self.data:
            # data type is 4 bytes little endian
            result += int_to_little_endian(data_type, 4)
            # identifier needs to be in little endian
            result += identifier[::-1]
        return result


class GetCFiltersMessage:
    command = b"getcfilters"

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=1, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFilterMessage:
    command = b"cfilter"

    def __init__(self, filter_type, block_hash, filter_bytes, hashes):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_bytes = filter_bytes
        self.hashes = hashes
        self.f = len(self.hashes) * GOLOMB_M
        self.key = self.block_hash[::-1][:16]

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        block_hash = s.read(32)[::-1]
        num_bytes = read_varint(s)
        filter_bytes = s.read(num_bytes)
        substream = BytesIO(filter_bytes)
        n = read_varint(substream)
        bits = unpack_bits(substream.read())
        hashes = set()
        current = 0
        for _ in range(n):
            delta = decode_golomb(bits, GOLOMB_P)
            current += delta
            hashes.add(current)
        return cls(filter_type, block_hash, filter_bytes, hashes)

    def hash(self, raw_script_pubkey):
        return hash_to_range(self.key, raw_script_pubkey, self.f)

    def __contains__(self, raw_script_pubkey):
        if type(raw_script_pubkey) == bytes:
            return self.hash(raw_script_pubkey) in self.hashes
        else:
            for r in raw_script_pubkey:
                if self.hash(r) in self.hashes:
                    return True
            return False


class GetCFHeadersMessage:
    command = b"getcfheaders"

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=0, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFHeadersMessage:
    command = b"cfheaders"

    def __init__(self, filter_type, stop_hash, previous_filter_header, filter_hashes):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.previous_filter_header = previous_filter_header
        self.filter_hashes = filter_hashes

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        previous_filter_header = s.read(32)[::-1]
        filter_hashes_length = read_varint(s)
        filter_hashes = []
        for _ in range(filter_hashes_length):
            filter_hashes.append(s.read(32)[::-1])
        return cls(filter_type, stop_hash, previous_filter_header, filter_hashes)


class GetCFCheckPointMessage:
    command = b"getcfcheckpt"

    def __init__(self, filter_type=BASIC_FILTER_TYPE, stop_hash=None):
        self.filter_type = filter_type
        if stop_hash is None:
            raise RuntimeError("Need a stop hash")
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, "big")
        result += self.stop_hash[::-1]
        return result


class CFCheckPointMessage:
    command = b"cfcheckpt"

    def __init__(self, filter_type, stop_hash, filter_headers):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.filter_headers = filter_headers

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        filter_headers_length = read_varint(s)
        filter_headers = []
        for _ in range(filter_headers_length):
            filter_headers.append(s.read(32)[::-1])
        return cls(filter_type, stop_hash, filter_headers)


class GenericMessage:
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def serialize(self):
        return self.payload


class SimpleNode:
    def __init__(self, host, port=None, network="mainnet", logging=False):
        if port is None:
            port = PORT[network]
        self.network = network
        self.logging = logging
        # connect to socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        # create a stream that we can use with the rest of the library
        self.stream = self.socket.makefile("rb", None)

    def handshake(self):
        """Do a handshake with the other node. Handshake is sending a version message and getting a verack back."""
        # create a version message
        version = VersionMessage()
        # send the command
        self.send(version)
        # wait for a verack message
        self.wait_for(VerAckMessage)

    def send(self, message):
        """Send a message to the connected node"""
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize(), network=self.network
        )
        if self.logging:
            print("sending: {}".format(envelope))
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        """Read a message from the socket"""
        envelope = NetworkEnvelope.parse(self.stream, network=self.network)
        if self.logging:
            print("receiving: {}".format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        """Wait for one of the messages in the list"""
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
            # get the next network message
            envelope = self.read()
            # set the command to be evaluated
            command = envelope.command
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                # send pong
                self.send(PongMessage(envelope.payload))
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())

    def get_filtered_txs(self, block_hashes):
        """Returns transactions that match the bloom filter"""
        from buidl.merkleblock import MerkleBlock

        # create a getdata message
        getdata = GetDataMessage()
        # for each block request the filtered block
        for block_hash in block_hashes:
            # add_data (FILTERED_BLOCK_DATA_TYPE, block_hash) to request the block
            getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)
        # send the getdata message
        self.send(getdata)
        # initialize the results array we'll send back
        results = []
        # for each block hash
        for block_hash in block_hashes:
            # wait for the merkleblock command
            mb = self.wait_for(MerkleBlock)
            # check that the merkle block's hash is the same as the block hash
            if mb.hash() != block_hash:
                raise RuntimeError("Wrong block sent")
            # check that the merkle block is valid
            if not mb.is_valid():
                raise RuntimeError("Merkle Proof is invalid")
            # loop through the proved transactions from the Merkle block
            for tx_hash in mb.proved_txs():
                # wait for the tx command
                tx_obj = self.wait_for(Tx)
                # check that the hash matches
                if tx_obj.hash() != tx_hash:
                    raise RuntimeError(
                        "Wrong tx sent {} vs {}".format(tx_hash.hex(), tx_obj.id())
                    )
                # add to the results
                results.append(tx_obj)
        # return the results
        return results

    def is_tx_accepted(self, tx_obj):
        """Returns whether a transaction has been accepted on the network"""
        # sleep for a second to let everything propagate
        sleep(1)
        # create a GetDataMessage
        get_data = GetDataMessage()
        # ask for the tx
        get_data.add_data(TX_DATA_TYPE, tx_obj.hash())
        # send the GetDataMessage
        self.send(get_data)
        # now wait for a response
        got_tx = self.wait_for(Tx)
        if got_tx.id() == tx_obj.id():
            return True
