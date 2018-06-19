import asyncio
import logging
from typing import *

from mtproxy.downstream.types import AbstractTransport, ClientInfo
from mtproxy.mtproto.constants import RpcFlags
from mtproxy.utils.streams import LayeredStreamReaderBase, LayeredStreamWriterBase


LOGGER = logging.getLogger('mtproxy.transports')


class AbridgedTransport(AbstractTransport):
    PROTO_TAG = b'\xef\xef\xef\xef'
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2 | RpcFlags.PROTOCOL_ABRIDGED

    SHORT_PACKET_MAX_SIZE = 0x7f
    LONG_PACKET_MAX_SIZE = 2 ** 24

    @staticmethod
    async def read_message(stream: asyncio.StreamReader) -> Tuple[bytes, bool]:
        msg_len_bytes = await stream.readexactly(1)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        if msg_len >= 0x80:
            quick_ack_expected = True
            msg_len -= 0x80
        else:
            quick_ack_expected = False

        if msg_len == 0x7f:
            msg_len_bytes = await stream.readexactly(3)
            msg_len = int.from_bytes(msg_len_bytes, "little")

        msg_len *= 4

        msg = await stream.readexactly(msg_len)
        return msg, quick_ack_expected

    @staticmethod
    def write_message(stream: asyncio.StreamWriter, msg: bytes, simple_ack: bool) -> int:
        if len(msg) % 4 != 0:
            LOGGER.warning(f'MTProto abridged message length not aligned on 4: {len(msg)}')
            return 0

        if simple_ack:
            return stream.write(b'\xdd' + msg[::1])

        len_div_four = len(msg) // 4

        if len_div_four < AbridgedTransport.SHORT_PACKET_MAX_SIZE:
            return stream.write(bytes([len_div_four]) + msg)
        elif len_div_four < AbridgedTransport.LONG_PACKET_MAX_SIZE:
            return stream.write(b'\x7f' + int.to_bytes(len_div_four, 3, 'little') + msg)
        else:
            LOGGER.warning(f'MTProto abridged message too long: {len(msg)}')
            return 0


class IntermediateTransport(AbstractTransport):
    PROTO_TAG = b'\xee\xee\xee\xee'
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2 | RpcFlags.PROTOCOL_INTERMEDIATE

    @staticmethod
    async def read_message(stream: asyncio.StreamReader) -> Tuple[bytes, bool]:
        msg_len_bytes = await stream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        if msg_len & RpcFlags.QUICKACK.value:
            msg_len &= ~RpcFlags.QUICKACK.value
            quick_ack_expected = True
        else:
            quick_ack_expected = False

        msg = await stream.readexactly(msg_len)
        return msg, quick_ack_expected

    @staticmethod
    def write_message(stream: asyncio.StreamWriter, msg: bytes, simple_ack: bool) -> int:
        if simple_ack:
            return stream.write(b'\xdd' + msg)
        return stream.write(int.to_bytes(len(msg), 4, 'little') + msg)


KNOWN_TRANSPORTS = [AbridgedTransport, IntermediateTransport]


def get_transport_by_tag(tag: bytes):
    for transport_cls in KNOWN_TRANSPORTS:
        if transport_cls.PROTO_TAG == tag:
            return transport_cls


class MtProtoReader(LayeredStreamReaderBase):
    def __init__(self, upstream: LayeredStreamReaderBase, client_info: ClientInfo):
        super().__init__(upstream)
        self.client_info = client_info

    async def read(self, n=-1):
        message, quick_ack_expected = await self.client_info.transport.read_message(self.upstream)
        self.client_info.quick_ack_expected = quick_ack_expected
        return message


class MtProtoWriter(LayeredStreamWriterBase):
    def __init__(self, upstream: LayeredStreamWriterBase, client_info: ClientInfo):
        super().__init__(upstream)
        self.client_info = client_info

    def write(self, msg: bytes) -> int:
        return self.client_info.transport.write_message(self.upstream, msg, self.client_info.simple_ack_expected)
