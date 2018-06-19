import asyncio
import logging

from mtproxy.downstream.types import AbstractTransport, MTProtoMessage, RPCProxyAnswer, RPCSimpleAck
from mtproxy.mtproto.constants import RpcFlags

LOGGER = logging.getLogger('mtproxy.transports')


class AbridgedTransport(AbstractTransport):
    PROTO_TAG = b'\xef\xef\xef\xef'
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2 | RpcFlags.PROTOCOL_ABRIDGED

    SHORT_PACKET_MAX_SIZE = 0x7f
    LONG_PACKET_MAX_SIZE = 2 ** 24

    @staticmethod
    async def read_message(stream: asyncio.StreamReader) -> MTProtoMessage:
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
        return MTProtoMessage(msg, quick_ack_expected)

    @staticmethod
    def write_simple_ack(stream: asyncio.StreamWriter, resp: RPCSimpleAck):
        return stream.write(b'\xdd' + resp.data[::1])

    @staticmethod
    def write_proxy_answer(stream: asyncio.StreamWriter, resp: RPCProxyAnswer):
        data = resp.data
        if len(data) % 4 != 0:
            LOGGER.warning(f'MTProto abridged message length not aligned on 4: {len(data)}')

        len_div_four = len(data) // 4

        if len_div_four < AbridgedTransport.SHORT_PACKET_MAX_SIZE:
            stream.write(bytes([len_div_four]) + data)
        elif len_div_four < AbridgedTransport.LONG_PACKET_MAX_SIZE:
            stream.write(b'\x7f' + int.to_bytes(len_div_four, 3, 'little') + data)
        else:
            LOGGER.warning(f'MTProto abridged message too long: {len(data)}')


class IntermediateTransport(AbstractTransport):
    PROTO_TAG = b'\xee\xee\xee\xee'
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2 | RpcFlags.PROTOCOL_INTERMEDIATE

    @staticmethod
    async def read_message(stream: asyncio.StreamReader) -> MTProtoMessage:
        msg_len_bytes = await stream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, "little")

        if msg_len & RpcFlags.QUICKACK.value:
            msg_len &= ~RpcFlags.QUICKACK.value
            quick_ack_expected = True
        else:
            quick_ack_expected = False

        msg = await stream.readexactly(msg_len)
        return MTProtoMessage(msg, quick_ack_expected)

    @staticmethod
    def write_simple_ack(stream: asyncio.StreamWriter, resp: RPCSimpleAck):
        return stream.write(b'\xdd' + resp.data)

    @staticmethod
    def write_proxy_answer(stream: asyncio.StreamWriter, resp: RPCProxyAnswer):
        data = resp.data
        return stream.write(int.to_bytes(len(data), 4, 'little') + data)


KNOWN_TRANSPORTS = [AbridgedTransport, IntermediateTransport]


def get_transport_by_tag(tag: bytes):
    for transport_cls in KNOWN_TRANSPORTS:
        if transport_cls.PROTO_TAG == tag:
            return transport_cls
