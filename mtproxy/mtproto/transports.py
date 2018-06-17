import asyncio
from abc import ABC, abstractmethod
from typing import *

from mtproxy.util import RpcFlags


class AbstractTransport(ABC):
    PROTO_TAG = b''

    @staticmethod
    @abstractmethod
    async def read_message(stream: asyncio.StreamReader) -> Tuple[bytes, bool]:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    async def write_message(stream: asyncio.StreamWriter, msg: bytes) -> int:
        raise NotImplementedError


class AbridgedTransport(AbstractTransport):
    PROTO_TAG = b'\xef\xef\xef\xef'

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
    async def write_message(stream: asyncio.StreamWriter, msg: bytes) -> int:
        if len(msg) % 4 != 0:
            # logging("BUG: MTProtoFrameStreamWriter attempted to send msg with len %d" % len(data))
            return 0

        len_div_four = len(msg) // 4

        if len_div_four < AbridgedTransport.SHORT_PACKET_MAX_SIZE:
            return stream.write(bytes([len_div_four]) + msg)
        elif len_div_four < AbridgedTransport.LONG_PACKET_MAX_SIZE:
            return stream.write(b'\x7f' + int.to_bytes(len_div_four, 3, 'little') + msg)
        else:
            # print_err("Attempted to send too large pkt len =", len(data))
            return 0


class IntermediateTransport(AbstractTransport):
    PROTO_TAG = b'\xee\xee\xee\xee'

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
    async def write_message(stream: asyncio.StreamWriter, msg: bytes) -> int:
        return stream.write(int.to_bytes(len(msg), 4, 'little') + msg)


KNOWN_TRANSPORTS = [AbridgedTransport, IntermediateTransport]


def get_transport_by_tag(tag: bytes):
    for transport_cls in KNOWN_TRANSPORTS:
        if transport_cls.PROTO_TAG == tag:
            return transport_cls
