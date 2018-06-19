import asyncio
import dataclasses
from abc import ABC, abstractmethod
from typing import Union

from mtproxy.mtproto.constants import RpcFlags
from mtproxy.utils.streams import LayeredStreamReaderBase, LayeredStreamWriterBase


@dataclasses.dataclass
class RPCProxyAnswer:
    flags: int
    data: bytes


@dataclasses.dataclass
class RPCSimpleAck:
    data: bytes


TRPCProxyResponse = Union[RPCProxyAnswer, RPCSimpleAck]


class HandshakeError(OSError):
    pass


@dataclasses.dataclass
class MTProtoMessage:
    data: bytes
    quick_ack: bool


class AbstractTransport(ABC):
    PROTO_TAG = b''
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2

    @staticmethod
    @abstractmethod
    async def read_message(stream: asyncio.StreamReader) -> MTProtoMessage:
        raise NotImplementedError

    @classmethod
    def write_response(cls, stream: asyncio.StreamWriter, resp: TRPCProxyResponse):
        if isinstance(resp, RPCSimpleAck):
            return cls.write_simple_ack(stream, resp)
        elif isinstance(resp, RPCProxyAnswer):
            return cls.write_proxy_answer(stream, resp)
        else:
            raise TypeError(f'Unsupported proxy response type {type(resp)}!')

    @staticmethod
    @abstractmethod
    def write_simple_ack(stream: asyncio.StreamWriter, resp: RPCSimpleAck):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def write_proxy_answer(stream: asyncio.StreamWriter, resp: RPCProxyAnswer):
        raise NotImplementedError


@dataclasses.dataclass
class ClientInfo:
    transport: AbstractTransport
    proxy_username: str
    ip_address: str
    port: int
    quick_ack_expected: bool = False
    simple_ack_expected: bool = False


@dataclasses.dataclass
class HandshakeResult:
    client_info: ClientInfo
    dc_id: int
    read_stream: LayeredStreamReaderBase
    write_stream: LayeredStreamWriterBase
    enc_key: bytes
    enc_iv: int
