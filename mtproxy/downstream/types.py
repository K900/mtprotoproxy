import asyncio
import dataclasses
from abc import ABC, abstractmethod
from typing import *

from mtproxy.mtproto.constants import RpcFlags
from mtproxy.utils.streams import LayeredStreamReaderBase, LayeredStreamWriterBase


class HandshakeError(OSError):
    pass


class AbstractTransport(ABC):
    PROTO_TAG = b''
    HANDSHAKE_FLAGS = RpcFlags.EXTMODE2

    @staticmethod
    @abstractmethod
    async def read_message(stream: asyncio.StreamReader) -> Tuple[bytes, bool]:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def write_message(stream: asyncio.StreamWriter, msg: bytes) -> int:
        raise NotImplementedError


@dataclasses.dataclass
class ClientInfo:
    transport: AbstractTransport
    proxy_username: str
    ip_address: str
    port: int
    quick_ack_expected: bool = False


@dataclasses.dataclass
class HandshakeResult:
    client_info: ClientInfo
    dc_id: int
    read_stream: LayeredStreamReaderBase
    write_stream: LayeredStreamWriterBase
    enc_key: bytes
    enc_iv: int
