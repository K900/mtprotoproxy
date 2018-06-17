import asyncio

from mtproxy.handshake import ClientInfo
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase


class MtProtoReader(LayeredStreamReaderBase):
    def __init__(self, upstream: asyncio.StreamReader, client_ctx: ClientInfo):
        super().__init__(upstream)
        self.client_ctx = client_ctx

    async def read(self, n=-1):
        message, quick_ack_expected = await self.client_ctx.transport.read_message(self.upstream)
        self.client_ctx.quick_ack_expected = quick_ack_expected
        return message


class MtProtoWriter(LayeredStreamWriterBase):
    def __init__(self, upstream: asyncio.StreamWriter, client_ctx: ClientInfo):
        super().__init__(upstream)
        self.client_ctx = client_ctx

    async def write(self, msg: bytes) -> int:
        return await self.client_ctx.transport.write_message(self.upstream, msg)
