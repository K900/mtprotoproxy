from mtproxy.handshake import ClientInfo
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase


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
        return self.client_info.transport.write_message(self.upstream, msg)
