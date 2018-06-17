import asyncio


class LayeredStreamReaderBase:
    def __init__(self, upstream):
        super().__init__()
        self.upstream = upstream

    async def read(self, n=-1):
        return await self.upstream.read(n)

    async def readexactly(self, n):
        return await self.upstream.readexactly(n)


class LayeredStreamWriterBase:
    def __init__(self, upstream):
        self.upstream = upstream

    def write(self, data):
        return self.upstream.write(data)

    def write_eof(self):
        return self.upstream.write_eof()

    async def drain(self):
        return await self.upstream.drain()

    def close(self):
        return self.upstream.close()

    def abort(self):
        return self.upstream.transport.abort()

    @property
    def transport(self):
        return self.upstream.transport
