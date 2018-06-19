from abc import ABC, abstractmethod


class AbstractByteReader(ABC):
    @abstractmethod
    def read_bytes(self, n):
        raise NotImplementedError

    async def read_int(self, size, byteorder='little', signed=False):
        data = await self.read_bytes(size)
        return int.from_bytes(data, byteorder, signed=signed)


class AioByteReader(AbstractByteReader):
    def __init__(self, read_stream):
        self.read_stream = read_stream

    def read_bytes(self, n):
        return self.read_stream.readexactly(n)
