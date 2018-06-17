import asyncio
import hashlib
from typing import *
import logging

from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase

from Crypto.Cipher import AES
from Crypto.Util import Counter

from mtproxy.utils.misc import KEY_LEN, HANDSHAKE_HEADER_LEN, IV_LEN

LOGGER = logging.getLogger('mtproxy.crypto')


def key_iv_from_handshake(handshake: bytes):
    return handshake[HANDSHAKE_HEADER_LEN:HANDSHAKE_HEADER_LEN + KEY_LEN + IV_LEN]


def parse_key_iv(key_iv: bytes) -> Tuple[bytes, int]:
    return key_iv[:KEY_LEN], int.from_bytes(key_iv[KEY_LEN:], 'big')


def derive_key(prekey: bytes, secret: bytes) -> bytes:
    return hashlib.sha256(prekey + secret).digest()


def init_aes_ctr(key: bytes, iv: int) -> AES:
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))


def parse_and_init_aes_ctr(key_iv: bytes, secret: bytes = None) -> AES:
    key, iv = parse_key_iv(key_iv)
    return init_aes_ctr(key, iv, secret)


def init_aes_cbc(key, iv):
    return AES.new(key, AES.MODE_CBC, iv)


class AESReader(LayeredStreamReaderBase):
    def __init__(
            self,
            upstream: asyncio.StreamReader,
            aes: AES,
            block_size: int = 1
    ):
        super().__init__(upstream)
        self.block_size = block_size
        self.buf = bytearray()
        self.aes = aes
        self.passthrough = False

    async def read(self, n: int = -1) -> bytes:
        if self.buf:
            ret = bytes(self.buf)
            self.buf.clear()
            return ret
        else:
            data = await self.upstream.read(n)
            needed_till_full_block = -len(data) % self.block_size
            if needed_till_full_block > 0:
                data += self.upstream.readexactly(needed_till_full_block)
            return self.aes.decrypt(data)

    async def readexactly(self, n: int) -> bytes:
        if n > len(self.buf):
            to_read = n - len(self.buf)
            needed_till_full_block = -to_read % self.block_size

            to_read_block_aligned = to_read + needed_till_full_block
            data = await self.upstream.readexactly(to_read_block_aligned)
            self.buf += self.aes.decrypt(data)

        ret = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return ret


class AESWriter(LayeredStreamWriterBase):
    def __init__(
            self,
            upstream: asyncio.StreamWriter,
            aes: AES,
            block_size: int = 1
    ):
        super().__init__(upstream)
        self.aes = aes
        self.block_size = block_size
        self.passthrough = False

    def write(self, data: bytes) -> int:
        if len(data) % self.block_size != 0:
            LOGGER.error(f'attempted to write {len(data)} bytes - not aligned to block size {self.block_size}')
            return 0

        if self.passthrough:
            return self.upstream.write(data)
        else:
            encrypted = self.aes.encrypt(data)
            return self.upstream.write(encrypted)
