import asyncio
import hashlib
import logging
import random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from typing import Tuple

from mtproxy.mtproto.constants import HANDSHAKE_HEADER_LEN, IV_LEN, KEY_LEN
from mtproxy.utils.streams import AbstractByteReader

LOGGER = logging.getLogger('mtproxy.crypto')


def key_iv_from_handshake(handshake: bytes):
    return handshake[HANDSHAKE_HEADER_LEN:HANDSHAKE_HEADER_LEN + KEY_LEN + IV_LEN]


def parse_key_iv(key_iv: bytes) -> Tuple[bytes, int]:
    return key_iv[:KEY_LEN], int.from_bytes(key_iv[KEY_LEN:], 'big')


def derive_key(prekey: bytes, secret: bytes) -> bytes:
    return hashlib.sha256(prekey + secret).digest()


def init_aes_ctr(key: bytes, iv: int) -> AES:
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=iv))


def init_aes_cbc(key: bytes, iv: int) -> AES:
    return AES.new(key, AES.MODE_CBC, iv)


def random_bytes(n: int) -> bytearray:
    return bytearray([random.randrange(0, 256) for _ in range(n)])


class AESReader(AbstractByteReader):
    def __init__(
            self,
            upstream: AbstractByteReader,
            aes: AES,
            block_size: int = 1
    ):
        self.upstream = upstream
        self.block_size = block_size
        self.buf = bytearray()
        self.aes = aes

    async def read_bytes(self, n: int) -> bytes:
        if n > len(self.buf):
            to_read = n - len(self.buf)
            needed_till_full_block = -to_read % self.block_size

            to_read_block_aligned = to_read + needed_till_full_block
            data = await self.upstream.read_bytes(to_read_block_aligned)
            self.buf += self.aes.decrypt(data)

        ret = bytes(self.buf[:n])
        self.buf = self.buf[n:]
        return ret


class AESWriter:
    def __init__(
            self,
            upstream: asyncio.StreamWriter,
            aes: AES,
            block_size: int = 1
    ):
        self.upstream = upstream
        self.aes = aes
        self.block_size = block_size

    def write(self, data: bytes) -> int:
        if len(data) % self.block_size != 0:
            LOGGER.error(f'attempted to write {len(data)} bytes - not aligned to block size {self.block_size}')
            return 0

        encrypted = self.aes.encrypt(data)
        return self.upstream.write(encrypted)

    def drain(self):
        return self.upstream.drain()
