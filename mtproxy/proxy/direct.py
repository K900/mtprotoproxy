import asyncio
import logging
import random

from mtproxy import crypto
from mtproxy.handshake import HandshakeResult
from mtproxy.utils.misc import HANDSHAKE_LEN, PROTO_TAG_POS, HANDSHAKE_HEADER_LEN, KEY_LEN, IV_LEN

LOGGER = logging.getLogger('mtproxy.direct')

RESERVED_NONCE_FIRST_CHARS = [b'\xef']
RESERVED_NONCE_BEGINNINGS = [b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54',
                             b'\x47\x45\x54\x20', b'\xee\xee\xee\xee']
RESERVED_NONCE_CONTINUES = [b'\x00\x00\x00\x00']

TG_DATA_CENTERS_V4 = {
    1: '149.154.175.50',
    -1: '149.154.175.50',
    2: '149.154.167.51',
    -2: '149.154.167.51',
    3: '149.154.175.100',
    -3: '149.154.175.100',
    4: '149.154.167.91',
    -4: '149.154.167.91',
    5: '149.154.171.5',
    -5: '149.154.171.5'
}

TG_DATA_CENTERS_V6 = {
    1: '2001:b28:f23d:f001::a',
    -1: '2001:b28:f23d:f001::a',
    2: '2001:67c:04e8:f002::a',
    -2: '2001:67c:04e8:f002::a',
    3: '2001:b28:f23d:f003::a',
    -3: '2001:b28:f23d:f003::a',
    4: '2001:67c:04e8:f004::a',
    -4: '2001:67c:04e8:f004::a',
    5: '2001:b28:f23f:f005::a',
    -5: '2001:b28:f23f:f005::a'
}

TG_DATA_CENTER_PORT = 443


async def _try_connect(dc):
    try:
        result = await asyncio.open_connection(dc, TG_DATA_CENTER_PORT, limit=16384)
        LOGGER.info(f'Successfully connected to upstream server {dc}!')
        return result
    except ConnectionRefusedError:
        LOGGER.exception(f'Upstream server {dc} refused connection')
    except OSError:
        LOGGER.exception(f'Failed to connect to upstream server {dc}')


async def _try_connect_by_id(dc_id):
    LOGGER.debug(f'Attempting to connect to upstream dc_id={dc_id}')

    result = await _try_connect(TG_DATA_CENTERS_V6[dc_id])
    if result:
        return result

    LOGGER.error(f'Failed to connect to upstream dc_id={dc_id} over IPv6, trying IPv4...')
    result = await _try_connect(TG_DATA_CENTERS_V4[dc_id])
    if result:
        return result

    LOGGER.error(f'Failed to connect to upstream dc_id={dc_id} over IPv4, we die now')
    raise OSError(f'Unable to connect to dc_id={dc_id}')


async def connect(handshake_result: HandshakeResult, fast: bool = False):
    reader_tgt, writer_tgt = await _try_connect_by_id(handshake_result.dc_id)

    while True:
        handshake = bytearray([random.randrange(0, 256) for _ in range(HANDSHAKE_LEN)])
        if handshake[:1] in RESERVED_NONCE_FIRST_CHARS:
            continue
        if handshake[:4] in RESERVED_NONCE_BEGINNINGS:
            continue
        if handshake[4:8] in RESERVED_NONCE_CONTINUES:
            continue
        break

    handshake[PROTO_TAG_POS:PROTO_TAG_POS + 4] = handshake_result.client_info.transport.PROTO_TAG

    if fast:
        key_and_iv = handshake_result.enc_key + handshake_result.enc_iv.to_bytes(16, 'big')
        handshake[HANDSHAKE_HEADER_LEN:HANDSHAKE_HEADER_LEN + KEY_LEN + IV_LEN] = key_and_iv[::-1]

    handshake = bytes(handshake)

    enc_key_and_iv = crypto.key_iv_from_handshake(handshake)
    enc_key, enc_iv = crypto.parse_key_iv(enc_key_and_iv)
    aes_enc = crypto.init_aes_ctr(key=enc_key, iv=enc_iv)

    rnd_enc = handshake[:PROTO_TAG_POS] + aes_enc.encrypt(handshake)[PROTO_TAG_POS:]

    writer_tgt.write(rnd_enc)
    await writer_tgt.drain()

    writer_tgt = crypto.AESWriter(writer_tgt, aes=aes_enc)

    if not fast:
        dec_key, dec_iv = crypto.parse_key_iv(enc_key_and_iv[::-1])
        aes_dec = crypto.init_aes_ctr(key=dec_key, iv=dec_iv)
        reader_tgt = crypto.AESReader(reader_tgt, aes=aes_dec)

    return reader_tgt, writer_tgt
