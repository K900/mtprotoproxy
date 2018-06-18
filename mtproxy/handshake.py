import binascii

import asyncio
import dataclasses
import logging
from typing import Dict

from mtproxy import crypto
from mtproxy.mtproto import transports
from mtproxy.mtproto.transports import AbstractTransport
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase
from mtproxy.utils.misc import DC_ID_POS, HANDSHAKE_LEN, PROTO_TAG_POS

LOGGER = logging.getLogger('mtproxy.handshake')


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


class HandshakeError(OSError):
    pass


async def handle_handshake(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        secrets: Dict[str, bytes],
        fast: bool = False
) -> HandshakeResult:
    handshake = await reader.readexactly(HANDSHAKE_LEN)
    peer = writer.get_extra_info('peername')

    for username, secret in secrets.items():
        dec_prekey_and_iv = crypto.key_iv_from_handshake(handshake)
        dec_prekey, dec_iv = crypto.parse_key_iv(dec_prekey_and_iv)
        dec_key = crypto.derive_key(dec_prekey, secret)
        dec_aes = crypto.init_aes_ctr(key=dec_key, iv=dec_iv)

        decrypted = dec_aes.decrypt(handshake)

        proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
        transport = transports.get_transport_by_tag(proto_tag)
        if transport is None:
            LOGGER.warning(f'Received unsupported protocol tag: {binascii.hexlify(proto_tag)}, maybe wrong secret?')
            continue

        dc_id = int.from_bytes(decrypted[DC_ID_POS:DC_ID_POS + 2], 'little', signed=True)

        client_info = ClientInfo(
            transport=transport,
            proxy_username=username,
            ip_address=peer[0],
            port=peer[1],
        )

        enc_prekey, enc_iv = crypto.parse_key_iv(dec_prekey_and_iv[::-1])
        enc_key = crypto.derive_key(enc_prekey, secret)

        if fast:
            writer = writer
        else:
            enc_aes = crypto.init_aes_ctr(key=enc_key, iv=enc_iv)
            writer = crypto.AESWriter(writer, enc_aes)
            # no need to keep those any more than necessary
            enc_key = None
            enc_iv = None

        handshake_result = HandshakeResult(
            client_info=client_info,
            dc_id=dc_id,
            read_stream=crypto.AESReader(reader, dec_aes),
            write_stream=writer,
            enc_key=enc_key,
            enc_iv=enc_iv
        )

        return handshake_result

    raise HandshakeError(f'Client failed to pass handshake, maybe unsupported protocol or wrong secret?')
