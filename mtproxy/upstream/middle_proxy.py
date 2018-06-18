import binascii
import time

import asyncio
import hashlib
import logging
import socket

from mtproxy.downstream.handshake import HandshakeResult
from mtproxy.mtproto.constants import RpcFlags
from mtproxy.utils import crypto
from mtproxy.utils.streams import LayeredStreamReaderBase, LayeredStreamWriterBase

CBC_PADDING = 16
PADDING_FILLER = b'\x04\x00\x00\x00'

MIN_MSG_LEN = 12
MAX_MSG_LEN = 2 ** 24

LOGGER = logging.getLogger('mtproxy.middle_proxy')


class MTProtoFrameStreamReader(LayeredStreamReaderBase):
    def __init__(self, upstream, seq_no=0):
        super().__init__(upstream)
        self.seq_no = seq_no

    async def read(self, buf_size=-1):
        msg_len_bytes = await self.upstream.readexactly(4)
        msg_len = int.from_bytes(msg_len_bytes, 'little')

        # skip padding
        while msg_len == 4:
            msg_len_bytes = await self.upstream.readexactly(4)
            msg_len = int.from_bytes(msg_len_bytes, 'little')

        len_is_bad = (msg_len % len(PADDING_FILLER) != 0)
        if not MIN_MSG_LEN <= msg_len <= MAX_MSG_LEN or len_is_bad:
            LOGGER.warning('msg_len is bad, closing connection', msg_len)
            return b''

        msg_seq_bytes = await self.upstream.readexactly(4)
        msg_seq = int.from_bytes(msg_seq_bytes, 'little', signed=True)
        if msg_seq != self.seq_no:
            LOGGER.warning('unexpected seq_no')
            return b''

        self.seq_no += 1

        data = await self.upstream.readexactly(msg_len - 4 - 4 - 4)
        checksum_bytes = await self.upstream.readexactly(4)
        checksum = int.from_bytes(checksum_bytes, 'little')

        computed_checksum = binascii.crc32(msg_len_bytes + msg_seq_bytes + data)
        if computed_checksum != checksum:
            return b''
        return data


class MTProtoFrameStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream, seq_no=0):
        super().__init__(upstream)
        self.seq_no = seq_no

    def write(self, msg):
        len_bytes = int.to_bytes(len(msg) + 4 + 4 + 4, 4, 'little')
        seq_bytes = int.to_bytes(self.seq_no, 4, 'little', signed=True)
        self.seq_no += 1

        msg_without_checksum = len_bytes + seq_bytes + msg
        checksum = int.to_bytes(binascii.crc32(msg_without_checksum), 4, 'little')

        full_msg = msg_without_checksum + checksum
        padding = PADDING_FILLER * ((-len(full_msg) % CBC_PADDING) // len(PADDING_FILLER))

        return self.upstream.write(full_msg + padding)


class ProxyReqStreamReader(LayeredStreamReaderBase):
    async def read(self, n=-1):
        RPC_PROXY_ANS = b'\x0d\xda\x03\x44'
        RPC_CLOSE_EXT = b'\xa2\x34\xb6\x5e'

        data = await self.upstream.read(1)

        if len(data) < 4:
            return b''

        ans_type, ans_flags, conn_id, conn_data = data[:4], data[4:8], data[8:16], data[16:]
        if ans_type == RPC_CLOSE_EXT:
            return b''

        if ans_type != RPC_PROXY_ANS:
            LOGGER.warning('ans_type != RPC_PROXY_ANS', ans_type)
            return b''

        return conn_data


def align(b, s):
    missing = s - (len(b) % s)
    return b + b'\x00' * missing


class ProxyReqStreamWriter(LayeredStreamWriterBase):
    def __init__(self, upstream, client_info, proxy_tag, my_ip, my_port):
        super().__init__(upstream)
        self.client_info = client_info
        self.proxy_tag = proxy_tag

        self.remote_ip_port = self._encode_ip_port(client_info.ip_address, client_info.port)
        self.our_ip_port = self._encode_ip_port(my_ip, my_port)

        self.out_conn_id = crypto.random_bytes(8)

    @staticmethod
    def _encode_ip_port(address, port):
        if ':' not in address:
            result = b'\x00' * 10 + b'\xff\xff'
            result += socket.inet_pton(socket.AF_INET, address)
        else:
            result = socket.inet_pton(socket.AF_INET6, address)
        result += int.to_bytes(port, 4, 'little')
        return result

    def write(self, msg):
        RPC_PROXY_REQ = b'\xee\xf1\xce\x36'
        PROXY_TAG = b'\xae\x26\x1e\xdb'

        if len(msg) % 4 != 0:
            LOGGER.warning('BUG: attempted to send msg with len %d' % len(msg))
            return 0

        flags = self.client_info.transport.HANDSHAKE_FLAGS | RpcFlags.MAGIC

        if self.proxy_tag:
            flags |= RpcFlags.HAS_AD_TAG

        if self.client_info.quick_ack_expected:
            flags |= RpcFlags.QUICKACK

        if msg[:7] == b'\x00' * 7:
            flags |= RpcFlags.NOT_ENCRYPTED

        flags = flags.value.to_bytes(4, 'little')

        full_msg = bytearray()
        full_msg += RPC_PROXY_REQ + flags + self.out_conn_id
        full_msg += self.remote_ip_port + self.our_ip_port

        if self.proxy_tag:
            proxy_tag_bytes = PROXY_TAG + len(self.proxy_tag).to_bytes(1, 'big') + self.proxy_tag
            proxy_tag_bytes_aligned = align(proxy_tag_bytes, 4)
            full_msg += len(proxy_tag_bytes_aligned).to_bytes(4, 'little') + proxy_tag_bytes_aligned

        full_msg += msg

        return self.upstream.write(full_msg)


def get_middleproxy_aes_key_and_iv(nonce_srv, nonce_clt, clt_ts, srv_ip, clt_port, purpose,
                                   clt_ip, srv_port, middleproxy_secret, clt_ipv6=None,
                                   srv_ipv6=None):
    EMPTY_IP = b'\x00\x00\x00\x00'

    if not clt_ip or not srv_ip:
        clt_ip = EMPTY_IP
        srv_ip = EMPTY_IP

    s = bytearray()
    s += nonce_srv + nonce_clt + clt_ts + srv_ip + clt_port + purpose + clt_ip + srv_port
    s += middleproxy_secret + nonce_srv

    if clt_ipv6 and srv_ipv6:
        s += clt_ipv6 + srv_ipv6

    s += nonce_clt

    md5_sum = hashlib.md5(s[1:]).digest()
    sha1_sum = hashlib.sha1(s).digest()

    key = md5_sum[:12] + sha1_sum
    iv = hashlib.md5(s[2:]).digest()
    return key, iv


async def connect(proxy: 'MTProxy', client_handshake_result: HandshakeResult):
    START_SEQ_NO = -2
    NONCE_LEN = 16

    RPC_NONCE = b'\xaa\x87\xcb\x7a'
    RPC_HANDSHAKE = b'\xf5\xee\x82\x76'
    CRYPTO_AES = b'\x01\x00\x00\x00'

    RPC_NONCE_ANS_LEN = 32
    RPC_HANDSHAKE_ANS_LEN = 32

    # pass as consts to simplify code
    RPC_FLAGS = b'\x00\x00\x00\x00'

    use_ipv6_tg = False

    if use_ipv6_tg:
        addr, port = proxy.config_updater.pick_proxy_v6(client_handshake_result.dc_id)
    else:
        addr, port = proxy.config_updater.pick_proxy_v4(client_handshake_result.dc_id)

    try:
        reader_tgt, writer_tgt = await asyncio.open_connection(addr, port, limit=proxy.buffer_read)
        proxy.setup_socket(writer_tgt.get_extra_info('socket'))
    except ConnectionRefusedError:
        LOGGER.exception(f'Got connection refused while trying to connect to {addr}:{port}')
        return False
    except OSError:
        LOGGER.exception(f'Unable to connect to {addr}:{port}')
        return False

    writer_tgt = MTProtoFrameStreamWriter(writer_tgt, START_SEQ_NO)

    key_selector = proxy.config_updater.proxy_secret[:4]
    crypto_ts = int.to_bytes(int(time.time()) % (256 ** 4), 4, 'little')

    nonce = crypto.random_bytes(NONCE_LEN)

    msg = RPC_NONCE + key_selector + CRYPTO_AES + crypto_ts + nonce

    writer_tgt.write(msg)
    await writer_tgt.drain()

    reader_tgt = MTProtoFrameStreamReader(reader_tgt, START_SEQ_NO)
    ans = await reader_tgt.read(proxy.buffer_read)

    if len(ans) != RPC_NONCE_ANS_LEN:
        return False

    rpc_type, rpc_key_selector, rpc_schema, rpc_crypto_ts, rpc_nonce = (
        ans[:4], ans[4:8], ans[8:12], ans[12:16], ans[16:32]
    )

    if rpc_type != RPC_NONCE or rpc_key_selector != key_selector or rpc_schema != CRYPTO_AES:
        return False

    # get keys
    tg_ip, tg_port = writer_tgt.upstream.get_extra_info('peername')[:2]
    my_ip, my_port = writer_tgt.upstream.get_extra_info('sockname')[:2]

    my_ipv4, my_ipv6 = proxy.ip_info
    if not use_ipv6_tg:
        if my_ipv4:
            # prefer global ip settings to work behind NAT
            my_ip = my_ipv4

        tg_ip_bytes = socket.inet_pton(socket.AF_INET, tg_ip)[::-1]
        my_ip_bytes = socket.inet_pton(socket.AF_INET, my_ip)[::-1]

        tg_ipv6_bytes = None
        my_ipv6_bytes = None
    else:
        if my_ipv6:
            my_ip = my_ipv6

        tg_ip_bytes = None
        my_ip_bytes = None

        tg_ipv6_bytes = socket.inet_pton(socket.AF_INET6, tg_ip)
        my_ipv6_bytes = socket.inet_pton(socket.AF_INET6, my_ip)

    tg_port_bytes = int.to_bytes(tg_port, 2, 'little')
    my_port_bytes = int.to_bytes(my_port, 2, 'little')

    enc_key, enc_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b'CLIENT', clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=proxy.config_updater.proxy_secret, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    dec_key, dec_iv = get_middleproxy_aes_key_and_iv(
        nonce_srv=rpc_nonce, nonce_clt=nonce, clt_ts=crypto_ts, srv_ip=tg_ip_bytes,
        clt_port=my_port_bytes, purpose=b'SERVER', clt_ip=my_ip_bytes, srv_port=tg_port_bytes,
        middleproxy_secret=proxy.config_updater.proxy_secret, clt_ipv6=my_ipv6_bytes, srv_ipv6=tg_ipv6_bytes)

    aes_enc = crypto.init_aes_cbc(key=enc_key, iv=enc_iv)
    aes_dec = crypto.init_aes_cbc(key=dec_key, iv=dec_iv)

    SENDER_PID = b'IPIPPRPDTIME'
    PEER_PID = b'IPIPPRPDTIME'

    # TODO: pass client ip and port here for statistics
    handshake = RPC_HANDSHAKE + RPC_FLAGS + SENDER_PID + PEER_PID

    writer_tgt.upstream = crypto.AESWriter(writer_tgt.upstream, aes=aes_enc, block_size=16)
    writer_tgt.write(handshake)
    await writer_tgt.drain()

    reader_tgt.upstream = crypto.AESReader(reader_tgt.upstream, aes=aes_dec, block_size=16)

    handshake_ans = await reader_tgt.read(1)
    if len(handshake_ans) != RPC_HANDSHAKE_ANS_LEN:
        return False

    handshake_type, handshake_flags, handshake_sender_pid, handshake_peer_pid = (
        handshake_ans[:4], handshake_ans[4:8], handshake_ans[8:20], handshake_ans[20:32])
    if handshake_type != RPC_HANDSHAKE or handshake_peer_pid != SENDER_PID:
        return False

    writer_tgt = ProxyReqStreamWriter(writer_tgt, client_handshake_result.client_info, proxy.proxy_tag, my_ip, my_port)
    reader_tgt = ProxyReqStreamReader(reader_tgt)

    return reader_tgt, writer_tgt
