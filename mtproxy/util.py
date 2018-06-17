import enum
import socket

import config

HOUR = 24 * 60 * 60

HANDSHAKE_HEADER_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
PROTO_TAG_POS = 56
DC_ID_POS = 60


class RpcFlags(enum.Flag):
    NONE = 0x0
    NOT_ENCRYPTED = 0x2
    HAS_AD_TAG = 0x8
    MAGIC = 0x1000
    EXTMODE2 = 0x20000
    PROTOCOL_INTERMEDIATE = 0x20000000
    PROTOCOL_ABRIDGED = 0x40000000
    QUICKACK = 0x80000000


def set_keepalive(
        sock: socket.socket,
        interval: int = config.get('client_keepalive'),
        attempts: int = 5
):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, interval)
    if hasattr(socket, "TCP_KEEPINTVL"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
    if hasattr(socket, "TCP_KEEPCNT"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, attempts)


def set_bufsizes(
        sock: socket.socket,
        recv_buf: int = config.get('buffer_read'),
        send_buf: int = config.get('buffer_write')
):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buf)


def setup_socket(sock: socket.socket):
    set_keepalive(sock)
    set_bufsizes(sock)
