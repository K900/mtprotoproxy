import asyncio

import logging
import socket
from contextlib import suppress

LOGGER = logging.getLogger('mtproxy.utils.misc')

HOUR = 24 * 60 * 60

HANDSHAKE_HEADER_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
PROTO_TAG_POS = 56
DC_ID_POS = 60


def set_keepalive(
        sock: socket.socket,
        interval: int,
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
        recv_buf: int,
        send_buf: int
):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buf)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buf)


def setup_limits():
    try:
        import resource

        soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
    except (ValueError, OSError):
        LOGGER.exception("Failed to increase RLIMIT_NOFILE - this shouldn't be an issue "
                         "unless you have thousands of connections")
    except ImportError:
        LOGGER.debug('Resource limits are not supported on this platform - ignoring')


async def cancel_infinite(task: asyncio.Task):
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
