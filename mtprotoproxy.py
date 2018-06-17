#!/usr/bin/env python3

import asyncio
import collections
import logging
import socket
import sys
import time
import urllib.parse
import urllib.request

from mtproxy import handshake
from mtproxy.handshake import ClientInfo
from mtproxy.proxy import direct
from mtproxy.stat_tracker import tracker
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase
from mtproxy.util import setup_socket

LOGGER = logging.getLogger('mtproxy')

try:
    import resource

    soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
except (ValueError, OSError):
    print("Failed to increase the limit of opened files", flush=True, file=sys.stderr)
except ImportError:
    pass

import config

PORT = getattr(config, "PORT")
USERS = getattr(config, "USERS")

# load advanced settings
PREFER_IPV6 = getattr(config, "PREFER_IPV6", socket.has_ipv6)
# disables tg->client trafic reencryption, faster but less secure
FAST_MODE = getattr(config, "FAST_MODE", True)
STATS_PRINT_PERIOD = getattr(config, "STATS_PRINT_PERIOD", 600)
PROXY_INFO_UPDATE_PERIOD = getattr(config, "PROXY_INFO_UPDATE_PERIOD", 60 * 60 * 24)
READ_BUF_SIZE = config.get('buffer_read')
WRITE_BUF_SIZE = config.get('buffer_write')
AD_TAG = bytes.fromhex(config.get('ad_tag'))

USE_MIDDLE_PROXY = (len(AD_TAG) == 16)

my_ip_info = {"ipv4": None, "ipv6": None}


def print_err(*params):
    print(*params, file=sys.stderr, flush=True)


async def pump(
        reader: LayeredStreamReaderBase,
        writer: LayeredStreamWriterBase,
        client_info: ClientInfo
):
    tracker.track_pump_start(client_info)

    while True:
        data = await reader.read(READ_BUF_SIZE)
        if not data:
            writer.write_eof()
            await writer.drain()
            writer.close()
            break
        else:
            tracker.track_data_transferred(client_info, len(data))
            writer.write(data)
            await writer.drain()

    writer.transport.abort()

    tracker.track_pump_end(client_info)


async def handle_client(client_read, client_write):
    setup_socket(client_write.get_extra_info("socket"))

    result = await handshake.handle_handshake(client_read, client_write, secrets=USERS, fast=FAST_MODE)
    reader_tg, writer_tg = await direct.connect(result, fast=FAST_MODE)

    tracker.track_connected(result.client_info)

    # if not USE_MIDDLE_PROXY:
    # else:
    #     flags = RpcFlags.EXTMODE2
    #     if proto_tag == PROTO_TAG_ABRIDGED:
    #         flags |= RpcFlags.PROTOCOL_ABRIDGED
    #     elif proto_tag == PROTO_TAG_INTERMEDIATE:
    #         flags |= RpcFlags.PROTOCOL_INTERMEDIATE
    #
    #     tg_data = await do_middleproxy_handshake(peer, flags, dc_idx)

    # if USE_MIDDLE_PROXY:
    #     if proto_tag == PROTO_TAG_ABRIDGED:
    #         reader_clt = MTProtoCompactFrameStreamReader(reader_clt, peer)
    #         writer_clt = MTProtoCompactFrameStreamWriter(writer_clt)
    #     elif proto_tag == PROTO_TAG_INTERMEDIATE:
    #         reader_clt = MTProtoIntermediateFrameStreamReader(reader_clt, peer)
    #         writer_clt = MTProtoIntermediateFrameStreamWriter(writer_clt)

    asyncio.ensure_future(pump(reader_tg, result.write_stream, result.client_info))
    asyncio.ensure_future(pump(result.read_stream, writer_tg, result.client_info))


async def handle_client_wrapper(reader, writer):
    try:
        await handle_client(reader, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError, TimeoutError, OSError):
        peer = writer.get_extra_info('peername')
        LOGGER.exception(f'Client {peer} failed to connect!')
        writer.transport.abort()


def init_ip_info():
    global USE_MIDDLE_PROXY
    global PREFER_IPV6
    global my_ip_info
    TIMEOUT = 5

    try:
        with urllib.request.urlopen('https://v4.ifconfig.co/ip', timeout=TIMEOUT) as f:
            if f.status != 200:
                raise Exception("Invalid status code")
            my_ip_info["ipv4"] = f.read().decode().strip()
    except Exception:
        pass

    if PREFER_IPV6:
        try:
            with urllib.request.urlopen('https://v6.ifconfig.co/ip', timeout=TIMEOUT) as f:
                if f.status != 200:
                    raise Exception("Invalid status code")
                my_ip_info["ipv6"] = f.read().decode().strip()
        except Exception:
            PREFER_IPV6 = False
        else:
            print_err("IPv6 found, using it for external communication")

    if USE_MIDDLE_PROXY:
        if ((not PREFER_IPV6 and not my_ip_info["ipv4"]) or
                (PREFER_IPV6 and not my_ip_info["ipv6"])):
            print_err("Failed to determine your ip, advertising disabled")
            USE_MIDDLE_PROXY = False


def loop_exception_handler(loop, context):
    exception = context.get("exception")
    transport = context.get("transport")
    if exception:
        if isinstance(exception, TimeoutError):
            if transport:
                print_err("Timeout, killing transport")
                transport.abort()
                return
        if isinstance(exception, OSError):
            IGNORE_ERRNO = {
                10038  # operation on non-socket on Windows, likely because fd == -1
            }
            if exception.errno in IGNORE_ERRNO:
                return

    loop.default_exception_handler(context)


def main():
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    loop = asyncio.get_event_loop()
    loop.set_exception_handler(loop_exception_handler)

    stats_printer_task = asyncio.Task(tracker.log_loop())
    asyncio.ensure_future(stats_printer_task)

    # if USE_MIDDLE_PROXY:
    #     middle_proxy_updater_task = asyncio.Task(update_middle_proxy_info())
    #     asyncio.ensure_future(middle_proxy_updater_task)

    task_v4 = asyncio.start_server(handle_client_wrapper,
                                   '0.0.0.0', PORT, limit=READ_BUF_SIZE, loop=loop)
    server_v4 = loop.run_until_complete(task_v4)

    if socket.has_ipv6:
        task_v6 = asyncio.start_server(handle_client_wrapper,
                                       '::', PORT, limit=READ_BUF_SIZE, loop=loop)
        server_v6 = loop.run_until_complete(task_v6)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server_v4.close()
    loop.run_until_complete(server_v4.wait_closed())

    if socket.has_ipv6:
        server_v6.close()
        loop.run_until_complete(server_v6.wait_closed())

    loop.close()


if __name__ == "__main__":
    init_ip_info()
    main()
