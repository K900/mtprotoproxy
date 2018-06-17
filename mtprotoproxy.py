#!/usr/bin/env python3

import asyncio
import logging
import socket
import sys

from mtproxy import handshake, config
from mtproxy.handshake import ClientInfo
from mtproxy.proxy import direct
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase
from mtproxy.utils import misc as umisc
from mtproxy.utils.stat_tracker import tracker

LOGGER = logging.getLogger('mtproxy')

PORT = config.get('port')
SECRETS = config.get('secrets')

FAST_MODE = config.get('fast_mode')
READ_BUF_SIZE = config.get('buffer_read')

AD_TAG = config.get('ad_tag')
if AD_TAG:
    AD_TAG = bytes.fromhex(AD_TAG)

USE_MIDDLE_PROXY = config.get('middle_proxy')

if AD_TAG and not USE_MIDDLE_PROXY:
    LOGGER.warning('ad_tag is set, but use middle_proxy is disabled - enabling automatically')
    USE_MIDDLE_PROXY = True

if USE_MIDDLE_PROXY and FAST_MODE:
    LOGGER.warning('middle proxy is incompatible with fast mode - disabling fast mode')
    FAST_MODE = False

my_ip_info = {"ipv4": None, "ipv6": None}


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
    umisc.setup_socket(client_write.get_extra_info("socket"))

    result = await handshake.handle_handshake(client_read, client_write, secrets=SECRETS, fast=FAST_MODE)
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


def loop_exception_handler(loop, context):
    exception = context.get("exception")
    transport = context.get("transport")
    if exception:
        if isinstance(exception, TimeoutError):
            if transport:
                logging.exception("Timeout, killing transport")
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

    umisc.setup_limits()

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
    main()
