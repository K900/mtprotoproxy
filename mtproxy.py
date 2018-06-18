#!/usr/bin/env python3

import asyncio
import click
import coloredlogs
import logging
from enum import Enum
from typing import *

from mtproxy import handshake
from mtproxy.handshake import ClientInfo
from mtproxy.proxy import direct
from mtproxy.streams import LayeredStreamReaderBase, LayeredStreamWriterBase
from mtproxy.utils import config_updater, misc as umisc, stat_tracker

LOGGER = logging.getLogger('mtproxy')


class MTProxy:
    class Mode(Enum):
        MIDDLE_PROXY = 'middle_proxy'
        DIRECT_FAST = 'direct_fast'
        DIRECT_SAFE = 'direct_safe'

    def __init__(
            self,
            loop: asyncio.AbstractEventLoop,
            listen: Tuple[Tuple[str, int]],
            secrets: Tuple[Tuple[str, str]],
            mode: 'MTProxy.Mode',
            proxy_tag: str,
            buffer_read: int,
            buffer_write: int,
            keepalive_timeout: int,
            stat_tracker_timeout: int,
            proxy_config_update_timeout: int
    ):
        self.loop = loop
        self.listen = listen
        self.secrets = self._convert_secrets(secrets)
        self.mode = mode
        self.proxy_tag = self._convert_and_check_length(proxy_tag)
        self.buffer_read = buffer_read
        self.buffer_write = buffer_write
        self.keepalive_timeout = keepalive_timeout

        self.stat_tracker = stat_tracker.StatTracker(stat_tracker_timeout)
        self.config_updater = config_updater.ProxyConfigUpdater(proxy_config_update_timeout)

        self.servers = {}
        self.aux_tasks = set()
        self.pump_tasks = set()

    @staticmethod
    def _convert_and_check_length(hex_str: Optional[str]) -> Optional[bytes]:
        if hex_str is None:
            return None

        data = bytes.fromhex(hex_str)

        if len(data) != 16:
            raise ValueError('Secret length must be exactly 16 bytes!')

        return data

    @staticmethod
    def _convert_secrets(secrets: Tuple[Tuple[str, str]]) -> Dict[str, bytes]:
        new_secrets = {}
        for name, secret in secrets:
            new_secrets[name] = MTProxy._convert_and_check_length(secret)
        return new_secrets

    def _start_servers(self):
        LOGGER.debug('Starting servers...')

        for conf in self.listen:
            host, port = conf

            LOGGER.debug(f'Starting server for {host}:{port}...')
            self.servers[conf] = self._start_server(host, port)

    def _start_server(self, host, port):
        async def wrapper(reader, writer):
            try:
                await self.handle_client(reader, writer)
            except (asyncio.IncompleteReadError, ConnectionResetError, TimeoutError, OSError):
                peer = writer.get_extra_info('peername')
                LOGGER.exception(f'Client {peer} failed to connect!')
                writer.transport.abort()

        LOGGER.debug(f'Starting server on {host}:{port}...')

        task = asyncio.start_server(
            client_connected_cb=wrapper,
            host=host,
            port=port,
            limit=self.buffer_read,
            loop=self.loop
        )
        return self.loop.run_until_complete(task)

    def _start_auxiliary(self):
        LOGGER.debug('Starting auxiliary tasks...')

        LOGGER.debug('Starting stat logger...')

        stats_printer_task = asyncio.Task(self.stat_tracker.log_loop())
        asyncio.ensure_future(stats_printer_task)
        self.aux_tasks.add(stats_printer_task)

        if self.mode == MTProxy.Mode.MIDDLE_PROXY:
            LOGGER.debug('Starting config updater...')

            middle_proxy_updater_task = asyncio.Task(self.config_updater.update_loop())
            asyncio.ensure_future(middle_proxy_updater_task)
            self.aux_tasks.add(middle_proxy_updater_task)

    def start(self):
        self._start_servers()
        self._start_auxiliary()

    def _stop_servers(self):
        LOGGER.debug('Shutting down servers...')

        for conf, server in self.servers.items():
            host, port = conf
            LOGGER.debug(f'Shutting down server for {host}:{port}...')
            server.close()
            self.loop.run_until_complete(server.wait_closed())

    def _stop_pumps(self):
        LOGGER.debug('Shutting down pump workers...')

        for task in self.pump_tasks:
            self.loop.run_until_complete(umisc.cancel_infinite(task))

    def _stop_auxiliary(self):
        LOGGER.debug('Shutting down auxiliary tasks...')

        for task in self.aux_tasks:
            self.loop.run_until_complete(umisc.cancel_infinite(task))

    def stop(self):
        self._stop_servers()
        self._stop_pumps()
        self._stop_auxiliary()
        self.loop.close()

    def _setup_socket(self, sock):
        umisc.set_bufsizes(sock, self.buffer_read, self.buffer_write)
        umisc.set_keepalive(sock, self.keepalive_timeout)

    async def pump(
            self,
            reader: LayeredStreamReaderBase,
            writer: LayeredStreamWriterBase,
            client_info: ClientInfo
    ):
        self.stat_tracker.track_pump_start(client_info)

        while True:
            data = await reader.read(self.buffer_read)
            if not data:
                writer.write_eof()
                await writer.drain()
                writer.close()
                break
            else:
                self.stat_tracker.track_data_transferred(client_info, len(data))
                writer.write(data)
                await writer.drain()

        writer.transport.abort()

        self.stat_tracker.track_pump_end(client_info)

    async def handle_client(self, client_read, client_write):
        self._setup_socket(client_write.get_extra_info("socket"))

        use_fast_mode = (self.mode == MTProxy.Mode.DIRECT_FAST)

        result = await handshake.handle_handshake(
            reader=client_read,
            writer=client_write,
            secrets=self.secrets,
            fast=use_fast_mode
        )

        if self.mode in (
            MTProxy.Mode.DIRECT_FAST,
            MTProxy.Mode.DIRECT_SAFE
        ):
            reader_tg, writer_tg = await direct.connect(result, fast=use_fast_mode)
        else:
            raise NotImplemented

        self.stat_tracker.track_connected(result.client_info)

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

        pump_in = asyncio.Task(self.pump(reader_tg, result.write_stream, result.client_info))
        pump_out = asyncio.Task(self.pump(result.read_stream, writer_tg, result.client_info))

        self.pump_tasks.add(pump_in)
        self.pump_tasks.add(pump_out)

        asyncio.ensure_future(pump_in, loop=self.loop)
        asyncio.ensure_future(pump_out, loop=self.loop)


@click.command('mtproxy')
@click.option('--listen', '-l', multiple=True, type=(str, int), default=[('::', 3256), ('0.0.0.0', 3256)])
@click.option('--secret', '-s', multiple=True, type=(str, str), required=True)
@click.option('--mode', '-m', type=click.Choice(m.name for m in MTProxy.Mode))
@click.option('--proxy-tag', '-t', type=str)
@click.option('--buffer-read', type=int, default=16384)
@click.option('--buffer-write', type=int, default=65536)
@click.option('--keepalive-timeout', type=int, default=40)
@click.option('--stat-tracker-timeout', type=int, default=60)
@click.option('--proxy-config-update-timeout', type=int, default=60 * 60)
def main(
        listen: Tuple[Tuple[str, int]],
        secret: Tuple[Tuple[str, str]],
        mode: str,
        proxy_tag: str,
        buffer_read: int,
        buffer_write: int,
        keepalive_timeout: int,
        stat_tracker_timeout: int,
        proxy_config_update_timeout: int
):
    coloredlogs.install(level=logging.DEBUG)

    if mode is None:
        if proxy_tag:
            LOGGER.debug('proxy_tag is set, mode is not set, assuming middle_proxy')
            mode = MTProxy.Mode.MIDDLE_PROXY
        else:
            LOGGER.debug('mode is not set, proxy_tag is not set, assuming direct_fast')
            mode = MTProxy.Mode.DIRECT_FAST
    else:
        mode = MTProxy.Mode[mode]

    LOGGER.info('Starting proxy...')

    umisc.setup_limits()

    LOGGER.debug('Starting server...')

    proxy = MTProxy(
        loop=asyncio.get_event_loop(),
        listen=listen,
        secrets=secret,
        mode=mode,
        proxy_tag=proxy_tag,
        buffer_read=buffer_read,
        buffer_write=buffer_write,
        keepalive_timeout=keepalive_timeout,
        stat_tracker_timeout=stat_tracker_timeout,
        proxy_config_update_timeout=proxy_config_update_timeout
    )

    proxy.start()

    LOGGER.info('Proxy is ready!')

    try:
        proxy.loop.run_forever()
    except KeyboardInterrupt:
        pass

    LOGGER.info('Shutting down...')
    proxy.stop()
    LOGGER.info('Goodbye!')


if __name__ == "__main__":
    main()
