import asyncio
import logging
import socket
from contextlib import suppress
from enum import Enum
from typing import *

from mtproxy.downstream import handshake
from mtproxy.tasks import config_updater, ip_getter, stat_tracker
from mtproxy.upstream import direct, middle_proxy

LOGGER = logging.getLogger('mtproxy.upstream')


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

        if self.mode == MTProxy.Mode.MIDDLE_PROXY:
            LOGGER.debug('Trying to get our IP address...')
            self.ip_info = ip_getter.get_ip_info_sync()

            if self.ip_info == (None, None):
                LOGGER.warning('Failed to discover our external IP address, disabling MIDDLE_PROXY mode...')
                self.mode = MTProxy.Mode.DIRECT_FAST

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

    @staticmethod
    async def _cancel_infinite(task: asyncio.Task):
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    def _stop_pumps(self):
        LOGGER.debug('Shutting down pump workers...')

        for task in self.pump_tasks:
            self.loop.run_until_complete(self._cancel_infinite(task))

    def _stop_auxiliary(self):
        LOGGER.debug('Shutting down auxiliary tasks...')

        for task in self.aux_tasks:
            self.loop.run_until_complete(self._cancel_infinite(task))

    def stop(self):
        self._stop_servers()
        self._stop_pumps()
        self._stop_auxiliary()
        self.loop.close()

    def setup_socket(self, sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, self.keepalive_timeout)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.keepalive_timeout)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_read)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.buffer_write)

    def start_worker(self, coro):
        task = asyncio.Task(coro)
        self.pump_tasks.add(task)
        asyncio.ensure_future(task, loop=self.loop)

    async def handle_client(self, client_read, client_write):
        self.setup_socket(client_write.get_extra_info("socket"))

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
            tg_read, tg_write = await direct.connect(result, fast=use_fast_mode)
            client_read = result.read_stream
            client_write = result.write_stream

            async def pump(reader, writer):
                while True:
                    data = await reader.read(self.buffer_read)
                    if not data:
                        writer.write_eof()
                        await writer.drain()
                        writer.close()
                        break

                    writer.write(data)
                    await writer.drain()

                writer.transport.abort()

            self.start_worker(pump(client_read, tg_write))
            self.start_worker(pump(tg_read, client_write))
        elif self.mode == MTProxy.Mode.MIDDLE_PROXY:
            proxy_reader, proxy_writer = await middle_proxy.connect(self, result)

            logging.debug('middle proxy handshake ok')

            async def pump_middle_proxy_up():
                while True:
                    message = await result.client_info.transport.read_message(result.read_stream)
                    logging.debug(f'got client request {message}')

                    if not message:
                        proxy_writer.write_stream.write_eof()
                        await proxy_writer.write_stream.drain()
                        proxy_writer.write_stream.close()
                        break

                    proxy_writer.write_proxy_request(message)
                    await proxy_writer.write_stream.drain()

            async def pump_middle_proxy_down():
                while True:
                    response = await proxy_reader.read_proxy_response()
                    logging.debug(f'got proxy response {response}')

                    if not response:
                        result.write_stream.write_eof()
                        await result.write_stream.drain()
                        result.write_stream.close()
                        break

                    result.client_info.transport.write_response(result.write_stream, response)
                    await result.write_stream.drain()

            self.start_worker(pump_middle_proxy_up())
            self.start_worker(pump_middle_proxy_down())
        else:
            raise ValueError(f'Unknown mode: {self.mode}')

        self.stat_tracker.track_connected(result.client_info)
