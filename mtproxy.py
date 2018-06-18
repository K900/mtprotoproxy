#!/usr/bin/env python3

import asyncio
import click
import coloredlogs
import logging
from typing import *

from mtproxy.proxy import MTProxy

LOGGER = logging.getLogger('mtproxy')


def try_setup_limits():
    try:
        import resource

        soft_fd_limit, hard_fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard_fd_limit, hard_fd_limit))
    except (ValueError, OSError):
        LOGGER.exception("Failed to increase RLIMIT_NOFILE - this shouldn't be an issue "
                         "unless you have thousands of connections")
    except ImportError:
        LOGGER.debug('Resource limits are not supported on this platform - ignoring')


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

    LOGGER.info('Starting upstream...')

    try_setup_limits()

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
