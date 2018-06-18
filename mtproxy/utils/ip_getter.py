import asyncio

import aiohttp
import logging

from typing import *

LOGGER = logging.getLogger('mtproxy.ip_getter')


async def _get_ip_info_one(session: aiohttp.ClientSession, mode: str) -> Optional[str]:
    try:
        response = await session.get(f'https://{mode}.ifconfig.co/ip')
        text = await response.text()
        return text.strip()
    except aiohttp.ClientError:
        return None


async def get_ip_info() -> Tuple[Optional[str], Optional[str]]:
    async with aiohttp.ClientSession() as session:
        ipv4 = await _get_ip_info_one(session, 'v4')
        ipv6 = await _get_ip_info_one(session, 'v6')
        LOGGER.info(f'Discovered our external IPv4: {ipv4}, IPv6: {ipv6}')
        return ipv4, ipv6


def get_ip_info_sync() -> Tuple[Optional[str], Optional[str]]:
    return asyncio.get_event_loop().run_until_complete(get_ip_info())
