import aiohttp

from typing import *


async def _get_ip_info_one(session: aiohttp.ClientSession, mode: str) -> Optional[str]:
    try:
        response = await session.get(f'https://{mode}.ifconfig.co/ip')
        text = await response.text()
        return text
    except aiohttp.ClientError:
        return None


async def get_ip_info() -> Tuple[Optional[str], Optional[str]]:
    async with aiohttp.ClientSession() as session:
        ipv4 = await _get_ip_info_one(session, 'v4')
        ipv6 = await _get_ip_info_one(session, 'v6')
        return ipv4, ipv6
