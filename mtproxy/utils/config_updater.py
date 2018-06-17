import asyncio
import logging
from collections import defaultdict
from typing import *

import aiohttp

from mtproxy.utils.util import HOUR

LOGGER = logging.getLogger('mtproxy.proxy_config')

API_BASE_URL = 'https://core.telegram.org/'
PROXY_CONFIG_URL_V6 = 'https://core.telegram.org/getProxyConfigV6'
PROXY_SECRET_URL = 'https://core.telegram.org/getProxySecret'

DEFAULT_PROXIES_V4 = {
    1: ('149.154.175.50', 8888),
    -1: ('149.154.175.50', 8888),
    2: ('149.154.162.38', 80),
    -2: ('149.154.162.38', 80),
    3: ('149.154.175.100', 8888),
    -3: ('149.154.175.100', 8888),
    4: ('91.108.4.136', 8888),
    -4: ('91.108.4.136', 8888),
    5: ('91.108.56.181', 8888),
    -5: ('91.108.56.181', 8888)
}

DEFAULT_PROXIES_V6 = {
    1: ('2001:b28:f23d:f001::d', 8888),
    -1: ('2001:b28:f23d:f001::d', 8888),
    2: ('2001:67c:04e8:f002::d', 80),
    -2: ('2001:67c:04e8:f002::d', 80),
    3: ('2001:b28:f23d:f003::d', 8888),
    -3: ('2001:b28:f23d:f003::d', 8888),
    4: ('2001:67c:04e8:f004::d', 8888),
    -4: ('2001:67c:04e8:f004::d', 8888),
    5: ('2001:b28:f23f:f005::d', 8888),
    -5: ('2001:67c:04e8:f004::d', 8888)
}

DEFAULT_PROXY_SECRET = bytes.fromhex(
    'c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721'
    'd046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698'
    '6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c'
    '54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212'
)

TProxyConfig = Dict[int, Set[Tuple[str, int]]]


class ProxyConfigUpdater:
    def __init__(self, http_session: aiohttp.ClientSession, update_timeout: int=1 * HOUR):
        self.proxy_list_v4 = DEFAULT_PROXIES_V4
        self.proxy_list_v6 = DEFAULT_PROXIES_V6
        self.proxy_secret = DEFAULT_PROXY_SECRET

        self.session = http_session
        self.update_timeout = update_timeout

    async def _api_request(self, method: str) -> aiohttp.ClientResponse:
        return await self.session.get(API_BASE_URL + method)

    async def _load_and_parse_proxies(self, method: str) -> TProxyConfig:
        LOGGER.info(f'Loading proxies from {method}...')
        response = await self._api_request(method)
        LOGGER.debug(f'Proxy config loaded, parsing...')
        return self._parse_proxy_list(await response.text())

    async def _load_secret(self) -> bytes:
        LOGGER.debug(f'Loading proxy secret...')
        response = await self._api_request('getProxySecret')
        LOGGER.info('Proxy secret loaded')
        return response.content

    @staticmethod
    def _parse_proxy_list(text: str) -> TProxyConfig:
        proxies = defaultdict(set)

        for line in text.split('\n'):
            line = line.strip()

            LOGGER.debug(f'  parsing line: {line}')

            if line.startswith('#') or not line:
                continue

            line = line.rstrip(';')
            proxy_for, dc_id, host_port = line.split()

            if proxy_for != 'proxy_for':
                raise ValueError(f'Invalid proxy config line: {line}')

            dc_id = int(dc_id)
            host, port = host_port.rsplit(':', maxsplit=1)
            if host.startswith('[') and host.endswith(']'):
                # strip IPv6 brackets
                host = host[1:-1]
            port = int(port)

            LOGGER.debug(f'    parsed host: {host}, port: {port}, dc_id: {dc_id}')

            if dc_id in proxies:
                LOGGER.warning(f'Duplicate dc_id in proxy list: {dc_id}')

            proxies[dc_id].add((host, port))

        total_proxies = sum(len(s) for s in proxies.values())
        LOGGER.info(f'Proxies parsed: {total_proxies}')

        return proxies

    async def _update_all(self) -> None:
        self.proxy_list_v4 = await self._load_and_parse_proxies('getProxyConfig')
        self.proxy_list_v6 = await self._load_and_parse_proxies('getProxyConfigV6')
        self.proxy_secret = await self._load_secret()

    async def update_loop(self) -> None:
        while True:
            await self._update_all()
            LOGGER.debug(f'Will now sleep for {self.update_timeout} seconds')
            await asyncio.sleep(self.update_timeout)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()

    async def wrapper():
        async with aiohttp.ClientSession() as session:
            await ProxyConfigUpdater(session).update_loop()

    loop.run_until_complete(wrapper())
