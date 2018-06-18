import asyncio
import logging
from collections import defaultdict

import random
from typing import *

import aiohttp

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

TProxyConfig = Dict[int, List[Tuple[str, int]]]


class ProxyConfigUpdater:
    def __init__(self, update_timeout: int):
        self.proxy_list_v4 = DEFAULT_PROXIES_V4
        self.proxy_list_v6 = DEFAULT_PROXIES_V6
        self.proxy_secret = DEFAULT_PROXY_SECRET

        self.update_timeout = update_timeout

    @staticmethod
    async def _api_request(session: aiohttp.ClientSession, method: str) -> aiohttp.ClientResponse:
        return await session.get(API_BASE_URL + method)

    async def _load_and_parse_proxies(self, session: aiohttp.ClientSession, method: str) -> TProxyConfig:
        LOGGER.info(f'Loading proxies from {method}...')
        response = await self._api_request(session, method)
        LOGGER.debug(f'Proxy config loaded, parsing...')
        return self._parse_proxy_list(await response.text())

    async def _load_secret(self, session: aiohttp.ClientSession) -> bytes:
        LOGGER.debug(f'Loading proxy secret...')
        response = await self._api_request(session, 'getProxySecret')
        LOGGER.info('Proxy secret loaded')
        return await response.read()

    @staticmethod
    def _parse_proxy_list(text: str) -> TProxyConfig:
        proxies = defaultdict(list)

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

            proxies[dc_id].append((host, port))

        total_proxies = sum(len(s) for s in proxies.values())
        LOGGER.info(f'Proxies parsed: {total_proxies}')

        return proxies

    async def update_loop(self) -> None:
        async with aiohttp.ClientSession() as session:
            while True:
                self.proxy_list_v4 = await self._load_and_parse_proxies(session, 'getProxyConfig')
                self.proxy_list_v6 = await self._load_and_parse_proxies(session, 'getProxyConfigV6')
                self.proxy_secret = await self._load_secret(session)

                LOGGER.debug(f'Will now sleep for {self.update_timeout} seconds')
                await asyncio.sleep(self.update_timeout)

    def pick_proxy_v4(self, dc_id):
        return random.choice(self.proxy_list_v4[dc_id])

    def pick_proxy_v6(self, dc_id):
        return random.choice(self.proxy_list_v6[dc_id])