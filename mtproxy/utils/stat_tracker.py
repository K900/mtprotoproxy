import asyncio
import logging
from collections import defaultdict

import dataclasses

from mtproxy.handshake import ClientInfo

LOGGER = logging.getLogger('mtproxy.stat_tracker')


@dataclasses.dataclass
class Statistic:
    username: str
    total_bytes: int = 0
    total_connections: int = 0
    current_connections_x2: int = 0

    def __init__(self, username):
        self.username = username

    @property
    def current_connections(self) -> int:
        return self.current_connections_x2 // 2

    def pretty_print(self) -> str:
        return f'{self.username}: {self.total_connections} total connections, {self.current_connections} active ' \
               f'connections, {self.total_bytes} bytes transferred '


class StatTracker:
    def __init__(self, log_timeout):
        self.stats = defaultdict(Statistic)
        self.log_timeout = log_timeout

    def _get_statistic(self, client_info: ClientInfo) -> Statistic:
        if client_info.proxy_username not in self.stats:
            LOGGER.debug(f'No stats recorded for client {client_info.proxy_username}, creating...')
            self.stats[client_info.proxy_username] = Statistic(client_info.proxy_username)
        return self.stats[client_info.proxy_username]

    def track_connected(self, client_info: ClientInfo):
        self._get_statistic(client_info).total_connections += 1

    def track_pump_start(self, client_info: ClientInfo):
        self._get_statistic(client_info).current_connections_x2 += 1

    def track_pump_end(self, client_info: ClientInfo):
        self._get_statistic(client_info).current_connections_x2 -= 1

    def track_data_transferred(self, client_info: ClientInfo, size: int):
        self._get_statistic(client_info).total_bytes += size

    def log_all(self):
        for username in sorted(self.stats.keys()):
            LOGGER.info(self.stats[username].pretty_print())

    async def log_loop(self):
        while True:
            self.log_all()
            LOGGER.debug(f'Will now sleep for {self.log_timeout} seconds')
            await asyncio.sleep(self.log_timeout)
