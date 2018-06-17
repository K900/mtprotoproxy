import pathlib
from typing import Any

import toml

PORT = 3256

# name -> secret (32 hex chars)
USERS = {
    "tg": "00000000000000000000000000000000",
    "tg2": "0123456789abcdef0123456789abcdef"
}

# Tag for advertising, obtainable from @MTProxybot
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"

__config_path = pathlib.Path('config.toml')

if __config_path.exists():
    __config = toml.load(__config_path.open())
else:
    __config = {}

__defaults = {
    'ad_tag': '',
    'stat_log_timeout': 60,
    'buffer_read': 16384,
    'buffer_write': 65536,
    'client_keepalive': 40
}


def get(key: str) -> Any:
    return __config.get(key, __defaults[key])
