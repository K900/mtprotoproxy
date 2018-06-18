# Async MTProto Proxy

Fast and somewhat more complicated to setup mtproto proxy.

## Requirements

You need Python 3.6 and [Pipenv](https://pipenv.org) for this to work.
All other dependencies are available on PyPI and will be downloaded by Pipenv automatically.

## Starting up
    
1. `git clone https://github.com/K900/mtprotoproxy.git; cd mtprotoproxy`
2. `pipenv install`
3. `pipenv run ./mtproxy.py [arguments]`

## Arguments

* `--listen`, `-l` - specifies a `(host, port)` pair for the server to listen on. The format is `host port` (note no `:`!).
    * Pass `0.0.0.0 1234` to listen on all IPv4 interfaces, port 1234.
    * Pass `:: 1234` to listen on all IPv6 interfaces, port 1234.
    * This option can be specified multiple times.
    * The default is to listen on all interfaces, port 3256.
* `--secret`, `-s` - specifies a `(username, secret)` pair for the server to accept from clients. The format is `username secret`.
    * The username is only used for statistics tracking.
    * The secret needs to be exactly 16 bytes, encoded in hexadecimal (without spaces). This is the same format most Telegram clients and t.me links use.
    * This option can be specified multiple times.
    * This option is **REQUIRED** to be passed at least once.
* `--mode`, `-m` - specifies a mode for the proxy to run in.
    * `DIRECT_FAST` - connects directly to Telegram's endpoint servers, same ones clients connect to. The traffic is not reencrypted in transit.
    * `DIRECT_SAFE` - same as `DIRECT_FAST`, with an additional layer of AES encryption between the proxy and Telegram servers.
    * `MIDDLE_PROXY` - connects to intermediate frontend servers dynamically loaded from Telegram's API via MTProto RPC.
        * Slower and more complex, but allows setting the proxy tag and advertising a channel.
        * Can also be helpful in situations where direct connectivity to Telegram endpoints is not available.
    * The default is `DIRECT_FAST`, except when `--proxy-tag` is set, in which case it is `MIDDLE_PROXY`.
* `--proxy-tag`, `-t` - sets the proxy tag to be sent along with forwarded packets, allowing stat tracking and channel ads.
    * The tag needs to be exactly 16 bytes, encoded in hexadecimal.
* `--stat-tracker-timeout` - how often statistics are logged, in seconds.
    * The default is 60 (i.e. every minute).
* `--proxy-config-update-timeout` - how often intermediate proxy lists are updated, in seconds.
    * The default is 3600 (i.e. every hour).

## Advanced options

* `--buffer-read` - sets the read buffer size for all sockets, and the proxy itself.
* `--buffer-write` - sets the buffer write time for all sockets.
* `--keepalive-timeout` - sets the keepalive timeout for all sockets.

## Performance

The proxy performance should be enough to comfortably serve about 4 000 simultaneous users on
the smallest VDS instance with 1 CPU core and 1024MB RAM.
