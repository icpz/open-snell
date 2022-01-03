# open-snell

An open source port of [snell](https://github.com/surge-networks/snell)

# Features

Currently server/client supports both v1 and v2, only server supports v3.

# Build

## Requirements

+ git

+ go 1.17+

## Build Steps

Only tested on macOS.

```bash

# clone and enter the repo

make

# or `make server/client' to build snell-server/snell-client separately

```

The binaries are produced at `./build/snell-{server,client}`

# Usage

An ini file is needed (compatible with the offical port):

```ini
# snell.conf

# section "snell-client" is used by snell-client
[snell-client]
listen = 0.0.0.0:1234
server = 1.2.3.4:5678
psk = psk
obfs = tls
obfs-host = www.bing.com
version = 1 # default 2

# section "snell-server" is used by snell-client
[snell-server]
listen = 0.0.0.0:5678
psk = psk
obfs = tls
```

Start the `snell-*`:

```bash
./snell-{server,client} -c ./snell.conf
```

# Docker image

The auto-built docker image is also available at [ghcr.io/icpz/snell-server:latest](https://github.com/icpz/open-snell/pkgs/container/snell-server) and [ghcr.io/icpz/snell-client:latest](https://github.com/icpz/open-snell/pkgs/container/snell-client).

# License

```
Copyright (C) 2020-, icpz <y@icpz.dev>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

# Thanks

+ [Dreamacro/clash](https://github.com/Dreamacro/clash)
+ [surge-networks/snell](https://github.com/surge-networks/snell)

