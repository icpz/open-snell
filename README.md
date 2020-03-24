# open-snell

An open source port of [snell](https://github.com/surge-networks/snell)

# Features

Currently the `snell-server` functions as the latest snell v2.0, **WITH** encryption method auto-negotiation and v1 compatibility.

~~The encryption method is `aes-128-gcm` fixed, so~~ please update the client to the latest version.

# Build

## Requirements

+ git

## Build Steps

Only tested on macOS.

```bash

# clone and enter the repo

go build ./cmd/snell-client

```

The binary is produced at `./snell-client`

# Usage

An ini file is needed:

```ini
# snell-client.conf
[snell-client]
listen = 0.0.0.0:1234
server = 1.2.3.4:5678
psk = psk
obfs = tls
obfs-host = www.bing.com
```

Start the `snell-client`:

```bash
./snell-client -c ./snell-client.conf
```

# License

```
Copyright (C) 2020-, icpz <cc@icpz.dev>

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

+ [clash](https://github.com/Dreamacro/clash)
+ [snell](https://github.com/surge-networks/snell)

