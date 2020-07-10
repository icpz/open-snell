# open-snell

An open source port of [snell](https://github.com/surge-networks/snell)

# Features

Currently only snell v1 is supported.

# Build

## Requirements

+ git

## Build Steps

Only tested on macOS.

```bash

# clone and enter the repo

make

```

The binaries are produced at `./build/snell-{server,client}`

# Usage

An ini file is needed:

```ini
# snell.conf
[snell-client]
listen = 0.0.0.0:1234
server = 1.2.3.4:5678
psk = psk
obfs = tls
obfs-host = www.bing.com

[snell-server]
listen = 0.0.0.0:5678
psk = psk
obfs = tls
```

Start the `snell-*`:

```bash
./snell-{server,client} -c ./snell.conf
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

