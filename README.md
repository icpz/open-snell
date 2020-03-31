# open-snell

An open source port of [snell](https://github.com/surge-networks/snell)

# Features

Currently the `snell-server` only functions as the original snell v2.0b12,
WITH encryption method auto-negotiation and v1 compatibility.

~~The encryption method is `aes-128-gcm` fixed, so~~ please update the client
to the latest version.

# Build

Only supports unix-like operating system.

## Requirements

+ [cmake](https://cmake.org) 3.13+
+ clang 7.0+
+ libc++ 7.0+
+ libsodium 1.0.17+
+ openssl 1.1+

## Build Steps

Only tested on macOS and Debian 9 currently.

```bash

# clone and enter the repo

# if linux:
#export CC=clang CXX=clang++ CXXFLAGS=-stdlib=libc++

mkdir -p build && cd build

cmake -DCMAKE_BUILD_TYPE=Release ..

make

```

The binary is produced at `build/snell_server/snell-server`

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

