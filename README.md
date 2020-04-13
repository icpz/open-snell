# open-snell

An open source port of [snell](https://github.com/surge-networks/snell)

# Features

Currently the `snell-server` functions as the latest snell v2.0, **WITH** encryption method auto-negotiation and v1 compatibility.

~~The encryption method is `aes-128-gcm` fixed, so~~ please update the client to the latest version.

# Build

Only supports unix-like operating system.

## Requirements

+ [cmake](https://cmake.org) 3.13+
+ clang 7.0+
+ libc++ 7.0+ (for linux)
+ libsodium 1.0.17+
+ openssl 1.1+

## Build Steps

Only tested on macOS and Debian 9+ currently.

```bash

# clone and enter the repo

# if linux:
#export CC=clang CXX=clang++ CXXFLAGS=-stdlib=libc++

mkdir -p build && cd build

cmake -DCMAKE_BUILD_TYPE=Release ..

make

```

The binary is produced at `build/snell_server/snell-server`

# Docker Image

For users of amd64 architecture, the docker image is prebuilt [here](https://hub.docker.com/r/icpz/snell-server).

For other platforms, please build the image locally.

## Basic Usage

Pull the image (** only valid for amd64 arch **)

```bash
docker pull icpz/snell-server
```

Start server

```bash
export SN_LISTEN_PORT=18888
export SN_PSK=this-is-password

docker run -t --rm -p $SN_LISTEN_PORT:$SN_LISTEN_PORT icpz/snell-server -l 0.0.0.0:$SN_LISTEN_PORT -k "$SN_PSK" --obfs=tls
```

## With docker-compose

Prepare for a `docker-compose.yml` file:

```yaml
version: '3'

services:
  snell-server:
    image: icpz/snell-server
    container_name: snell-server
    ports:
      - "127.0.0.1:${SN_LISTEN_PORT}:${SN_LISTEN_PORT}"
    command: [ "-l", "0.0.0.0:${SN_LISTEN_PORT}", "-k", "${SN_PSK}", "--obfs", "${SN_OBFS}" ]
```

Compose a `.env` file in the same directory:

```bash
SN_LISTEN_PORT=18888
SN_PSK=this-is-password
SN_OBFS=none
```

Start up:

```bash
docker-compose up -d
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

