FROM debian:buster

COPY . /app/source

RUN apt-get update && apt-get install --no-install-recommends -y \
    cmake \
    git \
    clang-7 \
    libsodium-dev \
    libssl-dev \
    ca-certificates \
    make \
    libc++-7-dev \
    libc++abi-7-dev \
    pkg-config \
    && export CC=clang-7 CXX=clang++-7 CXXFLAGS=-stdlib=libc++ \
    && cd /app/source \
    && rm -rf build && mkdir -p build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j`nproc` \
    && cp snell_server/snell-server /usr/bin/ \
    && apt-get purge --auto-remove -y cmake git pkg-config clang-7 make libssl-dev \
    && rm -rf /var/lib/apt/lists/* /app/source/build

ENTRYPOINT [ "snell-server" ]
CMD [ "-h" ]

