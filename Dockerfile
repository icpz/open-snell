FROM debian:buster AS snell-build-stage
WORKDIR /app/source
COPY . .

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
    && rm -rf build && mkdir -p build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j`nproc` \
    && cp snell_server/snell-server /usr/bin/


FROM debian:buster
COPY --from=snell-build-stage /app/source/build/snell_server/snell-server /usr/bin/

RUN apt-get update && apt-get install --no-install-recommends -y \
    libsodium23 \
    libc++1-7 \
    libc++abi1-7

ENTRYPOINT [ "snell-server" ]
CMD [ "-h" ]

