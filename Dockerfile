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
    && /app/source/docker/package.sh


FROM busybox:glibc
COPY --from=snell-build-stage /app/pkg /

ENTRYPOINT [ "snell-server" ]
CMD [ "-h" ]

