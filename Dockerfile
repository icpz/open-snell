FROM debian:buster

ENV CC clang-7
ENV CXX clang++-7
ENV CXXFLAGS -stdlib=libc++

COPY . /app/source
RUN apt-get update && apt-get install -y \
    cmake \
    git \
    clang-7 \
    libsodium-dev \
    libssl-dev \
    build-essential \
    libc++-7-dev \
    libc++abi-7-dev \
    pkg-config

RUN  cd /app/source \
  && rm -rf build && mkdir -p build && cd build \
  && cmake -DCMAKE_BUILD_TYPE=Release .. \
  && make -j`nproc` \
  && cp snell_server/snell-server /usr/bin/ \
  && apt-get purge -y git cmake pkg-config clang-7 build-essential

CMD snell-server -h

