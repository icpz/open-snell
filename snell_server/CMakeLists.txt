cmake_minimum_required(VERSION 3.13)
project(snell-server)

if (APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
endif (APPLE)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.1 REQUIRED)

list(APPEND SRCS
    src/server.cc
    src/stream.cc
    src/session.cc
    src/crypto/chacha20_poly1305_ietf_cipher.cc
    src/crypto/aes_gcm_cipher.cc
    src/crypto/crypto_context.cc
    src/obfs/http.cc
    src/obfs/tls.cc
    src/ini.cc
    )

list(APPEND DEPS
    cxxopts
    spdlog
    asio
    PkgConfig::SODIUM
    OpenSSL::Crypto
    )

add_executable(snell-server ${SRCS})
target_link_libraries(snell-server ${DEPS})

