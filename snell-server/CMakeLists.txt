cmake_minimum_required(VERSION 3.13)
project(snell-server)

if (APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif (APPLE)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.0.2 REQUIRED)

if(${OPENSSL_VERSION} VERSION_GREATER_EQUAL 1.1)
    message(FATAL_ERROR "libcrypto too new, require <= 1.0.2")
endif()

list(APPEND SRCS
    src/server.cc
    src/session.cc
    src/chacha20_poly1305_ietf_cipher.cc
    src/aes_gcm_cipher.cc
    src/crypto_context.cc
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

