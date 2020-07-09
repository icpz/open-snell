/*
 * This file is part of open-snell.

 * open-snell is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * open-snell is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with open-snell.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/error_code.hpp>

#include "obfs/obfs.hh"
#include "crypto/crypto_context.hh"

class AsyncSnellStream {
public:
    AsyncSnellStream() = default;
    virtual ~AsyncSnellStream() = default;

    virtual asio::awaitable<size_t> AsyncReadSome(std::vector<uint8_t> &buf, bool &has_zero_chunk, asio::error_code &ec) = 0;
    virtual asio::awaitable<size_t> AsyncWrite(const uint8_t *buf, size_t len, bool add_zero_chunk, asio::error_code &ec) = 0;
    virtual void Shutdown(asio::ip::tcp::socket::shutdown_type type, asio::error_code &ec) = 0;

    static std::shared_ptr<AsyncSnellStream>
        NewServer(
            asio::ip::tcp::socket socket,
            std::shared_ptr<CryptoContext> crypto_ctx,
            std::shared_ptr<Obfuscator> obfs
        );
};

