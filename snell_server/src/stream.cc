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

#include <spdlog/spdlog.h>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/write.hpp>

#include "stream.hh"

class AsyncSnellStreamImpl : public AsyncSnellStream {
public:
    enum { BUF_SIZE = 8192 };

    AsyncSnellStreamImpl(
        asio::ip::tcp::socket socket,
        std::shared_ptr<CryptoContext> crypto_ctx,
        std::shared_ptr<Obfuscator> obfs
    ) : socket_{std::move(socket)},
        crypto_ctx_{crypto_ctx},
        obfs_{obfs}
    {
    }

    ~AsyncSnellStreamImpl() = default;

    asio::awaitable<size_t> AsyncReadSome(std::vector<uint8_t> &buf, bool &has_zero_chunk, asio::error_code &ec) override;
    asio::awaitable<size_t> AsyncWrite(const uint8_t *buf, size_t len, bool add_zero_chunk, asio::error_code &ec) override;

private:
    asio::ip::tcp::socket socket_;
    std::shared_ptr<CryptoContext> crypto_ctx_;
    std::shared_ptr<Obfuscator> obfs_;
};

asio::awaitable<size_t>
    AsyncSnellStreamImpl::AsyncReadSome(std::vector<uint8_t> &buf, bool &has_zero_chunk, asio::error_code &ec) {
        size_t nbytes;
        int ret;
        uint8_t buffer[BUF_SIZE];

        while (true) {
            nbytes = 0;
            if (!crypto_ctx_->HasPending()) {
                nbytes = co_await \
                    socket_.async_read_some(
                        asio::buffer(buffer, BUF_SIZE),
                        asio::redirect_error(asio::use_awaitable, ec)
                    );
                if (ec) {
                    SPDLOG_INFO("async snell stream read socket error, {}", ec.message());
                    break;
                }

                if (obfs_) {
                    ret = obfs_->DeObfsRequest(buffer, nbytes);
                    if (ret < 0) {
                        SPDLOG_ERROR("async snell stream read deobfs failed");
                        nbytes = 0;
                        ec = asio::error::fault;
                        break;
                    } else if (ret == 0) {
                        SPDLOG_TRACE("async snell stream read deobfs need more");
                        continue;
                    }
                    nbytes = ret;
                }
            }
            ret = crypto_ctx_->DecryptSome(buf, buffer, nbytes, has_zero_chunk);
            if (ret) {
                SPDLOG_ERROR("async snell stream read decrypt failed");
                nbytes = 0;
                ec = asio::error::fault;
                break;
            }
            if (buf.empty() && !has_zero_chunk) {
                SPDLOG_TRACE("async snell stream read decrypt need more");
                continue;
            }
            nbytes = buf.size();
            break;
        }

        co_return nbytes;
    }

asio::awaitable<size_t>
    AsyncSnellStreamImpl::AsyncWrite(const uint8_t *buf, size_t len, bool add_zero_chunk, asio::error_code &ec) {
        std::vector<uint8_t> buffer;
        int ret;
        ret = crypto_ctx_->EncryptSome(buffer, buf, len, add_zero_chunk);
        if (ret) {
            SPDLOG_ERROR("async snell stream write encrypt failed");
            ec = asio::error::fault;
            co_return size_t{0};
        }
        if (obfs_) {
            obfs_->ObfsResponse(buffer);
        }

        size_t nbytes = co_await asio::async_write(
            socket_,
            asio::buffer(buffer),
            asio::redirect_error(asio::use_awaitable, ec)
        );
        if (ec) {
            SPDLOG_ERROR("async snell stream write socket failed, {}", ec.message());
        }
        co_return nbytes;
    }

std::shared_ptr<AsyncSnellStream>
    AsyncSnellStream::NewServer(
        asio::ip::tcp::socket socket,
        std::shared_ptr<CryptoContext> crypto_ctx,
        std::shared_ptr<Obfuscator> obfs
    ) {
        return \
            std::make_shared<AsyncSnellStreamImpl>(
                std::move(socket),
                crypto_ctx, obfs
            );
    }

