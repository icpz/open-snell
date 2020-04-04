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

#include <utility>
#include <string_view>

#include <asio.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "stream.hh"
#include "session.hh"
#include "async_utils/async_latch.hh"
#include "crypto/crypto_context.hh"
#include "crypto/aes_gcm_cipher.hh"
#include "crypto/chacha20_poly1305_ietf_cipher.hh"

template<typename OStream>
OStream &operator<<(OStream &os, const asio::ip::tcp::endpoint &ep) {
    os << "[" << ep.address().to_string() << "]:" << ep.port();
    return os;
}

class SnellServerSessionImpl :
    public SnellServerSession,
    public std::enable_shared_from_this<SnellServerSessionImpl> {
    struct Client {
        Client() = default;

        Client(std::shared_ptr<AsyncSnellStream> stream)
            : stream{stream} {
        }

        void Reset() {
            buffer.clear();
            shutdown_after_forward = false;
        }

        std::shared_ptr<AsyncSnellStream> stream;
        std::vector<uint8_t> buffer;
        bool shutdown_after_forward = false;
    };

    struct Target {
        using ExecutorType = typename asio::ip::tcp::socket::executor_type;

        Target(ExecutorType ex)
            : socket{ex} {
        }

        void Reset(bool close_socket = false) {
            if (close_socket && socket.is_open()) {
                socket.close();
            }
        }

        asio::ip::tcp::socket socket;
    };

    enum { BUF_SIZE = 8192 };

public:
    SnellServerSessionImpl(
        asio::ip::tcp::socket socket,
        std::shared_ptr<Cipher> cipher,
        std::shared_ptr<Cipher> fallback,
        std::string_view psk,
        std::shared_ptr<Obfuscator> obfs = nullptr
    )
        : executor_{socket.get_executor()},
          client_{},
          target_{executor_},
          resolver_{executor_},
          latch_{executor_}
    {
        endpoint_ = socket.remote_endpoint();
        client_.stream = \
            AsyncSnellStream::NewServer(
                std::move(socket),
                CryptoContext::New(cipher, psk, fallback),
                obfs
            );
        SPDLOG_DEBUG("session from {} opened", endpoint_);
    }

    ~SnellServerSessionImpl() {
        SPDLOG_DEBUG("session {} from {} closed", uid_, endpoint_);
    }

    void Start() override {
        auto self{shared_from_this()};

        target_.Reset(true);
        client_.Reset();
        uid_ = "<none>";
        asio::co_spawn(
            executor_,
            [self]() { return self->DoHandleSubSessions(); },
            asio::detached
        );
    }

private:
    enum State {
        OK,
        RESTART,
        ERROR,
    };

    asio::awaitable<State> DoHandshake(int &cmd, std::string &host, uint16_t &port, bool &eof) {
        std::vector<uint8_t> plain;
        asio::error_code ec;
        bool has_zero_chunk;

        eof = false;
        while (true) {
            size_t nbytes = 0;

            nbytes = co_await client_.stream->AsyncReadSome(plain, has_zero_chunk, ec);
            if (ec) {
                if (ec == asio::error::eof) {
                    SPDLOG_DEBUG("session {} from {} tcp stream meets eof", uid_, endpoint_);
                    eof = true;
                } else {
                    SPDLOG_ERROR("session {} from {} tcp read error, {}", uid_, endpoint_, ec.message());
                }
                co_return ERROR;
            }

            uint8_t *phead = plain.data();
            size_t remained_size = plain.size();
            if (remained_size < 4) {
                SPDLOG_TRACE("session {} from {} handshake need more", uid_, endpoint_);
                continue;
            }

            if (phead[0] != 0x01) {
                SPDLOG_ERROR("session {} from {} unsupported protocol version 0x{:x}", uid_, endpoint_, phead[0]);
                co_return ERROR;
            }

            if (phead[1] == 0x00) { // ping
                SPDLOG_DEBUG("session {} from {} ping command", uid_, endpoint_);
                cmd = 0x00;
                co_return OK;
            } else if (phead[1] == 0x05 || phead[1] == 0x01) { // connect
                cmd = phead[1];
                SPDLOG_DEBUG("session {} from {} connect command", uid_, endpoint_);
                if (cmd == 0x01) {
                    SPDLOG_INFO("session {} from {} snell v1", uid_, endpoint_);
                    snell_v2_ = false;
                }
            } else {
                SPDLOG_ERROR("session {} from {} unsupported command, 0x{:x}", uid_, endpoint_, phead[1]);
                co_return ERROR;
            }
            int uid_len = phead[2];
            remained_size -= 3;
            phead += 3;
            if (remained_size < uid_len + 1) {
                SPDLOG_TRACE("session {} from {} handshake need more", uid_, endpoint_);
                continue;
            }
            SPDLOG_DEBUG("session {} from {} extract id len {}", uid_, endpoint_, uid_len);
            if (uid_len) {
                uid_.assign((char *)phead, uid_len);
                SPDLOG_DEBUG("session {} from {} extract id", uid_, endpoint_);
            }
            remained_size -= uid_len;
            phead += uid_len;

            int alen = phead[0];
            remained_size -= 1;
            phead += 1;
            if (remained_size < alen + 2) {
                SPDLOG_TRACE("session {} from {} handshake need more", uid_, endpoint_);
                continue;
            }
            host.assign((char *)phead, alen);
            remained_size -= alen;
            phead += alen;
            memcpy(&port, phead, 2);
            port = ntohs(port);
            SPDLOG_DEBUG("session {} from {} handshake extracted target [{}]:{}", uid_, endpoint_, host, port);
            remained_size -= 2;
            phead += 2;
            std::copy_n(phead, remained_size, std::back_inserter(client_.buffer));
            if (has_zero_chunk) {
                client_.shutdown_after_forward = true;
            }
            break;
        }
        co_return OK;
    }

    asio::awaitable<void> DoHandleSubSessions() {
        auto self{shared_from_this()};
        int cmd;
        std::string host;
        uint16_t port;
        asio::error_code ec;

        while (true) {
            bool eof = false;
            if ((co_await DoHandshake(cmd, host, port, eof)) == ERROR) {
                if (!eof) {
                    SPDLOG_ERROR("session {} from {} handshake failed, abort session", uid_, endpoint_);
                } else {
                    SPDLOG_INFO("session {} from {} handshake meets eof, end session", uid_, endpoint_);
                }
                co_return;
            }
            SPDLOG_TRACE("session {} from {} cmd {:x}", uid_, endpoint_, cmd);
            if (cmd == 0x05 || cmd == 0x01) {
                auto resolve_results = co_await \
                    resolver_.async_resolve(
                        host, std::to_string(port),
                        asio::redirect_error(asio::use_awaitable, ec)
                    );

                if (ec) {
                    SPDLOG_ERROR("session {} from {} failed to resolve [{}]:{}, {}", uid_, endpoint_, host, port, ec.message());
                    co_await DoWriteErrorBack(ec);
                    if (snell_v2_) {
                        continue;
                    } else {
                        break;
                    }
                }

                auto remote_endpoint = co_await \
                    asio::async_connect(
                        target_.socket, resolve_results,
                        asio::redirect_error(asio::use_awaitable, ec)
                    );

                if (ec) {
                    SPDLOG_ERROR("session {} from {} failed to connect [{}]:{}, {}", uid_, endpoint_, host, port, ec.message());
                    co_await DoWriteErrorBack(ec);
                    if (snell_v2_) {
                        continue;
                    } else {
                        break;
                    }
                }
                SPDLOG_INFO("session {} from {} connected to target {}", uid_, endpoint_, remote_endpoint);

                ec = latch_.Reset(2);
                if (ec) {
                    SPDLOG_CRITICAL("session {} from {} reset latch failed, {}", uid_, endpoint_, ec.message());
                    break;
                }
                asio::co_spawn(
                    executor_,
                    [self]() { return self->DoForwardC2T(); },
                    asio::detached
                );
                asio::co_spawn(
                    executor_,
                    [self]() { return self->DoForwardT2C(); },
                    asio::detached
                );
                ec = co_await latch_.AsyncWait();
                if (ec) {
                    SPDLOG_CRITICAL("session {} from {} wait latch failed, {}", uid_, endpoint_, ec.message());
                    break;
                }
                if (!snell_v2_) {
                    break;
                }
                uid_ = "<none>";
                SPDLOG_INFO("session {} from {} starts for new sub connection", uid_, endpoint_);
                continue;
            } else if (cmd == 0x00) {
                SPDLOG_DEBUG("session {} from {} sending pong back", uid_, endpoint_);
                co_await DoSendPongBack();
                break;
            } else {
                SPDLOG_ERROR("session {} from {} unknown command 0x{:x}", uid_, endpoint_, cmd);
                break;
            }
        }
        co_return;
    }

    asio::awaitable<void> DoForwardC2T() {
        auto self{shared_from_this()};
        asio::error_code ec;

        while (true) {
            size_t nbytes = 0;
            bool has_zero_chunk = false;

            if (client_.buffer.empty() && !client_.shutdown_after_forward) {
                SPDLOG_TRACE("session {} from {} client reading", uid_, endpoint_);
                nbytes = \
                    co_await client_.stream->AsyncReadSome(client_.buffer, has_zero_chunk, ec);
                if (ec) {
                    if (snell_v2_ || ec != asio::error::eof) {
                        SPDLOG_ERROR("session {} from {} client read error, {}", uid_, endpoint_, ec.message());
                    } else {
                        SPDLOG_INFO("session {} from {} client read meets eof", uid_, endpoint_);
                    }
                    break;
                }
            }

            if (!client_.buffer.empty()) {
                co_await asio::async_write(
                    target_.socket,
                    asio::buffer(client_.buffer),
                    asio::redirect_error(asio::use_awaitable, ec)
                );
                if (ec) {
                    SPDLOG_ERROR("session {} from {} target write error, {}", uid_, endpoint_, ec.message());
                    break;
                }
                client_.buffer.clear();
            }
            if (has_zero_chunk || client_.shutdown_after_forward) {
                SPDLOG_DEBUG("session {} from {} terminates forwarding c2s", uid_, endpoint_);
                break;
            }
        }
        target_.socket.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (ec) {
            SPDLOG_WARN("session {} from {} target shutdown send failed, {}", uid_, endpoint_, ec.message());
        }
        ec = co_await latch_.AsyncCountDown();
        if (ec) {
            SPDLOG_CRITICAL("session {} from {} latch count down failed, {}", uid_, endpoint_, ec.message());
        }
        client_.Reset();
    }

    asio::awaitable<void> DoForwardT2C() {
        auto self{shared_from_this()};
        asio::error_code ec;
        uint8_t buf[BUF_SIZE];
        size_t bias = 1;
        buf[0] = 0x00;

        while (true) {
            size_t nbytes = 0;
            bool add_zero_chunk = false;

            SPDLOG_TRACE("session {} from {} target reading", uid_, endpoint_);
            nbytes = co_await \
                target_.socket.async_read_some(
                    asio::buffer(buf, BUF_SIZE) + bias,
                    asio::redirect_error(asio::use_awaitable, ec)
                );
            if (ec && ec != asio::error::eof) {
                SPDLOG_ERROR("session {} from {} target read error, {}", uid_, endpoint_, ec.message());
                break;
            }
            if (ec == asio::error::eof) {
                SPDLOG_INFO("session {} from {} target read meets eof", uid_, endpoint_);
                add_zero_chunk = true;
            }
            nbytes += bias;
            bias = 0;

            co_await client_.stream->AsyncWrite(buf, nbytes, add_zero_chunk && snell_v2_, ec);
            if (ec) {
                SPDLOG_ERROR("session {} from {} client write error, {}", uid_, endpoint_, ec.message());
                break;
            }
            if (add_zero_chunk) {
                SPDLOG_DEBUG("session {} from {} terminates forwarding s2c", uid_, endpoint_);
                break;
            }
        }
        target_.socket.shutdown(asio::ip::tcp::socket::shutdown_receive, ec);
        if (ec) {
            SPDLOG_DEBUG("session {} from {} target shutdown receive failed, {}", uid_, endpoint_, ec.message());
        }
        ec = co_await latch_.AsyncCountDown();
        if (ec) {
            SPDLOG_CRITICAL("session {} from {} latch count down failed, {}", uid_, endpoint_, ec.message());
        }
        target_.Reset(true);
    }

    asio::awaitable<void> DoWriteErrorBack(asio::error_code ec) {
        uint8_t buf[512];
        size_t nbytes;
        const auto &emsg = ec.message();

        buf[0] = 0x02;
        buf[1] = static_cast<uint8_t>(std::min(emsg.size(), 255UL));
        emsg.copy((char *)buf + 2, buf[1]);
        nbytes = 2 + static_cast<size_t>(buf[1]);
        SPDLOG_DEBUG("session {} from {} write error back, {}", uid_, endpoint_, emsg);

        co_await client_.stream->AsyncWrite(buf, nbytes, true, ec);
        if (ec) {
            SPDLOG_ERROR("session {} from {} write error error, {}", uid_, endpoint_, ec.message());
        }

        target_.Reset(false);
        client_.Reset();
    }

    asio::awaitable<void> DoSendPongBack() {
        uint8_t pong[1] = {0x00};
        asio::error_code ec;

        co_await client_.stream->AsyncWrite(pong, sizeof pong, true, ec);
        if (ec) {
            SPDLOG_ERROR("session {} from {} write pong error, {}", uid_, endpoint_, ec.message());
        }
    }

    asio::ip::tcp::socket::executor_type executor_;
    Client client_;
    Target target_;
    asio::ip::tcp::resolver resolver_;
    asio::ip::tcp::endpoint endpoint_;
    AsyncLatch latch_;
    std::string uid_;
    bool snell_v2_ = true;
};

std::shared_ptr<SnellServerSession> \
SnellServerSession::New(asio::ip::tcp::socket socket, std::string_view psk, std::shared_ptr<Obfuscator> obfs) {
    static auto cipher = NewAes128Gcm();
    static auto fallback = NewChacha20Poly1305Ietf();
    return std::make_shared<SnellServerSessionImpl>(std::move(socket), cipher, fallback, psk, obfs);
}

