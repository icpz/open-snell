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

#include "session.hh"
#include "crypto/crypto_context.hh"
#include "crypto/aes_gcm_cipher.hh"

template<typename OStream>
OStream &operator<<(OStream &os, const asio::ip::tcp::endpoint &ep) {
    os << "[" << ep.address().to_string() << "]:" << ep.port();
    return os;
}

class SnellServerSessionImpl :
    public SnellServerSession,
    public std::enable_shared_from_this<SnellServerSessionImpl> {
    struct Peer {
        Peer(asio::ip::tcp::socket socket)
            : socket{std::move(socket)} {
        }

        template<class Executor>
        Peer(Executor &executor)
            : socket{executor} {
        }

        void Reset(bool close_socket = false) {
            if (close_socket && socket.is_open()) {
                socket.close();
            }
            buffer.clear();
            shutdown_after_forward = false;
        }

        asio::ip::tcp::socket socket;
        std::vector<uint8_t> buffer;
        bool shutdown_after_forward = false;
    };

    enum { BUF_SIZE = 8192 };

public:
    SnellServerSessionImpl(asio::ip::tcp::socket socket, std::shared_ptr<Cipher> cipher, std::string_view psk)
        : executor_{socket.get_executor()}, client_{std::move(socket)}, target_{executor_}, resolver_{executor_} {
        endpoint_ = client_.socket.remote_endpoint();
        enc_ctx_  = std::make_shared<CryptoContext>(cipher, psk);
        dec_ctx_  = std::make_shared<CryptoContext>(cipher, psk);
        SPDLOG_DEBUG("session opened {}", endpoint_);
    }

    ~SnellServerSessionImpl() {
        SPDLOG_DEBUG("session closed {}", endpoint_);
    }

    void Start() {
        auto self{shared_from_this()};

        target_.Reset(true);
        client_.Reset();
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
        uint8_t buf[BUF_SIZE];
        std::vector<uint8_t> plain;
        asio::error_code ec;
        bool has_zero_chunk;
        int ret;

        while (true) {
            size_t nbytes = co_await \
                client_.socket.async_read_some(
                    asio::buffer(buf, BUF_SIZE),
                    asio::redirect_error(asio::use_awaitable, ec)
                );
            if (ec) {
                if (ec == asio::error::eof) {
                    SPDLOG_DEBUG("session tcp stream meets eof {}", endpoint_);
                    eof = true;
                } else {
                    SPDLOG_ERROR("session tcp read error {}, {}", endpoint_, ec.message());
                }
                co_return ERROR;
            }
            ret = dec_ctx_->DecryptSome(plain, buf, nbytes, has_zero_chunk);
            if (ret) {
                SPDLOG_ERROR("session handshake decrypt failed {}", endpoint_);
                co_return ERROR;
            }
            uint8_t *phead = plain.data();
            size_t remained_size = plain.size();
            if (remained_size < 4) {
                SPDLOG_TRACE("session handshake need more {}", endpoint_);
                continue;
            }

            if (phead[0] != 0x01) {
                SPDLOG_ERROR("session unsupported protocol version {}, {:x}", endpoint_, phead[0]);
                co_return ERROR;
            }

            if (phead[1] == 0x00) { // ping
                SPDLOG_ERROR("session unimplemented ping command {}", endpoint_);
                cmd = 0x00;
                co_return OK;
            } else if (phead[1] == 0x05) { // connect
                cmd = 0x05;
            } else {
                SPDLOG_ERROR("session unsupported command {}, {:x}", endpoint_, phead[1]);
                co_return ERROR;
            }
            int uid_len = phead[2];
            remained_size -= 3;
            phead += 3;
            if (remained_size < uid_len + 1) {
                SPDLOG_TRACE("session handshake need more {}", endpoint_);
                continue;
            }
            if (uid_len) {
                current_uid_.assign((char *)phead, uid_len);
            }
            remained_size -= uid_len;
            phead += uid_len;

            int alen = phead[0];
            remained_size -= 1;
            phead += 1;
            if (remained_size < alen + 2) {
                SPDLOG_TRACE("session handshake need more {}", endpoint_);
                continue;
            }
            host.assign((char *)phead, alen);
            remained_size -= alen;
            phead += alen;
            memcpy(&port, phead, 2);
            port = ntohs(port);
            SPDLOG_DEBUG("session handshake extracted target {}, [{}]:{}", endpoint_, host, port);
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

        do {
            bool eof = false;
            if ((co_await DoHandshake(cmd, host, port, eof)) == ERROR) {
                if (!eof) {
                    SPDLOG_ERROR("session handshake failed, abort session {}", endpoint_);
                } else {
                    SPDLOG_INFO("session handshake meets eof, end session {}", endpoint_);
                }
                co_return;
            }
            SPDLOG_TRACE("session cmd {}, {:x}", endpoint_, cmd);
            if (cmd == 0x05) {
                auto resolve_results = co_await \
                    resolver_.async_resolve(
                        host, std::to_string(port),
                        asio::redirect_error(asio::use_awaitable, ec)
                    );

                if (ec) {
                    SPDLOG_ERROR("session failed to resolve {}, [{}]:{}, {}", endpoint_, host, port, ec.message());
                    co_await DoWriteErrorBack(ec);
                    continue;
                }

                auto remote_endpoint = co_await \
                    asio::async_connect(
                        target_.socket, resolve_results,
                        asio::redirect_error(asio::use_awaitable, ec)
                    );

                if (ec) {
                    SPDLOG_ERROR("session failed to connect {}, [{}]:{}, {}", endpoint_, host, port, ec.message());
                    co_await DoWriteErrorBack(ec);
                    continue;
                }
                SPDLOG_INFO("session connected to target {}->{}", endpoint_, remote_endpoint);

                ongoing_stream_ = 2;
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

                break;
                SPDLOG_INFO("session bidirection terminates {}", endpoint_);
            } else if (cmd == 0x00) {
                SPDLOG_DEBUG("session sending pong back {}", endpoint_);
                co_await DoSendPongBack();
            } else {
                SPDLOG_ERROR("session unknown command {}, {:x}", endpoint_, cmd);
                break;
            }
        } while (false);
        co_return;
    }

    asio::awaitable<void> DoForwardC2T() {
        auto self{shared_from_this()};
        asio::error_code ec;
        uint8_t buf[BUF_SIZE];

        while (true) {
            size_t nbytes = 0;
            bool has_zero_chunk = false;
            int ret;

            if (client_.buffer.empty() && !client_.shutdown_after_forward) {
                SPDLOG_TRACE("session client reading {}", endpoint_);
                nbytes = co_await \
                    client_.socket.async_read_some(
                        asio::buffer(buf, BUF_SIZE),
                        asio::redirect_error(asio::use_awaitable, ec)
                    );
                if (ec) {
                    SPDLOG_ERROR("session client read error {}, {}", endpoint_, ec.message());
                    break;
                }
            }
            ret = dec_ctx_->DecryptSome(client_.buffer, buf, nbytes, has_zero_chunk);
            if (ret) {
                SPDLOG_ERROR("session decrypt client error {}", endpoint_);
                break;
            }

            co_await asio::async_write(
                target_.socket,
                asio::buffer(client_.buffer),
                asio::redirect_error(asio::use_awaitable, ec)
            );
            if (ec) {
                SPDLOG_ERROR("session target write error {}, {}", endpoint_, ec.message());
                break;
            }
            client_.buffer.clear();
            if (has_zero_chunk || client_.shutdown_after_forward) {
                SPDLOG_DEBUG("session terminates forwarding c2s {}", endpoint_);
                break;
            }
        }
        target_.socket.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        if (ec) {
            SPDLOG_WARN("session target shutdown send failed {}, {}", endpoint_, ec.message());
        }
        --ongoing_stream_;
        if (!ongoing_stream_) {
            SPDLOG_INFO("session starts for new sub connection {}", endpoint_);
            Start();
        }
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
            int ret;

            SPDLOG_TRACE("session target reading {}", endpoint_);
            nbytes = co_await \
                target_.socket.async_read_some(
                    asio::buffer(buf, BUF_SIZE) + bias,
                    asio::redirect_error(asio::use_awaitable, ec)
                );
            if (ec && ec != asio::error::eof) {
                SPDLOG_ERROR("session target read error {}, {}", endpoint_, ec.message());
                break;
            }
            if (ec == asio::error::eof) {
                SPDLOG_INFO("session target read meets eof {}", endpoint_);
                add_zero_chunk = true;
            }
            nbytes += bias;
            bias = 0;

            ret = enc_ctx_->EncryptSome(target_.buffer, buf, nbytes, add_zero_chunk);
            if (ret) {
                SPDLOG_ERROR("session encrypt target error {}", endpoint_);
                break;
            }

            co_await asio::async_write(
                client_.socket,
                asio::buffer(target_.buffer),
                asio::redirect_error(asio::use_awaitable, ec)
            );
            if (ec) {
                SPDLOG_ERROR("session client write error {}, {}", endpoint_, ec.message());
                break;
            }
            target_.buffer.clear();
            if (add_zero_chunk) {
                SPDLOG_DEBUG("session terminates forwarding s2c {}", endpoint_);
                break;
            }
        }
        target_.socket.shutdown(asio::ip::tcp::socket::shutdown_receive, ec);
        if (ec) {
            SPDLOG_DEBUG("session target shutdown receive failed {}, {}", endpoint_, ec.message());
        }
        --ongoing_stream_;
        if (!ongoing_stream_) {
            SPDLOG_INFO("session starts for new sub connection {}", endpoint_);
            Start();
        }
    }

    asio::awaitable<void> DoWriteErrorBack(asio::error_code ec) {
        uint8_t buf[512];
        size_t nbytes;
        const auto &emsg = ec.message();

        buf[0] = 0x02;
        buf[1] = static_cast<uint8_t>(std::min(emsg.size(), 255UL));
        emsg.copy((char *)buf + 2, buf[1]);
        nbytes = 2 + static_cast<size_t>(buf[1]);
        SPDLOG_DEBUG("session write error back {}, {}", endpoint_, emsg);

        int ret = enc_ctx_->EncryptSome(target_.buffer, buf, nbytes, true);
        if (ret) {
            SPDLOG_ERROR("session encrypt error message error {}", endpoint_);
            goto __clean_up;
        }

        co_await asio::async_write(
            client_.socket, asio::buffer(target_.buffer),
            asio::redirect_error(asio::use_awaitable, ec)
        );
        if (ret) {
            SPDLOG_ERROR("session write pong error {}, {}", endpoint_, ec.message());
        }

    __clean_up:
        target_.Reset(false);
        client_.Reset();
    }

    asio::awaitable<void> DoSendPongBack() {
        uint8_t pong[1] = {0x00};
        asio::error_code ec;
        int ret = enc_ctx_->EncryptSome(target_.buffer, pong, sizeof pong, true);
        if (ret) {
            SPDLOG_ERROR("session encrypt pong error {}", endpoint_);
            co_return;
        }

        co_await asio::async_write(
            client_.socket, asio::buffer(target_.buffer),
            asio::redirect_error(asio::use_awaitable, ec)
        );
        if (ret) {
            SPDLOG_ERROR("session write pong error {}, {}", endpoint_, ec.message());
        }
    }

    asio::ip::tcp::socket::executor_type executor_;
    Peer client_;
    Peer target_;
    asio::ip::tcp::resolver resolver_;
    asio::ip::tcp::endpoint endpoint_;
    std::shared_ptr<CryptoContext> enc_ctx_;
    std::shared_ptr<CryptoContext> dec_ctx_;
    std::string current_uid_;
    int ongoing_stream_;
};

std::shared_ptr<SnellServerSession> \
SnellServerSession::New(asio::ip::tcp::socket socket, std::string_view psk) {
    static auto cipher = NewAes128Gcm();
    return std::make_shared<SnellServerSessionImpl>(std::move(socket), cipher, psk);
}

