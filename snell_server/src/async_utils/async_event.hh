#pragma once

#include <unistd.h>
#include <errno.h>

#include <stdint.h>
#include <exception>

#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/posix/stream_descriptor.hpp>

class AsyncEvent {
public:
    using ExecutorType = typename asio::posix::stream_descriptor::executor_type;

    AsyncEvent(const ExecutorType &ex) noexcept
        : executor_{ex}, event_{false}, reader_{executor_}, writer_{executor_}
    {
    }

    ~AsyncEvent() noexcept {
        reader_.close();
        writer_.close();
    }

    bool IsSet() const noexcept {
        return event_;
    }

    asio::awaitable<asio::error_code> AsyncSet() noexcept {
        asio::error_code ec;
        uint8_t byte[1] = {0x00};

        if (!IsSet()) {
            event_ = true;
            co_await \
                writer_.async_write_some(
                    asio::buffer(byte),
                    asio::redirect_error(asio::use_awaitable, ec)
                );
        }

        co_return ec;
    }

    asio::awaitable<asio::error_code> AsyncWait() noexcept {
        asio::error_code ec;

        while (!IsSet()) {
            co_await \
                reader_.async_wait(
                    asio::posix::stream_descriptor::wait_read,
                    asio::redirect_error(asio::use_awaitable, ec)
                );
            if (ec) {
                break;
            }
        }

        co_return ec;
    }

    asio::error_code Reset(bool flag = false) noexcept {
        asio::error_code ec;
        int fds[2];
        reader_.close();
        writer_.close();

        if (::pipe(fds)) {
            ec.assign(errno, asio::system_category());
            return ec;
        }

        reader_.assign(fds[0], ec);
        if (ec) {
            return ec;
        }
        writer_.assign(fds[1]);
        if (ec) {
            return ec;
        }
        event_ = false;
        return ec;
    }

private:
    ExecutorType executor_;
    bool event_;
    asio::posix::stream_descriptor reader_;
    asio::posix::stream_descriptor writer_;
};

