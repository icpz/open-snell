#pragma once

#include "async_event.hh"

class AsyncLatch {
public:
    using ExecutorType = typename AsyncEvent::ExecutorType;

    AsyncLatch(const ExecutorType &ex, ptrdiff_t counter = 0) noexcept
        : executor_{ex}, event_{executor_}, counter_{counter}
    {
    }

    ~AsyncLatch() noexcept = default;

    asio::awaitable<asio::error_code> AsyncCountDown(ptrdiff_t n = 1) noexcept {
        asio::error_code ec;
        counter_ -= n;
        if (counter_ <= 0) {
            ec = co_await event_.AsyncSet();
        }
        co_return ec;
    }

    asio::awaitable<asio::error_code> AsyncWait() noexcept {
        return event_.AsyncWait();
    }

    asio::error_code Reset(ptrdiff_t n = 0) noexcept {
        counter_ = n;
        if (counter_ > 0) {
            return event_.Reset();
        }
        return asio::error_code{};
    }

private:
    ExecutorType executor_;
    AsyncEvent   event_;
    ptrdiff_t    counter_;
};

