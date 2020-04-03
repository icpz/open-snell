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

