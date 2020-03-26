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

#include <string_view>

#include <asio/ip/tcp.hpp>

class SnellServerSession {
public:
    virtual ~SnellServerSession() = default;

    virtual void Start() = 0;

    static std::shared_ptr<SnellServerSession> \
        New(asio::ip::tcp::socket socket, std::string_view psk);
};

