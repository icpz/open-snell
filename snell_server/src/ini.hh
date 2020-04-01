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
#include <string>

class INI {
public:
    INI() = default;
    INI(INI &&) = default;
    virtual ~INI() = default;

    virtual std::string Get(std::string_view section, std::string_view key, std::string_view default_value) const = 0;

    virtual bool Exists(std::string_view section, std::string_view key) const = 0;

    static std::shared_ptr<INI> FromFile(std::string_view filename);

private:
    INI(const INI &) = delete;
};

