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

#include <stdint.h>
#include <vector>
#include <memory>

class Obfuscator {
public:
    virtual ~Obfuscator() = default;

    virtual int ObfsRequest(std::vector<uint8_t> &buf) = 0;
    virtual int DeObfsResponse(uint8_t *buf, int len) = 0;

    virtual int ObfsResponse(std::vector<uint8_t> &buf) = 0;
    virtual int DeObfsRequest(uint8_t *buf, int len) = 0;

    virtual std::shared_ptr<Obfuscator> Duplicate() const = 0;

};

