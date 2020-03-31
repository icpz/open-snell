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
#include <memory>

class Cipher {
public:
    enum { TAG_SIZE = 16 };

    virtual ~Cipher() = default;

    virtual int Encrypt(uint8_t *ctext, size_t *clen, const uint8_t *ptext, size_t plen, const uint8_t *nonce, const uint8_t *key) const = 0;
    virtual int Decrypt(uint8_t *ptext, size_t *plen, const uint8_t *ctext, size_t clen, const uint8_t *nonce, const uint8_t *key) const = 0;

    virtual size_t SaltSize() const { return 16U; }
    virtual size_t KeySize() const { return 32U; }
    virtual size_t NonceSize() const { return 12U; }
};

