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
#include <string_view>
#include <memory>

#include "cipher.hh"

class CryptoContext {
public:
    enum { OK, ERROR = -1 };
    enum { UNINITIALIZED, ENCRYPT, DECRYPT };

    CryptoContext(std::shared_ptr<Cipher> cipher, std::string_view psk);
    ~CryptoContext();

    int EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen, bool add_zero_chunk);
    int DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen, bool &has_zero_chunk);

private:

    void DeriveKey(const uint8_t *salt);

    uint32_t state_;
    std::shared_ptr<Cipher> cipher_;
    std::string_view psk_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> nonce_;
    std::vector<uint8_t> buffer_;
};

