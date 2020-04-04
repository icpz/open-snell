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

#include <sodium.h>

#include "chacha20_poly1305_ietf_cipher.hh"

class Chacha20Poly1305IetfCipher : public Cipher {
public:
    virtual ~Chacha20Poly1305IetfCipher() = default;

    int Encrypt(uint8_t *c, size_t *clen, const uint8_t *ptext, size_t plen, const uint8_t *nonce, const uint8_t *key) const override {
        unsigned long long clenll;
        int ret = \
            crypto_aead_chacha20poly1305_ietf_encrypt(
                c, &clenll, ptext, plen,
                nullptr, 0, nullptr, nonce, key
            );
        if (ret == 0) {
            *clen = static_cast<size_t>(clenll);
        }
        return ret;
    }

    int Decrypt(uint8_t *p, size_t *plen, const uint8_t *ctext, size_t clen, const uint8_t *nonce, const uint8_t *key) const override {
        unsigned long long plenll;
        int ret = \
            crypto_aead_chacha20poly1305_ietf_decrypt(
                p, &plenll, nullptr, ctext, clen,
                nullptr, 0, nonce, key
            );
        if (ret == 0) {
            *plen = static_cast<size_t>(plenll);
        }
        return ret;
    }
};

std::shared_ptr<Cipher> NewChacha20Poly1305Ietf() {
    return std::make_shared<Chacha20Poly1305IetfCipher>();
}
