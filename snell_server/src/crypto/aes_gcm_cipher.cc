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

#include <openssl/evp.h>

#include "aes_gcm_cipher.hh"

class Aes128GcmCipher : public Cipher {
public:
    Aes128GcmCipher()
        : ctx_{EVP_CIPHER_CTX_new()} {
    }

    virtual ~Aes128GcmCipher() {
        EVP_CIPHER_CTX_free(ctx_);
    }

    int Encrypt(uint8_t *c, size_t *clen, const uint8_t *ptext, size_t plen, const uint8_t *nonce, const uint8_t *key) const override {
        int ret;
        int encrypted_len = plen;
        uint8_t *ptag = c + plen;

        *clen = 0;
        EVP_EncryptInit_ex(ctx_, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
        ret =  (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key, nonce) > 0)
            && (EVP_EncryptUpdate(ctx_, c, &encrypted_len, ptext, plen) > 0);
        *clen += encrypted_len;
        ret = ret && (EVP_EncryptFinal_ex(ctx_, c + encrypted_len, &encrypted_len) > 0)
            && (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ptag) > 0);
        *clen += encrypted_len + TAG_SIZE;

        return !ret;
    }

    int Decrypt(uint8_t *p, size_t *plen, const uint8_t *ctext, size_t clen, const uint8_t *nonce, const uint8_t *key) const override {
        int ret;
        int plain_len = clen - TAG_SIZE;
        uint8_t *ptag = const_cast<uint8_t *>(ctext + plain_len);

        *plen = 0;
        EVP_DecryptInit_ex(ctx_, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
        ret =  (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, ptag) > 0)
            && (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key, nonce) > 0)
            && (EVP_DecryptUpdate(ctx_, p, &plain_len, ctext, plain_len) > 0);
        *plen += plain_len;
        ret = ret && (EVP_DecryptFinal_ex(ctx_, p + plain_len, &plain_len) > 0);
        *plen += plain_len;

        return !ret;
    }

    const char *Name() const noexcept override {
        return "AES-128-GCM";
    }

private:
    EVP_CIPHER_CTX *ctx_;
};

std::shared_ptr<Cipher> NewAes128Gcm() {
    return std::make_shared<Aes128GcmCipher>();
}

