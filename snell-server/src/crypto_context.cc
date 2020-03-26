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
#include <arpa/inet.h>
#include <assert.h>

#include <spdlog/spdlog.h>

#include "crypto_context.hh"

const size_t CHUNK_MAX_SIZE = 0x3FFFU;
const size_t TAG_SIZE = 16U;

CryptoContext::CryptoContext(std::shared_ptr<Cipher> cipher, std::string_view psk)
    : cipher_(cipher), psk_(psk),
      key_(cipher->KeySize()), nonce_(cipher->NonceSize()) {
    state_ = 0;
}

CryptoContext::~CryptoContext() {
}

int CryptoContext::EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen, bool add_zero_chunk) {
    if (state_ == DECRYPT) {
        SPDLOG_CRITICAL("encrypt context invalid state");
        return ERROR;
    }

    if (plen == 0 && !add_zero_chunk) {
        SPDLOG_TRACE("encrypt context nothing to be done");
        return OK;
    }

    if (state_ == UNINITIALIZED) {
        uint8_t salt[256];
        size_t salt_size = cipher_->SaltSize();
        SPDLOG_TRACE("encrypt context initializing");
        randombytes_buf(salt, salt_size);
        DeriveKey(salt);
        ctext.insert(ctext.end(), salt, salt + salt_size);
        state_ = ENCRYPT;
        SPDLOG_TRACE("encrypt context initializing done");
    }

    size_t remained_size = plen;
    auto *phead = ptext;
    uint8_t buffer[65536];
    int ret = 0;
    while (remained_size) {
        size_t clen;
        auto curr_chunk_size = static_cast<uint16_t>(std::min(CHUNK_MAX_SIZE, remained_size));
        uint8_t chunk_size_buf[sizeof curr_chunk_size];
        curr_chunk_size = htons(curr_chunk_size);
        memcpy(&chunk_size_buf, &curr_chunk_size, sizeof curr_chunk_size);
        curr_chunk_size = ntohs(curr_chunk_size);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, chunk_size_buf, sizeof chunk_size_buf,
                nonce_.data(), key_.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk size failed with {}", ret);
            break;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        ctext.insert(ctext.end(), buffer, buffer + clen);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, phead, curr_chunk_size,
                nonce_.data(), key_.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk body failed with {}", ret);
            break;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        ctext.insert(ctext.end(), buffer, buffer + clen);
        remained_size -= curr_chunk_size;
        phead += curr_chunk_size;
    }

    if (add_zero_chunk) {
        size_t clen;
        auto curr_chunk_size = static_cast<uint16_t>(0);
        uint8_t chunk_size_buf[sizeof curr_chunk_size];
        curr_chunk_size = htons(curr_chunk_size);
        memcpy(&chunk_size_buf, &curr_chunk_size, sizeof curr_chunk_size);
        curr_chunk_size = ntohs(curr_chunk_size);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, chunk_size_buf, sizeof chunk_size_buf,
                nonce_.data(), key_.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk size failed with {}", ret);
            return ret;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        ctext.insert(ctext.end(), buffer, buffer + clen);
    }

    return ret;
}

int CryptoContext::DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen, bool &has_zero_chunk) {
    if (state_ == ENCRYPT) {
        SPDLOG_CRITICAL("decrypt context invalid state");
        return ERROR;
    }

    has_zero_chunk = false;
    if (clen == 0) {
        SPDLOG_TRACE("decrypt context nothing to be done");
        return OK;
    }

    buffer_.insert(buffer_.end(), ctext, ctext + clen);

    if (state_ == UNINITIALIZED) {
        size_t salt_size = cipher_->SaltSize();
        SPDLOG_TRACE("decrypt context initializing");
        if (buffer_.size() < salt_size) {
            SPDLOG_TRACE("decrypt context initializing need more data");
            return OK;
        }
        const uint8_t *salt = buffer_.data();
        DeriveKey(salt);
        buffer_.erase(buffer_.begin(), buffer_.begin() + salt_size);
        state_ = DECRYPT;
        SPDLOG_TRACE("decrypt context initializing done");
    }

    size_t remained_size = buffer_.size();
    auto *chead = buffer_.data();
    uint8_t buffer[65536];
    int ret = 0;
    while (remained_size) {
        uint16_t curr_chunk_size;
        size_t mlen;
        size_t excepted_size = sizeof curr_chunk_size + TAG_SIZE;
        if (remained_size < excepted_size) {
            SPDLOG_TRACE("decrypt context need more data");
            break;
        }

        ret = \
            cipher_->Decrypt(
                reinterpret_cast<uint8_t *>(&curr_chunk_size), &mlen,
                chead, sizeof curr_chunk_size + TAG_SIZE,
                nonce_.data(), key_.data()
            );
        if (ret) {
            SPDLOG_WARN("cipher decrypt chunk size failed with {}", ret);
            break;
        }
        curr_chunk_size = ntohs(curr_chunk_size);
        if (curr_chunk_size) {
            excepted_size += curr_chunk_size + TAG_SIZE;
        }
        if (remained_size < excepted_size) {
            SPDLOG_TRACE("decrypt context need more data");
            break;
        }
        chead += sizeof curr_chunk_size + TAG_SIZE;
        sodium_increment(nonce_.data(), nonce_.size());

        if (curr_chunk_size == 0) {
            SPDLOG_DEBUG("decrypt context zero chunk detected");
            has_zero_chunk = true;
            remained_size -= excepted_size;
            break;
        }

        ret = \
            cipher_->Decrypt(
                buffer, &mlen, chead, curr_chunk_size + TAG_SIZE,
                nonce_.data(), key_.data()
            );
        if (ret) {
            SPDLOG_WARN("cipher decrypt chunk body failed with {}", ret);
            break;
        }
        chead += curr_chunk_size + TAG_SIZE;
        sodium_increment(nonce_.data(), nonce_.size());
        ptext.insert(ptext.end(), buffer, buffer + mlen);
        remained_size -= excepted_size;
    }
    buffer_.erase(buffer_.begin(), buffer_.end() - remained_size);
    return ret;
}

void CryptoContext::DeriveKey(const uint8_t *salt) {
    int ret = \
        crypto_pwhash(
            key_.data(), key_.size(), psk_.data(), psk_.size(),
            salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13
        );
    assert(ret == 0);
}

