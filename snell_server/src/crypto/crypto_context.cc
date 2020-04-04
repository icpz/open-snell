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

class CryptoContextImpl : public CryptoContext {
public:
    using CipherPtr = CryptoContext::CipherPtr;

    enum { OK, ERROR = -1 };
    enum { UNINITIALIZED, ENCRYPT, DECRYPT };

private:
    struct Context {
        Context(size_t key_size, size_t nonce_size)
            : state{UNINITIALIZED}, key(key_size), nonce(nonce_size) {
        }

        void Queue(const uint8_t *data, size_t len) {
            buffer.insert(buffer.end(), data, data + len);
        }

        void Dequeue(size_t len) {
            buffer.erase(buffer.begin(), buffer.begin() + len);
        }

        void Increase() {
            sodium_increment(nonce.data(), nonce.size());
        }

        void DeriveKey(const uint8_t *salt, std::string_view psk) {
            int ret = \
                crypto_pwhash(
                    key.data(), key.size(), psk.data(), psk.size(),
                    salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13
                );
            assert(ret == 0);
        }

        uint32_t state;
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> buffer;
    };

public:
    CryptoContextImpl(CipherPtr cipher, std::string_view psk, CipherPtr fallback);
    ~CryptoContextImpl();

    int EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen, bool add_zero_chunk) override;
    int DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen, bool &has_zero_chunk) override;
    bool HasPending() const override {
        return decrypt_ctx_.buffer.size() > sizeof(uint16_t) + TAG_SIZE;
    }

private:

    CipherPtr cipher_;
    CipherPtr fallback_;
    std::string_view psk_;
    bool cipher_selected_;
    Context encrypt_ctx_;
    Context decrypt_ctx_;
};

CryptoContextImpl::CryptoContextImpl(CipherPtr cipher, std::string_view psk, CipherPtr fallback)
    : cipher_{cipher}, fallback_{fallback}, psk_{psk}, cipher_selected_{false},
      encrypt_ctx_{cipher_->KeySize(), cipher_->NonceSize()},
      decrypt_ctx_{cipher_->KeySize(), cipher_->NonceSize()} {
}

CryptoContextImpl::~CryptoContextImpl() {
}

int CryptoContextImpl::EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen, bool add_zero_chunk) {
    auto &ctx = encrypt_ctx_;
    if (ctx.state == DECRYPT) {
        SPDLOG_CRITICAL("encrypt context invalid state");
        return ERROR;
    }

    if (plen == 0 && !add_zero_chunk) {
        SPDLOG_TRACE("encrypt context nothing to be done");
        return OK;
    }

    if (ctx.state == UNINITIALIZED) {
        uint8_t salt[256];
        size_t salt_size = cipher_->SaltSize();
        SPDLOG_TRACE("encrypt context initializing");
        randombytes_buf(salt, salt_size);
        ctx.DeriveKey(salt, psk_);
        ctext.insert(ctext.end(), salt, salt + salt_size);
        ctx.state = ENCRYPT;
        SPDLOG_TRACE("encrypt context initializing done");
        if (!cipher_selected_) {
            cipher_selected_ = true;
            SPDLOG_DEBUG("encrypt context default cipher selected");
        }
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
                ctx.nonce.data(), ctx.key.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk size failed with {}", ret);
            break;
        }
        ctx.Increase();
        ctext.insert(ctext.end(), buffer, buffer + clen);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, phead, curr_chunk_size,
                ctx.nonce.data(), ctx.key.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk body failed with {}", ret);
            break;
        }
        ctx.Increase();
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
                ctx.nonce.data(), ctx.key.data()
            );
        if (ret) {
            SPDLOG_CRITICAL("cipher encrypt chunk size failed with {}", ret);
            return ret;
        }
        ctx.Increase();
        ctext.insert(ctext.end(), buffer, buffer + clen);
        SPDLOG_DEBUG("encrypt context zero chunk added");
    }

    return ret;
}

int CryptoContextImpl::DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen, bool &has_zero_chunk) {
    auto &ctx = decrypt_ctx_;
    if (ctx.state == ENCRYPT) {
        SPDLOG_CRITICAL("decrypt context invalid state");
        return ERROR;
    }

    has_zero_chunk = false;
    if (clen == 0 && !HasPending()) {
        SPDLOG_TRACE("decrypt context nothing to be done");
        return OK;
    }

    ctx.Queue(ctext, clen);

    if (ctx.state == UNINITIALIZED) {
        size_t salt_size = cipher_->SaltSize();
        SPDLOG_TRACE("decrypt context initializing");
        if (ctx.buffer.size() < salt_size) {
            SPDLOG_TRACE("decrypt context initializing need more data");
            return OK;
        }
        const uint8_t *salt = ctx.buffer.data();
        ctx.DeriveKey(salt, psk_);
        ctx.Dequeue(salt_size);
        ctx.state = DECRYPT;
        SPDLOG_TRACE("decrypt context initializing done");
    }

    size_t remained_size = ctx.buffer.size();
    auto *chead = ctx.buffer.data();
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
                ctx.nonce.data(), ctx.key.data()
            );
        if (ret) {
            if (!cipher_selected_ && fallback_) {
                SPDLOG_DEBUG("decrypt context retry with fallback cipher");
                cipher_ = fallback_;
                fallback_ = nullptr;
                continue;
            }
            SPDLOG_WARN("cipher decrypt chunk size failed with {}", ret);
            break;
        }
        if (!cipher_selected_) {
            SPDLOG_DEBUG("decrypt context cipher selected");
            cipher_selected_ = true;
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
        ctx.Increase();

        if (curr_chunk_size == 0) {
            SPDLOG_DEBUG("decrypt context zero chunk detected");
            has_zero_chunk = true;
            remained_size -= excepted_size;
            break;
        }

        ret = \
            cipher_->Decrypt(
                buffer, &mlen, chead, curr_chunk_size + TAG_SIZE,
                ctx.nonce.data(), ctx.key.data()
            );
        if (ret) {
            SPDLOG_WARN("cipher decrypt chunk body failed with {}", ret);
            break;
        }
        chead += curr_chunk_size + TAG_SIZE;
        ctx.Increase();
        ptext.insert(ptext.end(), buffer, buffer + mlen);
        remained_size -= excepted_size;
    }
    ctx.Dequeue(ctx.buffer.size() - remained_size);
    return ret;
}

std::shared_ptr<CryptoContext>
    CryptoContext::New(CipherPtr cipher, std::string_view psk, CipherPtr fallback) {
        return std::make_shared<CryptoContextImpl>(cipher, psk, fallback);
    }

