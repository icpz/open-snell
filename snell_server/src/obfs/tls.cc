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

#include <arpa/inet.h>

#include <stdint.h>
#include <algorithm>
#include <random>
#include <functional>
#include <array>

#include <spdlog/spdlog.h>

#include "obfs.hh"

#define CT_HTONS(x) htons(x)
#define CT_HTONL(x) htonl(x)
#define CT_NTOHS(x) ntohs(x)
#define CT_NTOHL(x) ntohl(x)

#define __PACKED __attribute__((packed))

struct ClientHello {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;

    uint8_t  handshake_type;
    uint8_t  handshake_len_1;
    uint16_t handshake_len_2;
    uint16_t handshake_version;

    uint32_t random_unix_time;
    uint8_t  random_bytes[28];
    uint8_t  session_id_len;
    uint8_t  session_id[32];
    uint16_t cipher_suites_len;
    uint8_t  cipher_suites[56];
    uint8_t  comp_methods_len;
    uint8_t  comp_methods[1];
    uint16_t ext_len;
} __PACKED;

struct ExtServerName {
    uint16_t ext_type;
    uint16_t ext_len;
    uint16_t server_name_list_len;
    uint8_t  server_name_type;
    uint16_t server_name_len;
} __PACKED;

struct ExtSessionTicket {
    uint16_t session_ticket_type;
    uint16_t session_ticket_ext_len;
} __PACKED;

struct ExtOthers {
    uint16_t ec_point_formats_ext_type;
    uint16_t ec_point_formats_ext_len;
    uint8_t  ec_point_formats_len;
    uint8_t  ec_point_formats[3];

    uint16_t elliptic_curves_type;
    uint16_t elliptic_curves_ext_len;
    uint16_t elliptic_curves_len;
    uint8_t  elliptic_curves[8];

    uint16_t sig_algos_type;
    uint16_t sig_algos_ext_len;
    uint16_t sig_algos_len;
    uint8_t  sig_algos[30];

    uint16_t encrypt_then_mac_type;
    uint16_t encrypt_then_mac_ext_len;

    uint16_t extended_master_secret_type;
    uint16_t extended_master_secret_ext_len;
} __PACKED;

struct ServerHello {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;

    uint8_t  handshake_type;
    uint8_t  handshake_len_1;
    uint16_t handshake_len_2;
    uint16_t handshake_version;

    uint32_t random_unix_time;
    uint8_t  random_bytes[28];
    uint8_t  session_id_len;
    uint8_t  session_id[32];
    uint16_t cipher_suite;
    uint8_t  comp_method;
    uint16_t ext_len;

    uint16_t ext_renego_info_type;
    uint16_t ext_renego_info_ext_len;
    uint8_t  ext_renego_info_len;

    uint16_t extended_master_secret_type;
    uint16_t extended_master_secret_ext_len;

    uint16_t ec_point_formats_ext_type;
    uint16_t ec_point_formats_ext_len;
    uint8_t  ec_point_formats_len;
    uint8_t  ec_point_formats[1];
} __PACKED;

struct ChangeCipherSpec {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;
    uint8_t  msg;
} __PACKED;

struct EncryptedHandshake {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;
} __PACKED;

static const ClientHello kClientHelloTemplate = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = 0,

    .handshake_type = 1,
    .handshake_len_1 = 0,
    .handshake_len_2 = 0,
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suites_len = CT_HTONS(56),
    .cipher_suites = {
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    },

    .comp_methods_len = 1,
    .comp_methods = { 0 },

    .ext_len = 0,
};

static const ExtServerName kExtServerNameTemplate = {
    .ext_type = 0,
    .ext_len = 0,
    .server_name_list_len = 0,
    .server_name_type = 0,
    .server_name_len = 0,
};

static const ExtSessionTicket kExtSessionTicketTemplate = {
    .session_ticket_type = CT_HTONS(0x0023),
    .session_ticket_ext_len = 0,
};

static const ExtOthers kExtOthersTemplate = {
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(4),
    .ec_point_formats_len = 3,
    .ec_point_formats = { 0x01, 0x00, 0x02 },

    .elliptic_curves_type = CT_HTONS(0x000a),
    .elliptic_curves_ext_len = CT_HTONS(10),
    .elliptic_curves_len = CT_HTONS(8),
    .elliptic_curves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 },

    .sig_algos_type = CT_HTONS(0x000d),
    .sig_algos_ext_len = CT_HTONS(32),
    .sig_algos_len = CT_HTONS(30),
    .sig_algos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    },

    .encrypt_then_mac_type = CT_HTONS(0x0016),
    .encrypt_then_mac_ext_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,
};

static const ServerHello kServerHelloTemplate = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = CT_HTONS(91),

    .handshake_type = 2,
    .handshake_len_1 = 0,
    .handshake_len_2 = CT_HTONS(87),
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suite = CT_HTONS(0xCCA8),
    .comp_method = 0,
    .ext_len = 0,

    .ext_renego_info_type = CT_HTONS(0xFF01),
    .ext_renego_info_ext_len = CT_HTONS(1),
    .ext_renego_info_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,

    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(2),
    .ec_point_formats_len = 1,
    .ec_point_formats = { 0 },
};

static const ChangeCipherSpec kChangeCipherSpecTemplate = {
    .content_type = 0x14,
    .version = CT_HTONS(0x0303),
    .len = CT_HTONS(1),
    .msg = 0x01,
};

static const EncryptedHandshake kEncryptedHandshakeTemplate = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0303),
    .len = 0,
};

const uint8_t kDataHeader[3] = {0x17, 0x03, 0x03};

struct Frame {
    int16_t  idx;
    uint16_t len;
    uint8_t  buf[2];
};

class TlsObfs : public Obfuscator {
public:
    TlsObfs(std::string_view hostname)
        : hostname_{hostname} {
        session_id_.back() = 0;
    }

    TlsObfs(const TlsObfs &o)
        : hostname_{o.hostname_}{
        session_id_.back() = 0;
    }

    ~TlsObfs() = default;

    int ObfsRequest(std::vector<uint8_t> &buf);
    int DeObfsResponse(uint8_t *buf, int len);

    int ObfsResponse(std::vector<uint8_t> &buf);
    int DeObfsRequest(uint8_t *buf, int len);

    std::shared_ptr<Obfuscator> Duplicate() const {
        return std::make_shared<TlsObfs>(*this);
    }

private:
    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    std::array<uint8_t, 33> session_id_;
    std::string_view hostname_;
    std::vector<uint8_t> buf_;
    Frame extra_ = { 0 };
};

std::shared_ptr<Obfuscator>
    NewTlsObfs(std::string_view host) {
        return std::make_shared<TlsObfs>(host);
    }

static void RandBytes(uint8_t *buf, size_t len);
static ssize_t ObfsAppData(std::vector<uint8_t> &buf);
static ssize_t DeObfsAppData(std::vector<uint8_t> &buf, size_t idx, Frame *frame);

int TlsObfs::ObfsRequest(std::vector<uint8_t> &buf) {
    if (!obfs_stage_) {
        size_t buf_len = buf.size();
        size_t hello_len = sizeof(ClientHello);
        size_t server_name_len = sizeof(ExtServerName);
        size_t host_len = hostname_.size();
        size_t ticket_len = sizeof(ExtSessionTicket);
        size_t other_ext_len = sizeof(ExtOthers);
        size_t tls_len = buf_len + hello_len + server_name_len
            + host_len + ticket_len + other_ext_len;

        buf.resize(tls_len);
        std::copy_backward(
            buf.begin(),
            buf.begin() + buf_len,
            buf.begin() + hello_len + ticket_len + buf_len
        );

        /* Client Hello Header */
        ClientHello *hello = (ClientHello *)buf.data();
        memcpy(hello, &kClientHelloTemplate, hello_len);
        hello->len = CT_HTONS(tls_len - 5);
        hello->handshake_len_2 = CT_HTONS(tls_len - 9);
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        RandBytes(hello->random_bytes, 28);
        RandBytes(hello->session_id, 32);
        hello->ext_len = CT_HTONS(tls_len - hello_len);

        /* Session Ticket */
        ExtSessionTicket *ticket = (ExtSessionTicket *)((uint8_t *)hello + hello_len);
        memcpy(ticket, &kExtSessionTicketTemplate, ticket_len);
        ticket->session_ticket_ext_len = CT_HTONS(buf_len);

        /* SNI */
        ExtServerName *server_name = (ExtServerName *)((uint8_t *)ticket + ticket_len + buf_len);
        memcpy(server_name, &kExtServerNameTemplate, server_name_len);
        server_name->ext_len = CT_HTONS(host_len + 3 + 2);
        server_name->server_name_list_len = CT_HTONS(host_len + 3);
        server_name->server_name_len = CT_HTONS(host_len);
        memcpy((uint8_t *)server_name + server_name_len, hostname_.data(), host_len);

        /* Other Extensions */
        memcpy((uint8_t *)server_name + server_name_len + host_len, &kExtOthersTemplate,
                other_ext_len);

        obfs_stage_ = 1;
    } else {
        ObfsAppData(buf);
    }

    return buf.size();
}

int TlsObfs::DeObfsResponse(uint8_t *buf, int len) {
    int ret;
    SPDLOG_TRACE("debofs tls response new data {} bytes", len);
    std::copy_n(buf, len, std::back_inserter(buf_));
    len = buf_.size();
    if (!deobfs_stage_) {
        SPDLOG_TRACE("deobfs tls initializing");

        size_t hello_len = sizeof(ServerHello);
        uint8_t *data = buf_.data();

        len -= hello_len;
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        ServerHello *hello = (ServerHello *)data;
        if (hello->content_type != kServerHelloTemplate.content_type) {
            SPDLOG_ERROR("deobfs tls content_type not matching");
            return -1;
        }

        size_t change_cipher_spec_len = sizeof(ChangeCipherSpec);
        size_t encrypted_handshake_len = sizeof(EncryptedHandshake);

        len -= change_cipher_spec_len + encrypted_handshake_len;
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len;
        EncryptedHandshake *encrypted_handshake =
            (EncryptedHandshake *)(data + hello_len + change_cipher_spec_len);
        size_t msg_len = CT_NTOHS(encrypted_handshake->len);

        buf_.erase(buf_.begin(), buf_.begin() + tls_len);

        deobfs_stage_ = 1;
        SPDLOG_TRACE("deobfs tls initializing done");

        if (buf_.size() > msg_len) {
            ret = DeObfsAppData(buf_, msg_len, &extra_);
        } else {
            extra_.idx = buf_.size() - msg_len;
        }
        ret = buf_.size();
        goto __clean_and_exit;
    }

    ret = DeObfsAppData(buf_, 0, &extra_);
__clean_and_exit:
    if (ret > 0) {
        std::copy(buf_.begin(), buf_.end(), buf);
        buf_.clear();
    }
    return ret;
}

int TlsObfs::ObfsResponse(std::vector<uint8_t> &buf) {
    if (!obfs_stage_) {
        SPDLOG_TRACE("obfs tls initializing");

        size_t buf_len = buf.size();
        size_t hello_len = sizeof(ServerHello);
        size_t change_cipher_spec_len = sizeof(ChangeCipherSpec);
        size_t encrypted_handshake_len = sizeof(EncryptedHandshake);
        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len + buf_len;

        buf.resize(tls_len);
        std::copy_backward(
            buf.begin(),
            buf.begin() + buf_len,
            buf.end()
        );

        uint8_t *data = buf.data();

        /* Server Hello */
        memcpy(data, &kServerHelloTemplate, hello_len);
        ServerHello *hello = (ServerHello *)data;
        hello->random_unix_time = CT_HTONL((uint32_t)time(nullptr));
        RandBytes(hello->random_bytes, 28);
        if (session_id_.back()) {
            memcpy(hello->session_id, session_id_.data(), 32);
        } else {
            RandBytes(hello->session_id, 32);
        }

        /* Change Cipher Spec */
        memcpy(data + hello_len, &kChangeCipherSpecTemplate, change_cipher_spec_len);

        /* Encrypted Handshake */
        memcpy(data + hello_len + change_cipher_spec_len, &kEncryptedHandshakeTemplate,
                encrypted_handshake_len);

        EncryptedHandshake *encrypted_handshake =
            (EncryptedHandshake *)(data + hello_len + change_cipher_spec_len);
        encrypted_handshake->len = CT_HTONS(buf_len);

        obfs_stage_ = 1;
        SPDLOG_TRACE("obfs tls initializing done");
    } else {
        ObfsAppData(buf);
    }

    return buf.size();
}

int TlsObfs::DeObfsRequest(uint8_t *buf, int len) {
    int ret;
    SPDLOG_TRACE("debofs tls request new data {} bytes", len);
    std::copy_n(buf, len, std::back_inserter(buf_));
    len = buf_.size();
    if (!deobfs_stage_) {
        SPDLOG_TRACE("deobfs tls initializing");

        uint8_t *data = buf_.data();

        len -= sizeof(ClientHello);
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        ClientHello *hello = (ClientHello *)data;
        if (hello->content_type != kClientHelloTemplate.content_type) {
            SPDLOG_ERROR("deobfs tls type not matched");
            return -1;
        }

        size_t hello_len = CT_NTOHS(hello->len) + 5;

        memcpy(session_id_.data(), hello->session_id, 32);
        session_id_.back() = 1;

        len -= sizeof(ExtSessionTicket);
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        ExtSessionTicket *ticket = (ExtSessionTicket *)(data + sizeof(ClientHello));
        if (ticket->session_ticket_type != kExtSessionTicketTemplate.session_ticket_type) {
            SPDLOG_ERROR("deobfs ticket type not matched");
            return -1;
        }

        size_t ticket_len = CT_NTOHS(ticket->session_ticket_ext_len);
        len -= ticket_len;
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        len -= sizeof(ExtServerName);
        if (len <= 0) {
            SPDLOG_TRACE("deobfs tls need more");
            return 0;
        }

        ExtServerName *sni = (ExtServerName *)((uint8_t *)ticket + sizeof(ExtSessionTicket) + ticket_len);
        if (sni->ext_type == 0) {
            size_t host_len = CT_NTOHS(sni->server_name_len);
            len -= host_len;
            if (len < 0) {
                SPDLOG_TRACE("deobfs tls need more");
                return 0;
            }
        }

        memmove(data, (uint8_t *)ticket + sizeof(ExtSessionTicket), ticket_len);

        if (buf_.size() > hello_len) {
            memmove(data + ticket_len, data + hello_len, buf_.size() - hello_len);
        }
        buf_.resize(buf_.size() + ticket_len - hello_len);

        deobfs_stage_ = 1;
        SPDLOG_TRACE("deobfs tls initializing done");

        if (buf_.size() > ticket_len) {
            ret = DeObfsAppData(buf_, ticket_len, &extra_);
        } else {
            extra_.idx = buf_.size() - ticket_len;
        }
        ret = buf_.size();
        goto __clean_and_exit;
    }

    ret = DeObfsAppData(buf_, 0, &extra_);
__clean_and_exit:
    if (ret > 0) {
        std::copy(buf_.begin(), buf_.end(), buf);
        buf_.clear();
    }
    return ret;
}

ssize_t ObfsAppData(std::vector<uint8_t> &buf) {
    size_t buf_len = buf.size();

    uint8_t frame_header[5];
    uint16_t len = CT_HTONS(buf_len);

    memcpy(frame_header, kDataHeader, 3);
    memcpy(frame_header + 3, &len, sizeof len);

    buf.insert(buf.begin(), frame_header, frame_header + 5);

    return buf.size();
}

ssize_t DeObfsAppData(std::vector<uint8_t> &buf, size_t idx, Frame *frame) {
    size_t bidx = idx, bofst = idx;
    uint8_t *data = buf.data();

    SPDLOG_TRACE("deobfs app data");
    while (bidx < buf.size()) {
        if (frame->len == 0) {
            if (frame->idx >= 0 && frame->idx < 3
                && data[bidx] != kDataHeader[frame->idx]) {
                SPDLOG_ERROR("invalid frame");
                return -1;
            } else if (frame->idx >= 3 && frame->idx < 5) {
                memcpy(frame->buf + frame->idx - 3, data + bidx, 1);
            } else if (frame->idx < 0) {
                bofst++;
            }
            frame->idx++;
            bidx++;
            if (frame->idx == 5) {
                memcpy(&frame->len, frame->buf, 2);
                frame->len = CT_NTOHS(frame->len);
                frame->idx = 0;
            }
            continue;
        }

        if (frame->len > 16384) {
            SPDLOG_ERROR("frame too big {}", frame->len);
            return -2;
        }

        int left_len = buf.size() - bidx;

        if (left_len > frame->len) {
            memmove(data + bofst, data + bidx, frame->len);
            bidx  += frame->len;
            bofst += frame->len;
            frame->len = 0;
        } else {
            memmove(data + bofst, data + bidx, left_len);
            bidx  = buf.size();
            bofst += left_len;
            frame->len -= left_len;
        }
    }

    buf.resize(bofst);

    return buf.size();
}

void RandBytes(uint8_t *buf, size_t len) {
    static std::default_random_engine e{ std::random_device{}() };
    static std::uniform_int_distribution<uint16_t> u{0, 255};
    std::generate_n(buf, len, std::bind(std::ref(u), std::ref(e)));
}

