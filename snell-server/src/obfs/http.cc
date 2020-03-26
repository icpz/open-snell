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

#include <stdint.h>
#include <string.h>
#include <ctime>
#include <algorithm>
#include <random>
#include <functional>
#include <string_view>

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

#include "obfs.hh"

class HttpObfs : public Obfuscator {
public:

    HttpObfs(std::string_view hostname, uint16_t port, std::string_view obfs_uri) {
        host_port_ = hostname;
        obfs_uri_ = obfs_uri;
        if (port != 80) {
            host_port_ += ":" + std::to_string(port);
        }
    }

    HttpObfs(const HttpObfs &o)
        : host_port_{o.host_port_},
          obfs_uri_{o.obfs_uri_},
          port_{o.port_}
    {
    }

    ~HttpObfs() = default;

    int ObfsRequest(std::vector<uint8_t> &buf);
    int DeObfsResponse(uint8_t *buf, int len);

    int ObfsResponse(std::vector<uint8_t> &buf);
    int DeObfsRequest(uint8_t *buf, int len);

    std::shared_ptr<Obfuscator> Duplicate() const {
        return std::make_shared<HttpObfs>(*this);
    }

private:
    void DeObfsHeader();

    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    std::string host_port_;
    std::string_view obfs_uri_;
    std::vector<uint8_t> buf_;
    uint16_t port_;
};

std::shared_ptr<Obfuscator>
    NewHttpObfs(std::string_view host, uint16_t port, std::string_view uri) {
        return std::make_shared<HttpObfs>(host, port, uri);
    }

static auto kHttpRequestTemplate = \
    "GET {:s} HTTP/1.1\r\n"
    "Host: {:s}\r\n"
    "User-Agent: curl/7.{:d}.{:d}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: {:s}\r\n"
    "Content-Length: {}\r\n"
    "\r\n";

static auto kHttpResponseTemplate = \
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.{}.{}\r\n"
    "Date: {}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: {}\r\n"
    "\r\n";

static std::default_random_engine kEngine{ std::random_device{}() };

static void RandB64(char *buf, size_t len);
static int CheckHeader(std::vector<uint8_t> &buf);
static int GetHeader(const char *header, const char *data, size_t len, std::string &value);

int HttpObfs::ObfsRequest(std::vector<uint8_t> &buf) {
    if (obfs_stage_) {
        return buf.size();
    }
    obfs_stage_ = 1;

    static int kMajorVersion = kEngine() % 51;
    static int kMinorVersion = kEngine() % 2;

    char b64[25];
    RandB64(b64, (sizeof b64) - 1);
    b64[24] = 0;

    auto obfs_buf = \
        fmt::format(
            kHttpRequestTemplate,
            obfs_uri_, host_port_,
            kMajorVersion, kMinorVersion,
            b64, buf.size()
        );
    buf.insert(buf.begin(), obfs_buf.begin(), obfs_buf.end());

    return buf.size();
}

int HttpObfs::DeObfsResponse(uint8_t *buf, int len) {
    int ret;
    std::copy_n(buf, len, std::back_inserter(buf_));
    DeObfsHeader();
    if ((ret = buf_.size()) > 0) {
        std::copy(buf_.begin(), buf_.end(), buf);
        buf_.clear();
    }
    return ret;
}

int HttpObfs::ObfsResponse(std::vector<uint8_t> &buf) {
    if (obfs_stage_) {
        return buf.size();
    }
    obfs_stage_ = 1;

    static int kMajorVersion = kEngine() % 11;
    static int kMinorVersion = kEngine() % 12;

    char datetime[64];
    char b64[25];

    std::time_t now;
    std::tm *tm_now;

    std::time(&now);
    tm_now = std::localtime(&now);
    std::strftime(datetime, sizeof datetime, "%a, %d %b %Y %H:%M:%S GMT", tm_now);

    RandB64(b64, (sizeof b64) - 1);
    b64[24] = 0;

    auto obfs_buf = \
        fmt::format(
            kHttpResponseTemplate,
            kMajorVersion,
            kMinorVersion,
            datetime,
            b64
        );
    buf.insert(buf.begin(), obfs_buf.begin(), obfs_buf.end());

    return buf.size();
}

int HttpObfs::DeObfsRequest(uint8_t *buf, int len) {
    if (deobfs_stage_) {
        return len;
    }

    std::copy_n(buf, len, std::back_inserter(buf_));
    int check_result = CheckHeader(buf_);
    if (check_result <= 0) {
        if (check_result == 0) {
            SPDLOG_DEBUG("deobfs request need more");
        } else {
            SPDLOG_ERROR("deobfs check header failed");
        }
        return check_result;
    }
    DeObfsHeader();
    int ret;
    if ((ret = buf_.size()) > 0) {
        std::copy(buf_.begin(), buf_.end(), buf);
        buf_.clear();
    }
    return ret;
}

void HttpObfs::DeObfsHeader() {
    if (deobfs_stage_) {
        return;
    }

    char *data = (char *)buf_.data();
    int len = buf_.size();
    size_t unused_length = 0;

    while (len >= 4) {
        if (data[0] == '\r' && data[1] == '\n'
            && data[2] == '\r' && data[3] == '\n') {
            len  -= 4;
            data += 4;
            unused_length += 4;
            deobfs_stage_ = 1;
            break;
        }
        len--;
        data++;
        unused_length++;
    }

    if (unused_length) {
        buf_.erase(buf_.begin(), buf_.begin() + unused_length);
    }
    return;
}

int CheckHeader(std::vector<uint8_t> &buf) {
    char *data = (char *)buf.data();
    int len = buf.size();

    SPDLOG_TRACE("obfs http checking header");
    if (len < 4) {
        SPDLOG_TRACE("obfs http checking header need more");
        return 0;
    }

    if (strncasecmp(data, "GET", 3) != 0) {
        SPDLOG_ERROR("obfs http method mismatch {}", std::string_view{data, 3});
        return -1;
    }

    {
        std::string protocol;
        int result = GetHeader("Upgrade:", data, len, protocol);
        if (result <= 0) {
            if (result == 0) {
                SPDLOG_TRACE("obfs http checking header need more");
            } else {
                SPDLOG_ERROR("obfs http upgrade field not found");
            }
            return result;
        }
        if (strncmp(protocol.c_str(), "websocket", result) != 0) {
            SPDLOG_ERROR("obfs http protocol mismatch {}", protocol);
            return -1;
        }
    }

    return buf.size();
}

void RandB64(char *buf, size_t len) {
    static const char kB64Chars[] = \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static std::uniform_int_distribution<> u{ 0, (sizeof kB64Chars) - 2 };

    auto last = std::generate_n(buf, len - 2, [&]() { return kB64Chars[u(kEngine)]; });
    if (kEngine() % 2) {
        *last++ = '=';
        *last = '=';
        return;
    }
    *last++ = kB64Chars[u(kEngine)];
    if (kEngine() % 2) {
        *last = '=';
        return;
    }
    *last = kB64Chars[u(kEngine)];
}

int NextHeader(const char **data, size_t *len) {
    int header_len;

    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    *data += 2;
    *len  -= 2;

    header_len = 0;
    while (*len > (size_t)(header_len + 1)
           && (*data)[header_len] != '\r'
           && (*data)[header_len + 1] != '\n') {
        header_len++;
    }

    return header_len;

}

int GetHeader(const char *header, const char *data, size_t data_len, std::string &value) {
    int len, header_len;

    header_len = strlen(header);

    while ((len = NextHeader(&data, &data_len)) != 0) {
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            while (header_len < len && isblank((uint8_t)data[header_len])) {
                header_len++;
            }

            value.append(data + header_len, len - header_len);

            return value.size();
        }
    }

    if (data_len == 0) {
        return 0;
    }

    return -1;
}

