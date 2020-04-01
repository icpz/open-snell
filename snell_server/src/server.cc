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


#include <cxxopts.hpp>
#include <spdlog/spdlog.h>
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/awaitable.hpp>

#include "session.hh"
#include "ini.hh"
#include "obfs/http.hh"
#include "obfs/tls.hh"

void SetupLogLevel(int verbose);
void StartServer(asio::ip::tcp::endpoint ep, std::string_view psk, std::shared_ptr<Obfuscator> tmpl);
asio::ip::tcp::endpoint ParseIpPort(std::string_view s, asio::error_code &ec);

int main(int argc, char *argv[]) {
    cxxopts::Options opts{argv[0], "Unofficial Snell Server"};
    opts.add_options()
        ("c,config",  "Configuration File", cxxopts::value<std::string>(), "Config")
        ("l,listen",  "Listening Address", cxxopts::value<std::string>(), "Ip:Port")
        ("k,key",     "Pre-shared Key", cxxopts::value<std::string>(), "Key")
        ("v,verbose", "Logging Level")
        ("obfs",      "Obfuscator Method", cxxopts::value<std::string>(), "ObfsMethod")
        ("obfs-host", "Obfs Hostname",
                      cxxopts::value<std::string>()->default_value("www.bing.com"),
                      "ObfsHost")
        ("h,help",    "Print Help");

    auto args = opts.parse(argc, argv);

    if (args.count("help")) {
        std::cout << opts.help() << std::endl;
        std::exit(0);
    }

    spdlog::set_pattern("%^%L %D %T.%f %t %@] %v%$");
    SetupLogLevel(args.count("verbose"));

    std::shared_ptr<Obfuscator> obfs_tmpl = nullptr;
    std::string listen;
    std::string psk;

    if (args.count("config")) {
        SPDLOG_INFO("configuration file specified, ignore other cli options");

        auto cf = INI::FromFile(args["config"].as<std::string>());
        if (!cf) {
            SPDLOG_CRITICAL("failed to parse configuration file {}", args["config"].as<std::string>());
            return -1;
        }

        listen = cf->Get("snell-server", "listen", "");
        psk    = cf->Get("snell-server", "psk", "");
        if (cf->Exists("snell-server", "obfs")) {
            auto obfs = cf->Get("snell-server", "obfs", "");
            auto obfs_host = cf->Get("snell-server", "obfs-host", "www.bing.com");
            if (obfs == "http") {
                SPDLOG_INFO("using obfs method {}, obfs-host {}", obfs, obfs_host);
                obfs_tmpl = NewHttpObfs(obfs_host);
            } else if (obfs == "tls") {
                SPDLOG_INFO("using obfs method {}, obfs-host {}", obfs, obfs_host);
                obfs_tmpl = NewTlsObfs(obfs_host);
            } else {
                SPDLOG_WARN("unknown obfs method {}, disable obfs", obfs);
            }
        }
    } else {
        listen = args["listen"].as<std::string>();
        psk = args["key"].as<std::string>();
        if (args.count("obfs")) {
            auto obfs = args["obfs"].as<std::string>();
            auto obfs_host = args["obfs-host"].as<std::string>();
            if (obfs == "http") {
                SPDLOG_INFO("using obfs method {}, obfs-host {}", obfs, obfs_host);
                obfs_tmpl = NewHttpObfs(obfs_host);
            } else if (obfs == "tls") {
                SPDLOG_INFO("using obfs method {}, obfs-host {}", obfs, obfs_host);
                obfs_tmpl = NewTlsObfs(obfs_host);
            } else {
                SPDLOG_WARN("unknown obfs method {}, disable obfs", obfs);
            }
        }
    }
    if (listen.empty() || psk.empty()) {
        SPDLOG_CRITICAL("listening address and psk should not be empty");
        return -1;
    }

    asio::error_code ec;
    auto ep = ParseIpPort(listen, ec);
    if (ec) {
        SPDLOG_CRITICAL("failed to parse ip:port {}, {}", listen, ec.message());
        return -1;
    }
    StartServer(std::move(ep), psk, obfs_tmpl);

    return 0;
}

void SetupLogLevel(int verbose) {
    auto level = spdlog::level::info;

    if (verbose > level) {
        verbose = level;
    }
    level = static_cast<decltype(level)>(level - verbose);
    spdlog::set_level(level);
}

static asio::awaitable<void>
    Listener(asio::ip::tcp::acceptor acceptor, std::string_view psk, std::shared_ptr<Obfuscator> tmpl) {
        while (true) {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            SPDLOG_DEBUG("accepted a new connection");
            decltype(tmpl) obfs = nullptr;
            if (tmpl) {
                obfs = tmpl->Duplicate();
            }
            SnellServerSession::New(std::move(socket), psk, obfs)->Start();
        }
    }

void StartServer(asio::ip::tcp::endpoint ep, std::string_view psk, std::shared_ptr<Obfuscator> tmpl) {
    asio::io_context ctx{1};
    auto bind_address = ep.address().to_string();
    auto port = ep.port();
    asio::ip::tcp::acceptor acceptor{ctx, std::move(ep)};

    asio::signal_set signals(ctx, SIGTERM, SIGINT);

    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });
    SPDLOG_INFO("start listening at [{}]:{}", bind_address, port);
    asio::co_spawn(
        ctx,
        [acceptor = std::move(acceptor), psk, tmpl]() mutable {
            return Listener(std::move(acceptor), psk, tmpl);
        },
        asio::detached
    );

    ctx.run();
}

asio::ip::tcp::endpoint ParseIpPort(std::string_view s, asio::error_code &ec) {
    ec.clear();
    auto pos = s.find_last_of(":");
    if (pos == std::string_view::npos) {
        ec = asio::error::invalid_argument;
        SPDLOG_ERROR("invalid listen address {}", s);
        return asio::ip::tcp::endpoint{};
    }
    auto port_string = s.substr(pos + 1);
    auto ip_string   = s.substr(0, pos);
    if (ip_string[0] == '[') {
        ip_string = ip_string.substr(1, ip_string.size() - 2);
    }
    auto ip   = asio::ip::make_address(ip_string, ec);
    auto port = static_cast<uint16_t>(std::stoul(std::string{port_string}));
    if (!ec) {
        return asio::ip::tcp::endpoint{ip, port};
    }
    return asio::ip::tcp::endpoint{};
}
