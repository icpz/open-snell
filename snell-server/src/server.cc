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
#include "obfs/http.hh"
#include "obfs/tls.hh"

void SetupLogLevel(int verbose);
void StartServer(asio::ip::address bind_address, int port, std::string_view psk, std::shared_ptr<Obfuscator> obfs);

int main(int argc, char *argv[]) {
    cxxopts::Options opts{argv[0], "Unofficial Snell Server"};
    opts.add_options()
        ("b,bind", "Bind Address",
                    cxxopts::value<std::string>()->default_value("0.0.0.0"),
                    "Address")
        ("p,port",    "Listening Port", cxxopts::value<int>(), "Port")
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

    auto bind_address = asio::ip::make_address(args["bind"].as<std::string>());
    auto port         = args["port"].as<int>();
    auto psk          = args["key"].as<std::string>();

    std::shared_ptr<Obfuscator> obfs_tmpl = nullptr;

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

    StartServer(bind_address, port, psk, obfs_tmpl);

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

void StartServer(asio::ip::address bind_address, int port, std::string_view psk, std::shared_ptr<Obfuscator> tmpl) {
    asio::io_context ctx{1};
    asio::ip::tcp::acceptor acceptor{ctx, {bind_address, static_cast<uint16_t>(port)}};

    asio::signal_set signals(ctx, SIGTERM, SIGINT);

    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });
    SPDLOG_INFO("start listening at [{}]:{}", bind_address.to_string(), port);
    asio::co_spawn(
        ctx,
        [acceptor = std::move(acceptor), psk, tmpl]() mutable {
            return Listener(std::move(acceptor), psk, tmpl);
        },
        asio::detached
    );

    ctx.run();
}
