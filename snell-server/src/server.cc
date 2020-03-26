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

void SetupLogLevel(int verbose);
void StartServer(asio::ip::address bind_address, int port, std::string_view psk);

int main(int argc, char *argv[]) {
    cxxopts::Options opts{argv[0], "Unofficial Snell Server"};
    opts.add_options()
        ("b,bind", "Bind Address",
                    cxxopts::value<std::string>()->default_value("0.0.0.0"),
                    "Address")
        ("p,port",    "Listening Port", cxxopts::value<int>(), "Port")
        ("k,key",     "Pre-shared Key", cxxopts::value<std::string>(), "Key")
        ("v,verbose", "Logging Level")
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

    StartServer(bind_address, port, psk);

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

static asio::awaitable<void> Listener(asio::ip::tcp::acceptor acceptor, std::string_view psk) {
    while (true) {
        auto socket = co_await acceptor.async_accept(asio::use_awaitable);
        SPDLOG_DEBUG("accepted a new connection");
        SnellServerSession::New(std::move(socket), psk)->Start();
    }
}

void StartServer(asio::ip::address bind_address, int port, std::string_view psk) {
    asio::io_context ctx{1};
    asio::ip::tcp::acceptor acceptor{ctx, {bind_address, static_cast<uint16_t>(port)}};

    asio::signal_set signals(ctx, SIGTERM, SIGINT);

    signals.async_wait([&ctx](auto, auto) { ctx.stop(); });
    SPDLOG_INFO("start listening at [{}]:{}", bind_address.to_string(), port);
    asio::co_spawn(
        ctx,
        [acceptor = std::move(acceptor), psk]() mutable {
            return Listener(std::move(acceptor), psk);
        },
        asio::detached
    );

    ctx.run();
}
