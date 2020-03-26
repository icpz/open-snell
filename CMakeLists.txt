cmake_minimum_required(VERSION 3.13)
project(snell)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines-ts -Wall")

set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET GLOBAL libsodium)

add_subdirectory(third_party)

add_subdirectory(snell-server)

