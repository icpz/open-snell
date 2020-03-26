cmake_minimum_required(VERSION 3.13)
project(third_party)

include(ExternalProject)

ExternalProject_Add(asio_project
    GIT_REPOSITORY    https://github.com/chriskohlhoff/asio
    GIT_TAG           asio-1-14-0
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    EXCLUDE_FROM_ALL  TRUE
)
ExternalProject_Get_property(asio_project SOURCE_DIR)
add_library(asio INTERFACE)
add_dependencies(asio asio_project)
file(MAKE_DIRECTORY ${SOURCE_DIR}/asio/include)
target_include_directories(asio INTERFACE ${SOURCE_DIR}/asio/include)



ExternalProject_Add(cxxopts_project
    GIT_REPOSITORY    https://github.com/jarro2783/cxxopts
    GIT_TAG           v2.0.0
    CMAKE_ARGS        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                      -DCXXOPTS_BUILD_TESTS=OFF
                      -DCXXOPTS_BUILD_EXAMPLES=OFF
    STEP_TARGETS      build install
    EXCLUDE_FROM_ALL  TRUE
)
ExternalProject_Get_property(cxxopts_project INSTALL_DIR)
add_library(cxxopts INTERFACE)
add_dependencies(cxxopts cxxopts_project-install)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
target_include_directories(cxxopts INTERFACE ${INSTALL_DIR}/include)
target_compile_options(cxxopts INTERFACE "-Wno-return-std-move")



ExternalProject_Add(spdlog_project
    GIT_REPOSITORY    https://github.com/gabime/spdlog
    GIT_TAG           v1.5.0
    CMAKE_ARGS        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                      -DCMAKE_BUILD_TYPE=Release
                      -DSPDLOG_BUILD_EXAMPLE=OFF
                      -DSPDLOG_BUILD_TESTS=OFF
    INSTALL_COMMAND   make install > /dev/null
    STEP_TARGETS      build install
    EXCLUDE_FROM_ALL  TRUE
)
ExternalProject_Get_property(spdlog_project INSTALL_DIR)
add_library(spdlog STATIC IMPORTED GLOBAL)
set_target_properties(spdlog PROPERTIES
    IMPORTED_LOCATION ${INSTALL_DIR}/lib/libspdlog.a
)
add_dependencies(spdlog spdlog_project-install)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
target_include_directories(spdlog INTERFACE ${INSTALL_DIR}/include)
target_compile_definitions(spdlog INTERFACE -DSPDLOG_COMPILED_LIB -DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE)

