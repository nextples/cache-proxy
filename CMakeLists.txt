cmake_minimum_required(VERSION 3.29)
project(cache_proxy C)

set(CMAKE_C_STANDARD 17)

include(FetchContent)

add_executable(cache_proxy src/main.c
        include/cache.h
        src/cache/cache.c
        include/const.h
        include/server.h
        include/proxy.h
        include/logger.h
        include/utils.h
        src/utils/logger.c
        src/net/server.c
        src/utils/utils.c
        src/net/proxy.c)

include_directories(${CMAKE_SOURCE_DIR}/include)

FetchContent_Declare(
        llhttp
        URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v8.1.0.tar.gz"
)

set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")

FetchContent_MakeAvailable(llhttp)

target_include_directories(cache_proxy PRIVATE ${llhttp_SOURCE_DIR}/include)

target_link_libraries(cache_proxy PRIVATE llhttp_static)