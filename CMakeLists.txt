cmake_minimum_required(VERSION 3.29)
project(cache_proxy C)

set(CMAKE_C_STANDARD 17)

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