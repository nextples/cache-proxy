#ifndef CONST_H
#define CONST_H

#define HTTP "http"
#define HOST "Host:"
#define END_STR '\0'

enum {
    MAX_BUFFER_SIZE = 1024 * 8,                 // 8 KB
    MAX_REQUEST_SIZE = 1024 * 64,               // 64 KB
    PORT = 8080,
    HOST_SIZE = 256 * sizeof(char),
    MAX_USERS_COUNT = 10,
    CACHE_SIZE = 1024,
    HASH_TABLE_SIZE = CACHE_SIZE * 2,
    STREAM_START_SIZE = 1024 * 1024,            // 1 MB
};

enum error {
    SOCKET_ERROR = -1,
    LISTEN_ERROR = -1,
    BIND_ERROR = -1,
    WRITE_ERROR = -1,
    ADDR_INFO_STATUS_ERROR = 0,
    PTHREAD_ERROR = -1,
};

#endif //CONST_H