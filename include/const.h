#ifndef CONST_H
#define CONST_H

#define HTTP "http"
#define HOST "Host:"
#define END_STR '\0'

enum {
    MAX_BUFFER_SIZE = 1024 * 16,                // 16 KB
    PORT = 8080,
    HOST_SIZE = 50,
    MAX_USERS_COUNT = 10,
    MAX_CACHE_RECORD_SIZE = 1024 * 1024 * 4,    // 4 MB
    WAIT_SERVER_RESPONSE_TIMEOUT = 1000,        // in ms
    CACHE_RECORD_TTL = 300,                     // in sec
    CACHE_SIZE = 1024,
    HASH_TABLE_SIZE = CACHE_SIZE * 2,
};

enum error {
    SOCKET_ERROR = -1,
    SEND_ERROR = -1,
    LISTEN_ERROR = -1,
    BIND_ERROR = -1,
    WRITE_ERROR = -1,
    NOT_FOUND_CACHE = -1,
    ADD_INFO_STATUS_ERROR = 0,
    PTHREAD_ERROR = -1,
    CACHE_ERROR = -1,
};

#endif //CONST_H