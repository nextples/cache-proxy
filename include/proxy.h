#ifndef PROXY_H
#define PROXY_H

#include <semaphore.h>

#include "cache.h"

typedef struct {
    int client_socket;
    char *request;
    cache_t *cache;
    sem_t *semaphore;
} context_t;

typedef struct {
    int status_code;
    long content_length;
} response_headers_t;

void run_proxy();

void free_context(context_t *ctx);

#endif //PROXY_H
