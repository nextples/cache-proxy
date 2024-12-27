#ifndef PROXY_H
#define PROXY_H

#include <semaphore.h>

#include "cache.h"

typedef struct {
    int client_socket;
    char *request;
    cache_t *cache;
    cache_node_t *node;
    sem_t *semaphore;
} context_t;

void run_proxy();

void free_context(context_t *ctx);

#endif //PROXY_H
