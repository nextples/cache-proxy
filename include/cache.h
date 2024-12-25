#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <pthread.h>

#include "stream.h"

typedef struct cache_node {
    char *key;                      // request
    stream_t *stream;

    struct cache_node *q_prev;
    struct cache_node *q_next;
    struct cache_node *hc_next;     // hash-chain next
} cache_node_t;

typedef struct cache {
    cache_node_t **hash_table;
    cache_node_t *q_head;
    cache_node_t *q_tail;

    size_t cap;
    size_t size;

    pthread_rwlock_t lock;
} cache_t;

cache_t *cache_init(size_t cap);

void node_init(cache_node_t *node, const char *key, stream_t *stream);

void node_destroy(cache_node_t *node);

int cache_put(cache_t *cache, const char *key);

stream_t *cache_get_stream(cache_t *cache, const char *key);

void cache_destroy(cache_t *cache);

#endif //CACHE_H
