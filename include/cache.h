#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <pthread.h>

typedef struct cache_node_t {
    char *key;                      // request
    char *response;
    size_t response_size;
    time_t expires_at;              // time during which the cache is considered relevant
    struct cache_node_t *prev;
    struct cache_node_t *next;
    struct cache_node_t *hash_next;
} cache_node_t;

typedef struct {
    cache_node_t **hash_table;
    cache_node_t *head;
    cache_node_t *tail;
    size_t max_size;
    size_t current_size;
    pthread_mutex_t lock;
} cache_t;

cache_node_t *create_cache_node(const char *key, const char *response, const size_t response_size, const time_t expires_at);

void free_cache_node(cache_node_t *node);

cache_t *create_cache(size_t max_size);

int cache_put(cache_t *cache, cache_node_t *new_node);

cache_node_t *cache_get(cache_t *cache, const char *key);

void delete_cache(cache_t *cache);

#endif //CACHE_H
