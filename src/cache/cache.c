#include "cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "const.h"
#include "logger.h"

unsigned int hash_function(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + (unsigned char)(*key++);
    }
    return hash % HASH_TABLE_SIZE;
}

// need to be free by node_free
void node_init(cache_node_t *node, const char *key, stream_t *stream) {
    log_message(LOG_LEVEL_INFO, "Starting \"node_init\"...");
    if (!key || !stream) {
        log_message(LOG_LEVEL_ERROR, "Invalid key or stream provided");
        return;
    }
    node->key = strdup(key);
    node->stream = stream;
    node->hc_next = NULL;
    node->q_next = NULL;
    node->q_prev = NULL;

    log_message(LOG_LEVEL_INFO, "Created cache node successfully");
}

void node_destroy(cache_node_t *node) {
    log_message(LOG_LEVEL_INFO, "Starting \"node_destroy\"...");
    if (!node) {
        log_message(LOG_LEVEL_WARNING, "Node is NULL");
        return;
    }

    if (node->key) {
        free(node->key);
        node->key = NULL;
    }

    if (node->stream) {
        stream_destroy(node->stream);
        node->stream = NULL;
    }

    log_message(LOG_LEVEL_INFO, "Node cleared successfully");
}

void cache_move_to_head(cache_t *cache, cache_node_t *node) {
    log_message(LOG_LEVEL_INFO, "Starting \"move_to_head\"...");
    if (node == cache->q_head) {
        return;
    }

    // delete from current pos
    if (node->q_prev) {
        node->q_prev->q_next = node->q_next;
    }
    if (node->q_next) {
        node->q_next->q_prev = node->q_prev;
    }
    if (node == cache->q_tail) {
        cache->q_tail = node->q_prev;
    }

    // put into head
    node->q_next = cache->q_head;
    node->q_prev = NULL;
    if (cache->q_head) {
        cache->q_head->q_prev = node;
    }
    cache->q_head = node;
    if (!cache->q_tail) {
        cache->q_tail = node;
    }
    log_message(LOG_LEVEL_INFO, "Moving node to head successfully");
}

void cache_evict_tail(cache_t *cache) {
    log_message(LOG_LEVEL_INFO, "Starting \"evict_tail\"...");
    cache_node_t *to_remove = cache->q_tail;

    if (to_remove) {
        // remove from hash table
        size_t remove_index = hash_function(to_remove->key);
        cache_node_t **chain = &cache->hash_table[remove_index];
        while (*chain && *chain != to_remove) {
            chain = &(*chain)->hc_next;
        }
        if (*chain) {
            *chain = to_remove->hc_next;
        }

        // remove from queue
        cache->q_tail = to_remove->q_prev;
        if (cache->q_tail) {
            cache->q_tail->q_next = NULL;
        } else {
            cache->q_head = NULL;
        }

        free(to_remove->key);
        free(to_remove);
        cache->size--;
    }
    log_message(LOG_LEVEL_INFO, "Evict tail node successfully");
}

cache_node_t *cache_put(cache_t *cache, const char *key, int *is_exist) {
    log_message(LOG_LEVEL_INFO, "Starting \"cache_put\"...");
    pthread_rwlock_wrlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock locked to write");
    *is_exist = 0;

    size_t index = hash_function(key);

    // find node associated with this key
    cache_node_t *current = cache->hash_table[index];
    while (current) {
        if (strcmp(current->key, key) == 0) {
            log_message(LOG_LEVEL_WARNING, "Node associated with key already exists");
            *is_exist = 1;
            atomic_fetch_add(&current->stream->connections, 1);

            pthread_rwlock_unlock(&cache->lock);
            log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
            log_message(LOG_LEVEL_INFO, "\"cache_put\" finished");
            return current;
        }
        current = current->hc_next;
    }

    // create new node
    cache_node_t *node = malloc(sizeof(cache_node_t));
    if (!node) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache node");
        pthread_rwlock_unlock(&cache->lock);
        log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
        return NULL;
    }

    stream_t *stream = malloc(sizeof(stream_t));
    if (!stream) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache stream");
        free(node);
        pthread_rwlock_unlock(&cache->lock);
        log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
        return NULL;
    }
    stream_init(stream, STREAM_START_SIZE);
    node_init(node, key, stream);

    // put into hash chain
    node->hc_next = cache->hash_table[index];
    cache->hash_table[index] = node;

    // put into queue head
    node->q_next = cache->q_head;
    if (cache->q_head) {
        cache->q_head->q_prev = node;
    }
    cache->q_head = node;

    if (!cache->q_tail) {
        cache->q_tail = node;
    }

    cache->size++;

    if (cache->size > cache->cap) {
        cache_evict_tail(cache);
    }

    pthread_rwlock_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
    log_message(LOG_LEVEL_INFO, "\"cache_put\" finished successfully");
    return node;
}

stream_t *cache_get_stream(cache_t *cache, const char *key) {
    log_message(LOG_LEVEL_INFO, "Starting \"cache_get_stream\"...");
    pthread_rwlock_rdlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock locked to read");

    size_t index = hash_function(key);
    cache_node_t *current = cache->hash_table[index];

    while (current) {
        if (strcmp(current->key, key) == 0) {
            log_message(LOG_LEVEL_INFO, "Node associated with key found");
            cache_move_to_head(cache, current);

            pthread_rwlock_unlock(&cache->lock);
            log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
            return current->stream;
        }
        current = current->hc_next;
    }

    log_message(LOG_LEVEL_INFO, "Node associated with key not found");
    pthread_rwlock_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
    return NULL; // node not found
}

cache_t *cache_init(size_t cap) {
    log_message(LOG_LEVEL_INFO, "Starting \"cache_init\"...");
    cache_t *cache = (cache_t *) malloc(sizeof(cache_t));
    if (!cache) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache");
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Allocated cache for %lu entries", cap);

    cache->hash_table = (cache_node_t **)calloc(HASH_TABLE_SIZE, sizeof(cache_node_t *));
    if (!cache->hash_table) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache hash table");
        free(cache);
        return NULL;
    }

    cache->q_head = NULL;
    cache->q_tail = NULL;

    cache->cap = cap;
    cache->size = 0;

    if (pthread_rwlock_init(&cache->lock, NULL) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to initialize cache rwlock");
        free(cache->hash_table);
        free(cache);
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "\"cache_init\" finished successfully");
    return cache;
}

cache_node_t *cache_remove(cache_t *cache, const char *key) {
    log_message(LOG_LEVEL_INFO, "Starting \"cache_remove\"...");
    pthread_rwlock_wrlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock locked to write");

    size_t index = hash_function(key);
    cache_node_t **chain = &cache->hash_table[index];
    cache_node_t *current = *chain;

    while (current) {
        if (strcmp(current->key, key) == 0) {
            log_message(LOG_LEVEL_INFO, "Node associated with key found");

            // remove from hash chain
            *chain = current->hc_next;

            // remove from queue
            if (current->q_prev) {
                current->q_prev->q_next = current->q_next;
            }
            if (current->q_next) {
                current->q_next->q_prev = current->q_prev;
            }
            if (current == cache->q_head) {
                cache->q_head = current->q_next;
            }
            if (current == cache->q_tail) {
                cache->q_tail = current->q_prev;
            }

            cache->size--;
            pthread_rwlock_unlock(&cache->lock);
            log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
            log_message(LOG_LEVEL_INFO, "\"cache_remove\" finished successfully");
            return current;
        }
        chain = &current->hc_next;
        current = current->hc_next;
    }

    log_message(LOG_LEVEL_INFO, "Node associated with key not found");
    pthread_rwlock_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
    return NULL; // node not found
}

void cache_destroy(cache_t *cache) {
    log_message(LOG_LEVEL_INFO, "Starting \"cache_destroy\"...");
    if (!cache) {
        log_message(LOG_LEVEL_WARNING, "Cache is not initialized");
        return;
    }
    pthread_rwlock_wrlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock locked to write");

    cache_node_t *node = cache->q_head;
    while (node) {
        cache_node_t *next = node->q_next;
        node_destroy(node);
        node = next;
    }
    free(cache->hash_table);

    pthread_rwlock_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Cache rwlock unlocked");
    pthread_rwlock_destroy(&cache->lock);

    free(cache);
    log_message(LOG_LEVEL_INFO, "Cache destroyed successfully");
}