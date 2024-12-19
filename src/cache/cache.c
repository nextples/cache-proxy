#include "../../include/cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../include/const.h"
#include "../../include/logger.h"

//TODO: перейти на потокобезопасную систему
//TODO: реализовать функцию для отслеживания состояния кэша
//TODO: реализовать GC

void remove_cache_node(cache_t *cache, cache_node_t *node_to_remove);
void remove_expired_nodes(cache_t *cache);

// Функция хеширования
unsigned int hash_function(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + (unsigned char)(*key++);
    }
    return hash % HASH_TABLE_SIZE;
}

// Создание новой ноды
cache_node_t *create_cache_node(const char *key, const char *response, const size_t response_size, const time_t expires_at) {
    cache_node_t *node = (cache_node_t *)malloc(sizeof(cache_node_t));
    if (!node) {
        log_message(LOG_LEVEL_WARNING, "Failed to allocate memory for cache node");
        return NULL;
    }
    node->key = strdup(key);
    if (!node->key) {
        log_message(LOG_LEVEL_WARNING, "Failed to duplicate key into node");
        free(node);
        return NULL;
    }
    node->response = (char *)malloc(response_size);
    if (!node->response) {
        log_message(LOG_LEVEL_WARNING, "Failed to allocate memory for response");
        free(node->key);
        free(node);
        return NULL;
    }
    memcpy(node->response, response, response_size);
    node->response_size = response_size;
    node->expires_at = expires_at;
    node->prev = node->next = node->hash_next = NULL;
    log_message(LOG_LEVEL_INFO, "Created cache node successfully");
    return node;
}

// Удаление ноды
void free_cache_node(cache_node_t *node) {
    if (node) {
        free(node->key);
        free(node->response);
        free(node);
    }
}

// Создание кэша
cache_t *create_cache(size_t max_size) {
    cache_t *cache = (cache_t *) malloc(sizeof(cache_t));
    if (!cache) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache");
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Allocated cache for %lu entries", max_size);

    cache->hash_table = (cache_node_t **)calloc(HASH_TABLE_SIZE, sizeof(cache_node_t *));
    if (!cache->hash_table) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for cache hash table");
        free(cache);
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Allocated memory for hash table");

    cache->head = cache->tail = NULL;
    cache->max_size = max_size;
    cache->current_size = 0;

    if (pthread_mutex_init(&cache->lock, NULL) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to initialize mutex");
        free(cache->hash_table);
        free(cache);
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Mutex initialized successfully");

    return cache;
}

// Перемещение ноды в конец списка
// not thread safety function, use only under mutex
void move_to_tail(cache_t *cache, cache_node_t *node) {
    if (cache->tail == node) {
        return; // Уже в конце
    }

    // Удалить ноду из текущей позиции
    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    if (cache->head == node) {
        cache->head = node->next;
    }

    // Добавить ноду в конец
    node->prev = cache->tail;
    node->next = NULL;
    if (cache->tail) {
        cache->tail->next = node;
    }
    cache->tail = node;
}

// Удаление устаревшей ноды
// not thread safety function. Use only under mutex
void remove_head(cache_t *cache) {

    if (!cache->head) return;

    cache_node_t *node = cache->head;
    cache->head = node->next;
    if (cache->head) cache->head->prev = NULL;
    else cache->tail = NULL;

    unsigned int hash = hash_function(node->key);
    cache_node_t **bucket = &cache->hash_table[hash];
    cache_node_t *current = *bucket;
    cache_node_t *prev = NULL;

    // Удалить ноду из хеш-цепочки
    while (current) {
        if (current == node) {
            if (prev) {
                prev->hash_next = current->hash_next;
            } else {
                *bucket = current->hash_next;
            }
            break;
        }
        prev = current;
        current = current->hash_next;
    }

    free_cache_node(node);
    cache->current_size--;
}

int is_empty(const cache_t *cache) {
    return cache->current_size == 0;
}

int is_full(const cache_t *cache) {
    return cache->current_size == cache->max_size;
}

// Добавление записи в кэш
int cache_put(cache_t *cache, cache_node_t *new_node) {
    pthread_mutex_lock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Lock cache mutex while put node");

    if (is_full(cache)) {
        remove_expired_nodes(cache);
    }

    if (!cache || !new_node) {
        log_message(LOG_LEVEL_WARNING, "Invalid arguments to cache_get");
        pthread_mutex_unlock(&cache->lock);
        log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while put node");
        return CACHE_ERROR;
    }

    unsigned int hash = hash_function(new_node->key);
    log_message(LOG_LEVEL_DEBUG, "Hash function returned %lu", hash);
    cache_node_t **bucket = &cache->hash_table[hash];
    cache_node_t *node = *bucket;

    // Если запись уже существует, обновить её
    while (node) {
        if (strcmp(node->key, new_node->key) == 0) {
            log_message(LOG_LEVEL_DEBUG, "Node already exists. Cache will be update");
            free(node->response);
            node->response = (char *)malloc(new_node->response_size);
            if (!node->response) {
                log_message(LOG_LEVEL_WARNING, "Failed to allocate memory for response update");
                pthread_mutex_unlock(&cache->lock);
                log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while put node");
                return CACHE_ERROR;
            }
            memcpy(node->response, new_node->response, new_node->response_size);
            node->response_size = new_node->response_size;
            node->expires_at = new_node->expires_at;

            move_to_tail(cache, node);
            log_message(LOG_LEVEL_DEBUG, "Updated cache node moved to the tail");
            pthread_mutex_unlock(&cache->lock);
            log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while put node");
            return 0;
        }
        node = node->hash_next;
    }

    log_message(LOG_LEVEL_DEBUG, "Response was not found in cache. Node will be pushed");
    // Если кэш переполнен, удалить самую старую запись
    if (cache->current_size >= cache->max_size) {
        log_message(LOG_LEVEL_INFO, "Cache is full. Start removing head");
        remove_head(cache);
        log_message(LOG_LEVEL_INFO, "Cache head node was removed");
        log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
    }

    // Добавить новую запись
    new_node->hash_next = *bucket;
    *bucket = new_node;

    if (cache->tail) {
        cache->tail->next = new_node;
        new_node->prev = cache->tail;
    } else {
        cache->head = new_node;
    }
    cache->tail = new_node;
    cache->current_size++;

    log_message(LOG_LEVEL_INFO, "Cache node was added successfully");
    log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);

    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while put node");
    return 0;
}

// Получение записи из кэша
cache_node_t *cache_get(cache_t *cache, const char *key) {
    pthread_mutex_lock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Lock cache mutex while getting node");

    if (!cache || !key) {
        log_message(LOG_LEVEL_WARNING, "Invalid arguments to cache_get");
        return NULL;
    }

    unsigned int hash = hash_function(key);
    log_message(LOG_LEVEL_DEBUG, "Hash function returned %lu", hash);
    cache_node_t *node = cache->hash_table[hash];

    if (node) {
        log_message(LOG_LEVEL_DEBUG, "Cache-chain found successfully");
    }
    else {
        log_message(LOG_LEVEL_DEBUG, "No cache-chain found");
    }

    while (node) {
        if (strcmp(node->key, key) == 0) {
            log_message(LOG_LEVEL_DEBUG, "Node found in chain successfully");
            if (node->expires_at < time(NULL)) {

                // Если запись устарела, удалить её
                remove_cache_node(cache, node);

                log_message(LOG_LEVEL_DEBUG, "Cached data was expired. Cache node removed successfully");
                pthread_mutex_unlock(&cache->lock);
                log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while getting node");
                return NULL;

            }
            move_to_tail(cache, node);
            log_message(LOG_LEVEL_DEBUG, "Node was moved to the tail");

            pthread_mutex_unlock(&cache->lock);
            log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while getting node");
            return node;
        }
        node = node->hash_next;
    }

    pthread_mutex_unlock(&cache->lock);
    log_message(LOG_LEVEL_DEBUG, "Unlock cache mutex while getting node");
    return NULL;
}

// not thread safety function, use only under mutex
void remove_cache_node(cache_t *cache, cache_node_t *node_to_remove) {
    if (!cache || !node_to_remove) {
        log_message(LOG_LEVEL_WARNING, "Invalid arguments to remove_cache_node");
        return;
    }

    // Удаление из двусвязного списка
    if (node_to_remove->prev) {
        node_to_remove->prev->next = node_to_remove->next;
    } else {
        cache->head = node_to_remove->next; // Если нода была головой
    }

    if (node_to_remove->next) {
        node_to_remove->next->prev = node_to_remove->prev;
    } else {
        cache->tail = node_to_remove->prev; // Если нода была хвостом
    }

    // Удаление из хэш-таблицы
    unsigned int hash = hash_function(node_to_remove->key);
    cache_node_t **bucket = &cache->hash_table[hash];
    cache_node_t *current = *bucket;
    cache_node_t *prev = NULL;

    while (current) {
        if (current == node_to_remove) {
            if (prev) {
                prev->hash_next = current->hash_next;
            } else {
                *bucket = current->hash_next;
            }
            break;
        }
        prev = current;
        current = current->hash_next;
    }

    // Удаляем ноду из памяти
    free_cache_node(node_to_remove);

    // Обновляем текущий размер кэша
    cache->current_size--;

    log_message(LOG_LEVEL_INFO, "Cache node removed successfully");
    log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
}


// Удаление кэша
void delete_cache(cache_t *cache) {
    pthread_mutex_lock(&cache->lock);

    if (!cache) return;

    cache_node_t *node = cache->head;
    while (node) {
        cache_node_t *next = node->next;
        free_cache_node(node);
        node = next;
    }
    free(cache->hash_table);

    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);

    free(cache);
    log_message(LOG_LEVEL_INFO, "Cache was removed");
}

// not thread safety function. use only under mutex
void remove_expired_nodes(cache_t *cache) {
    if (!cache) {
        log_message(LOG_LEVEL_WARNING, "Invalid cache pointer in remove_expired_nodes");
        return;
    }

    log_message(LOG_LEVEL_DEBUG, "Removing expired nodes...");

    time_t now = time(NULL); // Получаем текущее время
    cache_node_t *current = cache->head;

    while (current) {
        cache_node_t *next = current->next; // Сохраняем указатель на следующую ноду

        if (current->expires_at < now) {
            // log_message(LOG_LEVEL_INFO, "Removing expired node with key: %s", current->key);

            // Удаляем из двусвязного списка
            if (current->prev) {
                current->prev->next = current->next;
            } else {
                cache->head = current->next; // Если нода была головой
            }

            if (current->next) {
                current->next->prev = current->prev;
            } else {
                cache->tail = current->prev; // Если нода была хвостом
            }

            // Удаляем из хэш-таблицы
            unsigned int hash = hash_function(current->key);
            cache_node_t **bucket = &cache->hash_table[hash];
            cache_node_t *node = *bucket;
            cache_node_t *prev = NULL;

            while (node) {
                if (node == current) {
                    if (prev) {
                        prev->hash_next = node->hash_next;
                    } else {
                        *bucket = node->hash_next;
                    }
                    break;
                }
                prev = node;
                node = node->hash_next;
            }

            // Удаляем ноду из памяти
            free_cache_node(current);
            cache->current_size--;

            log_message(LOG_LEVEL_INFO, "Expired node removed successfully");
        }

        current = next; // Переходим к следующей ноде
    }

    log_message(LOG_LEVEL_INFO, "Expired nodes removal completed");
    log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
}