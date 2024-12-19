#include "cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "const.h"
#include "logger.h"

/**
 * @brief Задумка работы кэша (ala LRU-Cache)
 *
 * Этот кэш представляет собой структуру данных вида ключ-значение
 * с поддержкой автоматического удаления устаревших записей. Кэш работает по следующим принципам:
 *
 * 1. **Хэш-таблица с двусвязным списком**:
 *    - Данные хранятся в хэш-таблице для быстрого доступа по ключу.
 *    - Каждая запись дополнительно связана в двусвязный список для организации порядка записей.
 *    - Самые новые записи находятся в конце списка, а самые старые — в начале.
 *    - Для разрешения случаев коллизий используется метод хэш-цепочек.
 *
 * 2. **Устаревание данных**:
 *    - Каждая запись имеет поле `expires_at`, которое указывает время, в течение которого данная кэш-запись считается актуальной.
 *    - При доступе к записи кэш проверяет, не устарела ли она. Если срок действия истёк, запись удаляется.
 *
 * 3. **Механизм удаления**:
 *    - Если кэш достигает максимального размера, автоматически удаляется самая старая запись.
 *    - Устаревшие записи также удаляются при добавлении новых записей или при вызове функции удаления устаревших записей.
 *
 * 4. **Потокобезопасность**:
 *    - Все операции записи, удаления или доступа защищены мьютексом для предотвращения конфликтов в многопоточной среде.
 *    - Однако некоторые функции помечены как небезопасные для потоков (например, работа с устаревшими записями)
 *      и должны вызываться только внутри защищённого контекста.
 *
 * 5. **Обновление записей**:
 *    - Если запись с тем же ключом уже существует, она обновляется (включая данные и время истечения)
 *      и перемещается в конец списка как наиболее свежая.
 *
 */

void remove_cache_node(cache_t *cache, cache_node_t *node_to_remove);
void remove_expired_nodes(cache_t *cache);

/**
 * @brief Calculates a hash for a given string.
 * @param key The key for which the hash needs to be calculated.
 * @return The hash value.
 */
unsigned int hash_function(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + (unsigned char)(*key++);
    }
    return hash % HASH_TABLE_SIZE;
}

/**
 * @brief Creates a new cache node.
 * @param key The key for the cache entry.
 * @param response The response to be stored in the cache.
 * @param response_size The size of the response.
 * @param expires_at The expiration time of the cache entry.
 * @return A pointer to the created cache node, or NULL in case of an error.
 */
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

/**
 * @brief Frees the memory occupied by a cache node.
 * @param node The cache node to be freed.
 */
void free_cache_node(cache_node_t *node) {
    if (node) {
        free(node->key);
        free(node->response);
        free(node);
    }
}

/**
 * @brief Creates a new cache with a specified maximum size.
 * @param max_size The maximum number of entries in the cache.
 * @return A pointer to the created cache, or NULL in case of an error.
 */
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

/**
 * @brief Moves the specified node to the end of the cache's list.
 * @param cache A pointer to the cache.
 * @param node The node to be moved to the tail.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
void move_to_tail(cache_t *cache, cache_node_t *node) {
    if (cache->tail == node) {
        return;
    }

    // remove node from the current position
    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    if (cache->head == node) {
        cache->head = node->next;
    }

    // add node to the tail
    node->prev = cache->tail;
    node->next = NULL;
    if (cache->tail) {
        cache->tail->next = node;
    }
    cache->tail = node;
}

/**
 * @brief Removes the first node (head) from the cache's list.
 * @param cache A pointer to the cache.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
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

    // remove node from the hash-chain
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

/**
 * @brief Checks if the cache is empty.
 * @param cache A pointer to the cache.
 * @return 1 if the cache is empty, 0 otherwise.
 */
int is_empty(const cache_t *cache) {
    return cache->current_size == 0;
}

/**
 * @brief Checks if the cache is full.
 * @param cache A pointer to the cache.
 * @return 1 if the cache is full, 0 otherwise.
 */
int is_full(const cache_t *cache) {
    return cache->current_size >= cache->max_size;
}

/**
 * @brief Adds an entry to the cache.
 * @param cache A pointer to the cache.
 * @param new_node A pointer to the node to be added.
 * @return 0 if the operation is successful, or an error code otherwise.
 */
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

    // if record exists already, then update it
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

    // if cache is full, then remove the oldest node
    if (is_full(cache)) {
        log_message(LOG_LEVEL_INFO, "Cache is full. Start removing head");
        remove_head(cache);
        log_message(LOG_LEVEL_INFO, "Cache head node was removed");
        log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
    }

    // add new record
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

/**
 * @brief Retrieves an entry from the cache by its key.
 * @param cache A pointer to the cache.
 * @param key The key of the entry to retrieve.
 * @return A pointer to the found node, or NULL if the entry is missing or expired.
 */
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

/**
 * @brief Removes a node from the linked list and hash table.
 * @param cache A pointer to the cache.
 * @param node The node to be removed.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
static void remove_node_from_cache(cache_t *cache, cache_node_t *node) {
    if (!node) {
        log_message(LOG_LEVEL_WARNING, "Invalid arguments to remove_node_from_cache");
        return;
    }

    // delete from double-linked list
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        cache->head = node->next; // if node was the head
    }

    if (node->next) {
        node->next->prev = node->prev;
    } else {
        cache->tail = node->prev; // if node was the tail
    }

    // remove from hash table
    unsigned int hash = hash_function(node->key);
    cache_node_t **bucket = &cache->hash_table[hash];
    cache_node_t *current = *bucket;
    cache_node_t *prev = NULL;

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

    log_message(LOG_LEVEL_INFO, "Node removed successfully");
}


/**
 * @brief Removes a specified node from the cache.
 * @param cache A pointer to the cache.
 * @param node_to_remove The node to be removed.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
void remove_cache_node(cache_t *cache, cache_node_t *node_to_remove) {
    if (!cache || !node_to_remove) {
        log_message(LOG_LEVEL_WARNING, "Invalid arguments to remove_cache_node");
        return;
    }

    remove_node_from_cache(cache, node_to_remove);

    log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
}

/**
 * @brief Removes expired entries from the cache.
 * @param cache A pointer to the cache.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
void remove_expired_nodes(cache_t *cache) {
    if (!cache) {
        log_message(LOG_LEVEL_WARNING, "Invalid cache pointer in remove_expired_nodes");
        return;
    }

    log_message(LOG_LEVEL_DEBUG, "Removing expired nodes...");

    time_t now = time(NULL);
    cache_node_t *current = cache->head;

    while (current) {
        cache_node_t *next = current->next;

        if (current->expires_at < now) {
            remove_node_from_cache(cache, current);
        }
        current = next;
    }

    log_message(LOG_LEVEL_INFO, "Expired nodes removal completed");
    log_message(LOG_LEVEL_DEBUG, "Current cache size = %ld", cache->current_size);
}

/**
 * @brief Deletes the entire cache and frees all allocated resources.
 * @param cache A pointer to the cache.
 */
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