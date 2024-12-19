#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <pthread.h>

typedef struct cache_node_t {
    char *key;              // Хэш запроса
    char *response;         // Ответ сервера
    size_t response_size;   // Размер ответа
    time_t expires_at;      // Время истечения таймаута
    struct cache_node_t *prev; // Указатель на предыдущую ноду
    struct cache_node_t *next; // Указатель на следующую ноду
    struct cache_node_t *hash_next; // Указатель на следующую ноду в списке хеш-цепочки
} cache_node_t;

// Структура для управления кэшем
typedef struct {
    cache_node_t **hash_table; // Хэш-таблица
    cache_node_t *head;        // Голова двусвязного списка
    cache_node_t *tail;        // Хвост двусвязного списка
    size_t max_size;        // Максимальное количество записей
    size_t current_size;    // Текущее количество записей
    pthread_mutex_t lock;  // mutex для обеспечения потокобезопасности
} cache_t;

cache_node_t *create_cache_node(const char *key, const char *response, const size_t response_size, const time_t expires_at);

void free_cache_node(cache_node_t *node);

cache_t *create_cache(size_t max_size);

int cache_put(cache_t *cache, cache_node_t *new_node);

cache_node_t *cache_get(cache_t *cache, const char *key);

void delete_cache(cache_t *cache);

#endif //CACHE_H
