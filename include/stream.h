#ifndef STREAM_H
#define STREAM_H

#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>

#include "http_parser.h"

typedef struct stream {
    char *data;
    size_t size;
    size_t capacity;

    pthread_rwlock_t rw_lock;

    pthread_cond_t can_read;
    pthread_cond_t can_write;
    pthread_cond_t connect_event;
    pthread_mutex_t lock;

    atomic_int is_finished;
    atomic_int readers;
    atomic_int error;
    atomic_int connections;

    http_resp_stat_t *stat;
} stream_t;

void stream_init(stream_t *stream, size_t capacity);

void stream_write(stream_t *stream, const char *data, size_t cnt);

size_t stream_read_to(stream_t *stream, int fd, size_t cnt, size_t from);

size_t stream_read_all_to(stream_t *stream, int fd, size_t from);

void stream_finish(stream_t *stream);

void stream_destroy(stream_t *stream);

#endif //STREAM_H
