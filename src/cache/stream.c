#include "stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "const.h"
#include "logger.h"

void stream_init(stream_t *stream, size_t capacity) {
    log_message(LOG_LEVEL_INFO, "Starting \"stream_init\"...");

    stream->data = (char*)malloc(capacity);
    if (!stream->data) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for stream's buffer");
        return;
    }
    stream->size = 0;
    stream->capacity = capacity;
    pthread_rwlock_init(&stream->rw_lock, NULL);
    pthread_mutex_init(&stream->lock, NULL);
    pthread_cond_init(&stream->can_write, NULL);
    pthread_cond_init(&stream->can_read, NULL);
    pthread_cond_init(&stream->can_del, NULL);
    atomic_init(&stream->readers, 0);
    atomic_init(&stream->is_finished, 0);
    atomic_init(&stream->error, 0);
    http_resp_stat_t *response = calloc(1, sizeof(http_resp_stat_t));
    http_response_init(response);
    stream->stat = response;
    log_message(LOG_LEVEL_INFO, "Stream initialized successfully");
}

void buffer_expand(stream_t *stream, size_t new_cap) {
    log_message(LOG_LEVEL_INFO, "Starting \"buffer_expand\"...");
    char *new_data = malloc(new_cap * sizeof(char));

    if (!new_data) {
        log_message(LOG_LEVEL_ERROR, "Failed to expand memory for stream's buffer");
        exit(EXIT_FAILURE);
    }

    memcpy(new_data, stream->data, stream->size * sizeof(char));
    stream->data = new_data;
    stream->capacity = new_cap;
    log_message(LOG_LEVEL_INFO, "Buffer expanded successfully. Current capacity = %d", stream->capacity);
}

void stream_write(stream_t *stream, const char *data, size_t cnt) {
    log_message(LOG_LEVEL_INFO, "Starting \"stream_write\"...");
    pthread_mutex_lock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex locked", stream);

    while (atomic_load(&stream->readers) > 0) {
        log_message(LOG_LEVEL_DEBUG, "Writing is locked because of readers. Readers count = %d", atomic_load(&stream->readers));
        pthread_cond_wait(&stream->can_write, &stream->lock);
    }
    log_message(LOG_LEVEL_DEBUG, "Writing is unlocked");

    if (stream->size + cnt > stream->capacity) {
        buffer_expand(stream, stream->capacity + stream->capacity / 2 );
    }

    memcpy(stream->data + stream->size, data, cnt);
    stream->size += cnt;

    pthread_cond_broadcast(&stream->can_read);
    log_message(LOG_LEVEL_DEBUG, "Broadcasting to readers");

    pthread_mutex_unlock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex unlocked", stream);
    log_message(LOG_LEVEL_INFO, "\"stream_write\" finished successfully");
}

size_t stream_read_to(stream_t *stream, const int fd, const size_t cnt, const size_t from) {
    pthread_mutex_lock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex locked", stream);

    if (from > stream->size) {
        log_message(LOG_LEVEL_ERROR, "Start position exceeds available data size");
        return -1;
    }

    while (stream->size <= from || atomic_load(&stream->is_finished) == 0) {
        log_message(LOG_LEVEL_DEBUG, "Reading is locked");
        pthread_cond_wait(&stream->can_read, &stream->lock);
    }
    log_message(LOG_LEVEL_DEBUG, "Reading is unlocked");
    atomic_fetch_add(&stream->readers, 1);
    log_message(LOG_LEVEL_DEBUG, "Current count of readers on stream [%p] = %d", stream, atomic_load(&stream->readers));


    size_t available = stream->size - from;
    size_t to_read = (cnt < available) ? cnt : available;

    ssize_t written = write(fd, stream->data + from, to_read);
    if (written == -1) {
        log_message(LOG_LEVEL_ERROR, "Failed to write from stream [%p] to client", stream);
        atomic_fetch_sub(&stream->readers, 1);
        log_message(LOG_LEVEL_DEBUG, "Current count of readers on stream [%p] = %d", stream, atomic_load(&stream->readers));
        pthread_mutex_unlock(&stream->lock);
        log_message(LOG_LEVEL_ERROR, "Stream [%p] mutex unlocked", stream);
        return -1;
    }

    atomic_fetch_sub(&stream->readers, 1);
    log_message(LOG_LEVEL_DEBUG, "Current count of readers on stream [%p] = %d", stream, atomic_load(&stream->readers));
    pthread_cond_signal(&stream->can_write);
    log_message(LOG_LEVEL_DEBUG, "Signal to writer", stream);

    pthread_mutex_unlock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex unlocked", stream);
    return written;
}

size_t stream_read_all_to(stream_t *stream, const int fd, const size_t from) {
    log_message(LOG_LEVEL_INFO, "Starting \"stream_read_all_to\"...");
    if (!stream || !stream->data || fd < 0) {
    log_message(LOG_LEVEL_WARNING, "Invalid arguments");
        return -1;
    }
    if (!stream->is_finished) {
        log_message(LOG_LEVEL_WARNING, "Stream [%p] is not finished yet", stream);
        return -1;
    }

    pthread_rwlock_rdlock(&stream->rw_lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] rwlock locked to read", stream);

    const size_t data_len = stream->size;
    size_t offset = from;

    if (from > data_len) {
        log_message(LOG_LEVEL_ERROR, "Start position exceeds available data size");
        pthread_rwlock_unlock(&stream->rw_lock);
        log_message(LOG_LEVEL_DEBUG, "Stream [%p] rwlock unlocked", stream);
        return -1;
    }

    ssize_t written = 0;
    log_message(LOG_LEVEL_INFO, "Reading from stream [%p] to client...", stream);

    while (offset < data_len) {
        size_t to_write = (data_len - offset) < MAX_BUFFER_SIZE ? (data_len - offset) : MAX_BUFFER_SIZE;

        written = write(fd, stream->data + offset, to_write);
        if (written < 0) {
            log_message(LOG_LEVEL_ERROR, "Error writing to destination file descriptor", stream);
            pthread_rwlock_unlock(&stream->rw_lock);
            log_message(LOG_LEVEL_ERROR, "Stream [%p] rwlock unlocked", stream);
            return -1;
        }

        offset += written;
    }

    pthread_rwlock_unlock(&stream->rw_lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] rwlock unlocked", stream);
    log_message(LOG_LEVEL_INFO, "\"stream_read_all_to\" finished successfully");
    return offset - from; // written bytes count
}

void stream_finish(stream_t *stream) {
    log_message(LOG_LEVEL_INFO, "Starting \"stream_finish\"...");
    pthread_mutex_lock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex locked", stream);
    atomic_store(&stream->is_finished, 1);
    pthread_cond_broadcast(&stream->can_read);
    log_message(LOG_LEVEL_DEBUG, "Broadcasting to readers");
    pthread_mutex_unlock(&stream->lock);
    log_message(LOG_LEVEL_DEBUG, "Stream [%p] mutex unlocked", stream);
    log_message(LOG_LEVEL_INFO, "\"stream_finish\" finished successfully");
}

void stream_destroy(stream_t *stream) {
    log_message(LOG_LEVEL_INFO, "Starting \"stream_destroy\"...");
    pthread_mutex_lock(&stream->lock);
    pthread_rwlock_wrlock(&stream->rw_lock);

    if (!stream) {
        log_message(LOG_LEVEL_ERROR, "Invalid arguments");
        return;
    }
    if (stream->data) {
        free(stream->data);
    }
    pthread_mutex_unlock(&stream->lock);
    pthread_rwlock_unlock(&stream->rw_lock);
    pthread_mutex_destroy(&stream->lock);
    pthread_cond_destroy(&stream->can_write);
    pthread_cond_destroy(&stream->can_read);
}