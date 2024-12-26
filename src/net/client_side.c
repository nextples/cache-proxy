#include "client_side.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cache.h"
#include "const.h"
#include "logger.h"
#include "proxy.h"

void *response_reader_thread(void *args) {
    log_message(LOG_LEVEL_INFO, "[Reader] Thread started...");
    context_t *ctx = (context_t *) args;
    sem_t *semaphore = ctx->semaphore;
    int client_socket = ctx->client_socket;

    stream_t *stream = ctx->node->stream;
    if (stream == NULL) {
        log_message(LOG_LEVEL_ERROR, "[Reader] Failed to get stream from cache. Node was removed from cache");
        sem_post(semaphore);
        close(client_socket);
        return NULL;
    }

    size_t pos = 0;
    while(!atomic_load(&stream->is_finished)) {
        int written = stream_read_to(stream, client_socket, MAX_BUFFER_SIZE, pos);
        if (written < 0) {
            log_message(LOG_LEVEL_ERROR, "[Reader] Failed to read from stream");
            atomic_fetch_sub(&stream->connections, 1);
            sem_post(semaphore);
            close(client_socket);
            return NULL;
        }
        pos += written;
    }

    stream_read_all_to(stream, client_socket, pos);

    atomic_fetch_sub(&stream->connections, 1);
    pthread_cond_signal(&stream->connect_event);

    close(client_socket);
    sem_post(semaphore);
    log_message(LOG_LEVEL_INFO, "[Reader] Thread finished...");
    return NULL;
}
