#include "response_reader.h"

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
    cache_t *cache = ctx->cache;
    int client_socket = ctx->client_socket;
    char *request = ctx->request;

    stream_t *stream = cache_get_stream(cache, request);
    if (stream == NULL) {
        log_message(LOG_LEVEL_ERROR, "[Reader] Failed to get stream from cache");
        sem_post(semaphore);
        free_context(ctx);
        close(client_socket);
        return NULL;
    }

    size_t pos = 0;
    while(!atomic_load(&stream->is_finished)) {
        int written = stream_read_to(stream, client_socket, MAX_BUFFER_SIZE, pos);
        if (written < 0) {
            log_message(LOG_LEVEL_ERROR, "[Reader] Failed to read from stream");
            sem_post(semaphore);
            free_context(ctx);
            close(client_socket);
            return NULL;
        }
        pos += written;
    }

    stream_read_all_to(stream, client_socket, pos);

    close(client_socket);
    sem_post(semaphore);
    free_context(ctx);
    log_message(LOG_LEVEL_INFO, "[Reader] Thread finished...");
}
