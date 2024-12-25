#include "response_writer.h"

#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "const.h"
#include "logger.h"
#include "proxy.h"
#include "server.h"

void extract_host(const char *request, unsigned char *buf) {
    log_message(LOG_LEVEL_INFO, "Starting \"extract_host\"...");
    const unsigned char *host_result = memccpy(buf, strstr(request, HOST) + 6, '\r', HOST_SIZE);
    if (!host_result) {
        log_message(LOG_LEVEL_ERROR, "Failed to extract host string");
        return;
    }
    buf[host_result - buf - 1] = END_STR;
    log_message(LOG_LEVEL_INFO, "[Writer] Host name extracted successfully");
}

int send_request(const int fd, const char *request) {
    log_message(LOG_LEVEL_INFO, "Starting \"send_request\"...");
    if (fd < 0) {
        log_message(LOG_LEVEL_ERROR, "[Writer] Invalid arguments: fd < 0");
        return -1;
    }
    ssize_t bytes_sent = write(fd, request, strlen(request));
    if (bytes_sent == WRITE_ERROR) {
        log_message(LOG_LEVEL_ERROR, "[Writer] Error sending request to remote server.");
        return -1;
    }
    log_message(LOG_LEVEL_INFO, "\"send_request\" finished successfully");
    return 0;
}

void *response_writer_thread(void *args) {
    log_message(LOG_LEVEL_INFO, "[Writer] Thread started...");
    context_t *ctx = (context_t *) args;
    cache_t *cache = ctx->cache;
    sem_t *semaphore = ctx->semaphore;
    char *request = ctx->request;
    unsigned char host[HOST_SIZE];
    response_headers_t headers = {};
    int is_headers_set = 0;

    extract_host(request, host);
    const int remote_server = connect_to_remote(host);
    send_request(remote_server, request);

    stream_t *stream = cache_get_stream(cache, request);
    if (stream == NULL) {
        log_message(LOG_LEVEL_ERROR, "[Writer] Failed to get stream from cache");
        sem_post(semaphore);
        free_context(ctx);
        close(remote_server);
        return NULL;
    }

    char buffer[MAX_BUFFER_SIZE];
    int total_read = 0, read_bytes = 0, total_written = 0;
    size_t written = 0;

    log_message(LOG_LEVEL_INFO, "[Writer] Starting transfer response...");
    while (1) {
        memset(buffer, 0, MAX_BUFFER_SIZE);
        read_bytes = read(remote_server, buffer, MAX_BUFFER_SIZE);
        if (read_bytes > 0) {
            total_read += read_bytes;
            log_message(LOG_LEVEL_DEBUG, "Read %d bytes from server. Total: %d bytes", read_bytes, total_read);

            if (is_headers_set == 0) {
                //TODO: parse headers
            }

            stream_write(stream, buffer, read_bytes);

            written += read_bytes;
            total_written += read_bytes;
            log_message(LOG_LEVEL_DEBUG, "Sent %d bytes to client. Total: %d bytes", written, total_written);
        }
        else if (read_bytes == 0) {
            log_message(LOG_LEVEL_INFO, "Remote connection was closed by server");
            break;
        }
        else {
            // TODO: error check
            log_message(LOG_LEVEL_ERROR, "Error while reading data from remote server");
            break;
        }
    }

    stream_finish(stream);
    close(remote_server);
    log_message(LOG_LEVEL_INFO, "[Writer] Thread finished");
}
