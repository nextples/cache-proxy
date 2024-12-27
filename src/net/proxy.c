#include "proxy.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>

#include "logger.h"
#include "server.h"
#include "cache.h"
#include "const.h"
#include "client_side.h"
#include "server_side.h"

int server_is_on = 1;
sem_t semaphore;

void free_context(context_t *ctx);

void accept_new_client(int server_socket, cache_t *cache) {
    while (server_is_on) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);

        // wait for clients
        int client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addr_size);
        if (client_socket == SOCKET_ERROR) {
            log_message(LOG_LEVEL_ERROR, "Error while accepting new client: %s", strerror(errno));
            close(server_socket);
            cache_destroy(cache);
            exit(EXIT_FAILURE);
        }

        char *request = calloc(MAX_REQUEST_SIZE, sizeof(char));
        assert(request != NULL);
        int err = read_request(client_socket, request);
        if (err == EXIT_FAILURE) {
            free(request);
            close(client_socket);
            log_message(LOG_LEVEL_ERROR, "Connection closed");
            continue;
        }

        sem_wait(&semaphore);
        int cur_client_cnt = 0;
        sem_getvalue(&semaphore, &cur_client_cnt);

        log_message(LOG_LEVEL_INFO, "Started handling new client. Current clients numbers = %d", MAX_USERS_COUNT - cur_client_cnt);

        int is_node_exist = 0;
        cache_node_t *node = cache_put(cache, request, &is_node_exist);
        if (node == NULL) {
            log_message(LOG_LEVEL_ERROR, "Error while trying to put node in cache");
            free(request);
            close(client_socket);
            sem_post(&semaphore);
            sem_getvalue(&semaphore, &cur_client_cnt);
            log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", MAX_USERS_COUNT - cur_client_cnt);
            continue;
        }

        context_t *ctx = malloc(sizeof(context_t));
        if (ctx == NULL) {
            log_message(LOG_LEVEL_ERROR, "Memory allocation error for context");
            free(request);
            close(client_socket);
            sem_post(&semaphore);
            sem_getvalue(&semaphore, &cur_client_cnt);
            log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", MAX_USERS_COUNT - cur_client_cnt);
            continue;
        }
        ctx->client_socket = client_socket;
        ctx->request = request;
        ctx->cache = cache;
        ctx->node = node;
        ctx->semaphore=&semaphore;

        pthread_t response_reader;
        pthread_t response_writer;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (is_node_exist == 0) {
            int err1 = pthread_create(&response_writer, &attr, response_writer_thread, ctx);
            if (err1 == PTHREAD_ERROR) {
                log_message(LOG_LEVEL_ERROR, "Error while creating writer thread: %s", strerror(errno));
                free_context(ctx);
                close(client_socket);
                sem_post(&semaphore);
                sem_getvalue(&semaphore, &cur_client_cnt);
                log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", MAX_USERS_COUNT - cur_client_cnt);
                continue;
            }
        }

        int err2 = pthread_create(&response_reader, &attr, response_reader_thread, ctx);
        if (err2 == PTHREAD_ERROR) {
            log_message(LOG_LEVEL_ERROR, "Error while creating reader thread: %s", strerror(errno));
            free_context(ctx);
            close(client_socket);
            close(server_socket);
            cache_destroy(cache);
            sem_post(&semaphore);
            pthread_attr_destroy(&attr);
            sem_destroy(&semaphore);
            sem_getvalue(&semaphore, &cur_client_cnt);
            log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", MAX_USERS_COUNT - cur_client_cnt);
            exit(EXIT_FAILURE);
        }
    }
}

void free_context(context_t *ctx) {
    if (ctx != NULL) {
        if (ctx->request != NULL) {
            free(ctx->request);
        }
        free(ctx);
    }
}

void run_proxy() {
    log_message(LOG_LEVEL_INFO, "Cache Proxy v.1.0.2 is running...");
    sem_init(&semaphore, 0, MAX_USERS_COUNT);

    int server_socket = create_server_socket();
    if (server_socket == SOCKET_ERROR) {
        exit(EXIT_FAILURE);
    }

    cache_t *cache = cache_init(CACHE_SIZE);
    if (cache == NULL) {
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    log_message(LOG_LEVEL_INFO, "Server listening on port %d", PORT);

    accept_new_client(server_socket, cache);
    close(server_socket);
    cache_destroy(cache);

    sem_destroy(&semaphore);
}
