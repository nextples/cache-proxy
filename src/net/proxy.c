#include "proxy.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <semaphore.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include "logger.h"
#include "utils.h"
#include "server.h"
#include "cache.h"
#include "const.h"

int server_is_on = 1;
cache_t *cache;
sem_t thread_semaphore;
int cur_client_numb = 0;

void free_context(context *ctx);

/**
 * @brief Removes a node from the linked list and hash table.
 * @param cache A pointer to the cache.
 * @param node The node to be removed.
 * @note This function is not thread-safe. Use it only under a mutex lock.
 */
int send_from_cache(const char *request, int client_socket) {
    log_message(LOG_LEVEL_INFO, "Trying to send response from cache...");
    cache_node_t *node = cache_get(cache, request);
    if (node == NULL) {
        return EXIT_FAILURE;
    }
    log_message(LOG_LEVEL_INFO, "Sending cached response to client...");
    ssize_t send_bytes = write(client_socket, node->response, node->response_size);
    if (send_bytes == WRITE_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while sending cached data");
        close(client_socket);
        return EXIT_FAILURE;
    }
    log_message(LOG_LEVEL_INFO, "Cached response sent to client. Response len = %ld", send_bytes);
    return EXIT_SUCCESS;
}

/**
 * @brief Handles an individual client's request in a dedicated thread.
 *
 * This function processes the request sent by the client. It attempts to fetch the response
 * from the cache first. If no cached response is available, it forwards the request to a remote
 * server, receives the response, and forwards it back to the client. The response is cached if
 * it is within the allowable size limit.
 *
 * @param arg A pointer to the context structure containing the client's request and socket.
 * @return NULL always, as the function operates in a detached thread.
 *
 * @note The function handles errors such as connection issues, data sending/receiving errors,
 * and timeout scenarios gracefully by releasing resources and logging detailed information.
 */
void* handle_client_request(void *arg) {
    context *ctx = arg;
    int client_socket = ctx->client_socket;
    char *request0 = ctx->request;
    char request[MAX_BUFFER_SIZE];
    strcpy(request, request0);

    log_message(LOG_LEVEL_DEBUG, "Current cache size = %d", cache->current_size);
    if (send_from_cache(request, client_socket) == EXIT_SUCCESS) {
        free_context(ctx);
        close(client_socket);
        sem_post(&thread_semaphore);
        cur_client_numb--;
        log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
        return NULL;
    }

    // copy host name
    unsigned char host[HOST_SIZE];
    const unsigned char *host_result = memccpy(host, strstr(request, HOST) + 6, '\r', sizeof(host));
    host[host_result - host - 1] = END_STR;
    log_message(LOG_LEVEL_INFO, "Host name extracted from client request: %s", host);

    int dest_socket = connect_to_remote(host);
    if (dest_socket == SOCKET_ERROR) {
        free_context(ctx);
        close(client_socket);
        sem_post(&thread_semaphore);
        cur_client_numb--;
        log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Connected to remote server successfully");

    ssize_t bytes_sent = write(dest_socket, request, strlen(request));
    if (bytes_sent == WRITE_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while sending request to remote server");
        free_context(ctx);
        close(client_socket);
        close(dest_socket);
        sem_post(&thread_semaphore);
        cur_client_numb--;
        log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
        return NULL;
    }
    log_message(LOG_LEVEL_INFO, "Sent request to remote server successfully, request len = ", bytes_sent);

    // start resending data from server to client
    char *buffer = calloc(MAX_BUFFER_SIZE, sizeof(char));
    ssize_t all_bytes_read = 0, all_bytes_sent = 0;

    struct pollfd fds = {0};
    fds.fd = dest_socket;
    fds.events = POLLIN; // wait new data in fd mode

    char* cached_response = calloc(MAX_CACHE_RECORD_SIZE, sizeof(char));

    log_message(LOG_LEVEL_DEBUG, "Waiting for response from remote server...");
    int error_flag = 0;
    int too_large_flag = 0;
    while (1) {
        int ret = poll(&fds, 1, WAIT_SERVER_RESPONSE_TIMEOUT);

        if (ret > 0) {
            log_message(LOG_LEVEL_DEBUG, "Got data package from remote server");
            if (fds.revents & POLLIN) {
                memset(buffer, 0, MAX_BUFFER_SIZE);
                ssize_t bytes_read = read(dest_socket, buffer, MAX_BUFFER_SIZE);

                if (bytes_read > 0) {
                    all_bytes_read += bytes_read;
                    log_message(LOG_LEVEL_DEBUG, "Read %d bytes from server. Total: %d bytes", bytes_read, all_bytes_read);

                    bytes_sent = write(client_socket, buffer, bytes_read);
                    all_bytes_sent += bytes_sent;
                    log_message(LOG_LEVEL_DEBUG, "Sent %d bytes to client. Total: %d bytes", bytes_sent, all_bytes_sent);

                    if (too_large_flag == 0 && buffer_append(cached_response, MAX_CACHE_RECORD_SIZE, buffer) == -1) {
                        log_message(LOG_LEVEL_WARNING, "Response is too long to be cached. Current response length = %d", all_bytes_sent);
                        too_large_flag = 1;
                    }

                    if (bytes_sent == SEND_ERROR) {
                        log_message(LOG_LEVEL_ERROR, "Error while sending data to client");
                        free_context(ctx);
                        free(buffer);
                        free(cached_response);
                        close(client_socket);
                        close(dest_socket);
                        sem_post(&thread_semaphore);
                        cur_client_numb--;
                        log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
                        return NULL;
                    }
                }

                else if (bytes_read == 0) {
                    log_message(LOG_LEVEL_INFO, "Remote connection was closed by server");
                    break;
                } else {
                    log_message(LOG_LEVEL_ERROR, "Error while reading data from remote server");
                    error_flag = 1;
                    break;
                }
            }
        } else if (ret == 0) {
            log_message(LOG_LEVEL_INFO, "Timeout for waiting for data from a remote server. Data reading is finished");
            break;
        } else {
            log_message(LOG_LEVEL_ERROR, "Poll error. Data reading is terminated");
            error_flag = 1;
            break;
        }
    }

    if (all_bytes_read <= MAX_CACHE_RECORD_SIZE && error_flag != 1) {
        log_message(LOG_LEVEL_INFO, "Start creating cache node for response");

        cache_node_t *new_node = create_cache_node(
            request,
            cached_response,
            all_bytes_read,
            time(NULL) + CACHE_RECORD_TTL
            );

        if (new_node == NULL) {
            log_message(LOG_LEVEL_WARNING, "Error while creating cache node. Data wasn't cached");
        }
        else {
            int err = cache_put(cache, new_node);
            if (err == CACHE_ERROR) {
                log_message(LOG_LEVEL_WARNING, "Error while put cache node. Data wasn't cached");
                free_cache_node(new_node);
            }
        }
    }

    close(client_socket);
    close(dest_socket);

    free(buffer);
    free_context(ctx);
    free(cached_response);

    sem_post(&thread_semaphore);
    cur_client_numb--;
    log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
    return NULL;
}

/**
 * @brief Accepts new client connections and delegates their handling to separate threads.
 *
 * This function listens for incoming client connections on the server socket. For each accepted
 * client, it creates a new context structure to store client-specific data, spawns a detached thread
 * to process the client's request, and tracks the number of active clients.
 *
 * @param server_socket The socket descriptor used for listening to incoming client connections.
 *
 * @note This function continuously accepts clients until the `server_is_on` flag is set to 0.
 * It manages resources such as client sockets and context structures, ensuring proper cleanup
 * in case of errors.
 */
void accept_new_client(int server_socket) {
    while (server_is_on) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);

         // wait for clients
        int client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addr_size);
        if (client_socket == SOCKET_ERROR) {
            log_message(LOG_LEVEL_ERROR, "Error while accepting new client");
            close(server_socket);
            delete_cache(cache);
            exit(EXIT_FAILURE);
        }

        log_message(LOG_LEVEL_INFO, "Client connected from %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        char *request = calloc(MAX_BUFFER_SIZE, sizeof(char));
        assert(request != NULL);
        int err = read_request(client_socket, request);
        if (err == EXIT_FAILURE) {
            free(request);
            close(client_socket);
            continue;
        }

        sem_wait(&thread_semaphore);
        cur_client_numb++;
        log_message(LOG_LEVEL_INFO, "Started handling new client. Current clients numbers = %d", cur_client_numb);

        context *ctx = malloc(sizeof(context));
        if (ctx == NULL) {
            log_message(LOG_LEVEL_ERROR, "Memory allocation error for context");
            free(request);
            close(client_socket);
            sem_post(&thread_semaphore);
            cur_client_numb--;
            log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
            continue;
        }
        ctx->client_socket = client_socket;
        ctx->request = request;
        pthread_t handler_thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        err = pthread_create(&handler_thread, &attr, handle_client_request, ctx);
        if (err == PTHREAD_ERROR) {
            log_message(LOG_LEVEL_ERROR, "Error while creating handler thread");
            free_context(ctx);
            close(client_socket);
            close(server_socket);
            delete_cache(cache);
            sem_post(&thread_semaphore);
            pthread_attr_destroy(&attr);
            sem_destroy(&thread_semaphore);
            cur_client_numb--;
            log_message(LOG_LEVEL_INFO, "Finished handling client. Current clients numbers = %d", cur_client_numb);
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * @brief Frees memory allocated for a client context.
 *
 * This function releases the memory used by the context structure and its associated request data.
 *
 * @param ctx A pointer to the context structure to be freed.
 */
void free_context(context *ctx) {
    if (ctx != NULL) {
        if (ctx->request != NULL) {
            free(ctx->request);
        }
        free(ctx);
    }
}

/**
 * @brief Runs the proxy server.
 *
 * This function initializes the server and its resources, such as the cache and thread semaphore.
 * It sets up the server socket, begins listening for incoming connections, and processes each
 * client request. Upon termination, the function releases all allocated resources.
 *
 * @note The server operates indefinitely until the `server_is_on` flag is set to 0. Proper error
 * handling is in place for socket creation, cache initialization, and client handling.
 */
void run_proxy() {
    sem_init(&thread_semaphore, 0, MAX_USERS_COUNT);

    int server_socket = create_server_socket();
    if (server_socket == SOCKET_ERROR) {
        exit(EXIT_FAILURE);
    }

    cache = create_cache(CACHE_SIZE);
    if (cache == NULL) {
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    log_message(LOG_LEVEL_INFO, "Server listening on port %d", PORT);

    accept_new_client(server_socket);
    close(server_socket);
    delete_cache(cache);

    sem_destroy(&thread_semaphore);
}