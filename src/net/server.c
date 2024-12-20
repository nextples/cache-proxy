#include "server.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>

#include "logger.h"
#include "const.h"

int update_connection_header(char *request);

/**
 * @brief Creates and configures a server socket for listening to incoming client connections.
 *
 * This function sets up a socket, binds it to a specified port, and switches it to listening mode.
 * It ensures proper error handling for socket creation, binding, and listening.
 *
 * @return The file descriptor for the server socket if successful, or SOCKET_ERROR on failure.
 *
 * @note The function logs detailed information about the socket's creation and configuration status.
 */
int create_server_socket() {
    struct sockaddr_in server_addr;
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        log_message(LOG_LEVEL_ERROR, "Error while creating server socket");
        return SOCKET_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    log_message(LOG_LEVEL_INFO, "Server socket created successfully");

    int err = bind(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (err == BIND_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while binding server socket ");
        perror("");
        close(server_socket);
        return SOCKET_ERROR;
    }
    log_message(LOG_LEVEL_INFO, "Server socket bound to %d", server_addr.sin_addr.s_addr);

    // switch to listen mode
    err = listen(server_socket, MAX_USERS_COUNT);
    if (err == LISTEN_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while listening on server socket");
        close(server_socket);
        return SOCKET_ERROR;
    }
    return server_socket;
}

/**
 * @brief Establishes a connection to a remote server.
 *
 * This function resolves the host's address using DNS, creates a socket, and connects to the resolved address.
 *
 * @param host The hostname or IP address of the remote server.
 * @return The file descriptor for the connected socket if successful, or SOCKET_ERROR on failure.
 *
 * @note Proper error handling is implemented for DNS resolution, socket creation, and connection attempts.
 * The function logs relevant details for debugging.
 */
int connect_to_remote(char *host) {
    struct addrinfo hints = {0}, *res0;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(host, HTTP, &hints, &res0);
    if (status != ADD_INFO_STATUS_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while getting addr info");
        freeaddrinfo(res0);
        return SOCKET_ERROR;
    }

    // create socket associated with address got upper
    int dest_socket = socket(res0->ai_family, res0->ai_socktype, res0->ai_protocol);
    if (dest_socket == SOCKET_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while creating destination socket");
        return SOCKET_ERROR;
    }
    log_message(LOG_LEVEL_INFO, "Destination socket created successfully");

    int err = connect(dest_socket, res0->ai_addr, res0->ai_addrlen);
    if (err == SOCKET_ERROR) {
        log_message(LOG_LEVEL_ERROR, "Error while connecting to destination socket");
        close(dest_socket);
        freeaddrinfo(res0);
        return SOCKET_ERROR;
    }
    log_message(LOG_LEVEL_INFO, "Destination socket connected to %s", host);

    return dest_socket;
}

//TODO: write the annotation
int read_request(int client_socket, char *request) {
    log_message(LOG_LEVEL_INFO, "Reading request from client");
    if (request == NULL) {
        log_message(LOG_LEVEL_ERROR, "Error while reading request. Request's buffer is not initialized");
        return EXIT_FAILURE;
    }

    char buffer[MAX_BUFFER_SIZE];
    size_t all_bytes_read = 0;
    int err = 0;

    while (1) {
        ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            log_message(LOG_LEVEL_ERROR, "Error while reading request");
            return EXIT_FAILURE;
        }
        if (bytes_read == 0) {
            log_message(LOG_LEVEL_INFO, "Connection closed by client");
            err = 1;
            break;
        }

        if (all_bytes_read + bytes_read > MAX_REQUEST_SIZE) {
            log_message(LOG_LEVEL_ERROR, "Request too large. Buffer is overloaded");
            return EXIT_FAILURE;
        }

        memcpy(request + all_bytes_read, buffer, bytes_read);
        all_bytes_read += bytes_read;

        char *headers_end = strstr(request, "\r\n\r\n");
        if (headers_end != NULL) {
            break; // because supported only GET HTTP/1.0
        }
    }

    if (all_bytes_read < MAX_REQUEST_SIZE && err == 0) {
        request[all_bytes_read] = END_STR;
        log_message(LOG_LEVEL_INFO, "Request received successfully");
        log_message(LOG_LEVEL_DEBUG, "Request body: %s", request);
        err = update_connection_header(request);
        if (err == EXIT_FAILURE) {
            log_message(LOG_LEVEL_WARNING, "Request header was not swapped to \"close\"");
        }

    } else {
        log_message(LOG_LEVEL_ERROR, "Request is too large or wasn't read until end");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int update_connection_header(char *request) {
    log_message(LOG_LEVEL_INFO, "Updating connection header to closed");
    if (request == NULL) {
        log_message(LOG_LEVEL_WARNING, "Error while reading request. Request's buffer is not initialized");
        return EXIT_FAILURE;
    }

    char *connection_header = strstr(request, "Connection:");
    if (connection_header == NULL) {
        log_message(LOG_LEVEL_INFO, "Header \"Connection\" was not found in request");
        return EXIT_FAILURE;
    }

    char *value_start = connection_header + strlen("Connection:");
    while (*value_start == ' ' || *value_start == '\t') {
        value_start++; // skip spaces
    }

    // find string end
    char *value_end = strstr(value_start, "\r\n");
    if (value_end == NULL) {
    log_message(LOG_LEVEL_ERROR, "Error while swapping connection header");
        return EXIT_FAILURE;
    }

    size_t header_size = value_end - value_start;
    memset(value_start, ' ', header_size);
    strncpy(value_start, "close", 5);
    log_message(LOG_LEVEL_INFO, "Header \"Connection\" successfully swapped to \"close\"");
    log_message(LOG_LEVEL_DEBUG, "Updated request body: %s", request);
    return EXIT_SUCCESS;
}