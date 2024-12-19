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

/**
 * @brief Reads a request from a connected client socket.
 *
 * This function receives data from the client's socket, storing it in the provided buffer. It handles
 * scenarios where the connection is closed or an error occurs during reading.
 *
 * @param client_socket The socket descriptor for communication with the client.
 * @param request A buffer to store the received request. It must have a size of at least MAX_BUFFER_SIZE.
 * @return EXIT_SUCCESS if the request is successfully read, or EXIT_FAILURE on failure.
 *
 * @note The function appends a null terminator to the request and logs detailed information about the received data.
 */
int read_request(int client_socket, char *request) {
    ssize_t bytes_read = read(client_socket, request, MAX_BUFFER_SIZE);
    if (bytes_read < 0) {
        log_message(LOG_LEVEL_ERROR, "Error while reading request");
        close(client_socket);
        return EXIT_FAILURE;
    }
    if (bytes_read == 0) {
        log_message(LOG_LEVEL_ERROR, "Error while reading request: connection closed from client");
        close(client_socket);
        return EXIT_FAILURE;
    }
    request[bytes_read] = END_STR;
    log_message(LOG_LEVEL_INFO, "Request received from client: %s", request);
    return EXIT_SUCCESS;
}