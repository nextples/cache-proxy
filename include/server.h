#ifndef SERVER_H
#define SERVER_H

int create_server_socket();

int connect_to_remote(char *host);

int read_request(int client_socket, char *request);

#endif //SERVER_H
