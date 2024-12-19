#ifndef PROXY_H
#define PROXY_H

typedef struct {
    int client_socket;
    char *request;
} context;

void run_proxy();

#endif //PROXY_H
