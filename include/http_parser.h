#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

typedef struct {
    int status_code;
    long content_length;
    size_t headers_length;
    long total_length;
    char *headers;
} http_resp_stat_t;

void http_response_init(http_resp_stat_t *response);

int http_response_parse(const char *http_response, http_resp_stat_t *result);

void http_free_response(const http_resp_stat_t *response);

#endif //UTILS_H
