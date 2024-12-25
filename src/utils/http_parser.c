#include "http_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "const.h"
#include "llhttp.h"
#include "logger.h"

void http_response_init(http_resp_stat_t *response) {
    memset(response, 0, sizeof(http_resp_stat_t));
    response->status_code = -1;
    response->content_length = -1;
    response->headers_length = -1;
    response->total_length = -1;
    response->headers = calloc(MAX_BUFFER_SIZE / sizeof(char), sizeof(char));
}

int http_response_parse(const char *http_response, http_resp_stat_t *result) {
    const char *status_line_end = strstr(http_response, "\r\n");
    if (!status_line_end) {
        log_message(LOG_LEVEL_ERROR, "Failed while parsing http response: Invalid status line");
        return -1;
    }

    char protocol[16] = {0};
    int status_code = 0;
    if (sscanf(http_response, "%15s %d", protocol, &status_code) != 2) {
        log_message(LOG_LEVEL_ERROR, "Failed while parsing http response: can not parse status line");
        return -1;
    }
    result->status_code = status_code;

    const char *headers_start = status_line_end + 2; // skip "\r\n"
    const char *headers_end = strstr(headers_start, "\r\n\r\n");
    if (!headers_end) {
        log_message(LOG_LEVEL_ERROR, "Failed while parsing http response: there is not headers end");
        return -1;
    }

    result->headers_length = headers_end - http_response + 4; // +4 for \r\n\r\n

    size_t headers_size = result->headers_length;
    if (headers_size >= MAX_BUFFER_SIZE) {
        log_message(LOG_LEVEL_ERROR, "Failed while parsing http response: too long response");
        return -1;
    }
    strncpy(result->headers, http_response, headers_size);
    result->headers[headers_size] = '\0';

    const char *content_length_key = "Content-Length:";
    const char *content_length_pos = strstr(headers_start, content_length_key);
    if (content_length_pos && content_length_pos < headers_end) {
        content_length_pos += strlen(content_length_key);
        while (*content_length_pos == ' ') {
            content_length_pos++; // skip spaces
        }
        result->content_length = strtol(content_length_pos, NULL, 10);
    }

    if (result->content_length != -1) {
        result->total_length = result->headers_length + result->content_length;
    }

    return 0;
}
