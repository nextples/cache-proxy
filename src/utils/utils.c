#include "utils.h"

#include <string.h>

int buffer_append(char *buffer, size_t buffer_size, const char *str) {
    size_t current_length = strlen(buffer);
    size_t str_len = strlen(str);

    if (current_length + str_len >= buffer_size) {
        return -1;
    }

    memcpy(buffer + current_length, str, str_len);
    buffer[current_length + str_len] = '\0';

    return (int)str_len;
}