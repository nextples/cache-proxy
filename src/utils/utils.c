#include "utils.h"

#include <string.h>

/**
 * @brief Appends a string to the end of a buffer, ensuring it doesn't exceed the buffer's size.
 *
 * @param buffer The target buffer where the string will be appended.
 * @param buffer_size The size of the buffer.
 * @param str The string to append.
 * @return The number of bytes appended, or -1 if there is insufficient space in the buffer.
 *
 * @note Ensures the final string in the buffer is null-terminated.
 */
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