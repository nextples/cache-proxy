#include "../../include/utils.h"

#include <string.h>

// Функция для добавления строки в конец буфера
int buffer_append(char *buffer, size_t buffer_size, const char *str) {
    // Вычисляем текущую длину строки в буфере
    size_t current_length = strlen(buffer);

    // Вычисляем длину строки для добавления
    size_t str_len = strlen(str);

    // Проверяем, поместится ли строка в буфер
    if (current_length + str_len >= buffer_size) {
        return -1; // Ошибка: недостаточно места
    }

    // Копируем строку в конец буфера
    memcpy(buffer + current_length, str, str_len);

    // Завершаем строку нулевым символом
    buffer[current_length + str_len] = '\0';

    return (int)str_len; // Возвращаем количество добавленных байт
}