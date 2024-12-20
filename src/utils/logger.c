#include "logger.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>

static FILE *log_file = NULL;
static LogLevel current_log_level = LOG_LEVEL_DEBUG;
static int log_to_console = 1;

/**
 * @brief Converts a log level enum value to its corresponding string representation.
 *
 * @param level The log level (e.g., LOG_LEVEL_DEBUG, LOG_LEVEL_INFO).
 * @return A string representing the log level, or "UNKNOWN" for unrecognized levels.
 */
const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR:   return "ERROR";
        default:                return "UNKNOWN";
    }
}

/**
 * @brief Converts a log level to a corresponding ANSI color code for console output.
 *
 * @param level The log level (e.g., LOG_LEVEL_DEBUG, LOG_LEVEL_INFO).
 * @return A string representing the color code, or COLOR_RESET for unrecognized levels.
 */
const char* log_level_to_color(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return COLOR_DEBUG;
        case LOG_LEVEL_INFO:    return COLOR_INFO;
        case LOG_LEVEL_WARNING: return COLOR_WARNING;
        case LOG_LEVEL_ERROR:   return COLOR_ERROR;
        default:                return COLOR_RESET;
    }
}

/**
 * @brief Retrieves the current system time in the format "[YYYY-MM-DD HH:MM:SS]".
 *
 * @param buffer A buffer to store the formatted time string.
 * @param size The size of the buffer.
 *
 * @note The buffer size should be at least 20 bytes to accommodate the formatted string.
 */
void get_current_time(char *buffer, size_t size) {
    time_t raw_time;

    time(&raw_time);
    struct tm *time_info = localtime(&raw_time);

    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", time_info);
}

/**
 * @brief Initializes the logger by setting the log level, output mode, and optional log file.
 *
 * @param file_path Path to the log file. If NULL, logging to a file is disabled.
 * @param level The minimum log level to record (e.g., LOG_LEVEL_INFO).
 * @param console_output Flag to enable or disable console output (1 to enable, 0 to disable).
 *
 * @note If a file path is provided and the file cannot be opened, the function exits with an error.
 */
void logger_init(const char *file_path, LogLevel level, int console_output) {
    current_log_level = level;
    log_to_console = console_output;

    if (file_path) {
        log_file = fopen(file_path, "w");
        if (!log_file) {
            fprintf(stderr, "[ERROR] Failed to open log file: %s\n", file_path);
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * @brief Closes the logger by flushing and closing the log file, if one is open.
 *
 * @note This function should be called before the program exits to release resources properly.
 */
void logger_close() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

/**
 * @brief Logs a message with the specified log level.
 *
 * Formats the message with a timestamp, thread ID, log level, and the provided message.
 * Supports variable argument formatting.
 *
 * @param level The log level for the message (e.g., LOG_LEVEL_ERROR).
 * @param format A printf-style format string for the log message.
 * @param ... Additional arguments to format the message.
 *
 * @note Messages are logged only if their level is greater than or equal to the current log level.
 * Logs are written to the file (if open) and optionally to the console with appropriate colors.
 */
void log_message(LogLevel level, const char *format, ...) {
    if (level < current_log_level) {
        return;
    }

    char time_buffer[20];
    get_current_time(time_buffer, sizeof(time_buffer));

    char log_buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    va_end(args);

    char full_message[1100];
    snprintf(full_message, sizeof(full_message), "%s [%d] [%s]: %s\n", time_buffer, gettid(), log_level_to_string(level), log_buffer);

    if (log_file) {
        fprintf(log_file, "%s", full_message);
        fflush(log_file);
    }

    if (log_to_console) {
        fprintf(stdout, "%s%s%s", log_level_to_color(level), full_message, COLOR_RESET);
        fflush(stdout);
    }
}