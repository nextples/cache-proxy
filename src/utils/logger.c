#include "logger.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>

static FILE *log_file = NULL;
static log_lvl current_log_level = LOG_LEVEL_DEBUG;
static int log_to_console = 1;

const char* log_level_to_string(const log_lvl level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR:   return "ERROR";
        default:                return "UNKNOWN";
    }
}

const char* log_level_to_color(const log_lvl level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:   return COLOR_DEBUG;
        case LOG_LEVEL_INFO:    return COLOR_INFO;
        case LOG_LEVEL_WARNING: return COLOR_WARNING;
        case LOG_LEVEL_ERROR:   return COLOR_ERROR;
        default:                return COLOR_RESET;
    }
}

void get_current_time(char *buffer, const size_t size) {
    time_t raw_time;

    time(&raw_time);
    struct tm *time_info = localtime(&raw_time);

    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", time_info);
}

void logger_init(const char *file_path, const log_lvl level, const int console_output) {
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

void logger_close() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_message(const log_lvl level, const char *format, ...) {
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