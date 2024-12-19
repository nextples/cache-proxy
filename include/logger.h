#ifndef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} LogLevel;

#define COLOR_RESET   "\033[0m"
#define COLOR_DEBUG   "\033[36m" // Cyan
#define COLOR_INFO    "\033[32m" // Green
#define COLOR_WARNING "\033[33m" // Yellow
#define COLOR_ERROR   "\033[31m" // Red
#define COLOR_FATAL   "\033[35m" // Magenta

void logger_init(const char *file_path, LogLevel level, int console_output);

void logger_close();

void log_message(LogLevel level, const char *format, ...);

#endif //LOGGER_H
