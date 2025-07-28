#ifndef LOGGING_H
#define LOGGING_H
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

// Logging levels
#define LOG_LEVEL_NONE  0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_INFO  3
#define LOG_LEVEL_DEBUG 4

// Default log level: Change here or via -DLOG_LEVEL=...
#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

// Log level string helper
static inline const char *log_level_str(int level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default: return "LOG";
    }
}

// Returns pointer to the base filename within a path (no allocations)
static inline const char *basename_c(const char *path) {
    const char *slash = strrchr(path, '/');
    #ifdef _WIN32
    const char *backslash = strrchr(path, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
    #endif
    return slash ? slash + 1 : path;
}

// Core macro
#define LOG(level, fmt, ...) \
    do { \
        if ((level) <= LOG_LEVEL) { \
            fprintf(stderr, "[%s] %s:%d:%s(): " fmt "\n", \
                log_level_str(level), basename_c(__FILE__), __LINE__, __func__, ##__VA_ARGS__); \
        } \
    } while (0)

// Convenience wrappers
#define LOG_ERROR(fmt, ...) LOG(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG(LOG_LEVEL_WARN,  fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#endif
