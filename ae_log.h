#ifndef AE_LOG_H
#define AE_LOG_H

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

/* Log levels */
typedef enum {
    AE_LOG_SUCCESS = 0,
    AE_LOG_INFO = 1,
    AE_LOG_WARNING = 2,
    AE_LOG_ERROR = 3,
    AE_LOG_CRITICAL = 4,
    AE_LOG_DEBUG = 5
} ae_log_level_t;

/* ANSI color codes */
#define AE_COLOR_GREEN   "\033[1;32m"
#define AE_COLOR_CYAN    "\033[1;36m"
#define AE_COLOR_YELLOW  "\033[1;33m"
#define AE_COLOR_RED     "\033[1;31m"
#define AE_COLOR_MAGENTA "\033[1;35m"
#define AE_COLOR_BLUE    "\033[1;34m"
#define AE_COLOR_RESET   "\033[0m"

/* Get level string and color */
static inline void ae_get_level_info(ae_log_level_t level, const char **tag, const char **color) {
    static int use_color = -1;
    
    /* Determine if we should use colors (only on first call) */
    if (use_color == -1) {
        use_color = isatty(fileno(stderr));
    }
    
    switch (level) {
        case AE_LOG_SUCCESS:
            *tag = "[SUCCESS]";
            *color = use_color ? AE_COLOR_GREEN : "";
            break;
        case AE_LOG_INFO:
            *tag = "[INFO]";
            *color = use_color ? AE_COLOR_CYAN : "";
            break;
        case AE_LOG_WARNING:
            *tag = "[WARNING]";
            *color = use_color ? AE_COLOR_YELLOW : "";
            break;
        case AE_LOG_ERROR:
            *tag = "[ERROR]";
            *color = use_color ? AE_COLOR_RED : "";
            break;
        case AE_LOG_CRITICAL:
            *tag = "[CRITICAL]";
            *color = use_color ? AE_COLOR_MAGENTA : "";
            break;
        case AE_LOG_DEBUG:
            *tag = "[DEBUG]";
            *color = use_color ? AE_COLOR_BLUE : "";
            break;
        default:
            *tag = "[UNKNOWN]";
            *color = "";
            break;
    }
}

/* Main logging function */
static inline void ae_log(ae_log_level_t level, const char *fmt, ...) {
    char timestamp[64];
    time_t now;
    struct tm *tm_info;
    const char *tag;
    const char *color;
    const char *reset = "";
    static int use_color = -1;
    
    /* Determine if we should use colors */
    if (use_color == -1) {
        use_color = isatty(fileno(stderr));
    }
    
    if (use_color) {
        reset = AE_COLOR_RESET;
    }
    
    /* Get current time */
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Get level info */
    ae_get_level_info(level, &tag, &color);
    
    /* Print timestamp and level tag */
    fprintf(stderr, "[%s] %s%s%s ", timestamp, color, tag, reset);
    
    /* Print the actual message */
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}

#endif /* AE_LOG_H */

