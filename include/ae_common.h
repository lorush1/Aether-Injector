#ifndef AE_COMMON_H
#define AE_COMMON_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    AE_OK = 0,
    AE_ERROR_INVALID,
    AE_ERROR_NOT_FOUND,
    AE_ERROR_MEMORY,
    AE_ERROR_IO,
    AE_ERROR_PERMISSION,
    AE_ERROR_UNSUPPORTED
} ae_status_t;

typedef uintptr_t ae_addr_t;
typedef size_t ae_size_t;

#define AE_SYMBOL_NAME_MAX 256

#endif
