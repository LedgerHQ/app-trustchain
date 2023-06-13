#pragma once

#define ENABLE_DEBUG 1

#ifdef ENABLE_DEBUG
#include <stdint.h>

#define DEBUG_PRINT_BUF(buf, len) \
    debug_write_hex(buf, len);
#define DEBUG_PRINT(str) \
    debug_write(str);

void debug_write(char *buf);
void debug_write_hex(uint8_t *buf, uint32_t len);

#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINT_BUF(buf, len)
#endif