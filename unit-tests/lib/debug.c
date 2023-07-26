#include "debug.h"
#include <stdio.h>

void debug_write(const char *buf) {
    printf("%s", buf);
}

void debug_write_hex(const uint8_t *buf, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    debug_write("\n");
}