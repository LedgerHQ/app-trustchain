#include "debug.h"

#ifdef ENABLE_DEBUG

void debug_write(const char *buf) {
    asm volatile(
        "movs r0, #0x04\n"
        "movs r1, %0\n"
        "svc      0xab\n" ::"r"(buf)
        : "r0", "r1");
}

void debug_write_hex(const uint8_t *buf, uint32_t len) {
    char hex[3] = {0, 0, 0};
    const char *hex_chars = "0123456789abcdef";
    uint32_t offset;

    for (offset = 0; offset < len; offset++) {
        hex[0] = hex_chars[buf[offset] >> 4];
        hex[1] = hex_chars[buf[offset] & 0x0f];
        debug_write(hex);
    }
    debug_write("\n");
}

#endif