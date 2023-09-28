#pragma once

#define ENABLE_DEBUG
#define ENABLE_APDU_LOG

#ifdef ENABLE_DEBUG
#include <stdint.h>

#define DEBUG_PRINT_BUF(buf, len) debug_write_hex(buf, len);
#define DEBUG_PRINT(str)          debug_write(str);

#define DEBUG_PRINT_BN(prompt, bn)     \
    {                                  \
        uint8_t n[32];                 \
        cx_bn_export(bn, n, 32);       \
        debug_write(prompt);           \
        debug_write_hex(n, sizeof(n)); \
    }
#define DEBUG_LOG_BUF(prompt, buf, len) \
    {                                   \
        debug_write(prompt);            \
        debug_write_hex(buf, len);      \
    }

void debug_write(const char *buf);
void debug_write_hex(const uint8_t *buf, uint32_t len);

#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINT_BUF(buf, len)
#define DEBUG_PRINT_BN(prompt, bn)
#define DEBUG_LOG_BUF(...)
#endif

#ifdef ENABLE_APDU_LOG
#define APDU_LOG_BUF(buf, len)                                                 \
    {                                                                          \
        buffer_t apdu_log_buf;                                                 \
        apdu_log_buf.ptr = buf;                                                \
        apdu_log_buf.size = len;                                               \
        apdu_log_buf.offset = 0;                                               \
        io_send_response_pointer(apdu_log_buf.ptr, apdu_log_buf.size, 0x9000); \
        return -1;                                                             \
    }
#define APDU_LOG_BN(bn)                                                        \
    {                                                                          \
        uint8_t n[32];                                                         \
        cx_bn_export(bn, n, 32);                                               \
        buffer_t apdu_log_buf;                                                 \
        apdu_log_buf.ptr = n;                                                  \
        apdu_log_buf.size = 32;                                                \
        apdu_log_buf.offset = 0;                                               \
        io_send_response_pointer(apdu_log_buf.ptr, apdu_log_buf.size, 0x9000); \
        return -1;                                                             \
    }
#else
#define APDU_LOG_BUF(...)
#define APDU_LOG_BN(...)
#endif