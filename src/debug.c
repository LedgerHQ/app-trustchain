#include "debug.h"

#ifdef ENABLE_DEBUG

void debug_write(char *buf)
{
  asm volatile (
     "movs r0, #0x04\n"
     "movs r1, %0\n"
     "svc      0xab\n"
     :: "r"(buf) : "r0", "r1"
  );
}

void debug_write_hex(uint8_t *buf, uint32_t len)
{
  #define MAX_HEX_LEN 200
  char hex[MAX_HEX_LEN + 1];
  const char *hex_chars = "0123456789abcdef";

  int offset = 0;
  for (; offset < len; offset++) {
    hex[offset * 2] = hex_chars[buf[offset] >> 4];
    hex[offset * 2 + 1] = hex_chars[buf[offset] & 0x0f];
  }
  hex[offset * 2] = '\0';

  debug_write(hex);
  if (len * 2 > MAX_HEX_LEN) {
    debug_write("...\n");
  } else {
    debug_write("\n");
  }
}

#endif