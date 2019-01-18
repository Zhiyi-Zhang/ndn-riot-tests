
#include "print-helpers.h"

#include <stdio.h>

void print_hex(const char *msg, uint8_t *val, uint32_t val_len) {
  printf("%s\n", msg);
  for (uint32_t i = 0; i < val_len; i++) {
    printf("%02x", (unsigned int) *val);
  }
  printf("\n");
}
