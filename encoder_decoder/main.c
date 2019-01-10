/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-lite/encode/encoder.h"
#include "ndn-lite/encode/decoder.h"
#include "shell.h"
#include "msg.h"

int main(void)
{
  /* start shell */
  uint8_t buf[10] = {2,2,2,2,2,2,2,2,2,2};
  uint32_t type = 100;

  int block_size = encoder_probe_block_size(type, sizeof(buf));
  uint8_t block_value[block_size];
  struct ndn_encoder encoder;
  encoder_init(&encoder, block_value, block_size);

  encoder_append_type(&encoder, type);
  encoder_append_length(&encoder, sizeof(buf));
  encoder_append_raw_buffer_value(&encoder, buf, sizeof(buf));
  printf("\n***encoder encoding***\n");
  printf("block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", encoder.output_value[i]);
  }

  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t check_type = 0;
  uint32_t check_length = 0;
  decoder_get_type(&decoder, &check_type);
  decoder_get_type(&decoder, &check_length);
  uint8_t check_buf[check_length];
  decoder_get_raw_buffer_value(&decoder, check_buf, check_length);

  printf("\n***decoder decoding***\n");
  printf("check type %d\n", check_type);
  printf("check length %d\n", check_length);

  printf("\nTest END\n");

  return 0;
}
