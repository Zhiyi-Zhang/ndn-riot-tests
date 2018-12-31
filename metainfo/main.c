/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn_standalone/encode/metainfo.h"
#include "ndn_standalone/encode/name.h"
#include "shell.h"
#include "msg.h"

// static const shell_command_t shell_commands[] = {
//     { NULL, NULL, NULL }
// };

int main(void)
{
  /* start shell */
  puts("All up, running the shell now");
  // char line_buf[SHELL_DEFAULT_BUFSIZE];

  // tests start

  // component initialization
  char comp1[] = "aaaaaa";
  name_component_t component;
  name_component_from_string(&component, comp1, sizeof(comp1));
  printf("***component init***\ncheck type %u\n", (unsigned int) component.type);
  printf("check length %u\n", component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < component.size; i++) {
    printf("%d ", component.value[i]);
  }

  // metainfo test
  putchar('\n');
  ndn_metainfo_t meta;
  ndn_metainfo_init(&meta);
  ndn_metainfo_set_final_block_id(&meta, &component);

  // metainfo encode
  size_t block_size = ndn_metainfo_probe_block_size(&meta);
  uint8_t block_value[block_size];
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, block_size);
  ndn_metainfo_tlv_encode(&encoder, &meta);
  printf("***metainfo encode***\n");
  printf("check block size %d\n", (int) block_size);
  printf("check wire_encode content\n");
  for (size_t i = 0; i < block_size; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n***metainfo decode***\n");

  // metainfo decode
  ndn_metainfo_t meta_decode;
  printf("create a new metainfo \n");
  ndn_metainfo_from_tlv_block(&meta_decode, block_value, block_size);
  if (meta_decode.enable_ContentType == 0)
    printf("content_type correct\n");
  if (meta_decode.enable_FreshnessPeriod == 0)
    printf("freshness correct\n");
  printf("check finalblock_id content\n");
  for (size_t i = 0; i < meta_decode.final_block_id.size; i++) {
    printf("%d ", meta_decode.final_block_id.value[i]);
  }

  //shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
  /* should be never reached */
  return 0;
}
