/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encode/interest.h"
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

  // init a name
  char name_string[] = "/aaa/bbb/ccc/ddd";
  ndn_name_t name;
  ndn_name_from_string(&name, name_string, sizeof(name_string));
  printf("***init a name*** \n");
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // init an Interest
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, &name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);
  printf("***init an Interest*** \n");
  printf("hop limit: %d\n", interest.hop_limit);

  // Interest encodes
  uint32_t block_size = ndn_interest_probe_block_size(&interest);
  uint8_t block_value[block_size];
  uint32_t block_used_size = 0;
  ndn_interest_tlv_encode(&interest, block_value, block_size, &block_used_size);
  printf("***Interest Encodes*** \n");
  printf("block size: %d\n", (int) block_size);
  printf("block content: \n");
  for (size_t i = 0; i < block_size; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  // Interest decodes
  ndn_interest_t check_interest;
  printf("before function starts\n");
  int result = ndn_interest_from_block(&check_interest, block_value, block_size);
  printf("***Interest Decodes*** \n");
  printf("result number: %d\n", result);
  printf("hop limit: %d\n", interest.hop_limit);
  printf("name component size: %d\n", (int) check_interest.name.components_size);
  for (size_t i = 0; i < check_interest.name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) check_interest.name.components[i].type);
    for (size_t j = 0; j < check_interest.name.components[i].size; j++) {
      printf("%d ", check_interest.name.components[i].value[j]);
    }
    printf("\n");
  }

  // tests end

  // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
  /* should be never reached */
  return 0;
}
