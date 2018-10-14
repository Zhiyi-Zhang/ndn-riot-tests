/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encode/name.h"
#include "shell.h"
#include "msg.h"

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];

    // initialization
    char name[] = "aaaaaaaaaaaaaaaa";
    name_component_t component = name_component_from_string(name, sizeof(name));
    printf("check type %d\n", component.type);
    printf("check length %zu\n", component.size);
    printf("check buffer content\n");
    for (size_t i = 0; i < component.size; i++) {
      printf("%d ", component.value[i]);
    }

    // encoding
    ndn_block_t check_block;
    size_t block_size = name_component_block_size(&component);
    uint8_t block_value[block_size];
    check_block.value = block_value;
    check_block.size = block_size;
    name_component_wire_encode(&component, &check_block);
    printf("\n");
    printf("check block length %zu\n", check_block.size);
    printf("check block content\n");
    for (size_t i = 0; i < check_block.size; i++) {
      printf("%d ", check_block.value[i]);
    }

    // decoding
    size_t check_comp_size = decoder_probe_value_size(&check_block);
    uint8_t check_comp_value[check_comp_size];
    name_component_t check_component;
    check_component.value = check_comp_value;
    check_component.size = check_comp_size;
    name_component_from_block(&check_component, &check_block);
    printf("\n");
    printf("check type %d\n", check_component.type);
    printf("check length %zu\n", check_component.size);
    printf("check buffer content\n");
    for (size_t i = 0; i < check_component.size; i++) {
      printf("%d ", check_component.value[i]);
    }

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
