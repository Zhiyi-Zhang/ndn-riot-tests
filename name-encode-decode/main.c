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

    // component encoding
    name_component_block_t check_block;
    name_component_tlv_encode(&component, &check_block);
    printf("\n***component encoding***\n");
    printf("check block length %u\n", check_block.size);
    printf("check block content\n");
    for (size_t i = 0; i < check_block.size; i++) {
      printf("%d ", check_block.value[i]);
    }

    // component decoding
    name_component_t check_component;
    name_component_from_block(&check_component, &check_block);
    printf("\n***component decoding***\n");
    printf("check type %u\n", (unsigned int) check_component.type);
    printf("check length %u\n", check_component.size);
    printf("check buffer content\n");
    for (size_t i = 0; i < check_component.size; i++) {
      printf("%d ", check_component.value[i]);
    }

    // name initialization
    char comp2[] = "bbbbbb";
    char comp3[] = "cccccc";
    char comp4[] = "123456";
    name_component_t component2;
    name_component_from_string(&component2, comp2, sizeof(comp2));
    name_component_t component3;
    name_component_from_string(&component3, comp3, sizeof(comp3));
    name_component_t component4;
    name_component_from_string(&component4, comp4, sizeof(comp4));
    name_component_t components[3];
    components[0] = component;
    components[1] = component2;
    components[2] = component3;

    ndn_name_t name;
    ndn_name_init(&name, components, 3);
    printf("\n***name init***\ncheck name comp size %u\n", name.components_size);
    for (size_t i = 0; i < name.components_size; i++) {
      printf("comp type %u\n", (unsigned int) name.components[i].type);
      for (size_t j = 0; j < name.components[i].size; j++) {
        printf("%d ", name.components[i].value[j]);
      }
      printf("\n");
    }

    // name append
    ndn_name_append_component(&name, &component4);
    printf("***name append comp***\ncheck name comp size %u\n", name.components_size);
    for (size_t i = 0; i < name.components_size; i++) {
      printf("comp type %u\n", (unsigned int) name.components[i].type);
      for (size_t j = 0; j < name.components[i].size; j++) {
        printf("%d ", name.components[i].value[j]);
      }
      printf("\n");
    }

    // name encode
    size_t name_block_size = ndn_name_probe_block_size(&name);
    uint8_t name_block_value[name_block_size];
    ndn_block_t name_block;
    name_block.value = name_block_value;
    name_block.size = name_block_size;
    ndn_name_tlv_encode(&name, &name_block);
    printf("\n***name encoding***\n");
    printf("check block length %zu\n", name_block.size);
    printf("check block content\n");
    for (size_t i = 0; i < name_block.size; i++) {
      printf("%d ", name_block.value[i]);
    }

    // tests end

    // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
