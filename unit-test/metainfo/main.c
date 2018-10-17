/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encode/metainfo.h"
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

    // metainfo test
    putchar('\n');
    printf("***metainfo check***\n");
    ndn_metainfo_t meta;
    ndn_metainfo_init(&meta, -1, -1, &component);  
    size_t estimate = ndn_metainfo_probe_block_size(&meta);

    // metainfo encode
    uint8_t buffer[estimate];
    ndn_block_t wire_encode = { buffer, estimate };
    ndn_metainfo_tlv_encode(&meta, &wire_encode);
    printf("check wire_encode size %zu\n", wire_encode.size);

    // metainfo decode
    ndn_metainfo_t meta_decode;
    ndn_metainfo_tlv_decode(&meta_decode, &wire_encode);
    estimate = ndn_metainfo_probe_block_size(&meta_decode);
    printf("check meta_code esti size %zu\n", estimate);

    if( meta_decode.content_type == -1 ) printf("content_type correct\n");
    if( meta_decode.freshness == -1 ) printf("freshness correct\n");

    printf("check finalblock_id content\n");
    for (size_t i = 0; i < meta_decode.finalblock_id.size; i++) {
      printf("%d ", meta_decode.finalblock_id.value[i]);
    }

    //shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
