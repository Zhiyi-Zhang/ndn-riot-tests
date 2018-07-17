/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encoding/name.h"
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

    char name_str[] = "/ndn/zhiyi/001/bbb/a/dd";
    ndn_shared_block_t* shared_block = ndn_name_from_uri(name_str, sizeof(name_str));

    ndn_name_component_t comp;
    ndn_name_get_component_from_block(&shared_block->block, 2, &comp);

    puts("start decode");
    ndn_name_t name;
    ndn_name_wire_decode(&shared_block->block, &name);
    printf("\nsize of the name is %d \n", name.size);
    printf("component 1: %s \n", (char *)(name.comps[0].buf));
    printf("component 2: %s \n", (char *)(name.comps[1].buf));
    printf("component 3: %s \n", (char *)(name.comps[2].buf));
    printf("component 4: %s \n", (char *)(name.comps[3].buf));
    printf("component 5: %s \n", (char *)(name.comps[4].buf));
    printf("component 5: %s \n", (char *)(name.comps[5].buf));

    free(name.comps);
    ndn_shared_block_release(shared_block);

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
