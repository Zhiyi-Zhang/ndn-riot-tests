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

    char name_str[] = "/ndn/zhiyi";
    ndn_shared_block_t* shared_block = ndn_name_from_uri(name_str, sizeof(name_str));
    puts("the input name is \n");

    puts("start decode");
    ndn_name_t name;
    ndn_name_wire_decode(&shared_block->block, &name);
    printf("\nsize of the name is %d \n", name.size);
    printf("first component %s \n", (char *)(name.comps[0].buf));
    printf("second component %s \n", (char *)(name.comps[1].buf));

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
