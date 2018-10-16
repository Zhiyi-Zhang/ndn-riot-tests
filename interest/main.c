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

    char name_string[] = "/aaa/bbb/ccc/ddd";
    ndn_name_t name;
    ndn_name_from_string(&name, name_string, sizeof(name_string));

    // tests end

    // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
