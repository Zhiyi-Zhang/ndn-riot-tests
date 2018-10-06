/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encoding/certificate.h"
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

    char name_str[] = "/ndn/zhiyi/KEY/001/ndncert/002";
    ndn_shared_block_t* shared_block = ndn_name_from_uri(name_str, sizeof(name_str));

    ndn_name_t name;
    ndn_name_wire_decode(&shared_block->block, &name);

    printf("\nsize of the key name is %d \n", name.size);
    printf("first component %s \n", (char *)(name.comps[0].buf));
    printf("second component %s \n", (char *)(name.comps[1].buf));
    printf("third component %s \n", (char *)(name.comps[2].buf));
    printf("fourth component %s \n", (char *)(name.comps[3].buf));
    printf("fourth component %s \n", (char *)(name.comps[4].buf));
    printf("fourth component %s \n", (char *)(name.comps[5].buf));

    int result = ndn_cert_is_certificate_name(&name);
    printf("is certificate? %d", result);

    ndn_name_t identity_name;
    ndn_name_t key_name;

    ndn_cert_get_identity_name(&name, &identity_name);
    printf("\nsize of the identity name is %d \n", identity_name.size);
    printf("first component %s \n", (char *)(identity_name.comps[0].buf));
    printf("second component %s \n", (char *)(identity_name.comps[1].buf));

    ndn_cert_get_key_name(&name, &key_name);
    printf("\nsize of the key name is %d \n", key_name.size);
    printf("first component %s \n", (char *)(key_name.comps[0].buf));
    printf("second component %s \n", (char *)(key_name.comps[1].buf));
    printf("third component %s \n", (char *)(key_name.comps[2].buf));
    printf("fourth component %s \n", (char *)(key_name.comps[3].buf));

    free(name.comps);
    free(key_name.comps);
    free(identity_name.comps);
    ndn_shared_block_release(shared_block);

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
