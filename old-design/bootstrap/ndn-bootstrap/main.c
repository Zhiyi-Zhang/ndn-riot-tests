/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include <ndn-riot/encoding/ndn-constants.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>
#include <string.h>
#include "shell.h"
#include "xtimer.h"

//extern void ndn_test(void);
extern void *ndn_bootstrap(void *arg);

static const shell_command_t commands[] = {
    { NULL, NULL, NULL }
};

static kernel_pid_t pid;
static char bootstrap_stack[THREAD_STACKSIZE_MAIN];
#define DPRINT(...) printf(__VA_ARGS__)

int main(void)
{
    msg_t send, reply;
    reply.content.ptr = NULL;

    pid = thread_create(bootstrap_stack, sizeof(bootstrap_stack),
                            THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_bootstrap, NULL, "bootstrap");
	//ndn_bootstrap(NULL);
    send.content.ptr = reply.content.ptr;
    //uint32_t seconds = 10;
    //xtimer_sleep(seconds);
    uint32_t seconds = 10;
    xtimer_sleep(seconds);
    msg_send_receive(&send, &reply, pid);

    ndn_block_t* cert;
    ndn_block_t name;
    cert = reply.content.ptr;
    ndn_data_get_name(cert, &name);
    DPRINT("certificate ipc received, name=");
    ndn_name_print(&name);
    putchar('\n');

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}