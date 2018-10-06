/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Minimum NDN consumer
 *
 * @author      Wentao Shang <wentaoshang@gmaiil.com>
 *
 * @}
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>

extern void* ndn_controller(void*);

kernel_pid_t pid = KERNEL_PID_UNDEF;

int main(void)
{
	char* stack = (char*)malloc(THREAD_STACKSIZE_DEFAULT );
    pid = thread_create(stack, THREAD_STACKSIZE_DEFAULT,
                            THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_controller, NULL, "controller");
    free(stack);

    /* should be never reached */
    return 0;
}
