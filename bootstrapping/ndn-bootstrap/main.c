/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

//extern void ndn_test(void);
extern void ndn_bootstrap(void);

int main(void)
{
    //ndn_test();
    ndn_bootstrap();

    /* should be never reached */
    return 0;
}
