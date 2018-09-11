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
#include "xtimer.h"
#include "key.h"

//extern void ndn_test(void);
extern int ndn_bootstrap(int num, uint8_t* pub, uint8_t* pvt);

#define DPRINT(...) printf(__VA_ARGS__)

int main(void)
{

    ndn_bootstrap(0, pub_160r1, pvt_160r1);


    return 0;
}