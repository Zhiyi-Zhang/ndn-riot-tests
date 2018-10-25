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
#include <string.h>
#include <ndn-riot/encoding/ndn-constants.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/app.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/encoding/key.h>
#include <ndn-riot/msg-type.h>
#include <ndn-riot/helper/helper-app.h>
#include <ndn-riot/helper/helper-core.h>
#include "shell.h"
#include "xtimer.h"
#include "thread.h"

static ndn_keypair_t key;

static uint8_t ecc_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t ecc_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key

#define DPRINT(...) printf(__VA_ARGS__)

int test_bootstrap(int argc, char **argv)
{
    argc = argc;
    (void)argv;
    ndn_helper_bootstrap_start(&key);

    return 0;
}

int test_access(int argc, char **argv)
{
    argc = argc;
    (void)argv;

    /* initiate access control thread */
    ndn_helper_access_init();
    ndn_access_t access;
    access.ace = &key;
    access.opt = NULL;

    /* apply for producer encrytion key */
    uint8_t producer_key[32] = {0};
    uint8_t* ptr = ndn_helper_access_producer(&access);
    memcpy(producer_key, ptr, 32);

    /* print it out */
    DPRINT("encryption key is: ");
    for(unsigned i=0; i < 32; ++i) {
        printf("0x%02X ", (unsigned)producer_key[i]);
    }
    putchar('\n');

    return 0;
}

int test_discovery(int argc, char **argv)
{
    argc = argc;
    (void)argv;
    
    /* initiate discovery thread, register subprefixes and broadcast 
     * Notes: samr21-xpro will suffer from insufficient RAM here
     */
    ndn_helper_discovery_init();
    ndn_helper_discovery_register_prefix("/printer/desk");
    ndn_helper_discovery_register_prefix("/AC/desk");
    ndn_helper_discovery_start();

    return 0;
}

static const shell_command_t shell_commands[] = {
    { "node-bootstrap", "start node bootstrapping", test_bootstrap },
    { "node-access", "start node access control", test_access },
    { "node-discovery", "start node neighbour discovery", test_discovery },
    { NULL, NULL, NULL }
};

int main(void)
{
    key.pub = ecc_key_pub;
    key.pvt = ecc_key_pri;

    /* initiate the helper */
    ndn_helper_init();

    /* allow for command line tools */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}