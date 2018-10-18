/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/security/sign-verify.h"
#include "shell.h"
#include "msg.h"

// static const shell_command_t shell_commands[] = {
//     { NULL, NULL, NULL }
// };

static uint8_t private[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50,
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

static uint8_t public[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA,
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/


int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    // char line_buf[SHELL_DEFAULT_BUFSIZE];

    //initialize
    uint8_t data[100];
    uint8_t signature[64];

    for (size_t i = 0; i < 100; ++i) data[i] = 0x31;

    ndn_block_t input = { data, 100, 100 };

    ndn_buffer_t pub = { public, 64 };
    ndn_buffer_t pvt = { private, 32 };
    ndn_buffer_t signature_ecdsa = { signature, 64 };
    ndn_ecdsa_t ecdsa;
    ndn_ecdsa_set_public_key(&ecdsa, &pub);
    ndn_ecdsa_set_private_key(&ecdsa, &pvt);
    ndn_ecdsa_set_type(&ecdsa, NDN_ECDSA_CURVE_SECP160R1);

    int r = ndn_security_ecdsa_sign_value(&input, &ecdsa, &signature_ecdsa); 
    if(r == 0) printf("ECDSA signing success\n");

    r = ndn_security_ecdsa_verify_value(&input, &ecdsa, &signature_ecdsa); 
    if(r == 0) printf("ECDSA verification success\n");

    ndn_buffer_t key = { private, 32 };
    ndn_buffer_t signature_hmac = { signature, 32 };
    ndn_hmac_t hmac;
    ndn_hmac_set_key(&hmac, &key);
    r = ndn_security_hmac_sign_value(&input, &hmac, &signature_hmac);
    if(r == 0) printf("HMAC signing success\n");

    r = ndn_security_hmac_verify_value(&input, &hmac, &signature_hmac);
    if(r == 0) printf("HMAC verification success\n");


    r = ndn_security_digest_sign_value(&input, &signature_hmac);
    if(r == 0) printf("DIGEST signing success\n");

    r = ndn_security_digest_verify_value(&input, &signature_hmac);
    if(r == 0) printf("DIGEST verification success\n");

    // tests end

    // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
