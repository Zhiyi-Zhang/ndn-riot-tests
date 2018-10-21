/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/security/aes.h"
#include "shell.h"
#include "msg.h"

static uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int main(void)
{
    puts("All up, running the shell now");

    //initialize
    uint8_t key[7] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t data[15] = { 0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
                         0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32 };
    uint32_t j = 0;

    printf("plaintext before padding and encryption\n");
    while(j < 15){
        printf("0x%02x ", data[j++]);
    }
    putchar('\n');

    ndn_encrypter_t encrypter;
    ndn_encrypter_init(&encrypter, key, 7);
    uint32_t cipher_text_size = encrypter_get_padding_size(&encrypter, 15);
    printf("plaintext size after padding is %d\n", cipher_text_size);
    uint8_t cipher_text[cipher_text_size];
    ndn_encrypter_encrypt(&encrypter, iv, data, 15, cipher_text);
    
    printf("ciphertext after padding and encryption\n");
    j = 0;
    while(j < cipher_text_size){
        printf("0x%02x ", cipher_text[j++]);
    }
    putchar('\n');

    ndn_decrypter_t decrypter;
    ndn_decrypter_init(&decrypter, key, 7);
    uint8_t plain_text[15];
    ndn_decrypter_decrypt(&decrypter, iv, cipher_text, cipher_text_size, 
                          plain_text);

    // print decrypted plain text
    j = 0;
    printf("plaintext after decryption and unpadding\n");
    while(j < 15){
        printf("0x%02x ", plain_text[j++]);
    }


    // tests end

    // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
