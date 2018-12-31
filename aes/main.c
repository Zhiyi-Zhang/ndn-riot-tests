/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn_standalone/security/ndn-lite-aes.h"
#include "shell.h"
#include "msg.h"

static uint8_t iv[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t key[] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static uint8_t data[] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
  0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
  0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
  0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
  0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

int main(void)
{
  puts("Test AES-CBC Mode");

  //initialize
  uint32_t j = 0;
  printf("print raw data\n");
  while (j < sizeof(data)) {
    printf("0x%02x ", data[j++]);
  }
  putchar('\n');

  // encrypt
  uint8_t cipher_text[sizeof(data) + TC_AES_BLOCK_SIZE] = {0};
  ndn_encrypter_t encrypter;
  ndn_encrypter_aes_cbc_init(&encrypter, data, sizeof(data),
                             cipher_text, sizeof(cipher_text));
  ndn_encrypter_aes_cbc_encrypt(&encrypter, iv, key, sizeof(key));

  printf("ciphertext after encryption\n");
  j = 0;
  while (j < sizeof(data) + TC_AES_BLOCK_SIZE) {
    printf("0x%02x ", cipher_text[j++]);
  }
  putchar('\n');

  // decrypt
  uint8_t plain_text[sizeof(data)] = {0};
  ndn_decrypter_t decrypter;
  ndn_decrypter_aes_cbc_init(&decrypter, cipher_text, sizeof(cipher_text),
                             plain_text, sizeof(plain_text));
  ndn_decrypter_aes_cbc_decrypt(&decrypter, key, sizeof(key));

  // print decrypted plain text
  j = 0;
  printf("plaintext after decryption\n");
  while(j < sizeof(data)){
    printf("0x%02x ", plain_text[j++]);
  }

  // tests end
  return 0;
}
