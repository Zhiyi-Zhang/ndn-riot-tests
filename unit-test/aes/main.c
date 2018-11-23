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

  puts("Test AES-CBC Mode");

  //initialize
  uint8_t key[18] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
  uint8_t data[16] = { 0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
                       0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x33 };
  uint32_t j = 0;

  printf("print raw data\n");
  while(j < 16){
    printf("0x%02x ", data[j++]);
  }
  putchar('\n');

  ndn_encrypter_t encrypter;
  ndn_encrypter_init(&encrypter, key);
  uint8_t cipher_text_size = sizeof(data) + TC_AES_BLOCK_SIZE;
  uint8_t cipher_text[cipher_text_size];
  ndn_encrypter_cbc_set_buffer(&encrypter, data, 16, cipher_text, cipher_text_size);
  ndn_encrypter_cbc_encrypt(&encrypter, iv);

  printf("ciphertext after encryption\n");
  j = 0;
  while(j < cipher_text_size){
    printf("0x%02x ", cipher_text[j++]);
  }
  putchar('\n');

  ndn_decrypter_t decrypter;
  ndn_decrypter_init(&decrypter, key);
  uint8_t plain_text[cipher_text_size];
  ndn_decrypter_cbc_set_buffer(&decrypter, cipher_text, cipher_text_size, plain_text, cipher_text_size);
  ndn_decrypter_cbc_decrypt(&decrypter, iv);

  // print decrypted plain text
  j = 0;
  printf("plaintext after decryption\n");
  while(j < 16){
    printf("0x%02x ", plain_text[j++]);
  }

  // tests end

  puts("\nTest AES");
  uint8_t plaintext[TC_AES_BLOCK_SIZE];
  memcpy(plaintext, iv, TC_AES_BLOCK_SIZE);
  uint8_t expected[TC_AES_BLOCK_SIZE];
  uint8_t decrypted[TC_AES_BLOCK_SIZE];
  ndn_encrypter_set_buffer(&encrypter, plaintext, TC_AES_BLOCK_SIZE, expected, sizeof(expected));
  ndn_encrypter_encrypt(&encrypter);
  ndn_decrypter_set_buffer(&decrypter, expected, sizeof(expected), decrypted, sizeof(decrypted));
  ndn_decrypter_decrypt(&decrypter);
  j = 0;
  printf("plaintext after decryption\n");
  while(j < 16){
    printf("0x%02x ", decrypted[j++]);
  }

  // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
  /* should be never reached */
  return 0;
}
