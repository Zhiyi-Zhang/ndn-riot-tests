/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn_standalone/encode/data.h"
#include "ndn_standalone/security/ndn-lite-crypto-key.h"
#include "shell.h"
#include "msg.h"

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

static uint8_t iv[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t key[] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

int main(void)
{
  /* start shell */
  puts("All up, running the shell now");
  // char line_buf[SHELL_DEFAULT_BUFSIZE];

  uint8_t buf[16] = {2,2,2,2,2,2,2,2,2,2};
  uint8_t block_value[1024];
  ndn_encoder_t encoder;

  ndn_data_t data;
  ndn_data_set_content(&data, buf, sizeof(buf));

  // set name
  char name_string[] = "/smarthome/controller/zhiyi-phone";
  ndn_name_from_string(&data.name, name_string, sizeof(name_string));
  printf("***init data name*** \n");
  for (size_t i = 0; i < data.name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) data.name.components[i].type);
    for (size_t j = 0; j < data.name.components[i].size; j++) {
      printf("%d ", data.name.components[i].value[j]);
    }
    printf("\n");
  }
  encoder_init(&encoder, block_value, 1024);
  ndn_name_tlv_encode(&encoder, &data.name);
  printf("name block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }

  // set metainfo
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);

  // encoding digest
  encoder_init(&encoder, block_value, 1024);
  printf("\n***data encoding with digest sig***\n");
  ndn_data_tlv_encode_digest_sign(&encoder, &data);
  printf("data block length: %d \n", (int) encoder.offset);
  printf("data block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  ndn_data_t data_check;
  int result = ndn_data_tlv_decode_no_verify(&data_check, block_value, encoder.offset);
  if (result == 0) {
    printf("data encoding and digest sig verification succeeded");
  }
  else
    printf("result: %d\n", result);

  result = ndn_data_tlv_decode_digest_verify(&data_check, block_value, encoder.offset);
  if (result == 0) {
    printf("data encoding and digest sig verification succeeded");
  }
  else
    printf("result: %d\n", result);

  // encoding ecdsa
  ndn_ecc_prv_t prv_key;
  ndn_ecc_prv_init(&prv_key, private, sizeof(private), NDN_ECDSA_CURVE_SECP160R1, 1234);

  char id_string[] = "/smarthome/zhiyi";
  ndn_name_t identity;
  ndn_name_from_string(&identity, id_string, sizeof(id_string));
  printf("\n***init identity name*** \n");
  for (size_t i = 0; i < identity.components_size; i++) {
    printf("comp type %u\n", (unsigned int) identity.components[i].type);
    for (size_t j = 0; j < identity.components[i].size; j++) {
      printf("%d ", identity.components[i].value[j]);
    }
    printf("\n");
  }

  encoder_init(&encoder, block_value, 1024);
  printf("\n***data encoding with ecdsa sig***\n");
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &data, &identity, &prv_key);
  printf("data block length: %d \n", (int) encoder.offset);
  printf("data block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  ndn_ecc_pub_t pub_key;
  ndn_ecc_pub_init(&pub_key, public, sizeof(public), NDN_ECDSA_CURVE_SECP160R1, 1234);
  result = ndn_data_tlv_decode_ecdsa_verify(&data_check, block_value, encoder.offset, &pub_key);
  if (result == 0) {
    printf("data encoding and ecdsa sig verification succeeded");
  }
  else
    printf("result: %d\n", result);

  // encoding hmac
  ndn_hmac_key_t hmac_key;
  ndn_hmac_key_init(&hmac_key, private, sizeof(private), 5678);
  ndn_ecc_prv_init(&prv_key, private, sizeof(private), NDN_ECDSA_CURVE_SECP160R1, 1234);
  encoder_init(&encoder, block_value, 1024);
  printf("\n***data encoding with hmac sig***\n");
  ndn_data_tlv_encode_hmac_sign(&encoder, &data, &identity, &hmac_key);
  printf("data block length: %d \n", (int) encoder.offset);
  printf("data block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  result = ndn_data_tlv_decode_hmac_verify(&data_check, block_value, encoder.offset, &hmac_key);
  if (result == 0) {
    printf("data encoding and hmac sig verification succeeded");
  }
  else
    printf("result: %d\n", result);

  // Encrypted Data
  printf("\n***Encrypted Data Tests*** \n");
  ndn_aes_key_t aes;
  ndn_aes_key_init(&aes, key, sizeof(key), 1234);
  printf("\n***data content before encryption with aes***\n");
  printf("data content block length: %d \n", data.content_size);
  printf("data content block content: \n");
  for (size_t i = 0; i < data.content_size; i++) {
    printf("%d ", data.content_value[i]);
  }
  ndn_data_set_encrypted_content(&data, buf, sizeof(buf), &identity, iv, &aes);
  printf("\n***data content after encryption with aes***\n");
  printf("data content block length: %d \n", data.content_size);
  printf("data content block content: \n");
  for (size_t i = 0; i < data.content_size; i++) {
    printf("%d ", data.content_value[i]);
  }

  uint8_t decrypt_output[50] = {0};
  uint32_t used = 0;
  ndn_data_parse_encrypted_content(&data, decrypt_output, &used, &identity, iv, &aes);
  printf("\n***data content after parsing***\n");
  printf("data content block length: %d \n", data.content_size);
  printf("data content block content: \n");
  for (size_t i = 0; i < used; i++) {
    printf("%d ", decrypt_output[i]);
  }

  return 0;
}
