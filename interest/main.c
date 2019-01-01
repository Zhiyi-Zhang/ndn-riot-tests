/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn_standalone/encode/signed-interest.h"
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

void test_unsigned_interest(ndn_name_t* name)
{
  // init an Interest
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);
  printf("***init an Interest*** \n");
  printf("hop limit: %d\n", interest.hop_limit);

  // Interest encodes
  uint8_t block_value[200];
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, sizeof(block_value));
  ndn_interest_tlv_encode(&encoder, &interest);
  printf("***Interest Encodes*** \n");
  printf("block size: %d\n", (int) encoder.offset);
  printf("block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  // Interest decodes
  ndn_interest_t check_interest;
  printf("before function starts\n");
  int result = ndn_interest_from_block(&check_interest, block_value, encoder.offset);
  printf("***Interest Decodes*** \n");
  printf("result number: %d\n", result);
  printf("hop limit: %d\n", interest.hop_limit);
  printf("name component size: %d\n", (int) check_interest.name.components_size);
  for (size_t i = 0; i < check_interest.name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) check_interest.name.components[i].type);
    for (size_t j = 0; j < check_interest.name.components[i].size; j++) {
      printf("%d ", check_interest.name.components[i].value[j]);
    }
    printf("\n");
  }
}

void test_ecdsa_signed_interest(ndn_name_t* name, ndn_name_t* identity)
{
  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  ndn_ecc_prv_t prv_key;
  ndn_ecc_prv_init(&prv_key, private, sizeof(private), NDN_ECDSA_CURVE_SECP160R1, 1234);

  uint8_t pool[256];

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with ecdsa sig***\n");
  ndn_signed_interest_tlv_encode_ecdsa_sign(&encoder, &interest, identity, &prv_key);
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_ecc_pub_t pub_key;
  ndn_interest_t check_interest;
  ndn_ecc_pub_init(&pub_key, public, sizeof(public), NDN_ECDSA_CURVE_SECP160R1, 1234);
  ndn_interest_from_block(&check_interest, pool, encoder.offset);
  int result = ndn_signed_interest_ecdsa_verify(&check_interest, &pub_key);
  if (result == 0) {
    printf("interest encoding and ecdsa sig verification succeeded");
  }
  else
    printf("result: %d\n", result);
}

void test_hmac_signed_interest(ndn_name_t* name, ndn_name_t* identity)
{
  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  uint8_t pool[256];

  ndn_hmac_key_t hmac_key;
  ndn_hmac_key_init(&hmac_key, private, sizeof(private), 5678);

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with hmac sig***\n");
  ndn_signed_interest_tlv_encode_hmac_sign(&encoder, &interest, identity, &hmac_key);
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_interest_t check_interest;
  ndn_interest_from_block(&check_interest, pool, encoder.offset);
  int result = ndn_signed_interest_hmac_verify(&check_interest, &hmac_key);
  if (result == 0) {
    printf("interest encoding and hmac sig verification succeeded");
  }
  else
    printf("result: %d\n", result);
}

void test_digest_signed_interest(ndn_name_t* name)
{
  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  uint8_t pool[256];

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with digest sig***\n");
  ndn_signed_interest_tlv_encode_digest_sign(&encoder, &interest);
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_interest_t check_interest;
  ndn_interest_from_block(&check_interest, pool, encoder.offset);
  int result = ndn_signed_interest_digest_verify(&check_interest);
  if (result == 0) {
    printf("interest encoding and digest sig verification succeeded");
  }
  else
    printf("result: %d\n", result);
}
int main(void)
{
  // tests start

  // init a name
  char name_string[] = "/aaa/bbb/ccc/ddd";
  ndn_name_t name;
  ndn_name_from_string(&name, name_string, sizeof(name_string));
  printf("***init a name*** \n");
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

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

  test_unsigned_interest(&name);
  test_ecdsa_signed_interest(&name, &identity);
  test_hmac_signed_interest(&name, &identity);
  test_digest_signed_interest(&name);

  return 0;
}
