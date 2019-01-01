/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/signature.h"
#include "shell.h"
#include "msg.h"

static uint8_t bytes[] = {
  0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA,
  0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
  0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
  0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
  0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
  0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
  0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
  0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

int main(void)
{
  // name init
  char key_name_string[] = "/smarthome/controller/key/001";
  ndn_name_t name;
  ndn_name_from_string(&name, key_name_string, sizeof(key_name_string));
  printf("signature info key locator name: \n");
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // signature init
  ndn_signature_t signature1;
  ndn_signature_init(&signature1, NDN_SIG_TYPE_ECDSA_SHA256);
  char not_before[] = "20181031T000001";
  char not_after[] = "20191031T000001";
  ndn_signature_set_validity_period(&signature1, (uint8_t*)not_before, (uint8_t*)not_after);
  ndn_signature_set_key_locator(&signature1, &name);

  // signature info encoding
  uint32_t sig1_info_block_size = ndn_signature_info_probe_block_size(&signature1);
  uint8_t sig1_info_block[sig1_info_block_size];
  ndn_encoder_t encoder;
  encoder_init(&encoder, sig1_info_block, sig1_info_block_size);
  ndn_signature_info_tlv_encode(&encoder, &signature1);
  printf("***signature info encoding***\n");
  printf("signature info block size: %d\n", (int) sig1_info_block_size);
  printf("signature info block content: \n");
  for (size_t i = 0; i < sig1_info_block_size; i++) {
    printf("%d ", sig1_info_block[i]);
  }

  // signature info decoding
  ndn_signature_t signature1_check;
  ndn_decoder_t decoder;
  decoder_init(&decoder, sig1_info_block, sig1_info_block_size);
  ndn_signature_info_tlv_decode(&decoder, &signature1_check);
  printf("\n***signature info decoding***\n");
  printf("signature info key locator content: \n");
  for (size_t i = 0; i < signature1_check.key_locator_name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) signature1_check.key_locator_name.components[i].type);
    for (size_t j = 0; j < signature1_check.key_locator_name.components[i].size; j++) {
      printf("%d ", signature1_check.key_locator_name.components[i].value[j]);
    }
    printf("\n");
  }
  if (signature1_check.enable_ValidityPeriod)
    printf("successfully decode validity period\n");
  printf("signature validity period, not before:  \n");
  for (int i = 0; i < 15; i++) {
    printf("%d ",  signature1_check.validity_period.not_before[i]);
  }
  printf("\nsignature validity period, not after: \n");
  for (int i = 0; i < 15; i++) {
    printf("%d ",  signature1_check.validity_period.not_after[i]);
  }

  // signature value init
  ndn_signature_set_signature(&signature1, bytes, sizeof(bytes));
  printf("\nsignature value: \n");
  for (size_t i = 0; i < signature1.sig_size; i++) {
    printf("%d ", signature1.sig_value[i]);
  }

  // signature value encoding
  uint32_t sig1_value_block_size = ndn_signature_value_probe_block_size(&signature1);
  uint8_t sig1_value_block[sig1_value_block_size];
  encoder_init(&encoder, sig1_value_block, sig1_value_block_size);
  ndn_signature_value_tlv_encode(&encoder, &signature1);
  printf("\n***signature value encoding***\n");
  printf("signature value block size: %d\n", (int) sig1_value_block_size);
  printf("signature value block content: \n");
  for (size_t i = 0; i < sig1_value_block_size; i++) {
    printf("%d ", sig1_value_block[i]);
  }

  // signature value decoding
  decoder_init(&decoder, sig1_value_block, sig1_value_block_size);
  ndn_signature_value_tlv_decode(&decoder, &signature1_check);
  printf("\n***signature value decoding***\n");
  printf("signature value: \n");
  for (size_t i = 0; i < signature1_check.sig_size; i++) {
    printf("%d ", signature1_check.sig_value[i]);
  }
  return 0;
}
