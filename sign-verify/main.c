/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/security/ndn-lite-sha.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/ndn-enums.h"

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
  ndn_security_init();

  //initialize
  uint8_t data[100];
  uint8_t signature[64];
  int result = 0;
  uint32_t used_size = 0;

  for (size_t i = 0; i < 100; ++i)
    data[i] = 0x31;

  result = ndn_sha256_sign(data, sizeof(data),
                           signature, sizeof(signature), &used_size);
  if(result == 0)
    printf("sha256 signing succeeded\n");
  result = ndn_sha256_verify(data, sizeof(data),
                             signature, used_size);
  if(result == 0)
    printf("sha256 verification succeeded\n");

  ndn_ecc_pub_t ecc_pub;
  ndn_ecc_prv_t ecc_prv;
  ndn_ecc_pub_init(&ecc_pub, public, 64, NDN_ECDSA_CURVE_SECP160R1, 123);
  ndn_ecc_prv_init(&ecc_prv, private, 32, NDN_ECDSA_CURVE_SECP160R1, 123);
  result = ndn_ecdsa_sign(data, sizeof(data),
                          signature, sizeof(signature),
                          &ecc_prv, NDN_ECDSA_CURVE_SECP160R1, &used_size);
  if(result == 0)
    printf("ecdsa signing succeeded\n");
  result = ndn_ecdsa_verify(data, sizeof(data),
                            signature, used_size,
                            &ecc_pub, NDN_ECDSA_CURVE_SECP160R1);
  if(result == 0)
    printf("ecdsa verification succeeded\n");

  ndn_hmac_key_t hmac_key;
  ndn_hmac_key_init(&hmac_key, private, 32, 124);
  result = ndn_hmac_sign(data, sizeof(data),
                         signature, sizeof(signature), &hmac_key, &used_size);
  if(result == 0)
    printf("hmac signing succeeded\n");
  result = ndn_hmac_verify(data, sizeof(data), signature, used_size, &hmac_key);
  if(result == 0)
    printf("hmac verification succeeded\n");

  return 0;
}
