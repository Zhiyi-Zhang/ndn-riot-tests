
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest-tests-def.h"

#include "ndn-lite/ndn-enums.h"

#include <stdbool.h>

char *interest_test_names[INTEREST_NUM_TESTS] = {
  "test_interest",
};

bool interest_test_results[INTEREST_NUM_TESTS];

interest_test_t interest_tests[INTEREST_NUM_TESTS] = {
    {
      interest_test_names,
      0,
      NDN_ECDSA_CURVE_SECP160R1,
      interest_test_ecc_secp160r1_pub_key,
      sizeof(interest_test_ecc_secp160r1_pub_key),
      interest_test_ecc_secp160r1_prv_key,
      sizeof(interest_test_ecc_secp160r1_prv_key),
      interest_test_hmac_key,
      sizeof(interest_test_hmac_key),
      &interest_test_results[0]
    },
};

const uint8_t interest_test_ecc_secp160r1_pub_key[SECP160R1_PUB_KEY_SIZE] = {
  0xA1, 0x2B, 0xBF, 0x14, 0x77, 0x58, 0x51, 0xFD, 0xFF, 0x03, 
  0xAA, 0x5C, 0x88, 0x6E, 0xD5, 0xCB, 0xA4, 0xAA, 0x01, 0x0A, 
  0x04, 0x79, 0xFD, 0xF2, 0xF0, 0x9C, 0x81, 0x2B, 0x8A, 0xCA, 
  0xAA, 0x6D, 0x08, 0x84, 0xD0, 0xC2, 0xF0, 0x23, 0x6E, 0x37
};

const uint8_t interest_test_ecc_secp160r1_prv_key[SECP160R1_PRV_KEY_SIZE] = {
  0x00, 
  0x96, 0xC6, 0x5F, 0x59, 0x87, 0x62, 0xB9, 0x81, 0x2E, 0xE8, 
  0xEF, 0xAB, 0x7B, 0xB4, 0x4F, 0x74, 0x45, 0x88, 0x16, 0xD5
};

const uint8_t interest_test_hmac_key[INTEREST_TEST_HMAC_KEY_SIZE] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
};
