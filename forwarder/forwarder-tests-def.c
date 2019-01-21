
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "forwarder-tests-def.h"

#include "ndn-lite/ndn-enums.h"

char *forwarder_test_names[FORWARDER_NUM_TESTS] = {
  "test_forwarder",
};

bool forwarder_test_results[FORWARDER_NUM_TESTS];

forwarder_test_t forwarder_tests[FORWARDER_NUM_TESTS] = {
    {
      forwarder_test_names,
      0,
      NDN_ECDSA_CURVE_SECP160R1,
      test_ecc_secp160r1_public_raw_1,
      sizeof(test_ecc_secp160r1_public_raw_1),
      test_ecc_secp160r1_private_raw_1,
      sizeof(test_ecc_secp160r1_private_raw_1),
      &forwarder_test_results[0]
    },
};

const uint8_t test_ecc_secp160r1_private_raw_1[SECP160R1_PRI_KEY_SIZE] = {
  0x00,
  0xEA, 0xE0, 0xF1, 0x2F, 0x8D, 0x87, 0x9F, 0x1F, 0xE9, 0x4F,
  0xF1, 0x06, 0x40, 0x3C, 0xD4, 0x78, 0x8B, 0x0F, 0x72, 0x9F
};

const uint8_t test_ecc_secp160r1_public_raw_1[SECP160R1_PUB_KEY_SIZE] = {
  0x54, 0x4A, 0x85, 0xD7, 0x7E, 0x0D, 0xE0, 0xB5, 0x41, 0x49,
  0x36, 0x18, 0x69, 0xCA, 0xF4, 0x44, 0x30, 0x0A, 0x77, 0x91,
  0x82, 0xCF, 0x34, 0x2F, 0x6F, 0x27, 0x1C, 0xF7, 0xB0, 0x5C,
  0x07, 0xAD, 0x50, 0x6C, 0xEF, 0x23, 0x79, 0x00, 0x26, 0x84
};
