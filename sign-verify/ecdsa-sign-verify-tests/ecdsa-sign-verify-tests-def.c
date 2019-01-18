
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ecdsa-sign-verify-tests-def.h"

#include "../../../ndn-lite/ndn-enums.h"

#include "test-secp160r1-def.h"
#include "test-secp192r1-def.h"
#include "test-secp224r1-def.h"
#include "test-secp256r1-def.h"
#include "test-secp256k1-def.h"

char *ecdsa_sign_verify_test_names[ECDSA_SIGN_VERIFY_NUM_TESTS] = {
  "test_keypair_secp256r1_int1_pad_int2_pad",
  "test_keypair_secp256r1_int1_no_pad_int2_no_pad",
  "test_keypair_secp256r1_int1_pad_int2_no_pad",
  "test_keypair_secp256r1_int1_no_pad_int2_pad",
  "test_keypair_secp256k1_int1_pad_int2_pad",
  "test_keypair_secp256k1_int1_no_pad_int2_no_pad",
  "test_keypair_secp256k1_int1_pad_int2_no_pad",
  "test_keypair_secp256k1_int1_no_pad_int2_pad",
  "test_keypair_secp224r1_int1_pad_int2_pad",
  "test_keypair_secp224r1_int1_no_pad_int2_no_pad",
  "test_keypair_secp224r1_int1_pad_int2_no_pad",
  "test_keypair_secp224r1_int1_no_pad_int2_pad",
  "test_keypair_secp192r1_int1_pad_int2_pad",
  "test_keypair_secp192r1_int1_no_pad_int2_no_pad",
  "test_keypair_secp192r1_int1_pad_int2_no_pad",
  "test_keypair_secp192r1_int1_no_pad_int2_pad",
  "test_keypair_secp160r1_int1_pad_int2_pad",
  "test_keypair_secp160r1_int1_no_pad_int2_no_pad",
  "test_keypair_secp160r1_int1_pad_int2_no_pad",
  "test_keypair_secp160r1_int1_no_pad_int2_pad",
};

bool ecdsa_sign_verify_test_results[ECDSA_SIGN_VERIFY_NUM_TESTS];

ecdsa_sign_verify_test_t ecdsa_sign_verify_tests[ECDSA_SIGN_VERIFY_NUM_TESTS] = {
    {
      ecdsa_sign_verify_test_names,
      0,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_1, sizeof(test_ecc_secp256r1_pub_raw_1),
      test_ecc_secp256r1_prv_raw_1, sizeof(test_ecc_secp256r1_prv_raw_1),
      &ecdsa_sign_verify_test_results[0]
    },
    {
      ecdsa_sign_verify_test_names,
      1,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_2, sizeof(test_ecc_secp256r1_pub_raw_2),
      test_ecc_secp256r1_prv_raw_2, sizeof(test_ecc_secp256r1_prv_raw_2),
      &ecdsa_sign_verify_test_results[1]
    },
    {
      ecdsa_sign_verify_test_names,
      2,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_3, sizeof(test_ecc_secp256r1_pub_raw_3),
      test_ecc_secp256r1_prv_raw_3, sizeof(test_ecc_secp256r1_prv_raw_3),
      &ecdsa_sign_verify_test_results[2]
    },
    {
      ecdsa_sign_verify_test_names,
      3,
      NDN_ECDSA_CURVE_SECP256R1,
      test_ecc_secp256r1_pub_raw_4, sizeof(test_ecc_secp256r1_pub_raw_4),
      test_ecc_secp256r1_prv_raw_4, sizeof(test_ecc_secp256r1_prv_raw_4),
      &ecdsa_sign_verify_test_results[3]
    },
    {
      ecdsa_sign_verify_test_names,
      4,
      NDN_ECDSA_CURVE_SECP256K1,
      test_ecc_secp256k1_pub_raw_1, sizeof(test_ecc_secp256k1_pub_raw_1),
      test_ecc_secp256k1_prv_raw_1, sizeof(test_ecc_secp256k1_prv_raw_1),
      &ecdsa_sign_verify_test_results[4]
    },
    {
      ecdsa_sign_verify_test_names,
      5,
      NDN_ECDSA_CURVE_SECP256K1,
      test_ecc_secp256k1_pub_raw_2, sizeof(test_ecc_secp256k1_pub_raw_2),
      test_ecc_secp256k1_prv_raw_2, sizeof(test_ecc_secp256k1_prv_raw_2),
      &ecdsa_sign_verify_test_results[5]
    },
    {
      ecdsa_sign_verify_test_names,
      6,
      NDN_ECDSA_CURVE_SECP256K1,
      test_ecc_secp256k1_pub_raw_3, sizeof(test_ecc_secp256k1_pub_raw_3),
      test_ecc_secp256k1_prv_raw_3, sizeof(test_ecc_secp256k1_prv_raw_3),
      &ecdsa_sign_verify_test_results[6]
    },
    {
      ecdsa_sign_verify_test_names,
      7,
      NDN_ECDSA_CURVE_SECP256K1,
      test_ecc_secp256k1_pub_raw_4, sizeof(test_ecc_secp256k1_pub_raw_4),
      test_ecc_secp256k1_prv_raw_4, sizeof(test_ecc_secp256k1_prv_raw_4),
      &ecdsa_sign_verify_test_results[7]
    },
    {
      ecdsa_sign_verify_test_names,
      8,
      NDN_ECDSA_CURVE_SECP224R1,
      test_ecc_secp224r1_pub_raw_1, sizeof(test_ecc_secp224r1_pub_raw_1),
      test_ecc_secp224r1_prv_raw_1, sizeof(test_ecc_secp224r1_prv_raw_1),
      &ecdsa_sign_verify_test_results[8]
    },
    {
      ecdsa_sign_verify_test_names,
      9,
      NDN_ECDSA_CURVE_SECP224R1,
      test_ecc_secp224r1_pub_raw_2, sizeof(test_ecc_secp224r1_pub_raw_2),
      test_ecc_secp224r1_prv_raw_2, sizeof(test_ecc_secp224r1_prv_raw_2),
      &ecdsa_sign_verify_test_results[9]
    },
    {
      ecdsa_sign_verify_test_names,
      10,
      NDN_ECDSA_CURVE_SECP224R1,
      test_ecc_secp224r1_pub_raw_3, sizeof(test_ecc_secp224r1_pub_raw_3),
      test_ecc_secp224r1_prv_raw_3, sizeof(test_ecc_secp224r1_prv_raw_3),
      &ecdsa_sign_verify_test_results[10]
    },
    {
      ecdsa_sign_verify_test_names,
      11,
      NDN_ECDSA_CURVE_SECP224R1,
      test_ecc_secp224r1_pub_raw_4, sizeof(test_ecc_secp224r1_pub_raw_4),
      test_ecc_secp224r1_prv_raw_4, sizeof(test_ecc_secp224r1_prv_raw_4),
      &ecdsa_sign_verify_test_results[11]
    },
    {
      ecdsa_sign_verify_test_names,
      12,
      NDN_ECDSA_CURVE_SECP192R1,
      test_ecc_secp192r1_pub_raw_1, sizeof(test_ecc_secp192r1_pub_raw_1),
      test_ecc_secp192r1_prv_raw_1, sizeof(test_ecc_secp192r1_prv_raw_1),
      &ecdsa_sign_verify_test_results[12]
    },
    {
      ecdsa_sign_verify_test_names,
      13,
      NDN_ECDSA_CURVE_SECP192R1,
      test_ecc_secp192r1_pub_raw_2, sizeof(test_ecc_secp192r1_pub_raw_2),
      test_ecc_secp192r1_prv_raw_2, sizeof(test_ecc_secp192r1_prv_raw_2),
      &ecdsa_sign_verify_test_results[13]
    },
    {
      ecdsa_sign_verify_test_names,
      14,
      NDN_ECDSA_CURVE_SECP192R1,
      test_ecc_secp192r1_pub_raw_3, sizeof(test_ecc_secp192r1_pub_raw_3),
      test_ecc_secp192r1_prv_raw_3, sizeof(test_ecc_secp192r1_prv_raw_3),
      &ecdsa_sign_verify_test_results[14]
    },
    {
      ecdsa_sign_verify_test_names,
      15,
      NDN_ECDSA_CURVE_SECP192R1,
      test_ecc_secp192r1_pub_raw_4, sizeof(test_ecc_secp192r1_pub_raw_4),
      test_ecc_secp192r1_prv_raw_4, sizeof(test_ecc_secp192r1_prv_raw_4),
      &ecdsa_sign_verify_test_results[15]
    },
    {
      ecdsa_sign_verify_test_names,
      16,
      NDN_ECDSA_CURVE_SECP160R1,
      test_ecc_secp160r1_pub_raw_1, sizeof(test_ecc_secp160r1_pub_raw_1),
      test_ecc_secp160r1_prv_raw_1, sizeof(test_ecc_secp160r1_prv_raw_1),
      &ecdsa_sign_verify_test_results[16]
    },
    {
      ecdsa_sign_verify_test_names,
      17,
      NDN_ECDSA_CURVE_SECP160R1,
      test_ecc_secp160r1_pub_raw_2, sizeof(test_ecc_secp160r1_pub_raw_2),
      test_ecc_secp160r1_prv_raw_2, sizeof(test_ecc_secp160r1_prv_raw_2),
      &ecdsa_sign_verify_test_results[17]
    },
    {
      ecdsa_sign_verify_test_names,
      18,
      NDN_ECDSA_CURVE_SECP160R1,
      test_ecc_secp160r1_pub_raw_3, sizeof(test_ecc_secp160r1_pub_raw_3),
      test_ecc_secp160r1_prv_raw_3, sizeof(test_ecc_secp160r1_prv_raw_3),
      &ecdsa_sign_verify_test_results[18]
    },
    {
      ecdsa_sign_verify_test_names,
      19,
      NDN_ECDSA_CURVE_SECP160R1,
      test_ecc_secp160r1_pub_raw_4, sizeof(test_ecc_secp160r1_pub_raw_4),
      test_ecc_secp160r1_prv_raw_4, sizeof(test_ecc_secp160r1_prv_raw_4),
      &ecdsa_sign_verify_test_results[19]
    },
};

