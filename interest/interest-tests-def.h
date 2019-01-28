
/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef INTEREST_TESTS_DEF_H
#define INTEREST_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "interest-tests.h"

#define SECP160R1_PRV_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40
#define INTEREST_TEST_HMAC_KEY_SIZE 10

#define INTEREST_NUM_TESTS 1

extern char *interest_test_names[INTEREST_NUM_TESTS];

extern bool interest_test_results[INTEREST_NUM_TESTS];

extern interest_test_t interest_tests[INTEREST_NUM_TESTS];

extern const uint8_t interest_test_ecc_secp160r1_pub_key[SECP160R1_PUB_KEY_SIZE];

extern const uint8_t interest_test_ecc_secp160r1_prv_key[SECP160R1_PRV_KEY_SIZE];

extern const uint8_t interest_test_hmac_key[INTEREST_TEST_HMAC_KEY_SIZE];

#endif // INTEREST_TESTS_DEF_H
