
/*
 * Copyright (C) Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ACCESS_CONTROL_TESTS_DEF_H
#define ACCESS_CONTROL_TESTS_DEF_H

#include "access-control-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ACCESS_CONTROL_NUM_TESTS 1
#define SECP256R1_PRI_KEY_SIZE 32
#define SECP256R1_PUB_KEY_SIZE 64

extern char *access_control_test_names[ACCESS_CONTROL_NUM_TESTS];

extern bool access_control_test_results[ACCESS_CONTROL_NUM_TESTS];

extern access_control_test_t access_control_tests[ACCESS_CONTROL_NUM_TESTS];

extern const uint8_t access_control_test_ecc_secp256r1_prv_raw_1[SECP256R1_PRI_KEY_SIZE];

extern const uint8_t access_control_test_ecc_secp256r1_pub_raw_1[SECP256R1_PUB_KEY_SIZE];

#endif // ACCESS_CONTROL_TESTS_DEF_H
