
/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef AES_TESTS_DEF_H
#define AES_TESTS_DEF_H

#include "aes-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AES_TEST_KEY_SIZE 16
#define AES_TEST_DATA_SIZE 64
#define AES_TEST_IV_SIZE 16

#define AES_NUM_TESTS 1

extern char *aes_test_names[AES_NUM_TESTS];

extern bool aes_test_results[AES_NUM_TESTS];

extern aes_test_t aes_tests[AES_NUM_TESTS];

extern const uint8_t aes_test_iv[AES_TEST_IV_SIZE];

extern const uint8_t aes_test_key[AES_TEST_KEY_SIZE];

extern const uint8_t aes_test_data[AES_TEST_DATA_SIZE];

#endif // AES_TESTS_DEF_H
