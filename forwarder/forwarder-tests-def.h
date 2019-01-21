
/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef FORWARDER_TESTS_DEF_H
#define FORWARDER_TESTS_DEF_H

#include "forwarder-tests.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FORWARDER_NUM_TESTS 1
#define SECP160R1_PRI_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40

extern char *forwarder_test_names[FORWARDER_NUM_TESTS];

extern bool forwarder_test_results[FORWARDER_NUM_TESTS];

extern forwarder_test_t forwarder_tests[FORWARDER_NUM_TESTS];

extern const uint8_t test_ecc_secp160r1_private_raw_1[SECP160R1_PRI_KEY_SIZE];

extern const uint8_t test_ecc_secp160r1_public_raw_1[SECP160R1_PUB_KEY_SIZE];

#endif // FORWARDER_TESTS_DEF_H
