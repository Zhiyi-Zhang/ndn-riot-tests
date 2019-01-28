
/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef SERVICE_DISCOVERY_TESTS_DEF_H
#define SERVICE_DISCOVERY_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "service-discovery-tests.h"

#define SERVICE_DISCOVERY_NUM_TESTS 1
#define SECP160R1_PRV_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40

extern char *service_discovery_test_names[SERVICE_DISCOVERY_NUM_TESTS];

extern bool service_discovery_test_results[SERVICE_DISCOVERY_NUM_TESTS];

extern service_discovery_test_t service_discovery_tests[SERVICE_DISCOVERY_NUM_TESTS];

extern const uint8_t service_discovery_test_ecc_prv_key[SECP160R1_PRV_KEY_SIZE];

extern const uint8_t service_discovery_test_ecc_pub_key[SECP160R1_PUB_KEY_SIZE];

#endif // SERVICE_DISCOVERY_TESTS_DEF_H
