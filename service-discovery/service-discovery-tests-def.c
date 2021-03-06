
/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "service-discovery-tests-def.h"

#include "ndn-lite/ndn-enums.h"

#include <stdbool.h>

char *service_discovery_test_names[SERVICE_DISCOVERY_NUM_TESTS] = {
  "test_service_discovery",
};

bool service_discovery_test_results[SERVICE_DISCOVERY_NUM_TESTS];

service_discovery_test_t service_discovery_tests[SERVICE_DISCOVERY_NUM_TESTS] = {
    {
      service_discovery_test_names,
      0,
      NDN_ECDSA_CURVE_SECP160R1,
      service_discovery_test_ecc_pub_key,
      sizeof(service_discovery_test_ecc_pub_key),
      service_discovery_test_ecc_prv_key,
      sizeof(service_discovery_test_ecc_prv_key),
      &service_discovery_test_results[0]
    },
};

const uint8_t service_discovery_test_ecc_prv_key[SECP160R1_PRV_KEY_SIZE] = {
  0x00, 
  0x96, 0xC6, 0x5F, 0x59, 0x87, 0x62, 0xB9, 0x81, 0x2E, 0xE8, 
  0xEF, 0xAB, 0x7B, 0xB4, 0x4F, 0x74, 0x45, 0x88, 0x16, 0xD5
};

const uint8_t service_discovery_test_ecc_pub_key[SECP160R1_PUB_KEY_SIZE] = {
  0xA1, 0x2B, 0xBF, 0x14, 0x77, 0x58, 0x51, 0xFD, 0xFF, 0x03, 
  0xAA, 0x5C, 0x88, 0x6E, 0xD5, 0xCB, 0xA4, 0xAA, 0x01, 0x0A, 
  0x04, 0x79, 0xFD, 0xF2, 0xF0, 0x9C, 0x81, 0x2B, 0x8A, 0xCA, 
  0xAA, 0x6D, 0x08, 0x84, 0xD0, 0xC2, 0xF0, 0x23, 0x6E, 0x37
};
