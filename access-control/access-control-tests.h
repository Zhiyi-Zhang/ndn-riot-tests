
/*
 * Copyright (C) Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef ACCESS_CONTROL_TESTS_H
#define ACCESS_CONTROL_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_access_control_tests(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *ecc_pub_key_val;
  uint32_t ecc_pub_key_len;
  const uint8_t *ecc_prv_key_val;
  uint32_t ecc_prv_key_len;
  bool *passed;
} access_control_test_t;

#endif // ACCESS_CONTROL_TESTS_H
