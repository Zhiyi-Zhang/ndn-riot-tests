
/*
 * Copyright (C) Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "ecdsa-sign-verify-tests.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "ecdsa-sign-verify-tests-def.h"
#include "../../test-helpers.h"
#include "../../print-helpers.h"

#include "../../../ndn-lite/ndn-constants.h"
#include "../../../ndn-lite/ndn-enums.h"
#include "../../../ndn-lite/ndn-error-code.h"
#include "../../../ndn-lite/security/ndn-lite-sec-utils.h"
#include "../../../ndn-lite/security/ndn-lite-ecc.h"

#define TEST_ENCODER_BUFFER_LEN 500
#define TEST_NUM_NAME_COMPONENTS 5

static uint8_t test_message[10] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

static uint8_t test_signature[NDN_ASN1_ECDSA_MAX_ENCODED_SIG_SIZE];

static const uint32_t test_arbitrary_key_id = 666;

static ndn_ecc_prv_t test_ecc_prv_key;
static ndn_ecc_pub_t test_ecc_pub_key;

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_ecdsa_sign_verify_test(ecdsa_sign_verify_test_t *test);

bool run_ecdsa_sign_verify_tests(void) {
  memset(ecdsa_sign_verify_test_results, 0, sizeof(bool)*ECDSA_SIGN_VERIFY_NUM_TESTS);
  for (int i = 0; i < ECDSA_SIGN_VERIFY_NUM_TESTS; i++) {
    _run_ecdsa_sign_verify_test(&ecdsa_sign_verify_tests[i]);
  }
  return check_all_tests_passed(ecdsa_sign_verify_test_results, ecdsa_sign_verify_test_names,
                                ECDSA_SIGN_VERIFY_NUM_TESTS);
}

void _run_ecdsa_sign_verify_test(ecdsa_sign_verify_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;
  
  ndn_security_init();

  int ret_val = -1;

  ret_val = ndn_ecc_prv_init(&test_ecc_prv_key, test->ecc_prv_raw, test->ecc_prv_raw_len,
      test->ndn_ecdsa_curve, test_arbitrary_key_id);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_ecdsa_sign_verify_test", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  uint32_t signature_size;
  ret_val = ndn_ecdsa_sign(test_message, sizeof(test_message),
			   test_signature, sizeof(test_signature),
			   &test_ecc_prv_key,
			   test->ndn_ecdsa_curve,
			   &signature_size);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_ecdsa_sign_verify_test", "ndn_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  ret_val = ndn_ecc_pub_init(&test_ecc_pub_key, test->ecc_pub_raw, test->ecc_pub_raw_len,
      test->ndn_ecdsa_curve, test_arbitrary_key_id);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_ecdsa_sign_verify_test", "ndn_ecc_pub_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  ret_val = ndn_ecdsa_verify(test_message, sizeof(test_message),
			     test_signature, signature_size,
			     &test_ecc_pub_key,
			     test->ndn_ecdsa_curve);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_ecdsa_sign_verify_test", "ndn_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  if (_all_function_calls_succeeded) {
    *test->passed = true;
  } else {
    printf("One or more function calls within _run_ecdsa_sign_verify_test failed.\n");
    *test->passed = false;
  }
  
}
