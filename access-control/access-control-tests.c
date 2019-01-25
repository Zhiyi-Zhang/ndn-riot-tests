
/*
 * Copyright (C) Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "access-control-tests.h"

#include "access-control-tests-def.h"
#include "print-helpers.h"
#include "test-helpers.h"

#include <stdio.h>
#include "ndn-lite/ndn-enums.h"
#include "ndn-lite/app-support/access-control.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/encode/key-storage.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_access_control_test(access_control_test_t *test);

bool run_access_control_tests(void) {
  memset(access_control_test_results, 0, sizeof(bool)*ACCESS_CONTROL_NUM_TESTS);
  for (int i = 0; i < ACCESS_CONTROL_NUM_TESTS; i++) {
    _run_access_control_test(&access_control_tests[i]);
  }
  
  return check_all_tests_passed(access_control_test_results, access_control_test_names,
                                ACCESS_CONTROL_NUM_TESTS);
}

void _run_access_control_test(access_control_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;
  
  // tests start
  ndn_security_init();

  // set home prefix
  ndn_name_t home_prefix;
  char* home_prefix_str = "/ucla/cs/engvi";
  ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  // set shared prv and pub key
  ndn_key_storage_init();
  ndn_ecc_pub_t* pub_key = NULL;
  ndn_ecc_prv_t* prv_key = NULL;
  ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
  ret_val = ndn_ecc_pub_init(pub_key, test_ecc_secp256r1_pub_raw_1, sizeof(test_ecc_secp256r1_pub_raw_1),
			     NDN_ECDSA_CURVE_SECP256R1, test_arbitrary_key_id);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ecc_pub_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_ecc_prv_init(prv_key, test_ecc_secp256r1_prv_raw_1, sizeof(test_ecc_secp256r1_prv_raw_1),
			     NDN_ECDSA_CURVE_SECP256R1, test_arbitrary_key_id);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  // set producer, consumer and controller components and namesc
  char comp_producer[] = "producer";
  name_component_t component_producer;
  ret_val = name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  char comp_consumer[] = "consumer";
  name_component_t component_consumer;
  ret_val = name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  char comp_controller[] = "controller";
  name_component_t component_controller;
  ret_val = name_component_from_string(&component_controller, comp_controller, sizeof(comp_controller));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_name_t producer_identity = home_prefix;
  ret_val = ndn_name_append_component(&producer_identity, &component_producer);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_name_t consumer_identity = home_prefix;
  ret_val = ndn_name_append_component(&consumer_identity, &component_consumer);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_name_t controller_identity = home_prefix;
  ret_val = ndn_name_append_component(&controller_identity, &component_controller);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  uint32_t key_id = 1234;

  //printf("finish the preparation\n");
  ndn_interest_t interest;
  ndn_data_t response;
  uint8_t buffer[1024];

  // prepare ek interest
  //printf("***Encryptor prepare EK request***\n");
  ndn_encoder_t encoder;
  encoder_init(&encoder, buffer, sizeof(buffer));
  ret_val = ndn_ac_prepare_key_request_interest(&encoder,
                                      &home_prefix, &component_producer, key_id, prv_key, 1);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ac_prepare_key_request", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  // controller
  // set id and key
  ndn_ac_state_init(&controller_identity, pub_key, prv_key);
  ret_val = ndn_interest_from_block(&interest, buffer, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_ecdsa_verify(&interest, pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  encoder_init(&encoder, buffer, sizeof(buffer));
  
  //printf("***Controller react on EK request***\n");
  ret_val = ndn_ac_on_interest_process(&response, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ac_on_interest_process", ret_val);
    _all_function_calls_succeeded = false;
  }

  ret_val = ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
                                 prv_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_data_tlv_encode_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }

  printf("In access control test, value of encoded data:\n");
  for (uint32_t i = 0; i < encoder.offset; i++) {
    if (i > 0) printf(":");
    printf("%02X", encoder.output_value[i]);
  }
  printf("\n");
  
  //printf("EK Response TLV size is = %d\n", encoder.offset);
  ret_val = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  //printf("***Encryptor react on EK response***\n");
  ret_val = ndn_ac_on_ek_response_process(&response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  // prepare dk interest
  //printf("***Decryptor prepare DK request***\n");
  encoder_init(&encoder, buffer, sizeof(buffer));
  ret_val = ndn_ac_prepare_key_request_interest(&encoder,
                                      &home_prefix, &component_producer, key_id, prv_key, 0);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ac_prepare_key_request", ret_val);
    _all_function_calls_succeeded = false;
  }
  
  // controller receives dk request
  //printf("***Controller react on DK request***\n");
  ndn_interest_from_block(&interest, buffer, encoder.offset);
  ret_val = ndn_signed_interest_ecdsa_verify(&interest, pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_ac_on_interest_process(&response, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ac_on_interest_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  encoder_init(&encoder, buffer, sizeof(buffer));
  ret_val = ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
  					   prv_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_data_tlv_encode_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  //printf("DK Response TLV size is = %d\n", encoder.offset);
  ret_val = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_data_tlv_decode_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  //printf("***Decryptor react on DK response***\n");
  ret_val = ndn_ac_on_dk_response_process(&response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_access_control_test", "ndn_ac_on_dk_response_process", ret_val);
    _all_function_calls_succeeded = false;
  }

  if (_all_function_calls_succeeded) {
    *test->passed = true;
  }
  else {
    printf("In _run_access_control_test, one or more function calls failed.\n");
    *test->passed = false;
  }
}
