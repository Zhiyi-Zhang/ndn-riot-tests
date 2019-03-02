/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "interest-tests.h"
#include <stdio.h>
#include <stdbool.h>
#include "interest-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/encode/signed-interest.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_interest_test(interest_test_t *test);

bool run_interest_tests(void) {
  memset(interest_test_results, 0, sizeof(bool)*INTEREST_NUM_TESTS);
  for (int i = 0; i < INTEREST_NUM_TESTS; i++) {
    _run_interest_test(&interest_tests[i]);
  }

  return check_all_tests_passed(interest_test_results, interest_test_names,
                                INTEREST_NUM_TESTS);
}

void _test_unsigned_interest(ndn_name_t *name);
void _test_ecdsa_signed_interest(ndn_name_t *name, ndn_name_t *identity, interest_test_t *test);
void _test_hmac_signed_interest(ndn_name_t *name, ndn_name_t *identity, interest_test_t *test);
void _test_digest_signed_interest(ndn_name_t *name);

void _run_interest_test(interest_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  // tests start
  ndn_security_init();

  // init a name
  char name_string[] = "/aaa/bbb/ccc/ddd";
  ndn_name_t name;
  ret_val = ndn_name_from_string(&name, name_string, sizeof(name_string));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_interest_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***init a name*** \n");
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  char id_string[] = "/smarthome/zhiyi";
  ndn_name_t identity;
  ret_val = ndn_name_from_string(&identity, id_string, sizeof(id_string));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_interest_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***init identity name*** \n");
  for (size_t i = 0; i < identity.components_size; i++) {
    printf("comp type %u\n", (unsigned int) identity.components[i].type);
    for (size_t j = 0; j < identity.components[i].size; j++) {
      printf("%d ", identity.components[i].value[j]);
    }
    printf("\n");
  }

  _test_unsigned_interest(&name);
  _test_ecdsa_signed_interest(&name, &identity, test);
  _test_hmac_signed_interest(&name, &identity, test);
  _test_digest_signed_interest(&name);

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_interest_test, something went wrong.\n");
    *test->passed = false;
  }

}

void _test_unsigned_interest(ndn_name_t* name)
{

  int ret_val = -1;

  // init an Interest
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);
  printf("***init an Interest*** \n");
  printf("hop limit: %d\n", interest.hop_limit);

  // Interest encodes
  uint8_t block_value[200];
  ndn_encoder_t encoder;
  encoder_init(&encoder, block_value, sizeof(block_value));
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_unsigned_interest", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***Interest Encodes*** \n");
  printf("block size: %d\n", (int) encoder.offset);
  printf("block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", block_value[i]);
  }
  printf("\n");

  // Interest decodes
  ndn_interest_t check_interest;
  printf("before function starts\n");
  ret_val = ndn_interest_from_block(&check_interest, block_value, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_unsigned_interest", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***Interest Decodes*** \n");
  printf("hop limit: %d\n", interest.hop_limit);
  printf("name component size: %d\n", (int) check_interest.name.components_size);
  for (size_t i = 0; i < check_interest.name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) check_interest.name.components[i].type);
    for (size_t j = 0; j < check_interest.name.components[i].size; j++) {
      printf("%d ", check_interest.name.components[i].value[j]);
    }
    printf("\n");
  }
}

void _test_ecdsa_signed_interest(ndn_name_t* name, ndn_name_t* identity, interest_test_t *test)
{

  int ret_val = -1;

  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  ndn_ecc_prv_t prv_key;
  ret_val = ndn_ecc_prv_init(&prv_key, test->ecc_prv_key_val, test->ecc_prv_key_len, test->ndn_ecdsa_curve, 1234);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }


  uint8_t pool[256];

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with ecdsa sig***\n");
  ret_val = ndn_signed_interest_ecdsa_sign(&interest, identity, &prv_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_signed_interest_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_ecc_pub_t pub_key;
  ndn_interest_t check_interest;
  ret_val = ndn_ecc_pub_init(&pub_key, test->ecc_pub_key_val, test->ecc_pub_key_len, test->ndn_ecdsa_curve, 1234);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_ecc_pub_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_from_block(&check_interest, pool, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_ecdsa_verify(&check_interest, &pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_ecdsa_signed_interest", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
}

void _test_hmac_signed_interest(ndn_name_t* name, ndn_name_t* identity, interest_test_t *test)
{

  int ret_val = -1;

  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  uint8_t pool[256];

  ndn_hmac_key_t hmac_key;
  ret_val = ndn_hmac_key_init(&hmac_key, test->hmac_key_val, test->hmac_key_len, 5678);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_hmac_signed_interest", "ndn_hmac_key_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with hmac sig***\n");
  ret_val = ndn_signed_interest_hmac_sign(&interest, identity, &hmac_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_hmac_signed_interest", "ndn_signed_interest_hmac_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_hmac_signed_interest", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_interest_t check_interest;
  ret_val = ndn_interest_from_block(&check_interest, pool, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_hmac_signed_interest", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_hmac_verify(&check_interest, &hmac_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_hmac_signed_interest", "ndn_signed_interest_hmac_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
}

void _test_digest_signed_interest(ndn_name_t* name)
{

  int ret_val = -1;

  putchar('\n');
  ndn_interest_t interest;
  ndn_interest_from_name(&interest, name);
  ndn_interest_set_HopLimit(&interest, 1);
  ndn_interest_set_MustBeFresh(&interest, 1);
  ndn_interest_set_CanBePrefix(&interest, 1);

  uint8_t pool[256];

  ndn_encoder_t encoder;
  encoder_init(&encoder, pool, 256);
  printf("\n***interest signing with digest sig***\n");
  ret_val = ndn_signed_interest_digest_sign(&interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_digest_signed_interest", "ndn_signed_interest_digest_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_digest_signed_interest", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("interest block length: %d \n", (int) encoder.offset);
  printf("interest block content: \n");
  for (size_t i = 0; i < encoder.offset; i++) {
    printf("%d ", pool[i]);
  }
  printf("\n");

  ndn_interest_t check_interest;
  ret_val = ndn_interest_from_block(&check_interest, pool, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_digest_signed_interest", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_digest_verify(&check_interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_test_digest_signed_interest", "ndn_signed_interest_digest_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
}
