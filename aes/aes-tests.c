/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "aes-tests.h"
#include <stdio.h>
#include <string.h>
#include "aes-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/security/ndn-lite-aes.h"

#define PLAIN_TEXT_BUFFER_MAX_SIZE 255

static uint8_t plain_text[PLAIN_TEXT_BUFFER_MAX_SIZE];

#define CIPHER_TEXT_BUFFER_MAX_SIZE 255

static uint8_t cipher_text[CIPHER_TEXT_BUFFER_MAX_SIZE];

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;
static bool _decrypted_text_matched_original_text = false;
static bool _encrypted_text_different_from_original_text = false;

void _run_aes_test(aes_test_t *test);

bool run_aes_tests(void) {
  memset(aes_test_results, 0, sizeof(bool)*AES_NUM_TESTS);
  for (int i = 0; i < AES_NUM_TESTS; i++) {
    _run_aes_test(&aes_tests[i]);
  }

  return check_all_tests_passed(aes_test_results, aes_test_names,
                                AES_NUM_TESTS);
}

void _run_aes_test(aes_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  // tests start
  ndn_security_init();

  //puts("Test AES-CBC Mode");
  ndn_security_init();

  const uint8_t *data = test->data;
  uint32_t data_size = test->data_size;
  const uint8_t *key = test->key;
  uint32_t key_size = test->key_size;
  const uint8_t *iv = test->iv;

  //initialize
  /* uint32_t j = 0; */
  /* printf("print raw data\n"); */
  /* while (j < data_size) { */
  /*   printf("0x%02x ", data[j++]); */
  /* } */
  /* putchar('\n'); */

  // encrypt
  uint32_t cipher_text_size = ndn_aes_probe_padding_size(data_size) + NDN_AES_BLOCK_SIZE;
  ndn_aes_key_t aes_key;
  ndn_aes_key_init(&aes_key, key, key_size, 123);
  ret_val = ndn_aes_cbc_encrypt(data, data_size, cipher_text, cipher_text_size, iv, &aes_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_aes_test", "ndn_aes_cbc_encrypt", ret_val);
    _all_function_calls_succeeded = false;
  }
  /* printf("ciphertext after encryption\n"); */
  /* j = 0; */
  /* while (j < data_size + 16) { */
  /* printf("0x%02x ", cipher_text[j++]); */
  /* } */
  /* putchar('\n'); */
  // decrypt

  if (memcmp(cipher_text, data, data_size) != 0) {
    _encrypted_text_different_from_original_text = true;
  }
  else {
    printf("In _run_aes_test, the encrypted text was the same as the original text.\n");
  }
  ret_val = ndn_aes_cbc_decrypt(cipher_text, cipher_text_size, plain_text, sizeof(plain_text), iv, &aes_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_aes_test", "ndn_aes_cbc_decrypt", ret_val);
    _all_function_calls_succeeded = false;
  }
  // print decrypted plain text
  /* j = 0; */
  /* printf("plaintext after decryption\n"); */
  /* while(j < data_size){ */
  /* printf("0x%02x ", plain_text[j++]); */
  /* } */

  if (memcmp(plain_text, data, data_size) == 0) {
    _decrypted_text_matched_original_text = true;
  }
  else {
    printf("In _run_aes_test, the decrypted text did not match the original text.\n");
  }

  if (_all_function_calls_succeeded &&
      _decrypted_text_matched_original_text &&
      _encrypted_text_different_from_original_text) {
    *test->passed = true;
  }
  else {
    printf("In _run_aes_test, something went wrong.\n");
    *test->passed = false;
  }
}
