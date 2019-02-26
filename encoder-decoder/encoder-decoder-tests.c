
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "encoder-decoder-tests.h"

#include <stdio.h>

#include "encoder-decoder-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"

#include "ndn-lite/encode/encoder.h"
#include "ndn-lite/encode/decoder.h"
#include "shell.h"
#include "msg.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;
static bool _type_check_succeeded = false;
static bool _length_check_succeeded = false;

void _run_encoder_decoder_test(encoder_decoder_test_t *test);

bool run_encoder_decoder_tests(void) {
  memset(encoder_decoder_test_results, 0, sizeof(bool)*ENCODER_DECODER_NUM_TESTS);
  for (int i = 0; i < ENCODER_DECODER_NUM_TESTS; i++) {
    _run_encoder_decoder_test(&encoder_decoder_tests[i]);
  }
  
  return check_all_tests_passed(encoder_decoder_test_results, encoder_decoder_test_names,
                                ENCODER_DECODER_NUM_TESTS);
}

void _run_encoder_decoder_test(encoder_decoder_test_t *test) {
  
  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  /* start shell */
  uint8_t buf[10] = {2,2,2,2,2,2,2,2,2,2};
  uint32_t type = 100;

  int block_size = encoder_probe_block_size(type, sizeof(buf));
  uint8_t block_value[block_size];
  struct ndn_encoder encoder;
  encoder_init(&encoder, block_value, block_size);

  ret_val = encoder_append_type(&encoder, type);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "encoder_append_type", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = encoder_append_length(&encoder, sizeof(buf));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "encoder_append_length", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = encoder_append_raw_buffer_value(&encoder, buf, sizeof(buf));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "encoder_append_raw_buffer", ret_val);
    _all_function_calls_succeeded = false;
  }
  /* printf("\n***encoder encoding***\n"); */
  /* printf("block content: \n"); */
  /* for (size_t i = 0; i < encoder.offset; i++) { */
  /*   printf("%d ", encoder.output_value[i]); */
  /* } */

  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  uint32_t check_type = 0;
  uint32_t check_length = 0;
  ret_val = decoder_get_type(&decoder, &check_type);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "decoder_get_type", ret_val);
    _all_function_calls_succeeded = false;
  }  
  ret_val = decoder_get_type(&decoder, &check_length);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "decoder_get_type", ret_val);
    _all_function_calls_succeeded = false;
  }
  uint8_t check_buf[check_length];
  ret_val = decoder_get_raw_buffer_value(&decoder, check_buf, check_length);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_encoder_decoder_test", "decoder_get_raw_buffer", ret_val);
    _all_function_calls_succeeded = false;
  }

  /* printf("\n***decoder decoding***\n"); */
  /* printf("check type %d\n", check_type); */
  /* printf("check length %d\n", check_length); */

  if (check_type != type) {
    printf("In _run_encoder_decoder_test, got wrong type after encoding and decoding. Expected type was %d, got %d.\n", type, check_type);
    
  }
  else {
    _type_check_succeeded = true;
  }

  if (check_length != sizeof(buf)) {
    printf("In _run_encoder_decoder_test, got wrong length after enoding and decoding. Expected length was %u, got %d.\n", sizeof(buf), check_length);
  }
  else {
    _length_check_succeeded = true;
  }
  
  // printf("\nTest END\n");  

  if (_all_function_calls_succeeded &&
      _type_check_succeeded &&
      _length_check_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_encoder_decoder_test, something went wrong.\n");
    *test->passed = false;
  }
  
}
