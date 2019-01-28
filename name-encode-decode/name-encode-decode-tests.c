
/*
 * Copyright (C) 2018 Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "name-encode-decode-tests.h"

#include <stdio.h>
#include <string.h>

#include "name-encode-decode-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"

#include "ndn-lite/encode/name.h"
#include "shell.h"
#include "msg.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_name_encode_decode_test(name_encode_decode_test_t *test);

bool run_name_encode_decode_tests(void) {
  memset(name_encode_decode_test_results, 0, sizeof(bool)*NAME_ENCODE_DECODE_NUM_TESTS);
  for (int i = 0; i < NAME_ENCODE_DECODE_NUM_TESTS; i++) {
    _run_name_encode_decode_test(&name_encode_decode_tests[i]);
  }
  
  return check_all_tests_passed(name_encode_decode_test_results, name_encode_decode_test_names,
                                NAME_ENCODE_DECODE_NUM_TESTS);
}

void _run_name_encode_decode_test(name_encode_decode_test_t *test) {
  
  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;
  
  // component initialization
  char comp1[] = "aaaaaa";
  name_component_t component;
  ret_val = name_component_from_string(&component, comp1, sizeof(comp1));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***component init***\ncheck type %u\n", (unsigned int) component.type);
  printf("check length %u\n", component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < component.size; i++) {
    printf("%d ", component.value[i]);
  }

  // component encoding
  name_component_block_t check_block;
  ndn_encoder_t comp_encoder;
  encoder_init(&comp_encoder, check_block.value, NDN_NAME_COMPONENT_BLOCK_SIZE);
  ret_val = name_component_tlv_encode(&comp_encoder, &component);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  check_block.size = comp_encoder.offset;
  printf("\n***component encoding***\n");
  printf("check block length %u\n", comp_encoder.offset);
  printf("check block content\n");
  for (size_t i = 0; i < comp_encoder.offset; i++) {
    printf("%d ", check_block.value[i]);
  }

  // component decoding
  name_component_t check_component;
  ret_val = name_component_from_block(&check_component, &check_block);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }  
  printf("\n***component decoding***\n");
  printf("check type %u\n", (unsigned int) check_component.type);
  printf("check length %u\n", check_component.size);
  printf("check buffer content\n");
  for (size_t i = 0; i < check_component.size; i++) {
    printf("%d ", check_component.value[i]);
  }

  // name initialization
  char comp2[] = "bbbbbb";
  char comp3[] = "cccccc";
  char comp4[] = "123456";
  name_component_t component2;
  ret_val = name_component_from_string(&component2, comp2, sizeof(comp2));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  name_component_t component3;
  ret_val = name_component_from_string(&component3, comp3, sizeof(comp3));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }
  name_component_t component4;
  ret_val = name_component_from_string(&component4, comp4, sizeof(comp4));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "name_component_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  name_component_t components[3];
  components[0] = component;
  components[1] = component2;
  components[2] = component3;

  ndn_name_t name;
  ndn_name_init(&name, components, 3);
  printf("\n***name init***\ncheck name comp size %u\n", name.components_size);
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // name append
  ret_val = ndn_name_append_component(&name, &component4);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("***name append comp***\ncheck name comp size %u\n", name.components_size);
  for (size_t i = 0; i < name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) name.components[i].type);
    for (size_t j = 0; j < name.components[i].size; j++) {
      printf("%d ", name.components[i].value[j]);
    }
    printf("\n");
  }

  // name encode
  size_t name_block_size = ndn_name_probe_block_size(&name);
  uint8_t name_block_value[name_block_size];
  ndn_encoder_t name_encoder;
  encoder_init(&name_encoder, name_block_value, name_block_size);
  ret_val = ndn_name_tlv_encode(&name_encoder, &name);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***name encoding***\n");
  printf("check block length %u\n", name_encoder.offset);
  printf("check block content\n");
  for (size_t i = 0; i < name_encoder.offset; i++) {
    printf("%d ", name_block_value[i]);
  }

  // name decode
  ndn_name_t check_name;
  ret_val = ndn_name_from_block(&check_name, name_block_value, name_block_size);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_name_encode_decode_test", "ndn_name_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("\n***name decoding***\n");
  for (size_t i = 0; i < check_name.components_size; i++) {
    printf("comp type %u\n", (unsigned int) check_name.components[i].type);
    for (size_t j = 0; j < check_name.components[i].size; j++) {
      printf("%d ", check_name.components[i].value[j]);
    }
    printf("\n");
  }  
  
  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_name_encode_decode_test, something went wrong.\n");
    *test->passed = false;
  }
  
}
