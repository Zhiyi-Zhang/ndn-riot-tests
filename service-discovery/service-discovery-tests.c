/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang, Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "service-discovery-tests.h"
#include <stdio.h>
#include "service-discovery-tests-def.h"
#include "../print-helpers.h"
#include "../test-helpers.h"
#include "ndn-lite/security/ndn-lite-crypto-key.h"
#include "ndn-lite/app-support/service-discovery.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/security/ndn-lite-hmac.h"
#include "ndn-lite/security/ndn-lite-ecc.h"
#include "ndn-lite/ndn-services.h"

static const char *_current_test_name;
static bool _all_function_calls_succeeded = true;

void _run_service_discovery_test(service_discovery_test_t *test);

bool run_service_discovery_tests(void) {
  memset(service_discovery_test_results, 0, sizeof(bool)*SERVICE_DISCOVERY_NUM_TESTS);
  for (int i = 0; i < SERVICE_DISCOVERY_NUM_TESTS; i++) {
    _run_service_discovery_test(&service_discovery_tests[i]);
  }

  return check_all_tests_passed(service_discovery_test_results, service_discovery_test_names,
                                SERVICE_DISCOVERY_NUM_TESTS);
}

void _run_service_discovery_test(service_discovery_test_t *test) {

  _current_test_name = test->test_names[test->test_name_index];
  _all_function_calls_succeeded = true;

  int ret_val = -1;

  // tests start
  ndn_security_init();

  // intiate private and public key
  ndn_encoder_t encoder;

  // set home prefix
  ndn_name_t home_prefix;
  char* home_prefix_str = "/ucla/cs/engvi";
  ret_val = ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_name_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  // set producer, consumer and controller components and namesc
  char comp_producer[] = "producer";
  name_component_t component_producer;
  ret_val = name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  char comp_consumer[] = "consumer";
  name_component_t component_consumer;
  ret_val = name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "name_component_from_string", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_name_t consumer_identity = home_prefix;
  ret_val = ndn_name_append_component(&consumer_identity, &component_consumer);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_name_append_component", ret_val);
    _all_function_calls_succeeded = false;
  }

  ndn_interest_t interest;
  uint8_t buffer[1024];

  // intialization
  ndn_sd_init(&home_prefix, &component_producer);
  ndn_service_t* control_service = ndn_sd_register_get_self_service(NDN_SD_CONTROL,
                                                                    sizeof(NDN_SD_CONTROL));
  ndn_service_t* led_service = ndn_sd_register_get_self_service(NDN_SD_LED,
                                                                sizeof(NDN_SD_LED));

  // set service status
  ndn_sd_set_service_status(led_service, NDN_APPSUPPORT_SERVICE_BUSY);
  ndn_sd_set_service_status(control_service, NDN_APPSUPPORT_SERVICE_BUSY);

  // advertisement Interest generation and processing
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_sd_prepare_advertisement(&interest);
  printf("Advertisement Preparation Success\n");
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }

  ret_val = ndn_interest_from_block(&interest, buffer, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_sd_on_advertisement_process(&interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_sd_on_advertisement_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("Advertisement Processing Success");
  puts("\n");

  // query
  memset(buffer, 0, sizeof(buffer));
  encoder_init(&encoder, buffer, sizeof(buffer));
  printf("*** Find Neighbor by Identity ***\n");
  ndn_sd_identity_t* entry = ndn_sd_find_neigbor(&component_producer);
  if (entry) {
    printf("Service Provider Found: ");
    for (uint8_t i = 0; i < entry->identity.size; i++)
      printf("%c", (char)entry->identity.value[i]);
    printf("\n");

    printf("Service Provider's First Service Is: ");
    for (uint8_t i = 0; i < entry->services[0].id_size; i++)
      printf("%c", (char)entry->services[0].id_value[i]);
    printf("Service Provider's First Service Status: %d\n", entry->services[0].status);
    printf("\n");

    printf("Service Provider's Second Service Is: ");
    for (uint8_t i = 0; i < entry->services[1].id_size; i++)
      printf("%c", (char)entry->services[1].id_value[i]);
    printf("Service Provider's First Service Status: %d\n", entry->services[1].status);
    puts("\n");
  }

  // set shared prv and pub key
  ndn_ecc_prv_t prv_key;
  ret_val = ndn_ecc_prv_init(&prv_key, test->ecc_prv_key_val, test->ecc_prv_key_len, test->ndn_ecdsa_curve, 123);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_ecc_prv_init", ret_val);
    _all_function_calls_succeeded = false;
  }
  ndn_ecc_pub_t pub_key;
  ret_val = ndn_ecc_pub_init(&pub_key, test->ecc_pub_key_val, test->ecc_pub_key_len, test->ndn_ecdsa_curve, 456);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_ecc_pub_init", ret_val);
    _all_function_calls_succeeded = false;
  }

  printf("*** Query *** \n");
  ndn_sd_prepare_query(&interest, &entry->identity, &entry->services[0],
                       NULL, 0);
  printf("First Query Prepare Success, query service: ");
  for (uint8_t i = 0; i < entry->services[0].id_size; i++)
    printf("%c", (char)entry->services[0].id_value[i]);
  printf("\n");
  ret_val = ndn_signed_interest_ecdsa_sign(&interest, &consumer_identity, &prv_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_signed_interest_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }

  printf("Value of first service discovery query interest, encoded:\n");
  for (uint32_t i = 0; i < encoder.offset; i++) {
    if (i > 0) printf(":");
    printf("%02X", encoder.output_value[i]);
  }
  printf("\n");

  printf("First Query Signed\n");
  ret_val = ndn_interest_from_block(&interest, buffer, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_ecdsa_verify(&interest, &pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }

  // receive query
  ndn_data_t response;
  ret_val = ndn_sd_on_query_process(&interest, &response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_sd_on_query_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("First Query Processing Success\n");

  // receive query response
  ret_val = ndn_sd_on_query_response_process(&response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_sd_on_query_response_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("First Response Processing Success\n");
  printf("First Service Status via Query = %d", entry->services[0].status);
  puts("\n");

  printf("*** Find Neighbor by Service Name: %s ***\n", NDN_SD_CONTROL);
  ndn_sd_identity_t* entry_byservice =
    ndn_sd_find_first_service_provider(NDN_SD_CONTROL, sizeof(NDN_SD_CONTROL));
  if (entry_byservice) {
    printf("Service Provider Found: ");
    for (uint8_t i = 0; i < entry_byservice->identity.size; i++)
      printf("%c", (char)entry_byservice->identity.value[i]);
    printf("\n");

    printf("Service Provider's First Service Is: ");
    for (uint8_t i = 0; i < entry_byservice->services[0].id_size; i++)
      printf("%c", (char)entry_byservice->services[0].id_value[i]);
    printf("Service Provider's First Service Status: %d\n", entry_byservice->services[0].status);
    printf("\n");

    printf("Service Provider's Second Service Is: ");
    for (uint8_t i = 0; i < entry_byservice->services[1].id_size; i++)
      printf("%c", (char)entry_byservice->services[1].id_value[i]);
    printf("Service Provider's Second Service Status: %d\n", entry_byservice->services[1].status);
    printf("\n");
  }

  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_sd_prepare_query(&interest, &entry->identity, &entry->services[1],
                       NULL, 0);
  printf("Second Query Preparation Success\n");
  ret_val = ndn_signed_interest_ecdsa_sign(&interest, &consumer_identity, &prv_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_signed_interest_ecdsa_sign", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_tlv_encode", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("Second Query Signed\n");
  ret_val = ndn_interest_from_block(&interest, buffer, encoder.offset);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_interest_from_block", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_signed_interest_ecdsa_verify(&interest, &pub_key);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_signed_interest_ecdsa_verify", ret_val);
    _all_function_calls_succeeded = false;
  }
  ret_val = ndn_sd_on_query_process(&interest, &response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_sd_on_query_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("Second Query Processing Success\n");
  ret_val = ndn_sd_on_query_response_process(&response);
  if (ret_val != 0) {
    print_error(_current_test_name, "_run_service_discovery_test", "ndn_sd_on_query_response_process", ret_val);
    _all_function_calls_succeeded = false;
  }
  printf("Second Response Processing Success\n");
  printf("Second Service Status via Query = %d\n", entry->services[1].status);

  if (_all_function_calls_succeeded)
  {
    *test->passed = true;
  }
  else {
    printf("In _run_service_discovery_test, something went wrong.\n");
    *test->passed = false;
  }
}
