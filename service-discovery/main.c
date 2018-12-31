/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn_standalone/security/crypto-key.h"
#include "ndn_standalone/app-support/service-discovery.h"
#include "ndn_standalone/encode/signed-interest.h"
#include "ndn_standalone/security/ndn-lite-random.h"
#include "ndn_standalone/ndn-service.h"

static uint8_t private[32] = {
  0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
  0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50,
  0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
  0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

static uint8_t public[64] = {
  0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA,
  0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
  0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
  0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
  0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
  0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
  0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
  0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static int
random_fill(uint8_t *dest, unsigned size) {
  uint8_t *personalization = (uint8_t*)"ndn-iot-service-discovery";
  uint8_t *additional_input = (uint8_t*)"additional-input";
  uint8_t *seed = (uint8_t*)"seed";
  int r = ndn_random_hmacprng(personalization, sizeof(personalization),
                              dest, (uint32_t)size, seed, sizeof(seed),
                              additional_input, sizeof(additional_input));
  if (!r)
    return 1;
  return 0;
}

int main(void)
{
  /* start shell */
  puts("All up, running the shell now");

  // intiate private and public key
  ndn_encoder_t encoder;
  ndn_ecc_key_set_rng(&random_fill);

  // set home prefix
  ndn_name_t home_prefix;
  char* home_prefix_str = "/ucla/cs/engvi";
  ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));

  // set producer, consumer and controller components and namesc
  char comp_producer[] = "producer";
  name_component_t component_producer;
  name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));

  char comp_consumer[] = "consumer";
  name_component_t component_consumer;
  name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));

  ndn_name_t consumer_identity = home_prefix;
  ndn_name_append_component(&consumer_identity, &component_consumer);

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
  ndn_interest_tlv_encode(&encoder, &interest);

  ndn_interest_from_block(&interest, buffer, encoder.offset);
  ndn_sd_on_advertisement_process(&interest);
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
  ndn_ecc_prv_init(&prv_key, private, sizeof(private),
                   NDN_ECDSA_CURVE_SECP256R1, 123);
  ndn_ecc_pub_t pub_key;
  ndn_ecc_pub_init(&pub_key, public, sizeof(public), NDN_ECDSA_CURVE_SECP256R1, 456);
  ndn_ecc_key_make_key(&pub_key, &prv_key, NDN_ECDSA_CURVE_SECP256R1, 789);

  printf("*** Query *** \n");
  ndn_sd_prepare_query(&interest, &entry->identity, &entry->services[0],
                       NULL, 0);
  ndn_interest_tlv_encode(&encoder, &interest);
  printf("First Query Prepare Success, query service: ");
  for (uint8_t i = 0; i < entry->services[0].id_size; i++)
    printf("%c", (char)entry->services[0].id_value[i]);
  printf("\n");
  ndn_signed_interest_tlv_encode_ecdsa_sign(&encoder, &interest,
                                            &consumer_identity,
                                            &prv_key);
  printf("First Query Signed\n");
  ndn_interest_from_block(&interest, buffer, encoder.offset);
  int r = ndn_signed_interest_ecdsa_verify(&interest, &pub_key);
  if (!r)
    printf("Signed First Query Verified\n");

  // receive query
  ndn_data_t response;
  ndn_sd_on_query_process(&interest, &response);
  printf("First Query Processing Success\n");

  // receive query response
  ndn_sd_on_query_response_process(&response);
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
  ndn_signed_interest_tlv_encode_ecdsa_sign(&encoder, &interest,
                                            &consumer_identity,
                                            &prv_key);
  printf("Second Query Signed\n");

  ndn_interest_from_block(&interest, buffer, encoder.offset);
  r = ndn_signed_interest_ecdsa_verify(&interest, &pub_key);
  if (!r) printf("Signed Second Query Verified\n");
  ndn_sd_on_query_process(&interest, &response);
  printf("Second Query Processing Success\n");
  ndn_sd_on_query_response_process(&response);
  printf("Second Response Processing Success\n");
  printf("Second Service Status via Query = %d\n", entry->services[1].status);

  return 0;
}
