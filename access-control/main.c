/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn_standalone/security/sec-lib/micro-ecc/uECC.h"
#include "ndn_standalone/app-support/access-control.h"
#include "ndn_standalone/encode/signed-interest.h"
#include "ndn_standalone/security/ndn-lite-random.h"
#include "ndn_standalone/security/ndn-lite-key-storage.h"

static int
random_fill(uint8_t *dest, unsigned size) {
  uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
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

  // set home prefix
  ndn_name_t home_prefix;
  char* home_prefix_str = "/ucla/cs/engvi";
  ndn_name_from_string(&home_prefix, home_prefix_str, sizeof(home_prefix_str));

  // set shared prv and pub key
  ndn_key_storage_init();
  ndn_ecc_pub_t* pub_key = NULL;
  ndn_ecc_prv_t* prv_key = NULL;
  ndn_key_storage_get_empty_ecc_key(&pub_key, &prv_key);
  ndn_ecc_key_make_key(pub_key, prv_key, NDN_ECDSA_CURVE_SECP256R1, 456, random_fill);

  // set producer, consumer and controller components and namesc
  char comp_producer[] = "producer";
  name_component_t component_producer;
  name_component_from_string(&component_producer, comp_producer, sizeof(comp_producer));

  char comp_consumer[] = "consumer";
  name_component_t component_consumer;
  name_component_from_string(&component_consumer, comp_consumer, sizeof(comp_consumer));

  char comp_controller[] = "controller";
  name_component_t component_controller;
  name_component_from_string(&component_controller, comp_controller, sizeof(comp_controller));

  ndn_name_t producer_identity = home_prefix;
  ndn_name_append_component(&producer_identity, &component_producer);

  ndn_name_t consumer_identity = home_prefix;
  ndn_name_append_component(&consumer_identity, &component_consumer);

  ndn_name_t controller_identity = home_prefix;
  ndn_name_append_component(&controller_identity, &component_controller);

  uint32_t key_id = 1234;


  printf("finish the preparation\n");
  ndn_interest_t interest;
  ndn_data_t response;
  uint8_t buffer[1024];

  // prepare ek interest
  printf("***Encryptor prepare EK request***\n");
  ndn_encoder_t encoder;
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_ac_prepare_key_request_interest(&encoder,
                                      &home_prefix, &component_producer, key_id, prv_key, 1);

  // controller
  // set id and key
  ndn_ac_state_init(&controller_identity, pub_key, prv_key);
  ndn_interest_from_block(&interest, buffer, encoder.offset);
  int r = ndn_signed_interest_ecdsa_verify(&interest, pub_key);
  if (!r) printf("Signed EK Requset Verified\n");
  encoder_init(&encoder, buffer, sizeof(buffer));

  printf("***Controller react on EK request***\n");
  ndn_ac_on_interest_process(&response, &interest);

  ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
                                 prv_key);
  printf("EK Response TLV size is = %d\n", encoder.offset);
  r = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       pub_key);
  if(!r) printf("EK Response Verified\n");

  printf("***Encryptor react on EK response***\n");
  ndn_ac_on_ek_response_process(&response);

  // prepare dk interest
  printf("***Decryptor prepare DK request***\n");
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_ac_prepare_key_request_interest(&encoder,
                                      &home_prefix, &component_producer, key_id, prv_key, 0);

  // controller receives dk request
  printf("***Controller react on DK request***\n");
  ndn_interest_from_block(&interest, buffer, encoder.offset);
  r = ndn_signed_interest_ecdsa_verify(&interest, pub_key);
  if (!r) printf("Signed DK Requset Verified\n");
  ndn_ac_on_interest_process(&response, &interest);
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
                                 prv_key);
  printf("DK Response TLV size is = %d\n", encoder.offset);
  r = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       pub_key);
  if(!r) printf("DK Response Verified\n");
  printf("***Decryptor react on DK response***\n");
  ndn_ac_on_dk_response_process(&response);

  return 0;
}
