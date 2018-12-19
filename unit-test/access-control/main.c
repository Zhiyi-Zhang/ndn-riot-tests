/*
 * Copyright (C) 2018 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn_standalone/security/micro-ecc/uECC.h"
#include "ndn_standalone/app-support/access-control.h"
#include "ndn_standalone/encode/signed-interest.h"
#include "ndn_standalone/security/random.h"
#include "ndn_standalone/security/key-storage.h"

static uint8_t private[32] = {0};
static uint8_t public[64] = {0};

static int
random_fill(uint8_t *dest, unsigned size) {
  uint8_t *personalization = (uint8_t*)"ndn-iot-access-control";
  uint8_t *additional_input = (uint8_t*)"additional-input";
  uint8_t *seed = (uint8_t*)"seed";
  ndn_generator_t generator;
  ndn_generator_init(&generator, personalization, sizeof(personalization),
                     dest, (uint32_t)size);
  ndn_generator_set_Seed(&generator, seed, sizeof(seed));
  ndn_generator_set_AdditionalInput(&generator, additional_input, sizeof(additional_input));
  int r = ndn_generator_hmacprng_generate(&generator);
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
  ndn_key_storage_get_empty_ecc_key(pub_key, prv_key);
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

  // create key name
  ndn_name_t key_name = home_prefix;
  char comp_key_str[] = "KEY";
  name_component_t comp_key;
  name_component_from_string(&comp_key, comp_key, sizeof(comp_key));
  ndn_name_append_component(&key_name, &comp_key);

  uint8_t random_id[4] = {0x12, 0x34, 0x56, 0x78};
  name_component_t comp_keyid;
  name_component_from_buffer(&comp_keyid, TLV_GenericNameComponent,
                             random_id, sizeof(random_id));
  ndn_name_append_component(&key_name, &comp_keyid);


  uint8_t encoded_keyid[ndn_name_probe_block_size(&key_name)];
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoded_keyid, sizeof(encoded_keyid));
  ndn_name_tlv_encode(&encoder, &key_name);


  ndn_interest_t interest;
  ndn_data_t response;
  uint8_t buffer[1024];


  // prepare ek interest
  ndn_ac_prepare_ek_interest(&interest, &home_prefix, &component_producer,
                             encoded_keyid, sizeof(encoded_keyid));
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_signed_interest_tlv_encode_ecdsa_sign(&encoder, &interest,
                                            &producer_identity,
                                            &prv_key);
  printf("EK Interest TLV size is = %d\n", encoder.offset);

  // controller
  // set id and key
  ndn_ac_state_init(&controller_identity, &pub_key, &prv_key);
  ndn_interest_from_block(&interest, buffer, encoder.offset);
  int r = ndn_signed_interest_ecdsa_verify(&interest, &pub_key);
  if (!r) printf("Signed EK Requset Verified\n");
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_ac_on_interest_process(&interest, &response);
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
                                 &prv_key);
  printf("EK Response TLV size is = %d\n", encoder.offset);
  r = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       &pub_key);
  if(!r) printf("EK Response Verified\n");
  ndn_ac_ek_on_data_process(&response);

  // prepare dk interest
  ndn_ac_prepare_dk_interest(&interest, &home_prefix, &component_consumer,
                             encoded_keyid, sizeof(encoded_keyid));
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_signed_interest_tlv_encode_ecdsa_sign(&encoder, &interest,
                                            &consumer_identity,
                                            &prv_key);
  ndn_ac_on_interest_process(&interest, &response);
  encoder_init(&encoder, buffer, sizeof(buffer));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &response, &controller_identity,
                                 &prv_key);
  printf("DK Response TLV size is = %d\n", encoder.offset);
  r = ndn_data_tlv_decode_ecdsa_verify(&response, buffer, encoder.offset,
                                       &pub_key);
  if(!r) printf("DK Response Verified\n");
  ndn_ac_dk_on_data_process(&response);


  //shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
  /* should be never reached */
  return 0;
}
