/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "ndn-riot/security/micro-ecc/uECC.h"
#include "ndn-riot/app-support/access-control.h"
#include "ndn-riot/encode/signed-interest.h"
#include "ndn-riot/security/random.h"

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

static int random_fill(uint8_t *dest, unsigned size){
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

//static const shell_command_t shell_commands[] = {
//     { NULL, NULL, NULL }
//};

int main(void)
{
  /* start shell */
  puts("All up, running the shell now");
    
  //char line_buf[SHELL_DEFAULT_BUFSIZE];

  // intiate private and public key
  uECC_set_rng(&random_fill);
  uECC_Curve curve = uECC_secp256r1();  
  uECC_make_key(public, private, curve);
  
  // set home prefix
  char comp1[] = "ucla";
  char comp2[] = "cs";
  char comp3[] = "397";
  name_component_t component1;
  name_component_from_string(&component1, comp1, sizeof(comp1));
  name_component_t component2;
  name_component_from_string(&component2, comp2, sizeof(comp2));
  name_component_t component3;
  name_component_from_string(&component3, comp3, sizeof(comp3));
  name_component_t components[3];
  components[0] = component1;
  components[1] = component2;
  components[2] = component3;
  ndn_name_t home;
  ndn_name_init(&home, components, 3);

  // set shared prv and pub key
  ndn_ecc_prv_t prv_key;
  ndn_ecc_prv_init(&prv_key, private, sizeof(private), 
                   NDN_ECDSA_CURVE_SECP256R1, 123);

  ndn_ecc_pub_t pub_key;
  ndn_ecc_pub_init(&pub_key, public, sizeof(public), NDN_ECDSA_CURVE_SECP256R1, 456);  

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

  ndn_name_t producer_identity;
  ndn_name_init(&producer_identity, components, 3);
  ndn_name_append_component(&producer_identity, &component_producer);

  ndn_name_t consumer_identity;
  ndn_name_init(&consumer_identity, components, 3);
  ndn_name_append_component(&consumer_identity, &component_consumer);

  ndn_name_t controller_identity;
  ndn_name_init(&controller_identity, components, 3);
  ndn_name_append_component(&controller_identity, &component_controller);     

  // set test key id
  char comp_key[] = "KEY";
  name_component_t components_key[5];
  components_key[0] = component1;
  components_key[1] = component2;
  components_key[2] = component3;
  name_component_from_string(&components_key[3], comp_key, sizeof(comp_key));
  uint8_t random_id[4] = {0x12, 0x34, 0x56, 0x78};
  name_component_from_buffer(&components_key[4], TLV_GenericNameComponent, 
                             random_id, sizeof(random_id));
  ndn_name_t key_name;
  ndn_name_init(&key_name, components_key, 5);
  uint8_t encoded_keyid[ndn_name_probe_block_size(&key_name)];
  ndn_encoder_t encoder;
  encoder_init(&encoder, encoded_keyid, sizeof(encoded_keyid));
  ndn_name_tlv_encode(&encoder, &key_name);


  ndn_interest_t interest;
  ndn_data_t response;
  uint8_t buffer[1024];


  // prepare ek interest
  ndn_ac_prepare_ek_interest(&interest, &home, &component_producer, 
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
  ndn_ac_prepare_dk_interest(&interest, &home, &component_consumer, 
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
