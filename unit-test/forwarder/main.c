/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "ndn_standalone/encode/interest.h"
#include "ndn_standalone/forwarder/forwarder.h"
#include "ndn_standalone/face/direct-face.h"
#include "ndn_standalone/face/dummy-face.h"
#include <stdio.h>

int
on_data_callback(const uint8_t* data, uint32_t data_size)
{
  (void)data;
  (void)data_size;
  return 0;
}

int
on_interest_timeout_callback(const uint8_t* interest, uint32_t interest_size)
{
  (void)interest;
  (void)interest_size;
  return 0;
}

int
on_interest(const uint8_t* interest, uint32_t interest_size)
{
  (void)interest;
  (void)interest_size;
  return 0;
}

int main(void)
{
  // tests start
  ndn_forwarder_t* forwarder = ndn_forwarder_init();
  ndn_direct_face_t* direct_face = ndn_direct_face_construct(124);
  ndn_dummy_face_t dummy_face;
  ndn_dummy_face_construct(&dummy_face, 125);

  // add FIB entry
  char prefix_string[] = "/ndn";
  ndn_name_t prefix;
  ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
  ndn_forwarder_fib_insert(&prefix, &dummy_face.intf, 1);

  // create interest
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  char name_string[] = "/ndn/bbb/ccc/ddd";
  ndn_name_from_string(&interest.name, name_string, sizeof(name_string));
  uint8_t interest_block[256] = {0};
  ndn_encoder_t encoder;
  encoder_init(&encoder, interest_block, 256);
  ndn_interest_tlv_encode(&encoder, &interest);

  // express interest
  ndn_direct_face_express_interest(&interest.name,
                                   interest_block, encoder.offset,
                                   on_data_callback, on_interest_timeout_callback);
  (void)forwarder;
  (void)direct_face;

  return 0;
}
