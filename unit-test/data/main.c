/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn_standalone/encode/data.h"
#include "shell.h"
#include "msg.h"

static uint8_t private[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50,
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

static uint8_t public[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA,
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4,
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

// static const shell_command_t shell_commands[] = {
//     { NULL, NULL, NULL }
// };

int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    // char line_buf[SHELL_DEFAULT_BUFSIZE];

    uint8_t buf[10] = {2,2,2,2,2,2,2,2,2,2};
    uint8_t block_value[1024];
    ndn_encoder_t encoder;

    ndn_data_t data;
    ndn_data_init(&data, buf, sizeof(buf));

    // set name
    char name_string[] = "/smarthome/controller/zhiyi-phone";
    ndn_name_from_string(&data.name, name_string, sizeof(name_string));
    printf("***init data name*** \n");
    for (size_t i = 0; i < data.name.components_size; i++) {
      printf("comp type %u\n", (unsigned int) data.name.components[i].type);
      for (size_t j = 0; j < data.name.components[i].size; j++) {
        printf("%d ", data.name.components[i].value[j]);
      }
      printf("\n");
    }
    encoder_init(&encoder, block_value, 1024);
    ndn_name_tlv_encode(&encoder, &data.name);
    printf("name block content: \n");
    for (size_t i = 0; i < encoder.offset; i++) {
      printf("%d ", block_value[i]);
    }

    // set metainfo
    ndn_metainfo_init(&data.metainfo);
    ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);

    // encoding digest
    encoder_init(&encoder, block_value, 1024);
    printf("\n***data encoding with digest sig***\n");
    ndn_data_tlv_encode_digest_sign(&encoder, &data);
    printf("data block length: %d \n", (int) encoder.offset);
    printf("data block content: \n");
    for (size_t i = 0; i < encoder.offset; i++) {
      printf("%d ", block_value[i]);
    }
    printf("\n");

    ndn_data_t data_check;
    int result = ndn_data_tlv_decode_no_verify(&data_check, block_value, encoder.offset);
    if (result == 0) {
      printf("data encoding and digest sig verification succeeded");
    }
    else
      printf("result: %d\n", result);

    result = ndn_data_tlv_decode_digest_verify(&data_check, block_value, encoder.offset);
    if (result == 0) {
      printf("data encoding and digest sig verification succeeded");
    }
    else
      printf("result: %d\n", result);

    // encoding ecdsa
    ndn_ecc_prv_t prv_key;
    ndn_ecc_prv_init(&prv_key, private, sizeof(private), NDN_ECDSA_CURVE_SECP160R1, 1234);

    char id_string[] = "/smarthome/zhiyi";
    ndn_name_t identity;
    ndn_name_from_string(&identity, id_string, sizeof(id_string));
    printf("\n***init identity name*** \n");
    for (size_t i = 0; i < identity.components_size; i++) {
      printf("comp type %u\n", (unsigned int) identity.components[i].type);
      for (size_t j = 0; j < identity.components[i].size; j++) {
        printf("%d ", identity.components[i].value[j]);
      }
      printf("\n");
    }

    encoder_init(&encoder, block_value, 1024);
    printf("\n***data encoding with ecdsa sig***\n");
    ndn_data_tlv_encode_ecdsa_sign(&encoder, &data, &identity, &prv_key);
    printf("data block length: %d \n", (int) encoder.offset);
    printf("data block content: \n");
    for (size_t i = 0; i < encoder.offset; i++) {
      printf("%d ", block_value[i]);
    }
    printf("\n");

    ndn_ecc_pub_t pub_key;
    ndn_ecc_pub_init(&pub_key, public, sizeof(public), NDN_ECDSA_CURVE_SECP160R1, 1234);
    result = ndn_data_tlv_decode_ecdsa_verify(&data_check, block_value, encoder.offset, &pub_key);
    if (result == 0) {
      printf("data encoding and ecdsa sig verification succeeded");
    }
    else
      printf("result: %d\n", result);

    // encoding hmac
    ndn_hmac_key_t hmac_key;
    ndn_hmac_key_init(&hmac_key, private, sizeof(private), 5678);
    ndn_ecc_prv_init(&prv_key, private, sizeof(private), NDN_ECDSA_CURVE_SECP160R1, 1234);
    encoder_init(&encoder, block_value, 1024);
    printf("\n***data encoding with hmac sig***\n");
    ndn_data_tlv_encode_hmac_sign(&encoder, &data, &identity, &hmac_key);
    printf("data block length: %d \n", (int) encoder.offset);
    printf("data block content: \n");
    for (size_t i = 0; i < encoder.offset; i++) {
      printf("%d ", block_value[i]);
    }
    printf("\n");

    result = ndn_data_tlv_decode_hmac_verify(&data_check, block_value, encoder.offset, &hmac_key);
    if (result == 0) {
      printf("data encoding and hmac sig verification succeeded");
    }
    else
      printf("result: %d\n", result);


    // shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
