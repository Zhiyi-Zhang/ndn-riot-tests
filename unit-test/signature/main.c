/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encode/name.h"
#include "ndn-riot/encode/signature.h"
#include "shell.h"
#include "msg.h"

// static const shell_command_t shell_commands[] = {
//     { NULL, NULL, NULL }
// };


static uint8_t bytes[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; 

static uint8_t digest[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
};

int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    // char line_buf[SHELL_DEFAULT_BUFSIZE];

    // tests start

    // name initialization
    char comp1[] = "aaaaaa";
    name_component_t component;
    name_component_from_string(&component, comp1, sizeof(comp1));
    ndn_name_t name;
    ndn_name_init(&name, &component, 1);

    // signature with keydigest test
    ndn_signature_t signature1;
    ndn_signature_init(&signature1, NDN_SIG_TYPE_ECDSA_SHA256);

    ndn_buffer_t value = { bytes, 64 };
    ndn_signature_set_signataure_value(&signature1, &value);
    ndn_signature_enable_keylocator(&signature1);
    ndn_signature_enable_keylocator_keydigest(&signature1);

    ndn_buffer_t input = { digest, 32 };
    ndn_signature_set_keylocator_keydigest(&signature1, &input);

    size_t esti = ndn_signature_probe_block_size(&signature1);
    uint8_t holder1[esti];
    ndn_block_t output1 = { holder1, esti, esti };
    ndn_signature_tlv_encode(&signature1, &output1);

    ndn_signature_t signature1_check;
    ndn_signature_tlv_decode(&signature1_check, &output1);
    printf("***check signature 1 signature_value***\n"); 
    for (size_t i = 0; i < signature1_check.signature_value.size; i++) {
      printf("0x%02x ", signature1_check.signature_value.value[i]);
    }putchar('\n');

    printf("***check signature 1 keylocator.keydigest***\n"); 
    for (size_t i = 0; i < signature1_check.keylocator.keydigest.size; i++) {
      printf("0x%02x ", signature1_check.keylocator.keydigest.value[i]);
    }putchar('\n');    

    // signature with keyname test
    ndn_signature_t signature2;
    ndn_signature_init(&signature2, NDN_SIG_TYPE_ECDSA_SHA256);

    ndn_signature_set_signataure_value(&signature2, &value);
    ndn_signature_enable_keylocator(&signature2);
    ndn_signature_set_keylocator_keyname(&signature2, &name);

    esti = ndn_signature_probe_block_size(&signature2);
    uint8_t holder2[esti];
    ndn_block_t output2 = { holder2, esti, esti };
    ndn_signature_tlv_encode(&signature2, &output2);

    ndn_signature_t signature2_check;
    ndn_signature_tlv_decode(&signature2_check, &output2);
    printf("***check signature 2 signature_value***\n"); 
    for (size_t i = 0; i < signature2_check.signature_value.size; i++) {
      printf("0x%02x ", signature2_check.signature_value.value[i]);
    }putchar('\n');

    printf("***check signature 2 keylocator.keyname***\n"); 
    for (size_t i = 0; i < signature2_check.keylocator.keyname.components_size; i++) {
      printf("comp type %u\n", (unsigned int) signature2_check.keylocator.keyname.components[i].type);
      for (size_t j = 0; j < signature2_check.keylocator.keyname.components[i].size; j++) {
        printf("%d ", signature2_check.keylocator.keyname.components[i].value[j]);
      }
      printf("\n");
    }

    // signature without keylocator test
    ndn_signature_t signature3;
    ndn_signature_init(&signature3, NDN_SIG_TYPE_ECDSA_SHA256);
    ndn_signature_set_signataure_value(&signature3, &value);

    esti = ndn_signature_probe_block_size(&signature3);
    uint8_t holder3[esti];
    ndn_block_t output3 = { holder3, esti, esti };
    ndn_signature_tlv_encode(&signature3, &output3);

    ndn_signature_t signature3_check;
    ndn_signature_tlv_decode(&signature3_check, &output3);
    printf("***check signature 3 signature_value***\n"); 
    for (size_t i = 0; i < signature3_check.signature_value.size; i++) {
      printf("0x%02x ", signature3_check.signature_value.value[i]);
    }putchar('\n');

    //shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
