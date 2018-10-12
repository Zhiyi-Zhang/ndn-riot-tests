/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn-riot/encode/encoder.h"
#include "ndn-riot/encode/decoder.h"
// #include "ndn-riot/encoding/certificate.h"
#include "shell.h"
#include "msg.h"

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];

    uint8_t buf[10] = {2,2,2,2,2,2,2,2,2,2};
    uint32_t type = 100;

    int block_size = encoder_probe_block_size(type, sizeof(buf));
    uint8_t block_value[block_size];
    struct ndn_block block;
    block.value = block_value;
    block.size = block_size;
    struct ndn_encoder encoder;
    encoder_init(&encoder, &block);
    ndn_buffer_t buffer;
    buffer.value = buf;
    buffer.size = sizeof(buf);

    encoder_append_type(&encoder, type);
    encoder_append_length(&encoder, sizeof(buf));
    encoder_append_buffer_value(&encoder, &buffer);

    for (size_t i = 0; i < encoder.output->size; i++) {
      printf("%d", encoder.output->value[i]);
    }

    ndn_decoder_t decoder;
    decoder_init(&decoder, encoder.output);
    uint32_t check_type = 0;
    uint32_t check_length = 0;
    decoder_get_type(&decoder, &check_type);
    decoder_get_type(&decoder, &check_length);
    uint8_t check_buf[check_length];
    ndn_buffer_t check_buffer;
    check_buffer.value = check_buf;
    check_buffer.size = check_length;
    decoder_get_buffer_value(&decoder, &check_buffer);

    printf("check type %d", check_type);
    printf("check length %d", check_length);

    // char name_str[] = "/ndn/zhiyi/KEY/001/ndncert/002";
    // ndn_shared_block_t* shared_block = ndn_name_from_uri(name_str, sizeof(name_str));

    // ndn_name_t name;
    // ndn_name_wire_decode(&shared_block->block, &name);

    // printf("\nsize of the key name is %d \n", name.size);
    // printf("first component %s \n", (char *)(name.comps[0].buf));
    // printf("second component %s \n", (char *)(name.comps[1].buf));
    // printf("third component %s \n", (char *)(name.comps[2].buf));
    // printf("fourth component %s \n", (char *)(name.comps[3].buf));
    // printf("fourth component %s \n", (char *)(name.comps[4].buf));
    // printf("fourth component %s \n", (char *)(name.comps[5].buf));

    // int result = ndn_cert_is_certificate_name(&name);
    // printf("is certificate? %d", result);

    // ndn_name_t identity_name;
    // ndn_name_t key_name;

    // ndn_cert_get_identity_name(&name, &identity_name);
    // printf("\nsize of the identity name is %d \n", identity_name.size);
    // printf("first component %s \n", (char *)(identity_name.comps[0].buf));
    // printf("second component %s \n", (char *)(identity_name.comps[1].buf));

    // ndn_cert_get_key_name(&name, &key_name);
    // printf("\nsize of the key name is %d \n", key_name.size);
    // printf("first component %s \n", (char *)(key_name.comps[0].buf));
    // printf("second component %s \n", (char *)(key_name.comps[1].buf));
    // printf("third component %s \n", (char *)(key_name.comps[2].buf));
    // printf("fourth component %s \n", (char *)(key_name.comps[3].buf));

    // free(name.comps);
    // free(key_name.comps);
    // free(identity_name.comps);
    // ndn_shared_block_release(shared_block);

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
