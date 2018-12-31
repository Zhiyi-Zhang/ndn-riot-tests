/*
 * Copyright (C) 2018 Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "ndn_standalone/encode/encoder.h"
#include "ndn_standalone/encode/decoder.h"
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
    struct ndn_encoder encoder;
    encoder_init(&encoder, block_value, block_size);
    ndn_buffer_t buffer;
    buffer.value = buf;
    buffer.size = sizeof(buf);

    encoder_append_type(&encoder, type);
    encoder_append_length(&encoder, sizeof(buf));
    encoder_append_buffer_value(&encoder, &buffer);
    printf("\n***encoder encoding***\n");
    printf("block content: \n");
    for (size_t i = 0; i < encoder.offset; i++) {
      printf("%d ", encoder.output_value[i]);
    }

    ndn_decoder_t decoder;
    decoder_init(&decoder, block_value, block_size);
    uint32_t check_type = 0;
    uint32_t check_length = 0;
    decoder_get_type(&decoder, &check_type);
    decoder_get_type(&decoder, &check_length);
    uint8_t check_buf[check_length];
    ndn_buffer_t check_buffer;
    check_buffer.value = check_buf;
    check_buffer.size = check_length;
    decoder_get_buffer_value(&decoder, &check_buffer);

    printf("\n***decoder decoding***\n");
    printf("check type %d\n", check_type);
    printf("check length %d\n", check_length);

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should be never reached */
    return 0;
}
