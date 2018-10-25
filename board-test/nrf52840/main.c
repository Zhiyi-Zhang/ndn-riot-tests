#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nrf_802154.h"
#include "shell.h"
#include "msg.h"

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

#define MAX_MESSAGE_SIZE 16
#define CHANNEL          11

static volatile bool m_tx_in_progress;
static volatile bool m_tx_done;

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    uint8_t message[MAX_MESSAGE_SIZE];

    for (uint32_t i = 0; i < sizeof(message) / sizeof(message[0]); i++)
    {
        message[i] = i;
    }

    message[0] = 0x41;                // Set MAC header: short addresses, no ACK
    message[1] = 0x98;                // Set MAC header

    m_tx_in_progress = false;
    m_tx_done        = false;

    nrf_802154_init();
    nrf_802154_channel_set(CHANNEL);
    nrf_802154_receive();

    while (1)
    {
        if (m_tx_done)
        {
            m_tx_in_progress = false;
            m_tx_done        = false;
        }

        if (!m_tx_in_progress)
        {
            m_tx_in_progress = nrf_802154_transmit(message, sizeof(message), true);
        }
    }

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;

    return 0;
}

// void nrf_802154_transmitted(const uint8_t * p_frame, uint8_t * p_ack, uint8_t length, int8_t power, int8_t lqi)
// {
//     (void) p_frame;
//     (void) length;
//     (void) power;
//     (void) lqi;

//     m_tx_done = true;

//     if (p_ack != NULL)
//     {
//         nrf_802154_buffer_free(p_ack);
//     }
// }
