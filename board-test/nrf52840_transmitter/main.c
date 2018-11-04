#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "NRF_802154_driver/src/nrf_802154.h"

#define MAX_MESSAGE_SIZE 16
#define CHANNEL          11

static volatile bool m_tx_in_progress;
static volatile bool m_tx_done;

#define LED_PORT            (NRF_P0)
#define LED0_MASK           (1 << 13)
#define LED1_MASK           (1 << 14)
#define LED2_MASK           (1 << 15)
#define LED3_MASK           (1 << 16)
#define LED_MASK            (LED0_MASK | LED1_MASK | LED2_MASK | LED3_MASK)
#define LED0_ON             (LED_PORT->OUTCLR = LED0_MASK)
#define LED0_OFF            (LED_PORT->OUTSET = LED0_MASK)
#define LED0_TOGGLE         (LED_PORT->OUT   ^= LED0_MASK)

#define LED1_ON             (LED_PORT->OUTCLR = LED1_MASK)
#define LED1_OFF            (LED_PORT->OUTSET = LED1_MASK)
#define LED1_TOGGLE         (LED_PORT->OUT   ^= LED1_MASK)

#define LED2_ON             (LED_PORT->OUTCLR = LED2_MASK)
#define LED2_OFF            (LED_PORT->OUTSET = LED2_MASK)
#define LED2_TOGGLE         (LED_PORT->OUT   ^= LED2_MASK)

#define LED3_ON             (LED_PORT->OUTCLR = LED3_MASK)
#define LED3_OFF            (LED_PORT->OUTSET = LED3_MASK)
#define LED3_TOGGLE         (LED_PORT->OUT   ^= LED3_MASK)

int main(void)
{
  printf("802.15.4 packet transmitter starts\n");

  uint8_t message[MAX_MESSAGE_SIZE];

  for (uint32_t i = 0; i < sizeof(message) / sizeof(message[0]); i++) {
    message[i] = i;
  }

  message[0] = 0x41;                // Set MAC header: short addresses, no ACK
  message[1] = 0x98;                // Set MAC header

  m_tx_in_progress = false;
  m_tx_done        = false;

  nrf_802154_init();
  LED0_ON;
  nrf_802154_channel_set(CHANNEL);

  nrf_802154_receive();
  while (1) {
    if (m_tx_done) {
      m_tx_in_progress = false;
      m_tx_done        = false;
    }

    if (!m_tx_in_progress) {
      LED1_ON;
      m_tx_in_progress = nrf_802154_transmit(message, sizeof(message), true);
    }
  }

  return 0;
}

void nrf_802154_transmitted(const uint8_t * p_frame, uint8_t * p_ack,
                            uint8_t length, int8_t power, uint8_t lqi)
{
  (void) p_frame;
  (void) length;
  (void) power;
  (void) lqi;

  LED2_ON;
  printf("packet successfully transmitted!\n");
  m_tx_done = true;

  if (p_ack != NULL) {
    nrf_802154_buffer_free(p_ack);
  }
}
