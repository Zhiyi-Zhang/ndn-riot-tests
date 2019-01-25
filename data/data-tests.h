
#ifndef DATA_TESTS_H
#define DATA_TESTS_H

#include <stdbool.h>
#include <stdint.h>

// returns true if all tests passed, false otherwise
bool run_data_tests(void);

typedef struct {
  char **test_names;
  uint32_t test_name_index;
  int ndn_ecdsa_curve;
  const uint8_t *ecc_pub_key;
  uint32_t ecc_pub_key_size;
  const uint8_t *ecc_prv_key;
  uint32_t ecc_prv_key_size;
  uint8_t *iv;
  uint32_t aes_iv_size;
  const uint8_t *aes_key;
  uint32_t aes_key_size;
  bool *passed;
} data_test_t;


#endif // DATA_TESTS_H
