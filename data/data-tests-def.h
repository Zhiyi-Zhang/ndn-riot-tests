
#ifndef DATA_TESTS_DEF_H
#define DATA_TESTS_DEF_H

#include <stdint.h>
#include <stdbool.h>

#include "data-tests.h"

#define SECP160R1_PRV_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40
#define DATA_TEST_IV_SIZE 16
#define DATA_TEST_AES_KEY_SIZE 32

#define DATA_NUM_TESTS 1

extern char *data_test_names[DATA_NUM_TESTS];

extern bool data_test_results[DATA_NUM_TESTS];

extern data_test_t data_tests[DATA_NUM_TESTS];

extern const uint8_t data_test_ecc_prv_key[SECP160R1_PRV_KEY_SIZE];

extern const uint8_t data_test_ecc_pub_key[SECP160R1_PUB_KEY_SIZE];

extern uint8_t data_test_iv[DATA_TEST_IV_SIZE];

extern const uint8_t data_test_aes_key[DATA_TEST_AES_KEY_SIZE];


#endif // DATA_TESTS_DEF_H
