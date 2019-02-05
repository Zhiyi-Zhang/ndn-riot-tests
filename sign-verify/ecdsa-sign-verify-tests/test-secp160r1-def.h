
#ifndef TEST_SECP160R1_DEF_H
#define TEST_SECP160R1_DEF_H

#include <stdint.h>

#define SECP160R1_PRI_KEY_SIZE 21
#define SECP160R1_PUB_KEY_SIZE 40

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 21, second integer is length 21
extern const uint8_t test_ecc_secp160r1_prv_raw_1[SECP160R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp160r1_pub_raw_1[SECP160R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 20, second integer is length 20
extern const uint8_t test_ecc_secp160r1_prv_raw_2[SECP160R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp160r1_pub_raw_2[SECP160R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 21, second integer is length 20
extern const uint8_t test_ecc_secp160r1_prv_raw_3[SECP160R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp160r1_pub_raw_3[SECP160R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 20, second integer is length 21
extern const uint8_t test_ecc_secp160r1_prv_raw_4[SECP160R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp160r1_pub_raw_4[SECP160R1_PUB_KEY_SIZE];

#endif // TEST_SECP160R1_DEF_H
