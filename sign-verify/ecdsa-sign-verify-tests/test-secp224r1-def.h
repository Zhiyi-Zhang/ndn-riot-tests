
#ifndef TEST_SECP224R1_DEF_H
#define TEST_SECP224R1_DEF_H

#include <stdint.h>

#define SECP224R1_PRI_KEY_SIZE 28
#define SECP224R1_PUB_KEY_SIZE 56

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 29, second integer is length 29
extern const uint8_t test_ecc_secp224r1_prv_raw_1[SECP224R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp224r1_pub_raw_1[SECP224R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 28, second integer is length 28
extern const uint8_t test_ecc_secp224r1_prv_raw_2[SECP224R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp224r1_pub_raw_2[SECP224R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 29, second integer is length 28
extern const uint8_t test_ecc_secp224r1_prv_raw_3[SECP224R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp224r1_pub_raw_3[SECP224R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 28, second integer is length 29
extern const uint8_t test_ecc_secp224r1_prv_raw_4[SECP224R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp224r1_pub_raw_4[SECP224R1_PUB_KEY_SIZE];

#endif // TEST_SECP224R1_DEF_H