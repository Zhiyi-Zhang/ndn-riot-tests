
#ifndef TEST_SECP192R1_DEF_H
#define TEST_SECP192R1_DEF_H

#include <stdint.h>

#define SECP192R1_PRI_KEY_SIZE 24
#define SECP192R1_PUB_KEY_SIZE 48

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 25, second integer is length 25
extern const uint8_t test_ecc_secp192r1_prv_raw_1[SECP192R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp192r1_pub_raw_1[SECP192R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 24, second integer is length 24
extern const uint8_t test_ecc_secp192r1_prv_raw_2[SECP192R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp192r1_pub_raw_2[SECP192R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 25, second integer is length 24
extern const uint8_t test_ecc_secp192r1_prv_raw_3[SECP192R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp192r1_pub_raw_3[SECP192R1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 24, second integer is length 25
extern const uint8_t test_ecc_secp192r1_prv_raw_4[SECP192R1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp192r1_pub_raw_4[SECP192R1_PUB_KEY_SIZE];

#endif // TEST_SECP192R1_DEF_H
