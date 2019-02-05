
#ifndef TEST_SECP256K1_DEF_H
#define TEST_SECP256K1_DEF_H

#include <stdint.h>

#define SECP256K1_PRI_KEY_SIZE 32
#define SECP256K1_PUB_KEY_SIZE 64

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 33, second integer is length 33
extern const uint8_t test_ecc_secp256k1_prv_raw_1[SECP256K1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp256k1_pub_raw_1[SECP256K1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 32, second integer is length 32
extern const uint8_t test_ecc_secp256k1_prv_raw_2[SECP256K1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp256k1_pub_raw_2[SECP256K1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 33, second integer is length 32
extern const uint8_t test_ecc_secp256k1_prv_raw_3[SECP256K1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp256k1_pub_raw_3[SECP256K1_PUB_KEY_SIZE];

// if ecdsa deterministic signing is used with the micro-ecc backend for ecdsa signing,
// will generate a signature whose first integer is length 32, second integer is length 33
extern const uint8_t test_ecc_secp256k1_prv_raw_4[SECP256K1_PRI_KEY_SIZE];
extern const uint8_t test_ecc_secp256k1_pub_raw_4[SECP256K1_PUB_KEY_SIZE];

#endif // TEST_SECP256K1_DEF_H
