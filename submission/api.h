#include <hashes/sha256.h>
#include <ndn-riot/encoding/ndn-constants.h>
#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>
#include <crypto/ciphers.h>
#include "crypto/modes/cbc.h"
#include <uECC.h>
#include <string.h>

ndn_shared_block_t* ndn_test_signed_interest_create(ndn_block_t* name, void* selectors,
                                                uint8_t sig_type, uint32_t lifetime,
                                                ndn_block_t* key_name,
                                                const unsigned char* key,
                                                size_t key_len, int index);

int ndn_test_interest_verify_signature(ndn_block_t* block,
                              const unsigned char* key,
                              uint32_t algorithm,
                              size_t key_len, int index);