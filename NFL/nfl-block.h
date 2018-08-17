#ifndef NFL_BLOCK_H_
#define NFL_BLOCK_H_

#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>

#ifdef __cplusplus
extern "C" {
#endif

//all these stuff are read only
typedef struct nfl_key_pair {
    const uint8_t* pub;     
    const uint8_t* pvt;          
} nfl_key_pair_t;

typedef struct nfl_bootstrap_tuple {
    ndn_block_t m_cert;     
    ndn_block_t anchor_cert;
    ndn_block_t home_prefix;        
} nfl_bootstrap_tuple_t;

typedef struct nfl_discovery_tuple {
    ndn_block_t* identity;     
    ndn_block_t* service;       
} nfl_discovery_tuple_t;

#ifdef __cplusplus
}
#endif

#endif /* NFL_BLOCK_H_ */
/** @} */