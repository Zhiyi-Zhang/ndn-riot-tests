#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include "nfl-constant.h"
#include "nfl-block.h"
#include "discovery.h"

/*
    this function is used for ndn-riot app send ipc message to NFL, to start bootstrap 
*/

/*static int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);*/



#ifndef NFL_APP_H_
#define NFL_APP_H_

#ifdef __cplusplus
extern "C" {
#endif

nfl_bootstrap_tuple_t* nfl_start_bootstrap(nfl_key_pair_t* pair);

//caller must contain the memeory of tuple
nfl_bootstrap_tuple_t* nfl_extract_bootstrap_tuple(void);

int nfl_start_discovery(void);

int nfl_set_discovery_prefix(void* ptr);

int nfl_init_discovery(void);

ndn_block_t* nfl_start_discovery_query(nfl_discovery_tuple_t* tuple);

nfl_identity_entry_t* nfl_extract_discovery_list(void);


#ifdef __cplusplus
}
#endif

#endif /* NFL_APP_H_ */
/** @} */
