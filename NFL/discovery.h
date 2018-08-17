#ifndef NDN_DISCOVERY_H_
#define NDN_DISCOVERY_H_

#include "nfl-block.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NFL_SUBPREFIX_ENTRIES_NUMOF 20
#define NFL_SERVICE_ENTRIES_NUMOF 10
#define NFL_IDENTITY_ENTRIES_NUMOF 20
#define NFL_AVAILABLE_ENTRIES_NUMOF 20

typedef struct nfl_subprefix_entry{
    struct nfl_subprefix_entry* prev;  
    struct nfl_subprefix_entry* next;
    ndn_block_t sub;
}nfl_subprefix_entry_t;

typedef struct nfl_service_entry{
    struct nfl_service_entry* prev;
    struct nfl_service_entry* next;
    ndn_block_t ser;
}nfl_service_entry_t;

typedef struct nfl_available_entry{
    struct nfl_available_entry* prev;
    struct nfl_available_entry* next;
    ndn_block_t avail;
}nfl_available_entry_t;

typedef struct nfl_identity_entry{
    struct nfl_identity_entry* prev;
    struct nfl_identity_entry* next;
    ndn_block_t id;
    nfl_available_entry_t list[NFL_AVAILABLE_ENTRIES_NUMOF];
}nfl_identity_entry_t;

extern nfl_subprefix_entry_t _subprefix_table[NFL_SUBPREFIX_ENTRIES_NUMOF];
extern nfl_service_entry_t _service_table[NFL_SERVICE_ENTRIES_NUMOF];
extern nfl_identity_entry_t _identity_table[NFL_IDENTITY_ENTRIES_NUMOF];

void *nfl_discovery(void* bootstrapTuple);


#ifdef __cplusplus
}
#endif

#endif /* NDN_DISCOVERY_H_ */
/** @} */
