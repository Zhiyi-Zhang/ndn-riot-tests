#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>
#include "nfl-block.h"

/*
    this function is used for ndn-riot app send ipc message to NFL, to start bootstrap 
*/

static int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);
{
    msg_t msg, reply;
    msg.type = NFL_START_BOOTSTRAP;
    nfl_key_pair_t* key;
    key->pub = BKpub;
    key->pvt = BKpvt;
    msg.content.ptr = key;
    msg_send_receive(&send, &reply, ndn_pid); //here we need to know the pid of ndn, maybe include the header file?

}

/*
    caller must contain the memory of block
*/
static int nfl_extract_local_cert(ndn_block_t* cert);
{

}

static int nfl_extract_anchor_cert(ndn_block_t* cert);
{

}

static int nfl_extract_home_prefix(ndn_block_t* cert);
{

}

