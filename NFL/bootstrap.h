#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include <encoding/ndn-constants.h>
#include <app.h>
#include <ndn.h>
#include <encoding/name.h>
#include <encoding/interest.h>
#include <encoding/data.h>
#include <msg-type.h>
#include <crypto/ciphers.h>
#include <uECC.h>
#include <string.h>
#include <nfl-block.h>

static void *ndn_bootstrap(void *ptr);