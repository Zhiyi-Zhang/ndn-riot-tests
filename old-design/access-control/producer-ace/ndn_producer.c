/*
 * Copyright (C) 2016 Wentao Shang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Minimum NDN producer
 *
 * @author      Wentao Shang <wentaoshang@gmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "thread.h"
#include "random.h"
#include "crypto/ciphers.h"
#include "crypto/modes/cbc.h"
#include "uECC.h"
#include <hashes/sha256.h>
#include "ndn-riot/app.h"
#include "ndn-riot/ndn.h"
#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/data.h"
#include "ndn-riot/msg-type.h"

#include <stdio.h>
#include <string.h>

#include <inttypes.h>
#include <stdlib.h>

#define DPRINT(...) printf(__VA_ARGS__)
//#define DPRINT(...) {}

#define ACE_PRODUCER   3
#define ACE_PRODUCER_GLOBAL 4

static ndn_app_t* handle = NULL;


static uint8_t anchor_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static uint8_t com_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};
/*
static uint8_t com_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static uint8_t ace_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t ace_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/

static uint8_t TEST_1_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


static ndn_block_t home_prefix;
static ndn_block_t identity;
static unsigned char acehmac[32] = {0};

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
    uECC_HashContext uECC;
    sha256_context_t ctx;
} uECC_SHA256_HashContext;
static void _init_sha256(const uECC_HashContext *base)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_init(&context->ctx);
}

static void _update_sha256(const uECC_HashContext *base,
                           const uint8_t *message,
                           unsigned message_size)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void _finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}
#endif

static int ndn_make_signature(uint8_t pri_key[32], ndn_block_t* seg, uint8_t* buf_sig)
{
    uint32_t num;
    buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
    ndn_block_put_var_number(64, buf_sig + 1, 66 -1);
    int gl = ndn_block_get_var_number(seg->buf + 1, seg->len - 1, &num);
    uint8_t h[32] = {0}; 

    sha256(seg->buf + 1 + gl, seg->len - 1 - gl, h);
    uECC_Curve curve = uECC_secp160r1();

#ifndef FEATURE_PERIPH_HWRNG
    // allocate memory on heap to avoid stack overflow
    uint8_t *tmp = (uint8_t*)malloc(32 + 32 + 64);
    if (tmp == NULL) {
        DPRINT("producer-ace: Error during signing interest\n");
        return -1;
    }

    uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                malloc(sizeof(uECC_SHA256_HashContext));
    if (ctx == NULL) {
        free(tmp);
        DPRINT("producer-ace: Error during signing interest\n");
        return -1;
    }
       
    ctx->uECC.init_hash = &_init_sha256;
    ctx->uECC.update_hash = &_update_sha256;
    ctx->uECC.finish_hash = &_finish_sha256;
    ctx->uECC.block_size = 64;
    ctx->uECC.result_size = 32;
    ctx->uECC.tmp = tmp;
    int res = uECC_sign_deterministic(pri_key, h, sizeof(h), &ctx->uECC,
                                              buf_sig + 1 + gl, curve); 
    free(ctx);
    free(tmp);
    if (res == 0) {
        DPRINT("producer-ace: Error during signing interest\n");
        return -1;
    }
#else
    res = uECC_sign(pri_key, h, sizeof(h), buf_sig + 1 + gl, curve);
    if (res == 0) {
        return -1;
    }  
    return 0; //success
#endif
    return 0; //success
}


static int on_interest(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("producer-ace (pid=%" PRIkernel_pid "): interest received, name = ",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    ndn_shared_block_t* sdn = ndn_name_append_uint8(&in, 3);
    if (sdn == NULL) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): cannot append component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }

    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    const char* test = "/test/use/name";
    ndn_shared_block_t* st = ndn_name_from_uri(test, strlen(test));

    /* encrypt */
    cipher_t cipher;
    uint8_t key_1[16] = {0};
    uint8_t key_2[16] = {0};
    memcpy(key_1, acehmac, 16);
    memcpy(key_2, acehmac + 16, 16);

    /* construct 16x size block */
    int block_size = st->block.len / 16 + 1;
    uint8_t* plaintext = (uint8_t*)malloc(16 * block_size);
    memcpy(plaintext, st->block.buf, st->block.len);

    uint8_t* encrypt_first = (uint8_t*)malloc(16 * block_size);
    uint8_t* encrypt_second = (uint8_t*)malloc(16 * block_size);

    cipher_init(&cipher, CIPHER_AES_128, key_1, 16);
    cipher_encrypt_cbc(&cipher, TEST_1_IV, plaintext, 16 * block_size, encrypt_first);

    cipher_init(&cipher, CIPHER_AES_128, key_2, 16);
    cipher_encrypt_cbc(&cipher, TEST_1_IV, encrypt_first, 16 * block_size, encrypt_second);
    ndn_block_t tosend = { encrypt_second, 16 * block_size };

    ndn_shared_block_t* sd =
        ndn_data_create(&sdn->block, &meta, &tosend,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        com_key_pri, sizeof(com_key_pri));
    
    if (sd == NULL) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): cannot create data block\n",
               handle->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    DPRINT("producer-ace (pid=%" PRIkernel_pid "): send data to NDN thread, name =",
           handle->id);
    ndn_name_print(&sdn->block);
    putchar('\n');
    ndn_shared_block_release(sdn);

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, sd) != 0) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): cannot put data\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    free(encrypt_first);
    free(encrypt_second);
    free(plaintext);
    return NDN_APP_CONTINUE;
}


static int on_ace(ndn_block_t* interest, ndn_block_t* data)
{

    (void)interest;

    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);

    DPRINT("producer-ace: bootstrap response received, name =");
    ndn_name_print(&name);
    putchar('\n');

    /* verify the signature */
    r = ndn_data_verify_signature(data, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0) {
        DPRINT("producer-ace: fail to verify ace response\n");
    }
    else{
            DPRINT("producer-ace: ace response valid\n");

            ndn_block_t content;
            r = ndn_data_get_content(data, &content);
            assert(r == 0);

            /* extract content is shared secret */

            int len;
            const uint8_t* buf = content.buf;  //receive the pointer from the content type
            len = content.len; //receive the content length
            DPRINT("content TLV length: %u\n", len);

            //skip content type
            buf += 1;
            len -= 1;

            //skip content length (perhaps > 255 bytes)
            uint32_t num;
            int cl = ndn_block_get_var_number(buf, len, &num); 
            DPRINT("producer-ace: content L length= %d\n", cl);
            buf += cl;
            len -= cl;

            //store the ask from controller-ace */
            const struct uECC_Curve_t * curve;
            #if uECC_SUPPORTS_secp160r1
                curve = uECC_secp160r1();
            #endif

            uint8_t ace_controller[64] = {0};
            const uint8_t* ptr = buf;
            memcpy(ace_controller, ptr, 64);
            uECC_shared_secret(ace_controller, ace_key_pri, acehmac, curve);
            ptr = NULL;
 
    }
    return NDN_APP_STOP;  //return from ndn app
}

static int on_timeout(ndn_block_t* interest)
{
    ndn_block_t name;
    int r = ndn_interest_get_name(interest, &name);
    assert(r == 0);

    DPRINT("producer-ace (pid=%" PRIkernel_pid "): interest timeout, name =",
           handle->id);

    return NDN_APP_CONTINUE;  // block forever...
}

static int send_ace_interest(void)
{
    const char* uri = "/accesscontrol";

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));

    /* append constant parameters */
    sn = ndn_name_append_from_name(&home_prefix, &sn->block);
    sn = ndn_name_append_from_name(&sn->block, &identity);

    /* parameter convention 
        1 - controller
        2 - producer
        3 - consumer
    */

    /* append ASKpub */
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER);
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER_GLOBAL);

    /* optional parameter */
    sn = ndn_name_append_uint8(&sn->block, ACE_PRODUCER_GLOBAL);

    sn = ndn_name_append(&sn->block, ace_key_pub, sizeof(ace_key_pub));

    /* prepare the signature */
    uint8_t buf_sinfo[5]; 
    buf_sinfo[0] = NDN_TLV_SIGNATURE_INFO;
    ndn_block_put_var_number(3, buf_sinfo + 1, 5 - 1);

    // Write signature type (true signatureinfo content)
    buf_sinfo[2] = NDN_TLV_SIGNATURE_TYPE;
    ndn_block_put_var_number(1, buf_sinfo + 3, 5 - 3);
    buf_sinfo[4] = NDN_SIG_TYPE_ECDSA_SHA256;

    //append the signatureinfo
    sn = ndn_name_append(&sn->block, buf_sinfo, 5); 

    //making and append ECDSA signature by CKpri
    uint8_t buf_sibs[66]; //64 bytes for the value, 2 bytes for header 
    ndn_make_signature(com_key_pri, &sn->block, buf_sibs);
    sn = ndn_name_append(&sn->block, buf_sibs, 66);  //from what part we sign?

    uint32_t lifetime = 3000;  // 1 sec

    DPRINT("producer-ace (pid=%" PRIkernel_pid "): express interest, name =",
           handle->id);
    ndn_name_print(&sn->block);
    putchar('\n');

    int r = ndn_app_express_interest(handle, &sn->block, NULL, lifetime,
                                     on_ace, on_timeout);
    ndn_shared_block_release(sn);
    if (r != 0) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}


void ndn_producer(void)
{
    DPRINT("producer-ace (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    /* install home prefix */
    const char* prefix = "/ucla/cs/397";
    ndn_shared_block_t* sp = ndn_name_from_uri(prefix, strlen(prefix));

    const char* id = "/ty-device-0001";
    ndn_shared_block_t* sd = ndn_name_from_uri(id, strlen(id));

    home_prefix = sp->block; //shouldn't change sp again
    identity = sd->block; //shouldn't change sp again

    /* apply for access control */
    send_ace_interest();
    ndn_app_run(handle);

    /* 2nd phase */
    const char* service = "/ucla/cs/397/ty-device-0001/AC/override/cool";
    ndn_shared_block_t* ss = ndn_name_from_uri(service, strlen(service));


    DPRINT("producer-ace (pid=%" PRIkernel_pid "): register service prefix \"%s\"\n",
           handle->id, service);

    if (ndn_app_register_prefix(handle, ss, on_interest) != 0) {
        DPRINT("producer-ace (pid=%" PRIkernel_pid "): failed to register service prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return;
    }

    DPRINT("producer-ace pid=%" PRIkernel_pid "): enter app run loop again\n",
           handle->id);

    ndn_app_run(handle);

    ndn_app_destroy(handle);
}