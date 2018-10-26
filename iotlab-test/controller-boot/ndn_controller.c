/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <uECC.h>
#include <string.h>
#include <hashes/sha256.h>
#include <ndn-riot/encoding/ndn-constants.h>
#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>
#include <crypto/ciphers.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"

#define DPRINT(...) printf(__VA_ARGS__)
#define MAX_COUNT 5

static ndn_app_t* handle = NULL;

static uint8_t ecc_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // BKpub, shared via out-of-band approach

static uint8_t anchor_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t anchor_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key

static ndn_block_t m_certificate;
static ndn_block_t home_prefix;

/* diffie hellman part */
static uint64_t dh_p = 10000831; //this should be shared_tsk via out-of-band approach 
static uint64_t dh_g = 10000769; 
static uint32_t secrete[4];
static uint64_t dh_send[4];
static uint64_t dh_receive[4];
static uint64_t shared_tsk[4];
static ndn_block_t dh_token;

/* counter for identity allocation */
static int counter = 0;

/* montgomery algorithm used to do power & mode operation */
uint64_t montgomery(uint64_t n, uint32_t p, uint64_t m)     
{      
    uint64_t r = n % m;     
    uint64_t tmp = 1;     
    while (p > 1)     
    {     
        if ((p & 1)!=0)     
        {     
            tmp = (tmp * r) % m;     
        }     
        r = (r * r) % m;     
        p >>= 1;     
    }     
    return (r * tmp) % m;     
}    

static int on_certificate_request(ndn_block_t* interest)
{
    /* Incoming Interest-2: /{home-prefix}/cert/{digest of BKpub}/{CKpub}
     *                      /{signature of token}/{signature by BKpri}
     */
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot get name from Certificate Request"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }
    DPRINT("Controller (pid=%" PRIkernel_pid "): Certificate Request received, name =",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    ndn_block_t comm_key;
    int home_len = ndn_name_get_size_from_block(&home_prefix); 
    ndn_name_get_component_from_block(&in, home_len + 2, &comm_key);

    DPRINT("CKpub length: %d\n", comm_key.len);

    //issue test certificates
    char* identity[MAX_COUNT];
    int index = 0;
    identity[index++] = "/test-identity-0000";
    identity[index++] = "/test-identity-1111";
    identity[index++] = "/test-identity-2222";
    identity[index++] = "/test-identity-3333";
    identity[index++] = "/test-identity-4444";
    index = (counter++) % 5;

    const char* key_info = "/KEY/001/ndncer/002";
    ndn_shared_block_t* key_info_sp = ndn_name_from_uri(key_info, strlen(key_info));
    ndn_shared_block_t* identity_sp = ndn_name_from_uri(identity[index], strlen(identity[index]));
    ndn_shared_block_t* cert_name = ndn_name_append_from_name(&home_prefix, &identity_sp->block);
    cert_name = ndn_name_append_from_name(&cert_name->block, &key_info_sp->block);

    ndn_shared_block_release(key_info_sp);
    ndn_shared_block_release(identity_sp);

    /* prepare the anchor certificate private key signed certificate */ 
    ndn_shared_block_t* sdn = ndn_name_append_uint8(&in, 3);
    if (sdn == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }

    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_block_t tosend = { comm_key.buf, comm_key.len};

    ndn_shared_block_t* signed_cert = ndn_data_create(&cert_name->block, &meta, &tosend,
                                                      NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                                                      anchor_key_pri, sizeof(anchor_key_pri));

    /* prepare return data packet, signed by negotiated TSK */
    signed_cert = ndn_data_create(&sdn->block, &meta, &signed_cert->block,
                                  NDN_SIG_TYPE_HMAC_SHA256, NULL,
                                  (uint8_t*)shared_tsk, NDN_CRYPTO_SYMM_KEY);

    if (signed_cert == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create signed Certificate\n",
               handle->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): send Ceritificate Response to NDN thread, name=",
           handle->id);
    ndn_name_print(&sdn->block);
    putchar('\n');
    ndn_shared_block_release(sdn);

    // pass ownership of "signed_cert" to the API
    if (ndn_app_put_data(handle, signed_cert) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot put Ceritificate Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_bootstrap_request(ndn_block_t* interest)
{
   /* Incoming Interest-1: /ndn/sign-on/{digest of BKpub}/{Diffie Hellman Token}
    *                      /{ECDSA signature by BKpri}
    */

    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot get name from Bootstrap Request"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }
    DPRINT("Controller (pid=%" PRIkernel_pid "): Bootstrap Request received, name =",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    //TODO: retrieve and verify the {digest of BKpub}

    /* fetch diffie hellman token from interest */
    ndn_name_get_component_from_block(&in, 3, &dh_token); 
    memcpy(dh_receive, dh_token.buf, NDN_CRYPTO_TOKEN);

    /* generate 32 bits random number as secret */    
    secrete[0]  = random_uint32();
    secrete[1]  = random_uint32();
    secrete[2]  = random_uint32();
    secrete[3]  = random_uint32();

    /* derive the shared tsk */
    shared_tsk[0] = montgomery(dh_receive[0], secrete[0], dh_p);
    shared_tsk[1] = montgomery(dh_receive[1], secrete[1], dh_p);
    shared_tsk[2] = montgomery(dh_receive[2], secrete[2], dh_p);
    shared_tsk[3] = montgomery(dh_receive[3], secrete[3], dh_p);

    /* computes the diffie hellman token sent back */
    dh_send[0] = montgomery(dh_g, secrete[0], dh_p);
    dh_send[1] = montgomery(dh_g, secrete[1], dh_p);
    dh_send[2] = montgomery(dh_g, secrete[2], dh_p);
    dh_send[3] = montgomery(dh_g, secrete[3], dh_p);  

    /* TLV encode a token block */
    uint8_t* token = (uint8_t*)malloc(NDN_CRYPTO_TOKEN + 2); 
    token[0] = NDN_TLV_BLOB;  
    ndn_block_put_var_number(NDN_CRYPTO_TOKEN, token + 1, NDN_CRYPTO_TOKEN + 1);
    memcpy(token + 2, dh_send, NDN_CRYPTO_TOKEN);
     
    /* TLV encode a digest block */
    uint8_t* hash = (uint8_t*)malloc(NDN_CRYPTO_HASH + 2); 
    sha256(ecc_key_pub, sizeof(ecc_key_pub), hash + 2);                          
    hash[0] = NDN_TLV_BLOB;
    ndn_block_put_var_number(NDN_CRYPTO_HASH, hash + 1, NDN_CRYPTO_HASH + 1);

    /* prepare the content */
    int len =  NDN_CRYPTO_HASH + 2 + NDN_CRYPTO_TOKEN + 2 + m_certificate.len;
    uint8_t* buf = (uint8_t*)malloc(len);
 
    uint8_t* ptr = buf;
    memcpy(ptr, token, NDN_CRYPTO_TOKEN + 2); 
    ptr += (NDN_CRYPTO_TOKEN + 2);
    memcpy(ptr, hash, NDN_CRYPTO_HASH + 2); 
    ptr += (NDN_CRYPTO_HASH + 2);
    memcpy(ptr, m_certificate.buf, m_certificate.len); 
    ptr = NULL;

    ndn_block_t buffer = { buf, len };
    DPRINT("content length: %d\n", buffer.len);
    DPRINT("length of anchor certitiface : %d\n", m_certificate.len);

    ndn_shared_block_t* sd = ndn_name_append_uint8(&in, 3);
    if (sd == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }
    
    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    //prepare the packet
    ndn_shared_block_t* tosend = ndn_data_create(&sd->block, &meta, &buffer,
                        NDN_SIG_TYPE_HMAC_SHA256, NULL,
                        (uint8_t*)shared_tsk, NDN_CRYPTO_SYMM_KEY);

    if (tosend == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create anchor signed Certificate\n",
               handle->id);
        ndn_shared_block_release(sd);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): send Bootstrap Response to NDN thread, name =",
           handle->id);
    ndn_name_print(&sd->block);
    putchar('\n');
    ndn_shared_block_release(sd);

    // pass ownership of "tosend" to the API
    if (ndn_app_put_data(handle, tosend) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot put Bootstrap Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    free(buf);
    free(token);
    free(hash);
    return NDN_APP_CONTINUE;
}

int ndn_controller(int argc, char **argv)
{   
    argc = argc;
    (void)argv;
    
    DPRINT("Controller (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return -1;
    }

    //set the home prefix
    const char* string = "/ucla/cs/397";
    ndn_shared_block_t* prefix = ndn_name_from_uri(string, strlen(string)); //should not be released
    home_prefix = prefix->block;

    /* prepare self-signed anchor certificate */
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_block_t key = { anchor_key_pub, sizeof(anchor_key_pub) };
    ndn_shared_block_t* anchor_cert = ndn_data_create(&prefix->block, &meta, &key,
                                                      NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                                                      anchor_key_pri, sizeof(anchor_key_pri));
    m_certificate = anchor_cert->block;

    int r = ndn_data_verify_signature(&m_certificate, anchor_key_pub, sizeof(anchor_key_pub));
    if (r != 0)
        DPRINT("Controller fail to verify self certificate\n");
    else{
        DPRINT("Controller self certificate valid\n");
    }
    
    //set interest filter /ndn/sign-on
    const char* filter = "/ndn/sign-on";
    ndn_shared_block_t* sp = ndn_name_from_uri(filter, strlen(filter));
    if (sp == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create name from uri "
               "\"%s\"\n", handle->id, filter);
        return -1;
    }
    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix \"%s\"\n",
           handle->id, filter);

    // pass ownership of "sp" to the API
    if (ndn_app_register_prefix(handle, sp, on_bootstrap_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return -1;
    }

    //set interest filter /{home-prefix}/cert
    const char* cert = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn = ndn_name_from_uri(cert, strlen(cert));
    sn = ndn_name_append_from_name(&home_prefix, &sn->block);

    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix : ",
           handle->id);
    ndn_name_print(&sn->block);
    putchar('\n');

    if (ndn_app_register_prefix(handle, sn, on_certificate_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return -1;
    }

    /* start run controller */
    DPRINT("Controller (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);
    ndn_app_run(handle);

    ndn_app_destroy(handle);

    return -1;
}