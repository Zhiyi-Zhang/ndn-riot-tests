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
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include <ndn-riot/encoding/ndn-constants.h>
#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>
#include <ndn-riot/helper/access.h>
#include <crypto/ciphers.h>
#include "crypto/modes/cbc.h"
#include <uECC.h>
#include <string.h>

#define DPRINT(...) printf(__VA_ARGS__)
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
}; // this is secp160r1 key

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

static const uint8_t ace_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static const uint8_t ace_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

static ndn_block_t m_deviceCert;
static ndn_block_t m_Certificate;
static ndn_block_t home_prefix;

static uint64_t dh_p = 10000831;
static uint64_t dh_g = 10000769;
static uint32_t secrete_1[4];
static uint64_t bit_1[4];
static uint64_t bit_2[4];
static uint64_t shared[4];
static ndn_block_t HellmanToken;


uint64_t Montgomery(uint64_t n, uint32_t p, uint64_t m)     
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
    // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}

    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot get name from Certificate Request"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): Certificate Request received, name=",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    int home_len = ndn_name_get_size_from_block(&home_prefix);

    ndn_name_get_component_from_block(&in, home_len + 2, &m_deviceCert);

    ndn_shared_block_t* sdn = ndn_name_append_uint8(&in, 3);
    if (sdn == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }
    DPRINT("CKpub length: %d\n", m_deviceCert.len);


    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t tosend = { m_deviceCert.buf, m_deviceCert.len};

    
    char* id[5];
    id[0] = "/ty_device_0";
    id[1] = "/ty_device_1";
    id[2] = "/ty_device_2";
    id[3] = "/ty_device_3";
    id[4] = "/ty_device_4";

    int index = random_uint32() % 5;


    ndn_shared_block_t* id_ptr = ndn_name_from_uri(id[index], strlen(id[index]));
    id_ptr = ndn_name_append_from_name(&home_prefix, &id_ptr->block);

    ndn_shared_block_t* signed_cert =
        ndn_data_create(&id_ptr->block, &meta, &tosend,
                        NDN_SIG_TYPE_HMAC_SHA256, NULL,
                        anchor_key_pri, sizeof(anchor_key_pri));


    signed_cert =
        ndn_data_create(&sdn->block, &meta, &signed_cert->block,
                        NDN_SIG_TYPE_HMAC_SHA256, NULL,
                        (uint8_t*)shared, 8 * 4);

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

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, signed_cert) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot put Ceritificate Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }


    return NDN_APP_CONTINUE;
}

static int on_bootstrap_request(ndn_block_t* interest)
{
  // /ndn/sign-on/{digest of BKpub}/{Diffie Hellman Token}/{ECDSA signature by BKpri}
    
    ndn_block_t re;
    if (ndn_interest_get_name(interest, &re) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot get name from Bootstrap Request"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): Bootstrap Request received, name=",
           handle->id);
    ndn_name_print(&re);
    putchar('\n');

    //here we need to obtain bit_2 from name
    ndn_name_get_component_from_block(&re, 3, &HellmanToken); 

    memcpy(bit_2, HellmanToken.buf, 32);
    
    secrete_1[0]  = random_uint32();
    secrete_1[1]  = random_uint32();
    secrete_1[2]  = random_uint32();
    secrete_1[3]  = random_uint32();

    shared[0] = Montgomery(bit_2[0], secrete_1[0], dh_p);
    shared[1] = Montgomery(bit_2[1], secrete_1[1], dh_p);
    shared[2] = Montgomery(bit_2[2], secrete_1[2], dh_p);
    shared[3] = Montgomery(bit_2[3], secrete_1[3], dh_p);

    //ndn_name_t request;
    //request.size = 4; request.comps = &re;
    
    //TODO: retrieve and verify the {digest of BKpub}

    ndn_shared_block_t* sdn_new = ndn_name_append_uint8(&re, 3);
    if (sdn_new == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }

    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };


    /* 
    Incoming Packet Format
    Name: echo of I1->append /version
    Content: token
             BKpub digest
             anchor certificate
                               Name:  anchor prefix
                               Content： AKpub
                               Signature: AKpri
    Signature: AKpri
    */

    //token

    bit_1[0] = Montgomery(dh_g, secrete_1[0], dh_p);
    bit_1[1] = Montgomery(dh_g, secrete_1[1], dh_p);
    bit_1[2] = Montgomery(dh_g, secrete_1[2], dh_p);
    bit_1[3] = Montgomery(dh_g, secrete_1[3], dh_p);  

    uint8_t token[34] = {0};
    token[0] = 129; //whatever
    ndn_block_put_var_number(8, token + 1, 34 - 1);
    uint8_t* token_ptr = token + 2;
    memcpy(token_ptr, bit_1, 32);
     
    //BKpub digest
    uint8_t buf_di[34] = {0};  //34 bytes reserved for hash
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_di + 2);                          
    buf_di[0] = 130 ; /* = 0 */ //???????? 
    ndn_block_put_var_number(32, buf_di + 1, 34 - 1);

    //prepare the big content
    uint8_t* big_buf = (uint8_t*)malloc(34 + 34 + m_Certificate.len);
    int big_len =  34 + 34 + m_Certificate.len;

    DPRINT("length of anchor certitiface : %d\n", m_Certificate.len);
    //payload
    uint8_t* ptr = big_buf;
    memcpy(ptr, token, 34); ptr += 34;
    memcpy(ptr, buf_di, 34); ptr += 34;
    memcpy(ptr, m_Certificate.buf, m_Certificate.len); ptr = NULL;

    ndn_block_t bigbuffer = { big_buf, big_len};


    DPRINT("bigbuffer length: %d\n", bigbuffer.len);
    
    //make the packet
    ndn_shared_block_t* big_packet =
        ndn_data_create(&sdn_new->block, &meta, &bigbuffer,
                        NDN_SIG_TYPE_HMAC_SHA256, NULL,
                        (uint8_t*)shared, 8 * 4);
    //ndn_shared_block_t* big_packet =
    //    ndn_data_create(&sdn_new->block, &meta, &bigbuffer,
    //                    NDN_SIG_TYPE_DIGEST_SHA256, NULL,
    //                    NULL, 0);

    if (big_packet == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create signed Certificate\n",
               handle->id);
        ndn_shared_block_release(sdn_new);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): send Bootstrap Response to NDN thread, name=",
           handle->id);
    ndn_name_print(&sdn_new->block);
    putchar('\n');
    ndn_shared_block_release(sdn_new);

    //ndn_shared_block_release(big_packet_test);
    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, big_packet) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot put Bootstrap Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    free(big_buf);


    return NDN_APP_CONTINUE;
}

void* ndn_controller(void* ptr)

{
    DPRINT("Controller (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    (void)ptr;

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    //set the home prefix
    const char* string = "/ucla/cs/397";
    ndn_shared_block_t* prefix = ndn_name_from_uri(string, strlen(string));
    home_prefix = prefix->block;


    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_block_t keybuffer = { anchor_key_pub, sizeof(anchor_key_pub) };
    ndn_shared_block_t* anchor_cert =
    ndn_data_create(&prefix->block, &meta, &keybuffer,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        anchor_key_pri, sizeof(anchor_key_pri));
    m_Certificate = anchor_cert->block;

    int r = ndn_data_verify_signature(&m_Certificate, anchor_key_pub, sizeof(anchor_key_pub));
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
        return NULL;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix \"%s\"\n",
           handle->id, filter);
    // pass ownership of "sp" to the API
    if (ndn_app_register_prefix(handle, sp, on_bootstrap_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return NULL;
    }


    //set interest filter /home-prefix/cert
    const char* uri_cert = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri_cert, strlen(uri_cert));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sp1 = ndn_name_append(&home_prefix,
                                 (&sn_cert->block)->buf + 4, (&sn_cert->block)->len - 4);
    ndn_shared_block_release(sn_cert);

    if (ndn_app_register_prefix(handle, sp1, on_certificate_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return NULL;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix : ",
           handle->id);
    ndn_name_print(&sp1->block);
    putchar('\n');

    ndn_app_run(handle);

    DPRINT("Controller (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);
    ndn_app_destroy(handle);

    return NULL;

}