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
#include <crypto/ciphers.h>
#include <uECC.h>
#include <string.h>


#define DPRINT(...) printf(__VA_ARGS__)


static ndn_app_t* handle = NULL;
static ndn_app_t* handle_new = NULL;


/*static const uint8_t ecc_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};*/

static const uint8_t ecc_key_pub[] = {
     0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
     0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
     0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
     0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
     0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
     0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
     0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
     0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};

static const uint8_t anchor_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

static const uint8_t anchor_key_pub[] = {
     0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
     0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
     0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
     0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
     0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
     0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
     0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
     0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};


static ndn_block_t m_deviceCert;
static ndn_block_t m_Certificate;
static ndn_block_t home_prefix;


static int on_certificate_request(ndn_block_t* interest)
{
    // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot get name from Certificate Request"
               "\n", handle_new->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): Certificate Request received, name=",
           handle_new->id);
    ndn_name_print(&in);
    putchar('\n');

    ndn_name_get_component_from_block(&in, 3, &m_deviceCert);

    ndn_shared_block_t* sdn = ndn_name_append_uint8(&in, 3);
    if (sdn == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle_new->id);
        return NDN_APP_ERROR;
    }
    DPRINT("m_deviceCert length: %d\n", m_deviceCert.len);


    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t tosend = { m_deviceCert.buf, m_deviceCert.len};

    ndn_shared_block_t* signed_cert =
        ndn_data_create(&sdn->block, &meta, &tosend,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        anchor_key_pri, sizeof(anchor_key_pri));
    if (signed_cert == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create signed Certificate\n",
               handle_new->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): send Ceritificate Response to NDN thread, name=",
           handle_new->id);
    ndn_name_print(&sdn->block);
    putchar('\n');
    ndn_shared_block_release(sdn);

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, signed_cert) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot put Ceritificate Response\n",
               handle_new->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): return to the app\n", handle_new->id);
    return NDN_APP_CONTINUE;
}

static int on_bootstrap_request(ndn_block_t* interest)
{
  // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}
    
    DPRINT("in\n");
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
    uint8_t token[10] = {0};
    token[0] = 129; //whatever
    ndn_block_put_var_number(8, token + 1, 10 - 1);
     
    //BKpub digest
    uint8_t buf_di[34] = {0};  //34 bytes reserved for hash
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_di + 2);                          
    buf_di[0] = 130 ; /* = 0 */ //???????? 
    ndn_block_put_var_number(32, buf_di + 1, 34 - 1);

    //prepare the big content
    uint8_t* big_buf = (uint8_t*)malloc(10 + 34 + m_Certificate.len);
    int big_len =  10 + 34 + m_Certificate.len;

    DPRINT("length of anchor certitiface : %d\n", m_Certificate.len);
    //payload
    uint8_t* ptr = big_buf;
    memcpy(ptr, token, 10); ptr += 10;
    memcpy(ptr, buf_di, 34); ptr += 34;
    memcpy(ptr, m_Certificate.buf, m_Certificate.len); ptr = NULL;

    ndn_block_t bigbuffer = { big_buf, big_len};


    DPRINT("bigbuffer length: %d\n", bigbuffer.len);
    
    //make the packet
    ndn_shared_block_t* big_packet =
        ndn_data_create(&sdn_new->block, &meta, &bigbuffer,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        anchor_key_pri, sizeof(anchor_key_pri));
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

    free(big_packet);
    return NDN_APP_STOP;
}

void ndn_controller(void)
{
    DPRINT("Controller (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    //set the home prefix
    const char* string = "/demo";
    ndn_shared_block_t* prefix = ndn_name_from_uri(string, strlen(string));
    home_prefix = prefix->block;
    //ndn_shared_block_release(prefix);

    //set the anchor keyname

    /*const char* keystring = "/self-keeeey";
    ndn_shared_block_t* key = ndn_name_from_uri(keystring, strlen(keystring));
    ndn_shared_block_t* keyname = ndn_name_append(&home_prefix,
                                 (&key->block)->buf + 4, (&key->block)->len - 4);
    ndn_shared_block_release(key);*/

    //set the default certificate
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
        return;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix \"%s\"\n",
           handle->id, filter);
    // pass ownership of "sp" to the API
    if (ndn_app_register_prefix(handle, sp, on_bootstrap_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return;
    }


    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix : ",
           handle->id);
    ndn_name_print(&sp->block);
    putchar('\n');
    DPRINT("Controller (pid=%" PRIkernel_pid "): enter app run loop\n",
           handle->id);

    ndn_app_run(handle);

    DPRINT("Controller (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle->id);
    ndn_app_destroy(handle);




    handle_new = ndn_app_create();
    if (handle_new == NULL) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }
    //set interest filter /home-prefix/cert
    const char* uri_cert = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri_cert, strlen(uri_cert));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sp1 = ndn_name_append(&home_prefix,
                                 (&sn_cert->block)->buf + 4, (&sn_cert->block)->len - 4);
    ndn_shared_block_release(sn_cert);

    if (ndn_app_register_prefix(handle_new, sp1, on_certificate_request) != 0) {
        DPRINT("Controller (pid=%" PRIkernel_pid "): failed to register prefix\n",
               handle_new->id);
        ndn_app_destroy(handle_new);
        return;
    }

    DPRINT("Controller (pid=%" PRIkernel_pid "): register prefix : ",
           handle_new->id);
    ndn_name_print(&sp1->block);
    putchar('\n');
    DPRINT("Controller (pid=%" PRIkernel_pid "): enter app run loop\n",
           handle_new->id);

    ndn_app_run(handle_new);

    DPRINT("Controller (pid=%" PRIkernel_pid "): returned from app run loop\n",
           handle_new->id);
    ndn_app_destroy(handle_new);

}
