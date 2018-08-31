/*
 * Copyright (C) 2018 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     access-control
 * @{
 *
 * @file
 * @brief       Minimum NDN authentication server
 *
 * @author      Tianyuan Yu <royu9710@outlook.com>
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
#include "crypto/modes/cbc.h"
#include <uECC.h>
#include <string.h>

#define DPRINT(...) printf(__VA_ARGS__)
#define NFL_ACE_ENTRIES_NUMOF 20


#define ACE_CONTROLLER 1
#define ACE_CONSUMER   2
#define ACE_PRODUCER   3
#define ACE_PRODUCER_GLOBAL 4
#define ACE_CONSUMER_GLOBAL 5
#define ACE_USER_DEFINED 6
#define ACE_PRODUCER_USER_DEFINED 7
#define ACE_CONSUMER_USER_DEFINED 8

typedef struct nfl_service_entry{
    struct nfl_service_entry* prev;
    struct nfl_service_entry* next;
    ndn_block_t id;
    unsigned char seed[32]; 
}nfl_ace_entry_t;

static nfl_ace_entry_t _ace_table[NFL_ACE_ENTRIES_NUMOF];

static ndn_app_t* handle = NULL;


/*static const uint8_t ecc_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};

static const uint8_t ecc_key_pub[] = {
     0x2C, 0x3C, 0x18, 0xCB, 0x31, 0x88, 0x0B, 0xC3,
     0x73, 0xF4, 0x4A, 0xD4, 0x3F, 0x8C, 0x80, 0x24,
     0xD4, 0x8E, 0xBE, 0xB4, 0xAD, 0xF0, 0x69, 0xA6,
     0xFE, 0x29, 0x12, 0xAC, 0xC1, 0xE1, 0x26, 0x7E,
     0x2B, 0x25, 0x69, 0x02, 0xD5, 0x85, 0x51, 0x4B,
     0x91, 0xAC, 0xB9, 0xD1, 0x19, 0xE9, 0x5E, 0x97,
     0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11,
     0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
};*/

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

/*static uint8_t ecc_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
}; thi is secp160r1 key but not used */

static uint8_t anchor_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};
/*
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

static uint8_t TEST_1_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static ndn_block_t home_prefix;

static void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("0x%02X ", (unsigned)vli[i]);
    }
}


static void _ace_table_init(void)
{
    for (int i = 0; i < NFL_ACE_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _ace_table[i].id = init;
        for (int j = 0; j < 32; ++j) _ace_table[i].seed[j] = 0;
        _ace_table[i].next = NULL;
    }
}

static int ace_send_data(ndn_block_t* name, ndn_block_t* content)
{
    
    ndn_shared_block_t* sdn = ndn_name_append_uint8(name, 3);
    
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_shared_block_t* sd =
        ndn_data_create(&sdn->block, &meta, content,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        anchor_key_pri, sizeof(anchor_key_pri));
    
    if (sd == NULL) {
        DPRINT("controller-ace (pid=%" PRIkernel_pid "): cannot create data block\n",
               handle->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    DPRINT("controller-ace (pid=%" PRIkernel_pid "): send data to NDN thread, name =",
           handle->id);
    ndn_name_print(&sdn->block);
    putchar('\n');

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, sd) != 0) {
        DPRINT("controller-ace (pid=%" PRIkernel_pid "): cannot put data\n",
               handle->id);
        ndn_shared_block_release(sdn);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int ace_producer_operation(ndn_block_t* in, ndn_block_t* second,
                                     ndn_block_t* optional, ndn_block_t* dhbits, unsigned char* seed)
{
    uint8_t snd;
    memcpy(&snd, second->buf, 1);

    switch(snd){
        case ACE_PRODUCER_GLOBAL:
            DPRINT("controller-ace (pid=%" PRIkernel_pid "): producer global control"
                            "\n", handle->id);

            //optional block should be empty encoded block
            (void)optional;

            const struct uECC_Curve_t * curve;
            #if uECC_SUPPORTS_secp160r1
            curve = uECC_secp160r1();
            #endif
            uECC_shared_secret(dhbits->buf, ace_key_pri, seed, curve);

            //push back data packet
            ndn_block_t content = { ace_key_pub, sizeof(ace_key_pub) };
            ace_send_data(in, &content);

            break;

        case ACE_PRODUCER_USER_DEFINED:
            DPRINT("controller-ace (pid=%" PRIkernel_pid "): producer user defined control"
                            "\n", handle->id);

            //TODO:

            break;

        default:
            break;  

    }

    return NDN_APP_CONTINUE;
}

static int ace_consumer_operation(ndn_block_t* in, ndn_block_t* second,
                                     ndn_block_t* optional, ndn_block_t* dhbits)
{
    uint8_t snd;
    memcpy(&snd, second->buf, 1);

    switch(snd){
        case ACE_CONSUMER_GLOBAL:
            DPRINT("controller-ace (pid=%" PRIkernel_pid "): consumer global control"
                            "\n", handle->id);

            //TODO: here we should verify signed interest
            //optional parameter should contain a applied identity

            /* check whether list does have this identity */
            uint8_t* holder = (uint8_t*)malloc(optional->len + 4);
            holder[0] = NDN_TLV_NAME;
            ndn_block_put_var_number(optional->len + 2, holder + 1, optional->len + 4 - 1);
            holder[2] = NDN_TLV_NAME_COMPONENT;
            ndn_block_put_var_number(optional->len, holder + 3, optional->len + 4 - 3);
            memcpy(holder + 4, optional->buf, optional->len);
            ndn_block_t identity_name = { holder, optional->len + 4 };

            nfl_ace_entry_t* entry = NULL;
            for (int j = 0; j < NFL_ACE_ENTRIES_NUMOF && _ace_table[j].id.buf ; ++j) {
                int r = ndn_name_compare_block(&_ace_table[j].id, &identity_name); 
                if(r == 0){
                    entry = &_ace_table[j];
                    break;
                }
            }

            if(!entry){// no entry found, let the request timeout
                DPRINT("controller-ace (pid=%" PRIkernel_pid "): consumer required identity not found"
                            "\n", handle->id);

                free(holder);
                return NDN_APP_CONTINUE;
            }

            //does exist proper entry
            const struct uECC_Curve_t * curve;
            #if uECC_SUPPORTS_secp160r1
            curve = uECC_secp160r1();
            #endif

            unsigned char seed[32] = {0};
            uECC_shared_secret(dhbits->buf, ace_key_pri, seed, curve);
            DPRINT("seed\n");
            vli_print(seed, 32);putchar('\n');putchar('\n');


            //actucally here we do need encrypt the seed (AS-P)
            cipher_t cipher;
            uint8_t key_1[16] = {0};
            uint8_t key_2[16] = {0};
            memcpy(key_1, seed, 16);
            memcpy(key_2, seed + 16, 16);

            uint8_t encrypt_first[32] = {0};
            uint8_t encrypt_second[32] = {0};

            cipher_init(&cipher, CIPHER_AES_128, key_1, 16);
            cipher_encrypt_cbc(&cipher, TEST_1_IV, entry->seed, 32, encrypt_first);

            //cipher_t cipher_1 = cipher;
            cipher_init(&cipher, CIPHER_AES_128, key_2, 16);
            cipher_encrypt_cbc(&cipher, TEST_1_IV, encrypt_first, 32, encrypt_second);

            cipher_t ciphers;
            cipher_init(&ciphers, CIPHER_AES_128, key_2, 16);
            cipher_decrypt_cbc(&ciphers, TEST_1_IV, encrypt_second, 32, encrypt_first);

            cipher_init(&ciphers, CIPHER_AES_128, key_1, 16);
            uint8_t buffer_1[32];
            cipher_decrypt_cbc(&ciphers, TEST_1_IV, encrypt_first, 32, buffer_1);

            //push back data packet
            int buffer_len = 32 + 64;
            uint8_t buffer[96] = {0};
            memcpy(buffer, ace_key_pub, 64);
            memcpy(buffer + 64, encrypt_second, 32);
            ndn_block_t content = { buffer, buffer_len };
            ace_send_data(in, &content);
            free(holder);

            break;

        case ACE_CONSUMER_USER_DEFINED:
            DPRINT("controller-ace (pid=%" PRIkernel_pid "): consumer user defined control"
                            "\n", handle->id);

            //TODO:

            break;

        default:
            break;  

    }

    return NDN_APP_CONTINUE;
}

static int ace_user_defined_operation(ndn_block_t* in, ndn_block_t* second,
                                         ndn_block_t* optional, ndn_block_t* dhbits)
{
    (void)in; (void)second; (void)optional; (void)dhbits;
    return NDN_APP_CONTINUE;
}

static int on_interest(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("controller-ace (pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("controller-ace (pid=%" PRIkernel_pid "): interest received, name = ",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');


    /* analyze received name */
    int len = ndn_name_get_size_from_block(&home_prefix);

    ndn_block_t comp;

    /* check the identity */
    ndn_name_get_component_from_block(&in, len + 1, &comp);

    uint8_t* holder = (uint8_t*)malloc(comp.len + 4);
    holder[0] = NDN_TLV_NAME;
    ndn_block_put_var_number(comp.len + 2, holder + 1, comp.len + 4 - 1);
    holder[2] = NDN_TLV_NAME_COMPONENT;
    ndn_block_put_var_number(comp.len, holder + 3, comp.len + 4 - 3);
    memcpy(holder + 4, comp.buf, comp.len);
    ndn_block_t identity_name = { holder, comp.len + 4 };

    ndn_name_get_component_from_block(&in, len + 2, &comp); //first byte namespace
    uint8_t num;
    memcpy(&num, comp.buf, 1);
    
    /* compare the name TLV encoded identity to id table */
    nfl_ace_entry_t* entry = NULL;
    for (int j = 0; j < NFL_ACE_ENTRIES_NUMOF; ++j) {

        int r = ndn_name_compare_block(&_ace_table[j].id, &identity_name);     
        if (r == 0) {
            free(holder);//already collected this identity, free the candidate block

            ndn_block_t second, optional, dhbits;

            switch(num){
                case ACE_CONTROLLER:
                    DPRINT("controller-ace (pid=%" PRIkernel_pid "): don't support two controllers\n",
                                                                                         handle->id);
                    return -1;

                    break;

                case ACE_CONSUMER:
                    DPRINT("controller-ace (pid=%" PRIkernel_pid "): consumer update access control msg received\n",
                                                                                         handle->id);
                    ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                    ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                    ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                    ace_consumer_operation(&in, &second, &optional, &dhbits);

                    break;  
                
                case ACE_PRODUCER:
                    DPRINT("controller-ace (pid=%" PRIkernel_pid "): producer update access control msg received\n",
                                                                                         handle->id);

                    ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                    ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                    ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                    ace_producer_operation(&in, &second, &optional, &dhbits, _ace_table[j].seed);

                    break;

                case ACE_USER_DEFINED:
                    DPRINT("controller-ace (pid=%" PRIkernel_pid "): user update defined access control\n",
                                                                                         handle->id);
                    ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                    ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                    ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                    ace_user_defined_operation(&in, &second, &optional, &dhbits);

                break;


                default:
                    break;                   

            }


            break; //end search loop
        }

        if ((!entry) && (_ace_table[j].id.buf == NULL)) {
            entry = &_ace_table[j];
            //break; //allocate a empty seat and exit
        }   
    }

    if (entry != NULL){

        /* add identity */
        entry->prev = entry->next = NULL;
        entry->id = identity_name;

        /* functionalities */
        ndn_name_get_component_from_block(&in, len + 2, &comp); //first byte namespace
        uint32_t num;
        ndn_block_get_var_number(comp.buf, comp.len, &num);
        ndn_block_t second, optional, dhbits;

        switch(num){
            case ACE_CONTROLLER:
                DPRINT("controller-ace (pid=%" PRIkernel_pid "): don't support two controllers\n",
                                                                                     handle->id);
                return -1;

                break;

            case ACE_CONSUMER:
                DPRINT("controller-ace (pid=%" PRIkernel_pid "): consumer access control msg received\n",
                                                                                     handle->id);
                ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                ace_consumer_operation(&in, &second, &optional, &dhbits);

                break;  
            
            case ACE_PRODUCER:
                DPRINT("controller-ace (pid=%" PRIkernel_pid "): producer access control msg received\n",
                                                                                     handle->id);

                ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                ace_producer_operation(&in, &second, &optional, &dhbits, entry->seed);

                break;

            case ACE_USER_DEFINED:
                DPRINT("controller-ace (pid=%" PRIkernel_pid "): user defined access control\n",
                                                                                     handle->id);
                ndn_name_get_component_from_block(&in, len + 3, &second);//sencond byte
                ndn_name_get_component_from_block(&in, len + 4, &optional);//optional parameter
                ndn_name_get_component_from_block(&in, len + 5, &dhbits);//dh bits

                ace_user_defined_operation(&in, &second, &optional, &dhbits);

            break;


            default:
                break;                   

        }
    }

    return NDN_APP_CONTINUE;
}

void ndn_controller_ace(void)
{
    DPRINT("controller-ace (pid=%" PRIkernel_pid "): start\n", thread_getpid());

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("controller-ace (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    /* install home prefix */
    const char* prefix = "/ucla/cs/397";
    ndn_shared_block_t* sp = ndn_name_from_uri(prefix, strlen(prefix));
    home_prefix = sp->block;

    const char* ac = "/accesscontrol";
    ndn_shared_block_t* sa = ndn_name_from_uri(ac, strlen(ac));

    ndn_shared_block_t* ace = ndn_name_append_from_name(&sp->block, &sa->block);

    _ace_table_init();

    /* register prefix "/uvla/cs/397/accesscontrol" */    
    if (ndn_app_register_prefix(handle, ace, on_interest) != 0) {
        DPRINT("controller-ace (pid=%" PRIkernel_pid "): failed to register service prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return;
    }

    DPRINT("controller-ace pid=%" PRIkernel_pid "): enter app run loop\n",
           handle->id);

    ndn_app_run(handle);

    ndn_app_destroy(handle);
}