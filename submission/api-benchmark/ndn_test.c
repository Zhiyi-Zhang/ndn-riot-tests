/*
 * Copyright (C) 2018 Tianyuan Yu
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
 * @brief       API benchmark
 *
 * @author      Tianyuan <royu9710@outlook.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/data.h"
#include "random.h"
#include "xtimer.h"
#include "api.h"
#include "key.h"

static const unsigned char key[] = { 'd', 'u', 'm', 'm', 'y', 'k', 'e', 'y' ,
                                     'd', 'u', 'm', 'm', 'y', 'k', 'e', 'y' ,
                                     'd', 'u', 'm', 'm', 'y', 'k', 'e', 'y' ,
                                     'd', 'u', 'm', 'm', 'y', 'k', 'e', 'y' };
/*
static const uint8_t ecc_key_pri[] = {
    0x38, 0x67, 0x54, 0x73, 0x8B, 0x72, 0x4C, 0xD6,
    0x3E, 0xBD, 0x52, 0xF3, 0x64, 0xD8, 0xF5, 0x7F,
    0xB5, 0xE6, 0xF2, 0x9F, 0xC2, 0x7B, 0xD6, 0x90,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3
};*/

/*
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
*/

static uint8_t public[64] = {0};
static uint8_t private[32] = {0};

static void test_data_create_hmac(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 1000;
    printf("data_create HMAC start (repeat=%d)\n", repeat);

    ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
    if (sn == NULL) {
	printf("data_create HMAC failed\n");
	return;
    }

    bool err = false;
    ndn_shared_block_t *sd;
    begin = xtimer_now_usec();
    for (int i = 0; i < repeat; ++i) {
	ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

	ndn_block_t content = { buf, sizeof(buf) };

	sd = ndn_data_create(&sn->block, &meta, &content,
			     NDN_SIG_TYPE_HMAC_SHA256, NULL,
			     key, sizeof(key));

	if (sd == NULL) {
	    err = true;
	    break;
	}

	ndn_shared_block_release(sd);
    }
    end = xtimer_now_usec();

    ndn_shared_block_release(sn);

    if (!err)
	printf("data_create HMAC finished in %"PRIu32" us"
	       " (%"PRIu32" us on average)\n",
	       end - begin, (end - begin) / repeat);
    else
	printf("data_create HMAC failed\n");
}

static void test_data_create_ecdsa_with_index(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 100;
    printf("data_create_with_index ECDSA start (repeat=%d)\n", repeat);

    bool err = false;

    for(int seq = 0; seq < 5; ++seq){

        ndn_shared_block_t *sd;

        ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("data_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                memcpy(public, pub_160r1, 64);
                memcpy(private, pvt_160r1, 32);
                break;
            case 1:
                memcpy(public, pub_192r1, 64);
                memcpy(private, pvt_192r1, 32);
                break;
            case 2:
                memcpy(public, pub_224r1, 64);
                memcpy(private, pvt_224r1, 32);
                break;
            case 3:
                memcpy(public, pub_256r1, 64);
                memcpy(private, pvt_256r1, 32);
                break;
            case 4:
                memcpy(public, pub_256k1, 64);
                memcpy(private, pvt_256k1, 32);
                break;
        }

        begin = xtimer_now_usec();
        for (int i = 0; i < repeat; ++i) {
        ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

        ndn_block_t content = { buf, sizeof(buf) };

        sd = ndn_data_create_with_index(&sn->block, &meta, &content,
                     NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                     private, sizeof(private), seq);

        if (sd == NULL) {
            err = true;
            break;
        }

        ndn_shared_block_release(sd);
        }
        end = xtimer_now_usec();

        ndn_shared_block_release(sn);

        if (!err)
        printf("data_create_with_index ECDSA finished in %"PRIu32" us"
               " (%"PRIu32" us on average)\n",
               end - begin, (end - begin) / repeat);
        else
        printf("data_create_with_index ECDSA failed\n");
    }
}

static void test_data_verify_ecdsa_with_index(void)
{
    uint32_t begin, end;
    const char* uri = "/a/b/c/d";
    uint8_t buf[100] = {0};

    int repeat = 100;
    printf("data_verify_with_index ECDSA start (repeat=%d)\n", repeat);

    for(int seq = 0; seq < 5; ++seq){

        ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("data_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                memcpy(public, pub_160r1, 64);
                memcpy(private, pvt_160r1, 32);
                break;
            case 1:
                memcpy(public, pub_192r1, 64);
                memcpy(private, pvt_192r1, 32);
                break;
            case 2:
                memcpy(public, pub_224r1, 64);
                memcpy(private, pvt_224r1, 32);
                break;
            case 3:
                memcpy(public, pub_256r1, 64);
                memcpy(private, pvt_256r1, 32);
                break;
            case 4:
                memcpy(public, pub_256k1, 64);
                memcpy(private, pvt_256k1, 32);
                break;
        }


        ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

        ndn_block_t content = { buf, sizeof(buf) };

        ndn_shared_block_t* sd =
    	ndn_data_create_with_index(&sn->block, &meta, &content,
    			NDN_SIG_TYPE_ECDSA_SHA256, NULL,
    			private, sizeof(private), seq);

        if (sd == NULL) {
        	printf("data_verify_with_index ECDSA failed\n");
        	return;
        }
        ndn_shared_block_release(sn);

        int r;

        begin = xtimer_now_usec();
        for (int i = 0; i < repeat; ++i) {
        	r = ndn_data_verify_signature_with_index(&sd->block, public,
        				      sizeof(public), seq);
        	if (r != 0) {
        	    break;
        	}  
        }
        end = xtimer_now_usec();

        if (r == 0)
    	printf("data_verify_with_index ECDSA finished in %"PRIu32" us"
    	       " (%"PRIu32" us on average)\n",
    	       end - begin, (end - begin) / repeat);
        else
    	printf("data_verify_with_index ECDSA failed\n");

        ndn_shared_block_release(sd);
    }
}

static void test_signed_interest_create_with_index(void)
{
    int repeat = 1;
    printf("signed_interest_create_with_index start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";

    for(int seq = 0; seq < 5; ++seq){

        ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("data_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                memcpy(public, pub_160r1, 64);
                memcpy(private, pvt_160r1, 32);
                break;
            case 1:
                memcpy(public, pub_192r1, 64);
                memcpy(private, pvt_192r1, 32);
                break;
            case 2:
                memcpy(public, pub_224r1, 64);
                memcpy(private, pvt_224r1, 32);
                break;
            case 3:
                memcpy(public, pub_256r1, 64);
                memcpy(private, pvt_256r1, 32);
                break;
            case 4:
                memcpy(public, pub_256k1, 64);
                memcpy(private, pvt_256k1, 32);
                break;
        }

        bool err = false;

        uint32_t begin = xtimer_now_usec();
        //for (int i = 0; i < repeat; ++i) {
        	uint32_t lifetime = 0x4000;
        	ndn_shared_block_t *sb = ndn_signed_interest_create_with_index(&sn->block, NULL, NDN_SIG_TYPE_ECDSA_SHA256, 
                                    lifetime, NULL, private, 32, seq);
        	if (sb == NULL) {
        	    err = true;
        	    break;
    	    }

    	    ndn_shared_block_release(sb);
        //}
        uint32_t end = xtimer_now_usec();

        ndn_shared_block_release(sn);

        if (!err)
    	printf("signed_interest_create_with_index finished in "
    	       " (%"PRIu32" us on average)\n",
    	       end - begin);
        else
    	printf("signed_interest_create_with_index failed\n");
    }
}


static void test_signed_interest_create_with_hmac_index(void)
{
    int repeat = 1;
    printf("signed_interest_create_with_index start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";
    int key_len = 0;

    for(int seq = 0; seq < 3; ++seq){

        ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("name_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                key_len = 8;
                break;
            case 1:
                key_len = 16;
                break;
            case 2:
                key_len = 32;
                break;
        }

        bool err = false;

        uint32_t begin = xtimer_now_usec();
        //for (int i = 0; i < repeat; ++i) {
            uint32_t lifetime = 0x4000;
            ndn_shared_block_t *sb = ndn_signed_interest_create_with_index(&sn->block, NULL, NDN_SIG_TYPE_HMAC_SHA256, 
                                    lifetime, NULL, (uint8_t*)key, key_len, seq);
            if (sb == NULL) {
                err = true;
                break;
            }

            ndn_shared_block_release(sb);
        //}
        uint32_t end = xtimer_now_usec();

        ndn_shared_block_release(sn);

        if (!err)
        printf("signed_interest_create_with_hmac_index finished in "
               " (%"PRIu32" us on average)\n",
               end - begin);
        else
        printf("signed_interest_create_with_hmac_index failed\n");
    }
}

static void test_signed_interest_verify_with_index(void)
{
    int repeat = 256;
    printf("signed_interest_verify_with_index start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";

    for(int seq = 0; seq < 5; ++seq){

        ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("name_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                memcpy(public, pub_160r1, 64);
                memcpy(private, pvt_160r1, 32);
                break;
            case 1:
                memcpy(public, pub_192r1, 64);
                memcpy(private, pvt_192r1, 32);
                break;
            case 2:
                memcpy(public, pub_224r1, 64);
                memcpy(private, pvt_224r1, 32);
                break;
            case 3:
                memcpy(public, pub_256r1, 64);
                memcpy(private, pvt_256r1, 32);
                break;
            case 4:
                memcpy(public, pub_256k1, 64);
                memcpy(private, pvt_256k1, 32);
                break;
        }

        bool err = false;

        uint32_t lifetime = 0x4000;
        ndn_shared_block_t* sb = ndn_signed_interest_create_with_index(&sn->block, NULL, NDN_SIG_TYPE_ECDSA_SHA256, lifetime,
                                 NULL, private, 32, seq);
        if (sb == NULL) {
            err = true;
            break;
        }

        uint32_t begin = xtimer_now_usec();
        for (int i = 0; i < repeat; ++i) {

            int r = ndn_interest_verify_signature_with_index(&sb->block, public, NDN_SIG_TYPE_ECDSA_SHA256,
                                      64, seq);
            if (r != 0) {
                err = true;
                break;
            }
        }
        uint32_t end = xtimer_now_usec();
        
        ndn_shared_block_release(sb);
        ndn_shared_block_release(sn);

        if (!err)
        printf("signed_interest_verify_with_index finished in %"PRIu32" us"
               " (%"PRIu32" us on average)\n",
               end - begin, (end - begin) / repeat);
        else
        printf("verify_interest_create_with_index failed\n");
    }
}

static void test_signed_interest_verify_with_hmac_index(void)
{
    int repeat = 256;
    printf("signed_interest_verify_with_hmac_index start (repeat=%d)\n", repeat);

    const char* uri = "/a/b/c/d";
    int key_len = 0;

    for(int seq = 0; seq < 3; ++seq){

        ndn_shared_block_t *sn = ndn_name_from_uri(uri, strlen(uri));
        if (sn == NULL) {
            printf("name_create_with_index ECDSA failed\n");
            return;
        }

        switch(seq){
            case 0:
                key_len = 8;
                break;
            case 1:
                key_len = 16;
                break;
            case 2:
                key_len = 32;
                break;
        }

        bool err = false;

        uint32_t lifetime = 0x4000;
        ndn_shared_block_t *sb = ndn_signed_interest_create_with_index(&sn->block, NULL, NDN_SIG_TYPE_HMAC_SHA256, 
                                lifetime, NULL, (uint8_t*)key, key_len, seq);
        if (sb == NULL) {
            err = true;
            break;
        }

        uint32_t begin = xtimer_now_usec();
        for (int i = 0; i < repeat; ++i) {

            int r = ndn_interest_verify_signature_with_index(&sb->block, (uint8_t*)key, NDN_SIG_TYPE_HMAC_SHA256,
                                      key_len, seq);
            if (r != 0) {
                err = true;
                break;
            }
        }
        uint32_t end = xtimer_now_usec();
        
        ndn_shared_block_release(sb);
        ndn_shared_block_release(sn);

        if (!err)
        printf("signed_interest_verify_with_hmac_index finished in %"PRIu32" us"
               " (%"PRIu32" us on average)\n",
               end - begin, (end - begin) / repeat);
        else
        printf("verify_interest_create_with_hmac_index failed\n");
    }
}

int ndn_test(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s [interest|data]\n", argv[0]);
        return 1;
    }

    else if (strcmp(argv[1], "interest") == 0) {

	test_signed_interest_create_with_index();
    test_signed_interest_verify_with_index();
    test_signed_interest_create_with_hmac_index();
    test_signed_interest_verify_with_hmac_index();

    }

    else if (strcmp(argv[1], "data") == 0) {
	test_data_create_hmac();

    test_data_create_ecdsa_with_index();   

	test_data_verify_ecdsa_with_index();

    }
    else {
        puts("error: invalid command");
    }
    return 0;
}
