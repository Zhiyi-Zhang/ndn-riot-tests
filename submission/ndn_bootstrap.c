#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/nfl-constant.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>
#include "crypto/ciphers.h"
#include "uECC.h"
#include <string.h>
#include "api.h"

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


#define DPRINT(...) printf(__VA_ARGS__)

//ecc key generated for communication use (CK)

static uint8_t anchor_key_pub[64] = {0};
static ndn_block_t token;

static ndn_app_t* handle = NULL;

static ndn_block_t anchor_global;
static ndn_block_t certificate_global;
static ndn_block_t home_prefix;

static uint64_t dh_p = 10000831;
static uint64_t dh_g = 10000769;
static uint32_t secrete_1[4];
static uint64_t bit_1[4];
static uint64_t bit_2[4];
static uint64_t shared[4];
static uint32_t begin;
static int seq;

/*static uint8_t com_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};*/

static uint8_t com_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key


static uint8_t ecc_key_pri[32];
static uint8_t ecc_key_pub[64]; 

static uint64_t Montgomery(uint64_t n, uint32_t p, uint64_t m)     
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


//segment for signature and buffer_signature to write, returning the pointer to the buffer
//this function will automatically skip the NAME header, so just pass the whole NAME TLV 
static int ndn_make_signature_with_index(uint8_t pri_key[32], ndn_block_t* seg, uint8_t* buf_sig, int seq)
{
    uint32_t num;
    buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
    ndn_block_put_var_number(64, buf_sig + 1, 66 -1);
    int gl = ndn_block_get_var_number(seg->buf + 1, seg->len - 1, &num);
    uint8_t h[32] = {0}; 

    sha256(seg->buf + 1 + gl, seg->len - 1 - gl, h);

    const struct uECC_Curve_t * curves[5];

    int num_curves = 0;
#if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
#endif
#if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
#endif
#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif

#ifndef FEATURE_PERIPH_HWRNG
    // allocate memory on heap to avoid stack overflow
    uint8_t *tmp = (uint8_t*)malloc(32 + 32 + 64);
    if (tmp == NULL) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }

    uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                malloc(sizeof(uECC_SHA256_HashContext));
    if (ctx == NULL) {
        free(tmp);
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
       
    ctx->uECC.init_hash = &_init_sha256;
    ctx->uECC.update_hash = &_update_sha256;
    ctx->uECC.finish_hash = &_finish_sha256;
    ctx->uECC.block_size = 64;
    ctx->uECC.result_size = 32;
    ctx->uECC.tmp = tmp;
    int res = uECC_sign_deterministic(pri_key, h, sizeof(h), &ctx->uECC,
                                              buf_sig + 1 + gl, curves[seq]); 
    free(ctx);
    free(tmp);
    if (res == 0) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
#else
    res = uECC_sign(pri_key, h, sizeof(h), buf_sig + 1 + gl, curves[seq]);
    if (res == 0) {
        return -1;
    }  
    return 0; //success
#endif
    return 0; //success
}


static int ndn_make_hmac_signature(uint8_t* key_ptr, ndn_block_t* seg, uint8_t* buf_sig)
{
    //when you use this function, please check the length of buf_sig is 34
    uint32_t num;
    buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
    ndn_block_put_var_number(32, buf_sig + 1, 34 - 1);
    int gl = ndn_block_get_var_number(seg->buf + 1, seg->len - 1, &num);
    hmac_sha256(key_ptr, 8 * 4, (const unsigned*)(seg->buf + 1 + gl), //hard code the shared secret length
                        seg->len - 1 - gl, buf_sig + 2);

    return 0; //success
}


static int bootstrap_timeout(ndn_block_t* interest);

static int certificate_timeout(ndn_block_t* interest);

static int on_certificate_response(ndn_block_t* interest, ndn_block_t* data)
{

    uint32_t end = xtimer_now_usec();
    uint32_t last = end;
    DPRINT("(pid=%" PRIkernel_pid "): RTT=%"PRIu32"us\n",
           handle->id, end - begin);

    ndn_block_t name1;
    (void)interest;

    int r = ndn_data_get_name(data, &name1);  //need implementation
    assert(r == 0);

    r = ndn_data_verify_signature(data, (uint8_t*)shared, 8 * 4); 
    if (r != 0)
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): fail to verify certificate response, use HMAC\n",
               handle->id);
    else{ 

        /* install the certificate */
        ndn_block_t content_cert;
        r = ndn_data_get_content(data, &content_cert);
        assert(r == 0);
        
        const uint8_t* buf_cert = content_cert.buf;
        
        //skip the content header and install the global certificate
        buf_cert += 2;
        certificate_global.buf = buf_cert;
        certificate_global.len = content_cert.len - 2;

    }

    end = xtimer_now_usec();
    DPRINT("(pid=%" PRIkernel_pid "): process time =%"PRIu32"us\n",
           handle->id, end - last);


    return NDN_APP_STOP;  // block forever...
}

static int ndn_app_express_certificate_request(void) 
{
  // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}


    /* append the "cert" */
    const char* uri_cert = "/cert";  //info from the manufacturer
    ndn_shared_block_t* sn_cert = ndn_name_from_uri(uri_cert, strlen(uri_cert));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sn1_cert = ndn_name_append(&home_prefix,
                                 (&sn_cert->block)->buf + 4, (&sn_cert->block)->len - 4);

    ndn_shared_block_release(sn_cert);
    
    /* append the digest of BKpub */
    uint8_t* buf_di = (uint8_t*)malloc(32);  //32 bytes reserved for hash
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_di);                       
    ndn_shared_block_t* sn2_cert = ndn_name_append(&sn1_cert->block, buf_di, 32);   
    free((void*)buf_di);
    buf_di = NULL;
    ndn_shared_block_release(sn1_cert);

    ndn_shared_block_t* sn5_cert = ndn_name_append(&sn2_cert->block, com_key_pub, sizeof(com_key_pub)); 
    ndn_shared_block_release(sn2_cert);
 
    /* make the signature of token */
    /* make a block for token */
    uint8_t* buf_tk = (uint8_t*)malloc(34); //32 bytes reserved from the value, 2 bytes for header
    ndn_make_hmac_signature((uint8_t*)shared, &token, buf_tk);

    /* append the signature of token */
    ndn_shared_block_t* sn6_cert = ndn_name_append(&sn5_cert->block, buf_tk, 34);
    free((void*)buf_tk);
    buf_tk = NULL;
    ndn_shared_block_release(sn5_cert);

    //append the timestamp
    ndn_shared_block_t* sn7_cert = ndn_name_append_uint32(&sn6_cert->block, xtimer_now_usec());
    ndn_shared_block_release(sn6_cert);

    //append the random value
    ndn_shared_block_t* sn8_cert = ndn_name_append_uint32(&sn7_cert->block, random_uint32());
    ndn_shared_block_release(sn7_cert); 

    //now we have signinfo but carrying no keylocator
    // Write signature info header 
    uint8_t* buf_sinfo1 = (uint8_t*)malloc(5); 
    buf_sinfo1[0] = NDN_TLV_SIGNATURE_INFO;
    buf_sinfo1[1] = 3;

    // Write signature type (true signatureinfo content)
    buf_sinfo1[2] = NDN_TLV_SIGNATURE_TYPE;
    buf_sinfo1[3] = 1;
    buf_sinfo1[4] = NDN_SIG_TYPE_HMAC_SHA256;

    //append the signatureinfo
    ndn_shared_block_t* sn9_cert = ndn_name_append(&sn8_cert->block, buf_sinfo1, 5); 
    free((void*)buf_sinfo1);
    buf_sinfo1 = NULL;
    ndn_shared_block_release(sn8_cert);

    /* append the signature by shared secret derived HMAC */
    sn9_cert = ndn_signed_interest_create_with_index(&sn9_cert->block, NULL,
                                                NDN_SIG_TYPE_HMAC_SHA256, 3000,
                                                NULL,
                                                (uint8_t*)shared,
                                                8 * 4, seq);
    ndn_block_t sign;
    ndn_interest_get_name(&sn9_cert->block, &sign);

    uint32_t lifetime = 3000;  // 1 sec

    begin = xtimer_now_usec();

    int r = ndn_app_express_interest(handle, &sign, NULL, lifetime,
                                     on_certificate_response, 
                                     certificate_timeout); 
    ndn_shared_block_release(sn9_cert);
    if (r != 0) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}


static int on_bootstrapping_response(ndn_block_t* interest, ndn_block_t* data)
{

    (void)interest;

    uint32_t end = xtimer_now_usec();
    uint32_t last = end;
    DPRINT("(pid=%" PRIkernel_pid "): RTT=%"PRIu32"us\n",
           handle->id, end - begin);

    ndn_block_t name;
    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);

    ndn_name_print(&name);
    putchar('\n');

    ndn_block_t content;
    r = ndn_data_get_content(data, &content);
    assert(r == 0);

    uint32_t len; 



    const uint8_t* buf = content.buf;  //receive the pointer from the content type
    len = content.len; //receive the content length
    //DPRINT("content TLV length: %u\n", len);
    //skip content type
    buf += 1;
    len -= 1;

    //skip content length (perhaps > 255 bytes)
    uint32_t num;
    int cl = ndn_block_get_var_number(buf, len, &num); 

    buf += cl;
    len -= cl;

    //skip token's TLV (and push it back completely)
    token.buf = buf;
    token.len = 34;
    buf += 2;
    len -= 2;//skip header
    //process the token (4 * uint64_t)
    memcpy(bit_2, buf, 32); buf += 32; len -= 32;

    shared[0] = Montgomery(bit_2[0], secrete_1[0], dh_p);
    shared[1] = Montgomery(bit_2[1], secrete_1[1], dh_p);
    shared[2] = Montgomery(bit_2[2], secrete_1[2], dh_p);
    shared[3] = Montgomery(bit_2[3], secrete_1[3], dh_p);

    //skip 32 bytes of public key's hash (plus 2 types header)
    buf += 34;
    len -= 34;

    //set the anchor certificate
    anchor_global.buf = buf;
    anchor_global.len = len;
   

    //get certificate name - home prefix
    ndn_data_get_name(&anchor_global, &home_prefix);

    ndn_name_print(&home_prefix);
    putchar('\n');

    //then we need verify anchor's signature
    ndn_block_t AKpub;
    ndn_data_get_content(&anchor_global, &AKpub);

    memcpy(&anchor_key_pub, AKpub.buf + 2, 64);//skip the content and pubkey TLV header

    r = ndn_data_verify_signature_with_index(&anchor_global, anchor_key_pub, sizeof(anchor_key_pub), seq);
    if (r != 0)
        DPRINT("nfl-bootstrap: fail to verify sign-on response\n");
    else{

        end = xtimer_now_usec();
        DPRINT("(pid=%" PRIkernel_pid "): process time =%"PRIu32"us\n",
           handle->id, end - last);

        ndn_app_express_certificate_request(); 
    }
    return NDN_APP_CONTINUE;  // block forever...
}

static int ndn_app_express_bootstrapping_request(void)
{
     // /ndn/sign-on/{digest of BKpub}/{ECDSA signature by BKpri}

     
    const char* uri = "/ndn/sign-on";   
    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));

    //making and append the digest of BKpub      //don't have header
    uint8_t* buf_dibs = (uint8_t*)malloc(32);  
    sha256(ecc_key_pub, sizeof(ecc_key_pub), buf_dibs);                       
    ndn_shared_block_t* sn1 = ndn_name_append(&sn->block, buf_dibs, 32);   
    free(buf_dibs);
    ndn_shared_block_release(sn);

    //TODO: 256bit Diffie Hellman 
    random_init(0);
    secrete_1[0]  = random_uint32();
    secrete_1[1]  = random_uint32();
    secrete_1[2]  = random_uint32();
    secrete_1[3]  = random_uint32();

    bit_1[0] = Montgomery(dh_g, secrete_1[0], dh_p);
    bit_1[1] = Montgomery(dh_g, secrete_1[1], dh_p);
    bit_1[2] = Montgomery(dh_g, secrete_1[2], dh_p);
    bit_1[3] = Montgomery(dh_g, secrete_1[3], dh_p);
    //append the bit_1
    uint8_t* buf_dh = (uint8_t*)malloc(8 * 4);
    memcpy(buf_dh, bit_1, 32);
    ndn_shared_block_t* sn2_new = ndn_name_append(&sn1->block, buf_dh, 32); 
    ndn_shared_block_release(sn1);

    //now we have signinfo but carrying no keylocator
    // Write signature info header 
    uint8_t* buf_sinfo = (uint8_t*)malloc(5); 
    buf_sinfo[0] = NDN_TLV_SIGNATURE_INFO;
    ndn_block_put_var_number(3, buf_sinfo + 1, 5 - 1);

    // Write signature type (true signatureinfo content)
    buf_sinfo[2] = NDN_TLV_SIGNATURE_TYPE;
    ndn_block_put_var_number(1, buf_sinfo + 3, 5 - 3);
    buf_sinfo[4] = NDN_SIG_TYPE_ECDSA_SHA256;

    //append the signatureinfo
    ndn_shared_block_t* sn2 = ndn_name_append(&sn2_new->block, buf_sinfo, 5); 
    free(buf_sinfo);
    ndn_shared_block_release(sn2_new);

    //making and append ECDSA signature by BKpri
    uint8_t* buf_sibs = (uint8_t*)malloc(66); //64 bytes for the value, 2 bytes for header 
    ndn_make_signature_with_index(ecc_key_pri, &sn2->block, buf_sibs, seq);
    ndn_shared_block_t* sn3 = ndn_name_append(&sn2->block, buf_sibs, 66);  //from what part we sign?
    ndn_shared_block_release(sn2);
    free(buf_sibs);


    putchar('\n');

    uint32_t lifetime = 3000;  // 1 sec

    begin = xtimer_now_usec();

    int r = ndn_app_express_interest(handle, &sn3->block, NULL, lifetime,
                                     on_bootstrapping_response, 
                                     bootstrap_timeout);  
    ndn_shared_block_release(sn3);
    if (r != 0) {
        DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid "): failed to express interest\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int bootstrap_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid ") Bootstrapping Request Timeout\n", handle->id);
    
    return NDN_APP_STOP; 
}
static int certificate_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("nfl-bootstrap: (pid=%" PRIkernel_pid ") Certificate Request Timeout\n", handle->id);
    
    return NDN_APP_STOP; 
}

int ndn_bootstrap(int num, uint8_t* pub, uint8_t* pvt)
{
    seq = num;
    
    memcpy(ecc_key_pub, pub, 64);
    memcpy(ecc_key_pri, pvt, 32);
    

    handle = ndn_app_create();

    uint32_t all_begin = xtimer_now_usec();

    ndn_app_express_bootstrapping_request();  /* where all bootstrapping start */
    ndn_app_run(handle);

    uint32_t all_end = xtimer_now_usec();
    
    DPRINT("(pid=%" PRIkernel_pid "): overall time =%"PRIu32"us\n",
           handle->id, all_end - all_begin);

    ndn_app_destroy(handle);

    return 0;
}