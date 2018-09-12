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
#include "api.h"

#define DPRINT(...) printf(__VA_ARGS__)

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


ndn_shared_block_t* ndn_signed_interest_create_with_index(ndn_block_t* name, void* selectors,
                                                uint8_t sig_type, uint32_t lifetime,
                                                ndn_block_t* key_name,
                                                const unsigned char* key,
                                                size_t key_len, int index)
{
    if (name == NULL || name->buf == NULL || name->len <= 0) return NULL;

    if (sig_type != NDN_SIG_TYPE_DIGEST_SHA256 &&
        sig_type != NDN_SIG_TYPE_ECDSA_SHA256 &&
        sig_type != NDN_SIG_TYPE_HMAC_SHA256)
        return NULL;

    if (sig_type != NDN_SIG_TYPE_DIGEST_SHA256 && key == NULL)
        return NULL;

    if (sig_type == NDN_SIG_TYPE_ECDSA_SHA256 && key_len != 32)
        return NULL;

    if (key != NULL && key_len <= 0)
        return NULL;

    (void)selectors;  //TODO: support selectors.
    (void)key_name;    

    switch(sig_type){
        case NDN_SIG_TYPE_ECDSA_SHA256:{
            uint8_t buf_sinfo[5] = {0}; 
            buf_sinfo[0] = NDN_TLV_SIGNATURE_INFO;
            ndn_block_put_var_number(3, buf_sinfo + 1, 5 - 1);

            // Write signature type (true signatureinfo content)
            buf_sinfo[2] = NDN_TLV_SIGNATURE_TYPE;
            ndn_block_put_var_number(1, buf_sinfo + 3, 5 - 3);
            buf_sinfo[4] = NDN_SIG_TYPE_ECDSA_SHA256;

            //append the signatureinfo
            ndn_shared_block_t* sn = ndn_name_append(name, buf_sinfo, 5); 

            //making and append ECDSA signature
            uint8_t buf_sig[66] = {0}; //64 bytes for the value, 2 bytes for header 
            
            uint32_t num;
            buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
            ndn_block_put_var_number(64, buf_sig + 1, 66 -1);
            int gl = ndn_block_get_var_number(sn->block.buf + 1, sn->block.len - 1, &num);
            uint8_t h[32] = {0}; 

            sha256(sn->block.buf + 1 + gl, sn->block.len - 1 - gl, h);
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
                DPRINT("ndn_encoding: Error during signing interest\n");
                return NULL;
            }

            uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                        malloc(sizeof(uECC_SHA256_HashContext));
            if (ctx == NULL) {
                free(tmp);
                DPRINT("ndn_encoding: Error during signing interest\n");
                return NULL;
            }
               
            ctx->uECC.init_hash = &_init_sha256;
            ctx->uECC.update_hash = &_update_sha256;
            ctx->uECC.finish_hash = &_finish_sha256;
            ctx->uECC.block_size = 64;
            ctx->uECC.result_size = 32;
            ctx->uECC.tmp = tmp;
            int res = uECC_sign_deterministic(key, h, sizeof(h), &ctx->uECC,
                                                      buf_sig + 1 + gl, curves[index]); 
            free(ctx);
            free(tmp);
            if (res == 0) {
                DPRINT("ndn_encoding: Error during signing interest\n");
                return NULL;
            }
        #else
            res = uECC_sign(key, h, sizeof(h), buf_sig + 1 + gl, curve[index]);
            if (res == 0) {
                return NULL;
            }  

        #endif

            sn = ndn_name_append(&sn->block, buf_sig, 66); 
            name = &sn->block; 
        }
            break;

        case NDN_SIG_TYPE_HMAC_SHA256:{

            uint8_t buf_sinfo2[5] = {0}; 
            buf_sinfo2[0] = NDN_TLV_SIGNATURE_INFO;
            buf_sinfo2[1] = 3;

            // Write signature type (true signatureinfo content)
            buf_sinfo2[2] = NDN_TLV_SIGNATURE_TYPE;
            buf_sinfo2[3] = 1;
            buf_sinfo2[4] = NDN_SIG_TYPE_HMAC_SHA256;

            //append the signatureinfo
            ndn_shared_block_t* sn2 = ndn_name_append(name, buf_sinfo2, 5); 

            uint8_t buf_sig2[34];
            uint32_t num2;
            buf_sig2[0] = NDN_TLV_SIGNATURE_VALUE;
            ndn_block_put_var_number(32, buf_sig2 + 1, 34 -1);
            int gl = ndn_block_get_var_number(sn2->block.buf + 1, sn2->block.len - 1, &num2);
            hmac_sha256(key, 8 * 4, (const unsigned*)(sn2->block.buf + 1 + gl), //hard code the shared secret length
                                sn2->block.len - 1 - gl, buf_sig2 + 2);
            sn2 = ndn_name_append(&sn2->block, buf_sig2, 34);
            name = &sn2->block; 
        }
            break;
    }

    // Get length of the lifetime value
    int lt_len = ndn_block_integer_length(lifetime);

    ndn_block_t inst;
    int inst_len = name->len + lt_len + 8;
    inst.len = ndn_block_total_length(NDN_TLV_INTEREST, inst_len);
    uint8_t* buf = (uint8_t*)malloc(inst.len);
    if (buf == NULL) {
        DPRINT("ndn_encoding: cannot allocate memory for interest block\n");
        return NULL;
    }
    inst.buf = buf;

    // Fill in the Interest header.
    buf[0] = NDN_TLV_INTEREST;
    int l = ndn_block_put_var_number(inst_len, buf + 1, inst.len - 1);
    buf += l + 1;
    assert(inst.len == inst_len + 1 + l);

    // Fill in the name.
    memcpy(buf, name->buf, name->len);
    buf += name->len;

    // Fill in the nonce.
    uint32_t nonce = random_uint32();
    buf[0] = NDN_TLV_NONCE;
    buf[1] = 4;  // Nonce field length
    buf[2] = (nonce >> 24) & 0xFF;
    buf[3] = (nonce >> 16) & 0xFF;
    buf[4] = (nonce >> 8) & 0xFF;
    buf[5] = nonce & 0xFF;

    // Fill in the lifetime
    buf[6] = NDN_TLV_INTERESTLIFETIME;
    buf[7] = lt_len;
    ndn_block_put_integer(lifetime, buf + 8, buf[7]);

    ndn_shared_block_t* shared = ndn_shared_block_create_by_move(&inst);
    if (shared == NULL) {
        free((void*)inst.buf);
        return NULL;
    }

    return shared;
}


int ndn_interest_verify_signature_with_index(ndn_block_t* block,
                              const unsigned char* key,
                              uint32_t algorithm,
                              size_t key_len, int index)
{
    ndn_block_t name;

    if (block == NULL) return -1;
    
    ndn_interest_get_name(block, &name);
    const uint8_t* buf = name.buf;
    int len = name.len;
    uint32_t num;
    int l;

    if (algorithm != NDN_SIG_TYPE_DIGEST_SHA256 &&
        algorithm != NDN_SIG_TYPE_HMAC_SHA256 &&
        algorithm != NDN_SIG_TYPE_ECDSA_SHA256) {
        DPRINT("ndn_encoding: unknown signature type, cannot verify\n");
        return -1;
    }

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    int name_var = l;
    buf += l; 
    len -= l; 

    const uint8_t* sig_start = buf;
    
    ndn_block_t comp;
    int size = ndn_name_get_size_from_block(&name);
    ndn_name_get_component_from_block(&name, size - 2, &comp);
    const uint8_t* buf_info = comp.buf;
    len = comp.len;

    /* read signature info type */
    if (*buf_info != NDN_TLV_SIGNATURE_INFO) return -1;
    buf_info += 1;
    len -= 1;

    /* read signature info length */
    l = ndn_block_get_var_number(buf_info, len, &num);
    if (l < 0) return -1;
    buf_info += l;
    len -= l;

    /* read signature type type */
    if (*buf_info != NDN_TLV_SIGNATURE_TYPE) return -1;
    buf_info += 1;
    len -= 1;

    /* read signature type length */
    l = ndn_block_get_var_number(buf_info, len, &num);
    if (l < 0) return -1;
    buf_info += l;
    len -= l;

    /* read integer */
    l = ndn_block_get_integer(buf_info, (int)num, &algorithm);
    if (l < 0) return -1;
    buf_info += l;
    len -= l;

    // skip to signature value
    ndn_name_get_component_from_block(&name, size - 1, &comp);
    const uint8_t* buf_value = comp.buf;
    len = comp.len;
    ndn_block_t sig_value = { comp.buf, comp.len };

    /* read signature value type */
    if (*buf_value != NDN_TLV_SIGNATURE_VALUE) return -1;
    buf_value += 1;
    len -= 1;

    /* read signature value length */
    l = ndn_block_get_var_number(buf_value, len, &num);
    if (l < 0) return -1;
    buf_value += l;
    len -= l;

    /* verify signature */
    switch (algorithm) {
        case NDN_SIG_TYPE_HMAC_SHA256:
        {
            if (num != 32) {
                DPRINT("ndn_encoding: invalid hmac sig value length (%"PRIu32")\n",
                      num);
                return -1;
            }
            uint8_t h[32] = {0};
            if (key == NULL || key_len <= 0) {
                DPRINT("ndn_encoding: no hmac key, cannot verify signature\n");
                return -1;
            }
            //hmac_sha256(key, key_len, (const unsigned*)sig_start,
            //            sig_value.buf - sig_start, h);
            hmac_sha256(key, key_len, (const unsigned*)sig_start,
                        name.len - 1 - name_var - 36, h);
            if (memcmp(h, sig_value.buf + 2, sizeof(h)) != 0) {
                DPRINT("ndn_encoding: fail to verify HMAC_SHA256 signature\n");
                return -1;
            }
            else
                return 0;
        }

        case NDN_SIG_TYPE_ECDSA_SHA256:
        {
            if (num != 64) {
                DPRINT("ndn_encoding: invalid ecdsa sig value length (%"PRIu32")\n",
                      num);
                return -1;
            }
            if (key == NULL || key_len != 64) {
                DPRINT("ndn_encoding: invalid ecdsa key\n");
                return -1;
            }
            uint8_t h[32] = {0};
            //sha256(sig_start, sig_value.buf - sig_start, h);
            sha256(sig_start, name.len - 1 - name_var - 68, h);

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

            if (uECC_verify(key, h, sizeof(h),
                            sig_value.buf + 2, curves[index]) == 0) {
                DPRINT("ndn_encoding: fail to verify ECDSA_SHA256 signature\n");
                return -1;
            }
            else
                return 0;
        }

        default:
            break;
    }
    return -1;
}

ndn_shared_block_t* ndn_data_create_with_index(ndn_block_t* name,
                                    ndn_metainfo_t* metainfo,
                                    ndn_block_t* content,
                                    uint8_t sig_type,
                                    ndn_block_t* key_name,
                                    const unsigned char* key,
                                    size_t key_len, int index)
{
    if (name == NULL || name->buf == NULL || name->len <= 0 ||
        metainfo == NULL || content == NULL || content->buf == NULL ||
        content->len < 0)
        return NULL;

    if (sig_type != NDN_SIG_TYPE_DIGEST_SHA256 &&
        sig_type != NDN_SIG_TYPE_ECDSA_SHA256 &&
        sig_type != NDN_SIG_TYPE_HMAC_SHA256)
        return NULL;

    if (sig_type != NDN_SIG_TYPE_DIGEST_SHA256 && key == NULL)
        return NULL;

    if (sig_type == NDN_SIG_TYPE_ECDSA_SHA256 && key_len != 32)
        return NULL;

    if (key != NULL && key_len <= 0)
        return NULL;

    int ml = ndn_metainfo_total_length(metainfo);
    if (ml <= 0) return NULL;

    int cl = ndn_block_total_length(NDN_TLV_CONTENT, content->len);

    int kl = 0;
    if (key_name != NULL)
        kl = ndn_block_total_length(NDN_TLV_KEY_LOCATOR, key_name->len);

    int dl = name->len + ml + cl
        + ndn_block_total_length(NDN_TLV_SIGNATURE_INFO, 3 + kl);
    if (sig_type == NDN_SIG_TYPE_ECDSA_SHA256)
        // ecc p256 signature length is 64 bytes (plus 2 byte header)
        dl += 66;
    else
        // sha256 and hmac signature length is 32 bytes (plus 2 byte header)
        dl += 34;

    ndn_block_t data;
    data.len = ndn_block_total_length(NDN_TLV_DATA, dl);
    uint8_t* buf = (uint8_t*)malloc(data.len);
    if (buf == NULL) {
        DPRINT("ndn_encoding: cannot allocate memory for data block\n");
        return NULL;
    }
    data.buf = buf;

    int l, r = data.len;
    // Write data type and length
    buf[0] = NDN_TLV_DATA;
    l = ndn_block_put_var_number(dl, buf + 1, r - 1);
    int dataLength = l;
    buf += l + 1;
    r -= l + 1;
    assert(r == dl);

    // Write name
    memcpy(buf, name->buf, name->len);
    buf += name->len;
    r -= name->len;

    // Write metainfo
    ndn_metainfo_wire_encode(metainfo, buf, ml);
    buf += ml;
    r -= ml;

    // Write content
    buf[0] = NDN_TLV_CONTENT;
    l = ndn_block_put_var_number(content->len, buf + 1, r - 1);
    buf += l + 1;
    r -= l + 1;
    memcpy(buf, content->buf, content->len);
    buf += content->len;
    r -= content->len;

    // Write signature info
    buf[0] = NDN_TLV_SIGNATURE_INFO;
    l = ndn_block_put_var_number(3 + kl, buf + 1, r - 1);
    buf += l + 1;
    r -= l + 1;

    // Write signature type
    buf[0] = NDN_TLV_SIGNATURE_TYPE;
    buf[1] = 1;
    buf[2] = sig_type;
    buf += 3;
    r -= 3;

    // Write key locator
    if (key_name != NULL) {
        assert(kl > 0);
        buf[0] = NDN_TLV_KEY_LOCATOR;
        l = ndn_block_put_var_number(key_name->len, buf + 1, r - 1);
        assert(kl == 1 + l + key_name->len);
        buf += l + 1;
        r -= l + 1;
        memcpy(buf, key_name->buf, key_name->len);
        buf += key_name->len;
        r -= key_name->len;
    }

    // Write signature value
    buf[0] = NDN_TLV_SIGNATURE_VALUE;

    switch (sig_type) {
        case NDN_SIG_TYPE_DIGEST_SHA256:
            buf[1] = 32;
            sha256(data.buf + 1 + dataLength, dl - 34, buf + 2);
            break;

        case NDN_SIG_TYPE_HMAC_SHA256:
            buf[1] = 32;
            hmac_sha256(key, key_len, (const unsigned*)(data.buf + 1 + dataLength),
                        dl - 34, buf + 2);
            break;

        case NDN_SIG_TYPE_ECDSA_SHA256:
        {
            buf[1] = 64;
            uint8_t h[32] = {0};
            sha256(data.buf + 1 + dataLength, dl - 66, h);
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
                free((void*)data.buf);
                return NULL;
            }
            uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                malloc(sizeof(uECC_SHA256_HashContext));
            if (ctx == NULL) {
                free(tmp);
                free((void*)data.buf);
                return NULL;
            }
            ctx->uECC.init_hash = &_init_sha256;
            ctx->uECC.update_hash = &_update_sha256;
            ctx->uECC.finish_hash = &_finish_sha256;
            ctx->uECC.block_size = 64;
            ctx->uECC.result_size = 32;
            ctx->uECC.tmp = tmp;
            int res = uECC_sign_deterministic(key, h, sizeof(h), &ctx->uECC,
                                              buf + 2, curves[index]);
            free(ctx);
            free(tmp);
            if (res == 0) {
                free((void*)data.buf);
                return NULL;
            }
#else
            int res = uECC_sign(key, h, sizeof(h), buf + 2, curve);
            if (res == 0) {
                free((void*)data.buf);
                return NULL;
            }
#endif
        }
        break;

        default:
            break;
    }

    ndn_shared_block_t* sd = ndn_shared_block_create_by_move(&data);
    if (sd == NULL) {
        free((void*)data.buf);
        return NULL;
    }
    return sd;
}


int ndn_data_verify_signature_with_index(ndn_block_t* block,
                                        const unsigned char* key,
                                        size_t key_len, int index)
{
    if (block == NULL) return -1;

    const uint8_t* buf = block->buf;
    int len = block->len;
    uint32_t num;
    int l;
    uint32_t algorithm;

    /* read data type */
    if (*buf != NDN_TLV_DATA) return -1;
    buf += 1;
    len -= 1;

    /* read data length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    if ((int)num > len) return -1;  // incomplete packet

    const uint8_t* sig_start = buf;

    /* read name type */
    if (*buf != NDN_TLV_NAME) return -1;
    buf += 1;
    len -= 1;

    /* read name length and skip value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read metainfo type */
    if (*buf != NDN_TLV_METAINFO) return -1;
    buf += 1;
    len -= 1;

    /* read metainfo length and skip value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read content type */
    if (*buf != NDN_TLV_CONTENT) return -1;
    buf += 1;
    len -= 1;

    /* read content length and skip value */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l + (int)num;
    len -= l + (int)num;

    /* read signature info type */
    if (*buf != NDN_TLV_SIGNATURE_INFO) return -1;
    buf += 1;
    len -= 1;

    /* read signature info length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    ndn_block_t sig_value = { buf + (int)num, len - (int)num };

    /* read signature type type */
    if (*buf != NDN_TLV_SIGNATURE_TYPE) return -1;
    buf += 1;
    len -= 1;

    /* read signature type length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    /* read integer */
    l = ndn_block_get_integer(buf, (int)num, &algorithm);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    if (algorithm != NDN_SIG_TYPE_DIGEST_SHA256 &&
        algorithm != NDN_SIG_TYPE_HMAC_SHA256 &&
        algorithm != NDN_SIG_TYPE_ECDSA_SHA256) {
        DPRINT("ndn_encoding: unknown signature type, cannot verify\n");
        return -1;
    }

    // skip to signature value
    buf = sig_value.buf;
    len = sig_value.len;

    /* read signature value type */
    if (*buf != NDN_TLV_SIGNATURE_VALUE) return -1;
    buf += 1;
    len -= 1;

    /* read signature value length */
    l = ndn_block_get_var_number(buf, len, &num);
    if (l < 0) return -1;
    buf += l;
    len -= l;

    /* verify signature */
    switch (algorithm) {
        case NDN_SIG_TYPE_DIGEST_SHA256:
        {
            if (num != 32) {
                DPRINT("ndn_encoding: invalid digest sig value length (%"PRIu32")\n",
                      num);
                return -1;
            }
            uint8_t h[32] = {0};
            sha256(sig_start, sig_value.buf - sig_start, h);
            if (memcmp(h, sig_value.buf + 2, sizeof(h)) != 0) {
                DPRINT("ndn_encoding: fail to verify DigestSha256 signature\n");
                return -1;
            }
            else
                return 0;
        }

        case NDN_SIG_TYPE_HMAC_SHA256:
        {
            if (num != 32) {
                DPRINT("ndn_encoding: invalid hmac sig value length (%"PRIu32")\n",
                      num);
                return -1;
            }
            uint8_t h[32] = {0};
            if (key == NULL || key_len <= 0) {
                DPRINT("ndn_encoding: no hmac key, cannot verify signature\n");
                return -1;
            }
            hmac_sha256(key, key_len, (const unsigned*)sig_start,
                        sig_value.buf - sig_start, h);
            if (memcmp(h, sig_value.buf + 2, sizeof(h)) != 0) {
                DPRINT("ndn_encoding: fail to verify HMAC_SHA256 signature\n");
                return -1;
            }
            else
                return 0;
        }

        case NDN_SIG_TYPE_ECDSA_SHA256:
        {
            if (num != 64) {
                DPRINT("ndn_encoding: invalid ecdsa sig value length (%"PRIu32")\n",
                      num);
                return -1;
            }
            if (key == NULL || key_len != 64) {
                DPRINT("ndn_encoding: invalid ecdsa key\n");
                return -1;
            }
            uint8_t h[32] = {0};
            sha256(sig_start, sig_value.buf - sig_start, h);

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

            if (uECC_verify(key, h, sizeof(h),
                            sig_value.buf + 2, curves[index]) == 0) {
                DPRINT("ndn_encoding: fail to verify ECDSA_SHA256 signature\n");
                return -1;
            }
            else
                return 0;
        }

        default:
            break;
    }
    return -1; // never reach here
}
