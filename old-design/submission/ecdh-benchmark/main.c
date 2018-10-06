
#include <uECC.h>

#include <stdio.h>
#include <string.h>

#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include <crypto/ciphers.h>
#include "key.h"

static uint8_t private[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t public[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; 



void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("0x%02X ", (unsigned)vli[i]);
    }
}

int main(void) {

    int i;

    uint8_t secret[32] = {0};

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
    
    printf("Testing private key pairs\n");

    uint32_t begin, end;

    for(int j = 0; j < 5; ++j){

        switch(j){
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
        for (i = 0; i < 256; ++i) {
            printf(".");
            fflush(stdout);

            if (!uECC_shared_secret(public, private, secret, curves[j])) {
                printf("shared_secret() failed (1)\n");
                return 1;
            }

        }
        end = xtimer_now_usec();
        printf("shared secret average finished in %"PRIu32" us"
           "\n",
           (end - begin)/256);
        printf("\n");
    }
    
    return 0;
}