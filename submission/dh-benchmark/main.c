#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "random.h"
#include "xtimer.h"
#include "ndn-riot/encoding/name.h"
#include "ndn-riot/encoding/interest.h"
#include "ndn-riot/encoding/data.h"

static uint64_t dh_p = 10000831;
static uint64_t dh_g = 10000769;
static uint32_t secrete_1[4];
static uint32_t secrete_1_c[4];
static uint64_t bit_1[4];
static uint64_t bit_2[4];
static uint64_t bit_1_c[4];
static uint64_t bit_2_c[4];
static uint64_t shared[4];
static uint64_t shared_c[4];


static int r = 0;

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

int main(void)
{
    /*char str[] = "4567865434567896543456788543345678987654345";
    long num = 65621654;
    int result = mod(str, num);
    printf("(");
    printf("%d", mod(str, num));
    puts(")");*/
	uint32_t begin, end;
	int repeat = 1000;
	begin = xtimer_now_usec();

        //random_init(0);
        printf("%"PRIu32", ", random_uint32());
        printf("%"PRIu32", ", random_uint32());
        printf("%"PRIu32", ", random_uint32());
        printf("\n");

	for (int i = 0; i < repeat; ++i) {

	secrete_1[0]  = random_uint32();
    secrete_1[1]  = random_uint32();
    secrete_1[2]  = random_uint32();
    secrete_1[3]  = random_uint32();

	secrete_1_c[0]  = random_uint32();
    secrete_1_c[1]  = random_uint32();
    secrete_1_c[2]  = random_uint32();
    secrete_1_c[3]  = random_uint32();


    bit_1[0] = Montgomery(dh_g, secrete_1[0], dh_p);
    bit_1[1] = Montgomery(dh_g, secrete_1[1], dh_p);
    bit_1[2] = Montgomery(dh_g, secrete_1[2], dh_p);
    bit_1[3] = Montgomery(dh_g, secrete_1[3], dh_p);

    bit_1_c[0] = Montgomery(dh_g, secrete_1_c[0], dh_p);
    bit_1_c[1] = Montgomery(dh_g, secrete_1_c[1], dh_p);
    bit_1_c[2] = Montgomery(dh_g, secrete_1_c[2], dh_p);
    bit_1_c[3] = Montgomery(dh_g, secrete_1_c[3], dh_p);

    bit_2[0] = bit_1_c[0];
    bit_2[1] = bit_1_c[1];
    bit_2[2] = bit_1_c[2];
    bit_2[3] = bit_1_c[3];

    bit_2_c[0] = bit_1[0];
    bit_2_c[1] = bit_1[1];
    bit_2_c[2] = bit_1[2];
    bit_2_c[3] = bit_1[3];

    shared[0] = Montgomery(bit_2[0], secrete_1[0], dh_p);
    shared[1] = Montgomery(bit_2[1], secrete_1[1], dh_p);
    shared[2] = Montgomery(bit_2[2], secrete_1[2], dh_p);
    shared[3] = Montgomery(bit_2[3], secrete_1[3], dh_p);


    shared_c[0] = Montgomery(bit_2_c[0], secrete_1_c[0], dh_p);
    shared_c[1] = Montgomery(bit_2_c[1], secrete_1_c[1], dh_p);
    shared_c[2] = Montgomery(bit_2_c[2], secrete_1_c[2], dh_p);
    shared_c[3] = Montgomery(bit_2_c[3], secrete_1_c[3], dh_p);

    if(memcmp(shared, shared_c, sizeof(shared)) != 0){
    	printf("Wrong\n");
    }
  }
	end = xtimer_now_usec();
	printf("finished in %"PRIu32" us"
           " (%"PRIu32" us on average)\n",
           end - begin, (end - begin) / repeat);

	begin = xtimer_now_usec();

    const char* uri = "/a/b/c/d";
    uint8_t buf[600] = {0};

    ndn_shared_block_t* sn = ndn_name_from_uri(uri, strlen(uri));
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };

    ndn_block_t content = { buf, sizeof(buf) };

    ndn_shared_block_t* sd = ndn_data_create(&sn->block, &meta, &content,
                 NDN_SIG_TYPE_HMAC_SHA256, NULL,
                 (uint8_t*)shared_c, 8*4);
    ndn_shared_block_release(sn);

    for (int i = 0; i < repeat; ++i) {
    r = ndn_data_verify_signature(&sd->block, (uint8_t*)shared,
                      8*4);
    if (r != 0) { break; }
    }

    end = xtimer_now_usec();

    if (r == 0)
    printf("data HMAC finished in %"PRIu32" us"
           " (%"PRIu32" us on average)\n",
           end - begin, (end - begin) / repeat);
	else printf("No\n");

    printf("shared secret %s \n", (char *)(shared));
    printf("shared secret c %s \n", (char *)(shared_c));

	return 0;
}                                 
