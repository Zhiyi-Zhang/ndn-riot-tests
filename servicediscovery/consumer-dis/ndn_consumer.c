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
 * @brief       Minimum NDN consumer
 *
 * @author      Wentao Shang <wentaoshang@gmail.com>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "thread.h"
#include "random.h"
#include "xtimer.h"

#include <ndn-riot/app.h>
#include <ndn-riot/ndn.h>
#include <ndn-riot/encoding/name.h>
#include <ndn-riot/encoding/interest.h>
#include <ndn-riot/encoding/data.h>
#include <ndn-riot/msg-type.h>

#define DPRINT(...) printf(__VA_ARGS__)

static ndn_app_t* handle = NULL;

static uint8_t ecc_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

/*
static uint8_t ecc_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/


#define NFL_SUBPREFIX_ENTRIES_NUMOF 20
#define NFL_SERVICE_ENTRIES_NUMOF 10
#define NFL_IDENTITY_ENTRIES_NUMOF 20
#define NFL_AVAILABLE_ENTRIES_NUMOF 20

typedef struct nfl_subprefix_entry{
    struct nfl_subprefix_entry* prev;  
    struct nfl_subprefix_entry* next;
    ndn_block_t sub;
}nfl_subprefix_entry_t;

typedef struct nfl_service_entry{
    struct nfl_service_entry* prev;
    struct nfl_service_entry* next;
    ndn_block_t ser;
}nfl_service_entry_t;

typedef struct nfl_available_entry{
    struct nfl_available_entry* prev;
    struct nfl_available_entry* next;
    ndn_block_t avail;
}nfl_available_entry_t;

typedef struct nfl_identity_entry{
    struct nfl_identity_entry* prev;
    struct nfl_identity_entry* next;
    ndn_block_t id;
    nfl_available_entry_t list[NFL_AVAILABLE_ENTRIES_NUMOF];
}nfl_identity_entry_t;


static nfl_subprefix_entry_t _subprefix_table[NFL_SUBPREFIX_ENTRIES_NUMOF];
static nfl_service_entry_t _service_table[NFL_SERVICE_ENTRIES_NUMOF];
static nfl_identity_entry_t _identity_table[NFL_IDENTITY_ENTRIES_NUMOF];
static ndn_block_t home_prefix;
static ndn_block_t host_name;

void nfl_discovery_service_table_init(void)
{
    for (int i = 0; i < NFL_SERVICE_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _service_table[i].ser = init;
        _service_table[i].next = NULL;
    }
}

void nfl_discovery_subprefix_table_init(void)
{
    for (int i = 0; i < NFL_SUBPREFIX_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _subprefix_table[i].sub = init;
        _subprefix_table[i].next = NULL;
    }
}

void nfl_discovery_identity_table_init(void)
{
    for (int i = 0; i < NFL_IDENTITY_ENTRIES_NUMOF; ++i) {
        ndn_block_t init = {NULL, 0};
        _identity_table[i].id = init;
        _identity_table[i].next = NULL;
        
        /* initialize the avaiable table */
        for (int j = 0; j < NFL_AVAILABLE_ENTRIES_NUMOF; ++j) {
            _identity_table[i].list[j].avail = init;
            _identity_table[i].list[j].next = NULL;
        }
    }
}

static int nfl_discovery_collect(ndn_block_t* interest){

    /* skip home prefix and "servicediscovery" */
    int inter_len = ndn_name_get_size_from_block(interest);
    int home_len = ndn_name_get_size_from_block(&home_prefix);// home prefix should be name TLV
    int num = inter_len - home_len - 3; // number of available services

    ndn_block_t identity;
    ndn_name_get_component_from_block(interest, home_len + 1, &identity);

    /* check the identity table, first we need construct id a name TLV */
    uint8_t* holder = (uint8_t*)malloc(identity.len + 4);
    holder[0] = NDN_TLV_NAME;
    ndn_block_put_var_number(identity.len + 2, holder + 1, identity.len + 4 - 1);
    holder[2] = NDN_TLV_NAME_COMPONENT;
    ndn_block_put_var_number(identity.len, holder + 3, identity.len + 4 - 3);
    memcpy(holder + 4, identity.buf, identity.len);
    ndn_block_t identity_name = { holder, identity.len + 4 };

    /* compare the name TLV encoded identity to id table */
    nfl_identity_entry_t* entry = NULL;
    for (int j = 0; j < NFL_IDENTITY_ENTRIES_NUMOF/* && (_identity_table[j].id.buf)*/; ++j) {   
        int r = ndn_name_compare_block(&_identity_table[j].id, &identity_name);     
        if (r == 0) {
            free(holder);//already collected this identity, free the candidate block
            
            /* to recollect services */
            ndn_block_t init = {NULL, 0};
            for (int k = 0; k < NFL_AVAILABLE_ENTRIES_NUMOF; ++k) {
                _identity_table[j].list[k].avail = init;
                _identity_table[j].list[k].next = NULL;
            }

            for (int i = 0; i < num; ++i){ //within the service list
                ndn_block_t toadd;
                ndn_name_get_component_from_block(interest, home_len + 3 + i, &toadd);

                /* construct it in name TLV */
                uint8_t* hold = (uint8_t*)malloc(toadd.len + 4);
                hold[0] = NDN_TLV_NAME;
                ndn_block_put_var_number(toadd.len + 2, hold + 1, toadd.len + 4 - 1);
                hold[2] = NDN_TLV_NAME_COMPONENT;
                ndn_block_put_var_number(toadd.len, hold + 3, toadd.len + 4 - 3);
                memcpy(hold + 4, toadd.buf, toadd.len);
                ndn_block_t toadd_name = { hold, toadd.len + 4 };

                /* services in servicelist are unique, no need to check */
                _identity_table[j].list[i].prev = _identity_table[j].list[i].next = NULL;
                _identity_table[j].list[i].avail = toadd_name;

            }
            break;
        }

        if ((!entry) && (_identity_table[j].id.buf == NULL)) {
            entry = &_identity_table[j];
        }   
    }


    if (entry != NULL){ 
        /* add identity */
        entry->prev = entry->next = NULL;
        entry->id = identity_name;

        /* add services */
        for (int i = 0; i < num; ++i){ //within the service list
            ndn_block_t toadd;
            ndn_name_get_component_from_block(interest, home_len + 3 + i, &toadd);

            /* construct it in name TLV */
            uint8_t* hold = (uint8_t*)malloc(toadd.len + 4);
            hold[0] = NDN_TLV_NAME;
            ndn_block_put_var_number(toadd.len + 2, hold + 1, toadd.len + 4 - 1);
            hold[2] = NDN_TLV_NAME_COMPONENT;
            ndn_block_put_var_number(toadd.len, hold + 3, toadd.len + 4 - 3);
            memcpy(hold + 4, toadd.buf, toadd.len);
            ndn_block_t toadd_name = { hold, toadd.len + 4 };

            /* services in servicelist are unique, no need to check */
            entry->list[i].prev = entry->list[i].next = NULL;
            entry->list[i].avail = toadd_name;

        }
    }
    
    return 0;
}


static int nfl_discovery_add_subprefix(const char* sub)

{
    nfl_subprefix_entry_t* entry = NULL;
    
    ndn_shared_block_t* sn = ndn_name_from_uri(sub, strlen(sub));

    for (int i = 0; i < NFL_SUBPREFIX_ENTRIES_NUMOF; ++i) {
        int r = ndn_name_compare_block(&_subprefix_table[i].sub, &sn->block);
        if (r == 0) {
            DPRINT("nfl-discovery: subprefix entry already exists\n");
            return -1;
        }

        if ((!entry) && (_subprefix_table[i].sub.buf == NULL)) {
            entry = &_subprefix_table[i];
        }
    }

    if (!entry) {
        DPRINT("nfl-discovery: cannot allocate subprefix entry\n");
        return -1;
    }

    entry->prev = entry->next = NULL;
    entry->sub = sn->block;

    return 0;
}

static int nfl_discovery_make_service_list(void){
    
    ndn_block_t comp;
    /* extract the first part */

    for (int i = 0; _subprefix_table[i].sub.buf != NULL; ++i) {

        nfl_service_entry_t* entry = NULL;
        ndn_name_get_component_from_block(&_subprefix_table[i].sub, 0, &comp);

        /* construct a name */
        uint8_t* holder = (uint8_t*)malloc(comp.len + 4);
        holder[0] = NDN_TLV_NAME;
        ndn_block_put_var_number(comp.len + 2, holder + 1, comp.len + 4 - 1);
        holder[2] = NDN_TLV_NAME_COMPONENT;
        ndn_block_put_var_number(comp.len, holder + 3, comp.len + 4 - 3);
        memcpy(holder + 4, comp.buf, comp.len);
        ndn_block_t comp_name = { holder, comp.len + 4 };

        for (int j = 0; j < NFL_SERVICE_ENTRIES_NUMOF; ++j) {

            int r = ndn_name_compare_block(&_service_table[j].ser, &comp_name);     
            if (r == 0) {
                free(holder);
                break;
            }

            if ((!entry) && (_service_table[j].ser.buf == NULL)) {
                entry = &_service_table[j];
                break;
            }
        }

        if (!entry) continue;
        else{
            entry->prev = entry->next = NULL;
            entry->ser = comp_name;
        }
  
    }

    return 0;
}
            

/* how about we assume less than 10 services ? */
/* but we must use linked list to store the subprefix */
static int nfl_discovery_service_check(ndn_block_t* tocheck){
    
    int r = 1; 
    for (int i = 0; i < NFL_SERVICE_ENTRIES_NUMOF && _service_table[i].ser.buf; ++i) {
        r = ndn_name_compare_block(&_service_table[i].ser, tocheck);     
        if (r == 0) {
            DPRINT("nfl-discovery: find proper service name\n");
            return 0;// success
        }
    }
    
    DPRINT("nfl-discovery: no such service name\n");
    return -1;
}

/* please pass the service block in name TLV */

static int nfl_discovery_service_extract(ndn_block_t* service, ndn_block_t ptr[]){
    
    int r = nfl_discovery_service_check(service);
    if (r != 0) return -1;
 
    /* now we do have such service */
    for (int i = 0; i < NFL_SUBPREFIX_ENTRIES_NUMOF && _subprefix_table[i].sub.buf; ++i) {
        
        /* extract the first component to check */
        ndn_block_t first;
        ndn_name_get_component_from_block(&_subprefix_table[i].sub, 0, &first);

        /* construct the first component as name TLV */
        uint8_t* holder = (uint8_t*)malloc(first.len + 4);
        holder[0] = NDN_TLV_NAME;
        ndn_block_put_var_number(first.len + 2, holder + 1, first.len + 4 - 1);
        holder[2] = NDN_TLV_NAME_COMPONENT;
        ndn_block_put_var_number(first.len, holder + 3, first.len + 4 - 3);
        memcpy(holder + 4, first.buf, first.len);
        ndn_block_t first_name = { holder, first.len + 4 };

        /* compare it with service */
        r = ndn_name_compare_block(&first_name, service);
        if (r == 0) {
            DPRINT("nfl-discovery: find one subprefix = ");
            ndn_name_print(&_subprefix_table[i].sub);
            putchar('\n');
            ptr[i] = _subprefix_table[i].sub;
        }
    }

    return 0;//success
}

static ndn_shared_block_t* nfl_discovery_make_broadcast(ndn_block_t* id){
    const char* uri = "/servicelist";
    ndn_shared_block_t* sl = ndn_name_from_uri(uri, strlen(uri));

    for (int i = 0; i < NFL_SERVICE_ENTRIES_NUMOF && _service_table[i].ser.buf; ++i) {
        sl = ndn_name_append_from_name(&sl->block, &_service_table[i].ser); 
    }
    
    sl = ndn_name_append_from_name(id, &sl->block);

    return sl; 
}

static int on_query(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): service query received, name =",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    /* get wanted service name */
    int home_len = ndn_name_get_size_from_block(&home_prefix);
    ndn_block_t service;
    ndn_name_get_component_from_block(&in, home_len + 1, &service);

    /* reencode it into name TLV */
    uint8_t* holder = (uint8_t*)malloc(service.len + 4);
    holder[0] = NDN_TLV_NAME;
    ndn_block_put_var_number(service.len + 2, holder + 1, service.len + 4 - 1);
    holder[2] = NDN_TLV_NAME_COMPONENT;
    ndn_block_put_var_number(service.len, holder + 3, service.len + 4 - 3);
    memcpy(holder + 4, service.buf, service.len);
    ndn_block_t service_name = { holder, service.len + 4 };

    /* check and extract */
    ndn_block_t ptr[NFL_SUBPREFIX_ENTRIES_NUMOF];
    int r = nfl_discovery_service_extract(&service_name, ptr);
    if(r == -1){
        DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): no such service available, name =",
           handle->id);
        ndn_name_print(&service_name);
        putchar('\n');

        free(holder);
        /* perhaps return a NACK data ? */
        return NDN_APP_CONTINUE;
    }

    /* found match */
    int len = 0;
    for(int i = 0; i < NFL_SUBPREFIX_ENTRIES_NUMOF && ptr[i].buf; ++i) len += ptr[i].len;

    uint8_t* buffer = (uint8_t*)malloc(len);
    uint8_t* start = buffer;    
    for(int i = 0; i < NFL_SUBPREFIX_ENTRIES_NUMOF && ptr[i].buf; ++i){
        memcpy(start, ptr[i].buf, ptr[i].len); start += ptr[i].len;
    }
    ndn_block_t content = { buffer, len};

    /* send back data */
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    ndn_shared_block_t* back = ndn_name_append_uint8(&in, 2);
    ndn_shared_block_t* data =
        ndn_data_create(&back->block, &meta, &content,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL, ecc_key_pri, sizeof(ecc_key_pri));

    if (data == NULL) {
        DPRINT("nfl-discovery (pid=%" PRIkernel_pid "): cannot compose Query Response\n",
               handle->id);
        ndn_shared_block_release(data);
        return NDN_APP_ERROR;
    }

    DPRINT("nfl-discovery (pid=%" PRIkernel_pid "): send Query Response to NDN thread, name =",
           handle->id);
    ndn_name_print(&back->block);
    putchar('\n');
    ndn_shared_block_release(back);

    /* pass the packet */
    if (ndn_app_put_data(handle, data) != 0) {
        DPRINT("nfl-discovery (pid=%" PRIkernel_pid "): cannot put Query Response\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_query_response(ndn_block_t* interest, ndn_block_t* data){
    
    (void)interest;
    ndn_block_t name;
    ndn_data_get_name(data, &name);
    DPRINT("nfl-discovery (pid=%" PRIkernel_pid "): Query Response received, name =",
           handle->id);
    ndn_name_print(&name);
    putchar('\n');
    
     
    return NDN_APP_CONTINUE;
}

static int on_broadcast(ndn_block_t* interest)
{
    ndn_block_t in;
    if (ndn_interest_get_name(interest, &in) != 0) {
        DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): cannot get name from interest"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): broadcast received, name=",
           handle->id);
    ndn_name_print(&in);
    putchar('\n');

    nfl_discovery_collect(&in);

    /* expriment on query */
    uint32_t lifetime = 60000; // 1 minute
    ndn_shared_block_t* toquery = ndn_name_append_from_name(&home_prefix, &_identity_table[0].id);
    toquery = ndn_name_append_from_name(&toquery->block, &_identity_table[0].list[0].avail);
    const char* query = "/query/v3";
    ndn_shared_block_t* str = ndn_name_from_uri(query, strlen(query));
    toquery = ndn_name_append_from_name(&toquery->block, &str->block);    
    ndn_app_express_interest(handle, &toquery->block, NULL, lifetime, on_query_response, NULL);
    DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): query, name =", handle->id);
    ndn_name_print(&toquery->block);
    putchar('\n');

    return NDN_APP_CONTINUE;
}


void ndn_consumer(void)
{

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return;
    }

    const char* homeuri = "/ucla/cs/397";
    ndn_shared_block_t* homesp = ndn_name_from_uri(homeuri, strlen(homeuri));
    home_prefix = homesp->block;

    const char* prefix = "/servicediscovery";
    ndn_shared_block_t* spn = ndn_name_from_uri(prefix, strlen(prefix));
    spn = ndn_name_append_from_name(&home_prefix, &spn->block);

    const char* host = "/TY-samr21-xpro-001";
    ndn_shared_block_t* hostn = ndn_name_from_uri(host, strlen(host));
    host_name = hostn->block;


    /* set subprefix and service list */
    nfl_discovery_subprefix_table_init();
    nfl_discovery_service_table_init();

    nfl_discovery_add_subprefix("/printer/394/single-sided/blackwhite");
    nfl_discovery_add_subprefix("/printer/394/double-sided/blackwhite");
    nfl_discovery_add_subprefix("/printer/394/single-sided/color");
    nfl_discovery_add_subprefix("/printer/394/double-sided/color");
    nfl_discovery_add_subprefix("/temperature/desk002/left");
    nfl_discovery_add_subprefix("/temperature/desk002/right");
    nfl_discovery_add_subprefix("/video/door1/night");
    nfl_discovery_add_subprefix("/video/door2/evening");

    nfl_discovery_make_service_list();

    
    const char* check = "/printer";
    ndn_shared_block_t* check_sp = ndn_name_from_uri(check, strlen(check));
    nfl_discovery_service_check(&check_sp->block);

    const char* check1 = "/sensor";
    ndn_shared_block_t* check_sp1 = ndn_name_from_uri(check1, strlen(check1));
    nfl_discovery_service_check(&check_sp1->block);

    DPRINT("test subprefix extraction\n");
    ndn_block_t ptr[NFL_SUBPREFIX_ENTRIES_NUMOF];
    nfl_discovery_service_extract(&check_sp->block, ptr);


    /* register broadcast filter */
    ndn_app_register_prefix(handle, spn, on_broadcast);

    /* register unicast query filter */
    for (int j = 0; j < NFL_SERVICE_ENTRIES_NUMOF && _service_table[j].ser.buf; ++j) {
        ndn_shared_block_t* toquery = ndn_name_append_from_name(&home_prefix, &host_name);
        toquery = ndn_name_append_from_name(&toquery->block, &_service_table[j].ser);
        const char* query = "/query";
        ndn_shared_block_t* str = ndn_name_from_uri(query, strlen(query));
        toquery = ndn_name_append_from_name(&toquery->block, &str->block);
        ndn_app_register_prefix(handle, toquery, on_query);
    }

    /* make and broadcast interest */
    ndn_shared_block_t* tosend = ndn_name_append_from_name(&spn->block, &host_name);
    tosend = nfl_discovery_make_broadcast(&tosend->block);

    uint32_t lifetime = 60000; // 1 minute
    ndn_app_express_interest(handle, &tosend->block, NULL, lifetime, NULL, NULL);
    DPRINT("nfl-discovery(pid=%" PRIkernel_pid "): broadcast, name =", handle->id);
    ndn_name_print(&tosend->block);
    putchar('\n');
    
    ndn_app_run(handle);

    ndn_app_destroy(handle);
}