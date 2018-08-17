#include "nfl-core.h"
#include "face-table.h"
#include "app.h"
#include "netif.h"
#include "l2.h"
#include "pit.h"
#include "fib.h"
#include "cs.h"
#include "forwarding-strategy.h"
#include "encoding/ndn-constants.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "encoding/data.h"
#include "nfl-constant.h"
#include "msg-type.h"
#include "bootstrap.h"
#include "discovery.h"
//#include "nfl-block.h"
#define ENABLE_DEBUG 1
#include <debug.h>
#include <thread.h>
#include <timex.h>
#include <xtimer.h>

#define NFL_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#define NFL_PRIO              (THREAD_PRIORITY_MAIN - 3)
#define NFL_MSG_QUEUE_SIZE    (8U)

#if ENABLE_DEBUG
static char _stack[NFL_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[NFL_STACK_SIZE];
#endif

kernel_pid_t nfl_pid = KERNEL_PID_UNDEF;

kernel_pid_t nfl_bootstrap_pid = KERNEL_PID_UNDEF;
char bootstrap_stack[THREAD_STACKSIZE_MAIN];

kernel_pid_t nfl_discovery_pid = KERNEL_PID_UNDEF;
char discovery_stack[THREAD_STACKSIZE_MAIN];
nfl_subprefix_entry_t _subprefix_table[NFL_SUBPREFIX_ENTRIES_NUMOF];
nfl_service_entry_t _service_table[NFL_SERVICE_ENTRIES_NUMOF];
nfl_identity_entry_t _identity_table[NFL_IDENTITY_ENTRIES_NUMOF];

//below are the tables and tuples NFL thread need to maintain
static nfl_bootstrap_tuple_t bootstrapTuple;

static int _start_bootstrap(void* ptr)
{
    //ptr pointed to a key pair struct
    
    //assign value
    msg_t _send, _reply;
    _reply.content.ptr = NULL;
    nfl_bootstrap_pid = thread_create(bootstrap_stack, sizeof(bootstrap_stack),
                            THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, nfl_bootstrap, ptr, "nfl-bootstrap");
    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = _reply.content.ptr;
    _send.type = NFL_START_BOOTSTRAP;

    msg_send_receive(&_send, &_reply, nfl_bootstrap_pid);
    nfl_bootstrap_tuple_t* buffer = _reply.content.ptr;
    
    //check and store buffer tuple
    if(!buffer) return false;

    bootstrapTuple.m_cert.buf = (uint8_t*)malloc(buffer->m_cert.len);
    uint8_t* m_cert_ptr = (uint8_t*)malloc(buffer->m_cert.len);
    memcpy(m_cert_ptr, buffer->m_cert.buf, buffer->m_cert.len);
    bootstrapTuple.m_cert.buf = m_cert_ptr;
    bootstrapTuple.m_cert.len = buffer->m_cert.len;

    uint8_t* anchor_cert_ptr = (uint8_t*)malloc(buffer->anchor_cert.len);
    memcpy(anchor_cert_ptr, buffer->anchor_cert.buf, buffer->anchor_cert.len);
    bootstrapTuple.anchor_cert.buf = anchor_cert_ptr;
    bootstrapTuple.anchor_cert.len = buffer->anchor_cert.len;

    uint8_t* home_prefix_ptr = (uint8_t*)malloc(buffer->home_prefix.len);
    memcpy(home_prefix_ptr, buffer->home_prefix.buf, buffer->home_prefix.len);
    bootstrapTuple.home_prefix.buf = home_prefix_ptr;
    bootstrapTuple.home_prefix.len = buffer->home_prefix.len;

    if(bootstrapTuple.m_cert.buf){
        DEBUG("NFL: bootstrap success\n");

        ndn_block_t name;
        ndn_data_get_name(&bootstrapTuple.m_cert, &name);
        DEBUG("m_cert name =  ");
        ndn_name_print(&name);
        putchar('\n');

        return true;
    }
    
    return false;
}

static int _start_discovery(void)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = _reply.content.ptr;

    _send.type = NFL_START_DISCOVERY;
    msg_send_receive(&_send, &_reply, nfl_discovery_pid);

    DEBUG("NFL: Service Discovery start\n");
    return true;
}

static ndn_block_t* _start_discovery_query(void* ptr)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = ptr;
    _send.type = NFL_START_DISCOVERY_QUERY;
    
    ndn_app_send_msg_to_app(nfl_discovery_pid, NULL, NDN_APP_MSG_TYPE_TERMINATE);
    msg_send_receive(&_send, &_reply, nfl_discovery_pid);

    //_reply should contain a ndn_block_t content
    if(_reply.content.ptr){
        ndn_block_t* ptr = _reply.content.ptr;
        return ptr;
    }

    return NULL;
}

static int _set_discovery_prefix(void* ptr)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //ptr should indicate a uri
    _send.content.ptr = ptr;
    _send.type = NFL_SET_DISCOVERY_PREFIX;
    msg_send_receive(&_send, &_reply, nfl_discovery_pid);

    return true;
}

static int _init_discovery(void)
{
    //pass bootstrapTuple to discovery scenario
    if(bootstrapTuple.m_cert.buf == NULL){
         DEBUG("NFL: haven't bootstrapped yet\n");
         return false;
    }

    nfl_discovery_pid = thread_create(discovery_stack, sizeof(discovery_stack),
                        THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, nfl_discovery, &bootstrapTuple,
                        "nfl-discovery");
    return true;
}

/* Main event loop for NFL */
static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[NFL_MSG_QUEUE_SIZE];

    (void)args;
    msg_init_queue(msg_q, NFL_MSG_QUEUE_SIZE);

    //TODO: initialize the NFL here

    /* start event loop */
    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NFL_START_BOOTSTRAP:
                DEBUG("NFL: START_BOOTSTRAP message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                
                if(_start_bootstrap(msg.content.ptr)){
                    reply.content.ptr = &bootstrapTuple;
                }
                else reply.content.ptr = NULL;
                
                msg_reply(&msg, &reply);

                break;

            case NFL_START_DISCOVERY:
                DEBUG("NFL: START_DISCOVERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                _start_discovery();
                
                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_START_DISCOVERY_QUERY:
                DEBUG("NFL: START_DISCOVERY_QUERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                reply.content.ptr = _start_discovery_query(msg.content.ptr);
                
                msg_reply(&msg, &reply);
                break;

            case NFL_INIT_DISCOVERY:
                DEBUG("NFL: INIT_DISCOVERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                               
                _init_discovery();

                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_SET_DISCOVERY_PREFIX:
                DEBUG("NFL: SET_DISCOVERY_PREFIX message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                //ptr should point to a string
                _set_discovery_prefix(msg.content.ptr);
                
                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_EXTRACT_BOOTSTRAP_TUPLE:
                DEBUG("NFL: EXTRACT_BOOTSTRAP_TUPLE message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                if(bootstrapTuple.m_cert.buf) reply.content.ptr = &bootstrapTuple;
                else reply.content.ptr = NULL;

                msg_reply(&msg, &reply);
                break;

            case NFL_EXTRACT_DISCOVERY_LIST:
                DEBUG("NFL: EXTRACT_DISCOVERY_LIST message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                //extract the tuple
                reply.content.ptr = &_identity_table;           
                msg_reply(&msg, &reply);
                break;

            default:
                break;
        }
    }

    return NULL;
}


kernel_pid_t nfl_init(void)
{
    /* check if thread is already running */
    if (nfl_pid == KERNEL_PID_UNDEF) {
        /* start UDP thread */
        nfl_pid = thread_create(
            _stack, sizeof(_stack), NFL_PRIO,
            THREAD_CREATE_STACKTEST, _event_loop, NULL, "NFL");
    }
    return nfl_pid;
}

/** @} */
