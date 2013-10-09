/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_ssm.h"
#include "mercury_hash_table.h"
#include "mercury_list.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"
#include "na_private.h"
#include "na_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <ssm/dumb.h>
#include <ssm.h>
#include <ssmptcp.h>

#define DEBUG 0
static int na_ssm_finalize(void);
static int na_ssm_addr_lookup(const char *name, na_addr_t *addr);
static int na_ssm_addr_free(na_addr_t addr);
static na_size_t na_ssm_msg_get_max_expected_size(void);
static na_size_t na_ssm_msg_get_max_unexpected_size(void);
static na_size_t na_ssm_msg_get_maximum_size(void);
static na_tag_t na_ssm_msg_get_maximum_tag(void);
static int na_ssm_msg_send_unexpected(const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg);
static int na_ssm_msg_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_ssm_msg_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_ssm_msg_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_ssm_mem_register(void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle);
static int na_ssm_mem_deregister(na_mem_handle_t mem_handle);
static na_size_t na_ssm_mem_handle_get_serialize_size(na_mem_handle_t mem_handle);
static int na_ssm_mem_handle_serialize(void *buf, na_size_t buf_size, na_mem_handle_t mem_handle);
static int na_ssm_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);
static int na_ssm_mem_handle_free(na_mem_handle_t mem_handle);
static int na_ssm_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_ssm_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_ssm_wait(na_request_t request, unsigned int timeout,
        na_status_t *status);
static int na_ssm_progress(unsigned int timeout, na_status_t *status);
static int na_ssm_request_free(na_request_t request);
static na_bool_t na_ssm_verify(const char* protocol);
static na_class_t* na_ssm_initialize(const na_host_buffer_t *host_buffer,
                                     na_bool_t               listen);

static na_class_t na_ssm_g = {
        na_ssm_finalize,               /* finalize */
        na_ssm_addr_lookup,            /* addr_lookup */
        na_ssm_addr_free,              /* addr_free */
        na_ssm_msg_get_max_expected_size,     /* msg_get_max_expected_size */
        na_ssm_msg_get_max_unexpected_size,   /* msg_get_max_expected_size */
        na_ssm_msg_get_maximum_tag,
        na_ssm_msg_send_unexpected,    /* msg_send_unexpected */
        na_ssm_msg_recv_unexpected,    /* msg_recv_unexpected */
        na_ssm_msg_send,               /* msg_send */
        na_ssm_msg_recv,               /* msg_recv */
        na_ssm_mem_register,           /* mem_register */
        NULL,                          /* mem_register_segments */
        na_ssm_mem_deregister,         /* mem_deregister */
        na_ssm_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_ssm_mem_handle_serialize,   /* mem_handle_serialize */
        na_ssm_mem_handle_deserialize, /* mem_handle_deserialize */
        na_ssm_mem_handle_free,        /* mem_handle_free */
        na_ssm_put,                    /* put */
        na_ssm_get,                    /* get */
        na_ssm_wait,                   /* wait */
        na_ssm_progress,                /* progress */
        na_ssm_request_free
};

/* Private structs */

typedef struct na_ssm_destinfo{
    char proto[16];
	char hostname[64];
	int port;
} na_ssm_destinfo_t;

typedef struct na_ssm_addr{
    /* ssm_Iaddr addrs; */
    ssm_Haddr addr;
} na_ssm_addr_t;

typedef struct na_ssm_mem_handle{
    //ssm_md md;    //NULL
    ssm_mr mr;  //TODO: ? 
    ssm_bits matchbits; //TODO: delete
    void *buf;
    ssm_me me;
    ssm_cb_t cb;
} na_ssm_mem_handle_t;

//TODO: inc counter


typedef int ssm_size_t;
typedef ssm_bits ssm_tag_t;
typedef unsigned long ssm_msg_tag_t;


/* Used to differentiate Send requests from Recv requests */
typedef enum ssm_req_type {
    SSM_PUT_OP,
    SSM_GET_OP,
    SSM_SEND_OP,
    SSM_RECV_OP,
    SSM_UNEXP_SEND_OP,
    SSM_UNEXP_RECV_OP
} ssm_req_type_t;

typedef struct na_ssm_request {
    ssm_req_type_t type;
    ssm_bits matchbits;
    void *user_ptr;
    ssm_tx tx;
    ssm_cb_t cb;
    bool completed;
    ssm_me me;
    ssm_mr mr;
} na_ssm_request_t;


static ssm_Itp itp;
static ssm_id ssm;
static ssm_mr mr_msg;
static ssm_me me_msg;
static int ssmport;
static ssm_Iaddr iaddr;
static char c_proto[64];

//for TCP, UDP or IB...
typedef int (*na_ssm_connect)(void *addr, void *result_halder);
static na_ssm_connect p_na_ssm_connect;

/* Used to differentiate Send requests from Recv requests */


/* Message Size */
#define NA_SSM_UNEXPECTED_SIZE 1024*1024*64
#define NA_SSM_EXPECTED_SIZE 1024*1024*64

#define NA_SSM_UNEXPECTED_BUFFERCOUNT 64
#define NA_SSM_NEXT_UNEXPBUF_POS(n) (((n)+(1))%(NA_SSM_UNEXPECTED_BUFFERCOUNT))
char **buf_unexpected;



#define NA_SSM_TAG_UNEXPECTED_OFFSET 0
#define NA_SSM_TAG_EXPECTED_OFFSET (((ssm_bits)1)<<62)
#define NA_SSM_TAG_RMA_OFFSET (((ssm_bits)1)<<63)

#define min(a, b) ((a) < (b) ? (a) : (b))


#ifdef NA_HAS_CLIENT_THREAD
static hg_thread_mutex_t finalizing_mutex;
static bool              finalizing;
static hg_thread_t       progress_service;
#endif

/* List for requests */
static hg_thread_cond_t comp_req_cond;

/*---------------------------------------------------------------------------*/

/* Mutex used for tag generation */
/* TODO use atomic increment instead */
static hg_thread_mutex_t tag_mutex;

static hg_thread_mutex_t request_mutex;
static hg_thread_mutex_t testcontext_mutex;
static hg_thread_cond_t  testcontext_cond;
static hg_thread_mutex_t unexp_waitlist_mutex;
static hg_thread_cond_t  unexp_waitlist_cond;
static hg_thread_mutex_t unexp_buf_mutex;
static hg_thread_cond_t  unexp_buf_cond;
static hg_thread_mutex_t unexp_bufcounter_mutex;
static hg_thread_mutex_t gen_matchbits;
static bool              is_testing_context;

/* List and mutex for unexpected messages */
static hg_list_entry_t  *unexpected_wait_list;
//static hg_thread_mutex_t unexpected_wait_list_mutex;

/* List and mutex for unexpected buffers */
static hg_list_entry_t  *unexpected_buf;
static hg_thread_mutex_t unexpected_buf_mutex;

/* Buffers for unexpected data */
typedef struct na_ssm_unexpbuf{
    char *buf;
    ssm_me me;
    ssm_cb_t cb;
    ssm_mr mr;
    bool valid;
    ssm_bits bits;
    ssm_status status;
    ssm_Haddr addr;
    uint64_t bytes;
} na_ssm_unexpbuf_t;
static int unexpbuf_cpos;
static int unexpbuf_rpos;
static int unexpbuf_availpos;
static na_ssm_unexpbuf_t unexpbuf[NA_SSM_UNEXPECTED_BUFFERCOUNT];
static ssm_cb_t unexp_cb;
static ssm_me unexp_me;

/* u*/
typedef struct na_ssm_unexpected_wait{
    void *buf;
    na_size_t buf_size;
    na_size_t *actual_buf_size;
    na_addr_t *source;
    na_tag_t *tag;
    na_request_t *request;
    void *op_arg;
} na_ssm_unexpected_wait_t;

static ssm_bits cur_bits;

static const char na_ssm_name_g[] = "ssm";

const na_class_describe_t na_ssm_describe_g = {
    na_ssm_name_g,
    na_ssm_verify,
    na_ssm_initialize
};

/* generate unique matchbits */
static inline ssm_bits
generate_unique_matchbits()
{
    hg_thread_mutex_lock(&gen_matchbits);
    cur_bits++;
    hg_thread_mutex_unlock(&gen_matchbits);
    return cur_bits;
}


/* map functions */
static inline int
pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}
static inline unsigned int
pointer_hash(void *location)
{
    return (unsigned int) (unsigned long) location;
}


int addr_parser(const char *str, na_ssm_destinfo_t *addr)
{
    if(str == NULL){
        fprintf(stderr, "error: addr_parser() str is null\n");
        exit(0);
    }
#if DEBUG
    printf("addr_parser(): string = %s\n", str);
#endif
    sscanf(str, "%15[^:]://%63[^:]:%d", addr->proto, addr->hostname, &(addr->port));
    return 0;
}

static inline int post_unexpected_buf(int bufpos)
{


}

static inline int mark_as_completed(na_ssm_request_t *req)
{
    req->completed = 1;
    return 1;
}

static inline void show_stats(void *cbdat, ssm_result r)
{
    
    printf("\tcbdat             = %p\n", cbdat);
    printf("\tssm_id     id     = %p\n", r->id);
    printf("\tssm_me     me     = %p\n", r->me);
    printf("\tssm_tx     tx     = %p\n", r->tx);
    printf("\tssm_bits   bits   = %lu\n", r->bits);
    printf("\tssm_status status = %u\n", r->status);
    printf("\t         (%s)\n", ssm_status_str(r->status));
    printf("\tssm_op     op     = %u\n", r->op);
    printf("\t         (%s)\n", ssm_op_str(r->op));
    printf("\tssm_Haddr  addr   = %p\n", r->addr);
    printf("\tssm_mr     mr     = %p\n", r->mr);
    printf("\tssm_md     md     = %p\n", r->md);
    printf("\tuint64_t   bytes  = %lu\n", r->bytes);
}

void msg_send_cb(void *cbdat, void *evdat) 
{
    ssm_result r = evdat;
    (void)cbdat;

    if (r->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("msg_send_cb(): cb error");
        fprintf(stderr, "\t         (%s)\n", ssm_status_str(r->status));
        return;
    }
    
    hg_thread_mutex_lock(&request_mutex);
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    hg_thread_mutex_unlock(&request_mutex);
    ssm_mr_destroy(r->mr); //TODO: Error Handling
}

void unexp_msg_send_cb(void *cbdat, void *evdat) 
{
    ssm_result r = evdat;

    if(r->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("unexp_msg_send_cb(): cb error");
        return;
    }
    
    hg_thread_mutex_lock(&request_mutex);
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    hg_thread_mutex_unlock(&request_mutex);
    ssm_mr_destroy(r->mr); //TODO: Error Handling
}

void msg_recv_cb(void *cbdat, void *evdat)
{
    ssm_result r = evdat;

    if(r->status!=SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("msg_recv_cb(): cb error");
        return;
    }
    
    hg_thread_mutex_lock(&request_mutex);
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    hg_thread_mutex_unlock(&request_mutex);

    ssm_mr_destroy(r->mr); //TODO: Error Handling
    ssm_unlink(ssm, r->me);
}

void unexp_msg_recv_cb(void *cbdat, void *evdat)
{
    ssm_result r = evdat;

    hg_thread_mutex_lock(&unexp_buf_mutex);
    na_ssm_unexpbuf_t *cbd = &unexpbuf[unexpbuf_cpos];

    if (r->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("unexp_msg_recv_cb(): cb error");
        return;
    }
    
    cbd->valid = 1;
    cbd->bits = r->bits;
    cbd->status = r->status;
    cbd->addr = r->addr;
    cbd->bytes = r->bytes;
    unexpbuf_cpos = NA_SSM_NEXT_UNEXPBUF_POS(unexpbuf_cpos);
    hg_thread_cond_signal(&unexp_buf_cond);
    hg_thread_mutex_unlock(&unexp_buf_mutex);
}

void put_cb(void *cbdat, void *evdat) 
{
    ssm_result r = evdat;

    if (r->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("put_cb(): cb error");
        printf("\t         (%s)\n", ssm_status_str(r->status));
        return;
    }
    
    hg_thread_mutex_lock(&request_mutex);
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    hg_thread_mutex_unlock(&request_mutex);
}


void get_cb(void *cbdat, void *evdat) 
{
    ssm_result v_ssm_result = evdat;
    
    if (v_ssm_result->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("get_cb(): cb error");
        return;
    }

    hg_thread_mutex_lock(&request_mutex);
    
    mark_as_completed(cbdat);

    //wake up others
    hg_thread_cond_signal(&comp_req_cond);

    hg_thread_mutex_unlock(&request_mutex);
}

void postedbuf_cb(void *cbdat, void *evdat)
{
    ssm_result v_ssm_result = evdat;
    
    if (v_ssm_result->status != SSM_ST_COMPLETE)
    {
        NA_ERROR_DEFAULT("postedbuf_cb(): cb error");
        return;
    }

    return;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_progress_service
 *
 * Purpose:     Service to make one-sided progress
 *
 *---------------------------------------------------------------------------
 */
#ifdef NA_HAS_CLIENT_THREAD
static void* na_ssm_progress_service(void *args)
{
    na_bool_t service_done = 0;

    while (!service_done) {
        int na_ret;

        hg_thread_mutex_lock(&finalizing_mutex);
        service_done = (finalizing) ? 1 : 0;
        hg_thread_mutex_unlock(&finalizing_mutex);

        na_ret = na_ssm_progress(0, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            NA_ERROR_DEFAULT("Could not make progress");
            break;
        }

        sleep(0);

        if (service_done)
          break;
    }

    return NULL;
}
#endif

na_bool_t
na_ssm_verify(const char* protocol)
{
    na_bool_t accept = NA_FALSE;
    
    if (strcmp(protocol, "tcp") == 0)
    {
        accept = NA_TRUE;
    }

    return accept;
}

na_class_t*
na_ssm_initialize(const na_host_buffer_t *na_buffer,
                  na_bool_t               listen)
{
    if (na_buffer != NULL)
    {
        return NA_SSM_Init(na_buffer->na_protocol,
                           na_buffer->na_port,
                           listen);
    }

    return NULL;
}

/*---------------------------------------------------------------------------
 * Function:    NA_SSM_Init
 *
 * Purpose:     Initialize the network abstraction layer
 *
 *---------------------------------------------------------------------------
 */
na_class_t *NA_SSM_Init(char *proto, int port, int flags)
{
    if (flags == 0 )
    {
        flags = SSM_NOF;
    }
    
    ssmport = port;
    strncpy(c_proto, proto, sizeof(c_proto));

    if (strcmp(proto, "tcp") == 0)
    {
        itp = ssmptcp_new_tp(port, SSM_NOF);
        if(itp == NULL){
            printf("ssmptcp_new_tp() failed\n");
            return NULL;
        }
        ssm = ssm_start(itp, NULL, flags);
        if(ssm == NULL){
            printf("ssm_start() failed\n");
            return NULL;
        }
        iaddr = ssm_addr(ssm);
        /* TODO Error handling */
    }
    else
    {
        printf("Unknown protocol");
        exit(0);
    }

    /* Prepare buffers */
    int i;
    unexpbuf_cpos = 0;
    unexpbuf_rpos = 0;
    unexpbuf_availpos = -1;
    cur_bits = 0;
    unexp_cb.pcb = unexp_msg_recv_cb;
    unexp_cb.cbdata = NULL;
    unexp_me = ssm_link(ssm, 0, ((ssm_tag_t)0xffffffffffffffff >> 2), SSM_POS_HEAD, NULL, &unexp_cb, SSM_NOF);
#if DEBUG
    printf("\tssm_link(ssm = %d, mask = %p)\n",
            ssm, ((ssm_tag_t)0xffffffffffffffff >> 2));
#endif
    for(i = 0; i < NA_SSM_UNEXPECTED_BUFFERCOUNT; i++){
        unexpbuf[i].buf = (char *)malloc(NA_SSM_UNEXPECTED_SIZE);
        unexpbuf[i].mr = ssm_mr_create(NULL, unexpbuf[i].buf, NA_SSM_UNEXPECTED_SIZE);
        unexpbuf[i].valid = 0;
        if( ssm_post(ssm, unexp_me, unexpbuf[i].mr, SSM_NOF) < 0){
            NA_ERROR_DEFAULT("Post failed (init)");
        }
        unexpbuf_availpos = NA_SSM_NEXT_UNEXPBUF_POS(unexpbuf_availpos);
    }
    //unexpbuf_rpos = 0;
    // TODO: add free(at finalize phase)

    /* POST buffers for unexpected recieve */
    ssm_size_t size = NA_SSM_UNEXPECTED_SIZE;
    ssm_msg_tag_t ssm_tag = 0 + NA_SSM_TAG_UNEXPECTED_OFFSET;


    //TODO add is_server (need?)
    //is_server = (flags == BMI_INIT_SERVER) ? 1 : 0;
//
//    /* Automatically free all the values with the hash map */
//    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);
//
    /* Initialize cond variable */
    //hg_thread_mutex_init(&unexpected_wait_list_mutex);
    hg_thread_mutex_init(&unexpected_buf_mutex);
    hg_thread_mutex_init(&request_mutex);
    hg_thread_cond_init(&comp_req_cond);
    hg_thread_mutex_init(&unexp_waitlist_mutex);
    hg_thread_cond_init(&unexp_waitlist_cond);
    hg_thread_mutex_init(&unexp_buf_mutex);
    hg_thread_cond_init(&unexp_buf_cond);
    hg_thread_mutex_init(&unexp_bufcounter_mutex);
    hg_thread_mutex_init(&gen_matchbits);
#ifdef NA_HAS_CLIENT_THREAD
    hg_thread_mutex_init(&finalizing_mutex);
    hg_thread_create(&progress_service, &na_ssm_progress_service, NULL);
#endif

    return &na_ssm_g;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_finalize
 *
 * Purpose:     Finalize the network abstraction layer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_finalize(void)
{
	ssm_stop(ssm);
    /* TODO */
    /* add free */
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_addr_lookup
 *
 * Purpose:     Lookup an addr from a peer address/name
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_addr_lookup(const char *in_name, na_addr_t *in_addr)
{
    na_ssm_destinfo_t   v_dest;
    ssmptcp_addrargs_t  v_addrargs;
    na_ssm_addr_t      *v_ssm_addr     = NULL;

    printf("Addr: %s\n", in_name);

    addr_parser(in_name, &v_dest);

    v_addrargs.host = v_dest.hostname;
    v_addrargs.port = v_dest.port;

    v_ssm_addr = (na_ssm_addr_t *) malloc(sizeof(na_ssm_addr_t));

    if (v_ssm_addr != NULL)
    {
        v_ssm_addr->addr = ssm_addr_create(ssm, &v_addrargs);

        if(v_ssm_addr->addr < 0)
        {
            return NA_FAIL;
        }
    }

    *in_addr = (na_addr_t) v_ssm_addr;

    return NA_SUCCESS;
    
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_addr_free
 *
 * Purpose:     Free the addr from the list of peers
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_addr_free(na_addr_t addr)
{
#if DEBUG
    fprintf(stderr, "na_ssm_addr_free(addr = %p)\n", addr);
#endif
    na_ssm_addr_t *paddr = (na_ssm_addr_t *)addr;
    /* SSM addr destroy */
    //ssm_addr_destroy(ssm, paddr->addr);
    free(paddr);
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ssm_msg_get_max_expected_size(void)
{
    na_size_t max_expected_size = NA_SSM_EXPECTED_SIZE;
    return max_expected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ssm_msg_get_max_unexpected_size(void)
{
    na_size_t max_unexpected_size = NA_SSM_UNEXPECTED_SIZE;
    return max_unexpected_size;
}


/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_get_maximum_size
 *
 * Purpose:     Get the maximum size of a message
 *
 *---------------------------------------------------------------------------
 */
static na_size_t na_ssm_msg_get_maximum_size(void)
{
    //TODO fix
    return min(NA_SSM_EXPECTED_SIZE, NA_SSM_UNEXPECTED_SIZE);
}


/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_get_maximum_tag
 *
 * Purpose:     Get the maximum tag of a message
 *
 *---------------------------------------------------------------------------
 */
static na_tag_t na_ssm_msg_get_maximum_tag(void)
{
    //return min( max tag size of ssm or na_tag_t);
    return (na_tag_t)2147483647;
}


/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_send_unexpected
 *
 * Purpose:     Send an unexpected message to dest
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_msg_send_unexpected(const void *buf, na_size_t buf_size,
        na_addr_t dest, na_tag_t tag, na_request_t *request, void *op_arg)
{
    int ssm_ret, ret = NA_SUCCESS;
    ssm_size_t ssm_buf_size = (ssm_size_t) buf_size;

    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) dest;
    ssm_msg_tag_t ssm_tag = (ssm_msg_tag_t) tag;

    na_ssm_request_t *ssm_request = NULL;
    /* use addr as unique id*/
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    ssm_request->type = SSM_UNEXP_SEND_OP;
    ssm_request->matchbits = (ssm_bits)tag + NA_SSM_TAG_UNEXPECTED_OFFSET;
    ssm_request->user_ptr = op_arg;
    
#if DEBUG
    printf("na_ssm_msg_send_unexpected()\n");
    printf("\tbuf = %p, buf_size = %d, dest = %p, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, ssm_peer_addr->addr, tag, request, op_arg);
#endif

    ssm_mr mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    ssm_request->cb.pcb = unexp_msg_send_cb;
    ssm_request->cb.cbdata = ssm_request;

    ssm_tx stx; 
    stx = ssm_put(ssm, ssm_peer_addr->addr , mr, NULL, ssm_tag, &(ssm_request->cb), SSM_NOF);
#if DEBUG
    printf("\tssmput(ssm = %d, addr = %p, mr = %d, tag = %p\n",
            ssm, ssm_peer_addr->addr, mr, ssm_tag);
    printf("\ttx = %p\n", stx);
#endif

    ssm_request->tx = stx;
    *request = (na_request_t*) ssm_request;



    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_recv_unexpected
 *
 * Purpose:     Receive an unexpected message
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_msg_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
#if DEBUG
    printf("na_ssm_msg_recv_unexpected()\n");
    printf("\tbuf = %p, buf_size = %d, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, tag, request, op_arg);
#endif
    int ssm_ret, ret = NA_SUCCESS;
    hg_list_entry_t *entry = NULL;
    na_ssm_request_t *pssm_request = NULL;
    na_ssm_unexpected_wait_t *ssm_unexpected_entry = NULL;


    if (!buf) {
        NA_ERROR_DEFAULT("NULL buffer");
        ret = NA_FAIL;
        return ret;
    }
    hg_thread_mutex_lock(&unexp_buf_mutex);
    if(unexpbuf[unexpbuf_rpos].valid == 0){
        *actual_buf_size = 0;
        hg_thread_mutex_unlock(&unexp_buf_mutex);
        return ret;
    }
    pssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    pssm_request->type = SSM_UNEXP_RECV_OP;

#if DEBUG
    printf("\tassigned request = %p\n", pssm_request);
#endif

    if (unexpbuf[unexpbuf_rpos].status < 0) {
        NA_ERROR_DEFAULT("unexpected recv failed");
        /* TODO: free ?*/
        //TODO: request->status = ERROR

    }
    /*
    if(NA_SSM_UNEXPECTED_SIZE > (ssm_size_t)buf_size) {
        NA_ERROR_DEFAULT("buf_size is less than its of unexpected message");
        //ret = NA_FAIL;
        //return ret;
    }
    */
    na_ssm_unexpbuf_t *pbuf = &unexpbuf[unexpbuf_rpos];
    if (actual_buf_size) {
        *(actual_buf_size) = (na_size_t) pbuf->bytes;
    }
    if(source){
#if DEBUG
        fprintf(stderr, "\tcopy wait->source = %p\n", pbuf->addr);
#endif
        na_ssm_addr_t *psrc = (na_ssm_addr_t *)malloc(sizeof(na_ssm_addr_t));
        psrc->addr = pbuf->addr;
        *source = (na_addr_t) psrc;
        //((na_ssm_addr_t *)(source))->addr = pbuf->addr;
    }
    if(tag){
        *(tag) = (na_tag_t) pbuf->bits - NA_SSM_TAG_UNEXPECTED_OFFSET;
    }
    memcpy(buf, pbuf->buf, buf_size);
    na_ssm_request_t *preq = (na_ssm_request_t *)pssm_request;
    (preq->matchbits) = pbuf->bits;
    (preq->completed) = 1;


    /* Clean up the buflist */
    /* TODO: lock ? */
    pbuf->valid = 0;
    /* Post the buf again */
#if 0
    if( ssm_post(ssm, unexp_me, pbuf->mr, SSM_NOF) < 0){
        NA_ERROR_DEFAULT("Post failed (wait)");
    }
#endif
    unexpbuf_availpos = NA_SSM_NEXT_UNEXPBUF_POS(unexpbuf_availpos);
    unexpbuf_rpos = NA_SSM_NEXT_UNEXPBUF_POS(unexpbuf_rpos);
    *request = (na_request_t) pssm_request;

    hg_thread_mutex_unlock(&unexp_buf_mutex);
#if 0
    hg_thread_mutex_lock(&unexp_waitlist_mutex);
    pssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    pssm_request->type = SSM_UNEXP_RECV_OP;

    na_ssm_unexpected_wait_t *unexpected_wait = 
        (na_ssm_unexpected_wait_t *) malloc (sizeof(na_ssm_unexpected_wait_t));
    unexpected_wait->buf = buf;
    unexpected_wait->buf_size = buf_size;
    unexpected_wait->actual_buf_size = actual_buf_size;
    na_addr_t src = (na_addr_t)(na_ssm_addr_t *)malloc(sizeof(na_ssm_addr_t));
    *source = src;
    unexpected_wait->source = src;
    unexpected_wait->tag = tag;
    unexpected_wait->request = (na_request_t)pssm_request;
    unexpected_wait->op_arg = op_arg;
    
    if (!hg_list_append(&unexpected_wait_list, (hg_list_value_t)unexpected_wait)) {
        NA_ERROR_DEFAULT("Could not append unexpected_wait to list");
        ret = NA_FAIL;
    }

    *request = (na_request_t) pssm_request;
    hg_thread_mutex_unlock(&unexp_waitlist_mutex);
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_send
 *
 * Purpose:     Send an expected message to dest
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_msg_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int ret = NA_SUCCESS, ssm_ret;
    ssm_size_t ssm_buf_size = (ssm_size_t) buf_size;
    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) dest;
    ssm_msg_tag_t ssm_tag = (ssm_msg_tag_t) tag;

    na_ssm_request_t *ssm_request = NULL;
    /* use addr as unique id*/
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
#if DEBUG
    printf("\tassigned request = %p\n", ssm_request);
#endif
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    ssm_request->type = SSM_SEND_OP;
    ssm_request->matchbits = (ssm_bits)tag + NA_SSM_TAG_EXPECTED_OFFSET;
    ssm_request->user_ptr = op_arg;
    
    //na_ssm_mem_handle_t *mem_handle = (na_ssm_mem_handle_t *)malloc(sizeof(na_ssm_mem_handle_t)); //TODO: delete
    
#if DEBUG
    printf("na_ssm_msg_send()\n");
    printf("\tbuf = %p, buf_size = %d, dest = %p, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, ssm_peer_addr->addr, tag, request, op_arg);
#endif

    ssm_request->mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    ssm_request->cb.pcb = msg_send_cb;
    ssm_request->cb.cbdata = ssm_request;

    ssm_tx stx; 
    stx = ssm_put(ssm, ssm_peer_addr->addr, ssm_request->mr, NULL, ssm_request->matchbits, &(ssm_request->cb), SSM_NOF);
#if DEBUG
    printf("\ttx = %p\n", stx);
#endif
//    if (ssm_ret < 0) {
//        NA_ERROR_DEFAULT("SSM_post_send() failed");
//        //free(bmi_request);
//        //bmi_request = NULL;
//        ret = NA_FAIL;
//        return ret;
//    }

    ssm_request->tx = stx;
    *request = (na_request_t*) ssm_request;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_msg_recv
 *
 * Purpose:     Receive an expected message from source
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_msg_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    printf("na_ssm_msg_recv()\n");
#if DEBUG

    printf("\tbuf = %p, buf_size = %d, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, tag, request, op_arg);
#endif
    int ssm_ret, ret = NA_SUCCESS;
    ssm_size_t ssm_buf_size = (ssm_size_t) buf_size;
    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) source;
    ssm_msg_tag_t ssm_tag = (ssm_msg_tag_t) tag;
    na_ssm_request_t *ssm_request = NULL;
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
#if DEBUG
    printf("\tassigned request = %p\n", ssm_request);
#endif
    
    ssm_request->type = SSM_RECV_OP;
    ssm_request->matchbits = ssm_tag + NA_SSM_TAG_EXPECTED_OFFSET;
    ssm_request->user_ptr = op_arg;

    /* Allocate request */
    /* Register Memory */
    ssm_request->mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    /* Prepare callback function */
    ssm_request->cb.pcb = msg_recv_cb;
    ssm_request->cb.cbdata = ssm_request;
    /* Post the SSM recv request */
    /* TODO segfault */
    ssm_request->me = ssm_link(ssm, ssm_request->matchbits, 0x0 /* mask */, SSM_POS_HEAD, NULL, &(ssm_request->cb), SSM_NOF);
    ssm_ret = ssm_post(ssm, ssm_request->me, ssm_request->mr, SSM_NOF);

    if (ssm_ret < 0) {
        NA_ERROR_DEFAULT("ssm_post() failed");
        free(ssm_request);
        ret = NA_FAIL;
        return ret;
    }
    
    *request = (na_request_t) ssm_request;

    /* Mark request as done if immediate BMI completion detected */
    /* maybe it doesn't happen with ssm */

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_register
 *
 * Purpose:     Register memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_mem_register(void               *in_buf,
                        na_size_t           in_buf_size,
                        unsigned long       in_flags,
                        na_mem_handle_t    *out_mem_handle)
{
    na_ssm_mem_handle_t       *v_handle = NULL;
    int                        v_return = NA_SUCCESS;

    v_handle = (na_ssm_mem_handle_t *) malloc(sizeof(na_ssm_mem_handle_t));

    if (v_handle == NULL)
    {
        return NA_FAIL;
    }

    v_handle->mr = ssm_mr_create(NULL, in_buf, in_buf_size);

    if (v_handle->mr == NULL)
    {
        free(v_handle);
        return NA_FAIL;
    }

    v_handle->matchbits = generate_unique_matchbits() + NA_SSM_TAG_RMA_OFFSET;
    v_handle->cb.pcb    = postedbuf_cb;
    v_handle->cb.cbdata = NULL;

    v_handle->me = ssm_link(ssm,
                            v_handle->matchbits,
                            NA_SSM_TAG_RMA_OFFSET,
                            SSM_POS_HEAD,
                            NULL,
                            &(v_handle->cb),
                            SSM_NOF);

    v_return = ssm_post(ssm,
                        v_handle->me,
                        v_handle->mr,
                        SSM_POST_STATIC);

    if (v_return < 0)
    {
        free(v_handle);
        return NA_FAIL;
    }

    *out_mem_handle = v_handle;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_deregister
 *
 * Purpose:     Deregister memory
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_mem_deregister(na_mem_handle_t mem_handle)
{
    int rc;
    int ret;
    na_ssm_mem_handle_t *ssm_memh = (na_ssm_mem_handle_t *) mem_handle;
    rc = ssm_mr_destroy(ssm_memh->mr);
    if( rc == 0){
        ret = NA_SUCCESS;
    } else {
        ret = NA_FAIL;
    }
    return ret;
    //TODO delete from hash table
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_get_serialize_size
 *
 * Purpose:     Get size required to serialize handle
 *
 *---------------------------------------------------------------------------
 */
static na_size_t na_ssm_mem_handle_get_serialize_size(na_mem_handle_t mem_handle)
{
    (void) mem_handle;
    return sizeof(na_ssm_mem_handle_t);
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_serialize
 *
 * Purpose:     Serialize memory handle into a buffer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_mem_handle_serialize(void *buf, na_size_t buf_size,
        na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    na_ssm_mem_handle_t *ssmhandle = (na_ssm_mem_handle_t *) mem_handle;

    if (buf_size < sizeof(na_ssm_mem_handle_t))
    {
        printf("Error\n");
        ret = NA_FAIL;
    }
    else
    {
        memcpy(buf, ssmhandle, sizeof(na_ssm_mem_handle_t));
    }

    return ret;
    
    #if 0
    //TODO: only matchbits
#if DEBUG
    fprintf(stderr, "na_ssm_msm_handle_serialize(size = %d, h = %p)\n", buf_size, mem_handle);
#endif
    na_ssm_mem_handle_t *ssmhandle = (na_ssm_mem_handle_t *)mem_handle;
    ssm_bits *pbits = buf;

    int ret = NA_SUCCESS;
    if (buf_size < sizeof(ssm_bits)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        *pbits = htonl(ssmhandle->matchbits);
        //*pbits = (ssmhandle->matchbits);
        //printf("\tbits = %p\n", *pbits);
    }
    return ret;
    #endif
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_deserialize
 *
 * Purpose:     Deserialize memory handle from buffer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_mem_handle_deserialize(na_mem_handle_t *mem_handle,
        const void *buf, na_size_t buf_size)
{
    int ret = NA_SUCCESS;
    na_ssm_mem_handle_t *ssmhandle;

    if (buf_size < sizeof(na_ssm_mem_handle_t))
    {
        printf("Error\n");
        ret = NA_FAIL;
    }
    else
    {
        ssmhandle = (na_ssm_mem_handle_t *)malloc(sizeof(na_ssm_mem_handle_t));
        memcpy(ssmhandle, buf, sizeof(na_ssm_mem_handle_t));
        *mem_handle = (na_mem_handle_t) ssmhandle;
    }

    return ret;
    
    #if 0
#if DEBUG
    fprintf(stderr, "na_ssm_mem_handle_deserialize\n");
    fprintf(stderr, "\trecvd = %lu\n", *(uint64_t *)buf);
#endif
    int ret = NA_SUCCESS;
    na_ssm_mem_handle_t *ssm_mem_handle;
    ssm_bits *pbits = (ssm_bits *)buf;
    

    if (buf_size < sizeof(na_ssm_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
    } else {
        ssm_mem_handle = malloc(sizeof(na_ssm_mem_handle_t));
        /* Here safe to do a simple memcpy */
        ssm_mem_handle->matchbits = ntohl(*pbits);
#if DEBUG
        fprintf(stderr, "\tdeserialized matchbits = %p ( %lu )\n", ssm_mem_handle->matchbits, ssm_mem_handle->matchbits);
#endif
        *mem_handle = (na_mem_handle_t) ssm_mem_handle;
    }
    return ret;
    #endif
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_mem_handle_free
 *
 * Purpose:     Free memory handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_mem_handle_free(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    na_ssm_mem_handle_t *ssm_mem_handle = (na_ssm_mem_handle_t*) mem_handle;

    if (ssm_mem_handle) {
        free(ssm_mem_handle);
        ssm_mem_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_put
 *
 * Purpose:     Put data to remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    na_ssm_mem_handle_t *lh = (na_ssm_mem_handle_t *)local_mem_handle;
    na_ssm_mem_handle_t *rh = (na_ssm_mem_handle_t *)remote_mem_handle;
    /* mem layout */
    struct iovec *iov;
    iov = (struct iovec *)malloc(sizeof(struct iovec));
    char *pbuf = (char *)lh->buf;
    pbuf += local_offset;
    iov[0].iov_base = pbuf;
    iov[0].iov_len = length;
    int ssm_ret, ret = NA_SUCCESS;
    /* args */
    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) remote_addr;
    na_ssm_request_t *ssm_request = NULL;
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    ssm_request->type = SSM_PUT_OP;
    ssm_request->matchbits = lh->matchbits;
    
#if DEBUG
    printf("na_ssm_put()\n");
    printf("\tlocal_h->mr = %p, local_of = %ld, remote_h->mr = %p, remote_of = %ld, len = %ld, addr = %p\n", lh->mr, local_offset, rh->mr, remote_offset, length, ssm_peer_addr->addr);
#endif
    ssm_request->cb.pcb = put_cb;
    ssm_request->cb.cbdata = ssm_request;
    ssm_tx stx; 
    //stx = ssm_putv(ssm, ssm_peer_addr->addr , iov, 1, ssm_request->matchbits, &(ssm_request->cb), SSM_NOF);
    stx = ssm_put(ssm, ssm_peer_addr->addr, lh->mr, NULL, ssm_request->matchbits, &(ssm_request->cb), SSM_NOF);
#if DEBUG
    printf("\ttx = %p\n", stx);
#endif
    ssm_request->tx = stx;
    *request = (na_request_t*) ssm_request;
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_get
 *
 * Purpose:     Get data from remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int na_ssm_get(na_mem_handle_t    in_local_mem_handle,
               na_offset_t        in_local_offset,
               na_mem_handle_t    in_remote_mem_handle,
               na_offset_t        in_remote_offset,
               na_size_t          in_length,
               na_addr_t          in_remote_addr,
               na_request_t      *out_request)
{
    na_ssm_mem_handle_t *v_local_handle  = NULL;
    na_ssm_mem_handle_t *v_remote_handle = NULL;
    ssm_md               v_remote_md     = NULL;
    ssm_mr               v_local_mr      = NULL;
    na_ssm_addr_t       *v_ssm_peer_addr = NULL;
    na_ssm_request_t    *v_ssm_request   = NULL;
    ssm_tx               v_stx;

    v_local_handle  = (na_ssm_mem_handle_t *)in_local_mem_handle;
    v_remote_handle = (na_ssm_mem_handle_t *)in_remote_mem_handle;
    
    v_remote_md = ssm_md_add(NULL, in_remote_offset, in_length);

    if (v_remote_md == NULL)
    {
        return NA_FAIL;
    }

    v_local_mr = ssm_mr_create(NULL,
                               v_local_handle->buf + in_local_offset,
                               in_length);

    v_ssm_peer_addr = (na_ssm_addr_t *) in_remote_addr;
    
    v_ssm_request = (na_ssm_request_t *) malloc(sizeof(na_ssm_request_t));

    if (v_ssm_request == NULL)
    {
        ssm_md_release(v_remote_md);
        return NA_FAIL;
    }

    memset(v_ssm_request, 0, sizeof(na_ssm_request_t));
    v_ssm_request->type = SSM_GET_OP;
    v_ssm_request->matchbits = v_remote_handle->matchbits;
    v_ssm_request->cb.pcb = get_cb;
    v_ssm_request->cb.cbdata = v_ssm_request;

    v_stx = ssm_get(ssm,
                    v_ssm_peer_addr->addr,
                    v_remote_md,
                    v_local_mr,
                    v_ssm_request->matchbits,
                    &(v_ssm_request->cb),
                    SSM_NOF);

    if (v_stx <= 0)
    {
        free(v_ssm_request);
        ssm_md_release(v_remote_md);
        return NA_FAIL;
    }
    
    v_ssm_request->tx = v_stx;
    
    *out_request = (na_request_t*) v_ssm_request;
    
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_wait
 *
 * Purpose:     Wait for a request to complete or until timeout (ms) is reached
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_wait(na_request_t in_request,
                       unsigned int in_timeout,
                       na_status_t *out_status)
{
    int               v_na_status = NA_FAIL;
    na_ssm_request_t *v_request   = (na_ssm_request_t *) in_request;
    na_bool_t         v_completed = NA_FALSE;
    int               v_cond_ret  = 0;

    if (in_request == NULL)
    {
        goto out;
    }
    else
    {
        hg_thread_mutex_lock(&request_mutex);
        v_completed = v_request->completed;
        hg_thread_mutex_unlock(&request_mutex);

        if (!v_completed)
        {
            hg_thread_mutex_lock(&request_mutex);

            while (!v_completed)
            {
                v_cond_ret = hg_thread_cond_wait(&comp_req_cond,
                                                 &request_mutex);

                v_completed = v_request->completed;

                if (!v_completed)
                {
                    hg_thread_mutex_unlock(&request_mutex);
                }
            }

            hg_thread_mutex_unlock(&request_mutex);

            if (v_cond_ret < 0)
            {
                v_na_status = NA_FAIL;
                goto out;
            }
        }

        if (out_status && out_status != NA_STATUS_IGNORE)
        {
            if (v_completed)
              out_status->completed = NA_TRUE;
        }

        v_na_status = NA_SUCCESS;
    }

 out:
    return v_na_status;
}

/*---------------------------------------------------------------------------
 * Function:    na_ssm_progress
 *
 * Purpose:     Track completion of RMA operations and make progress
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_ssm_progress(unsigned int timeout, na_status_t *status)
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000*10;
#if DEBUG
    puts("Call ssm_wait()");
#endif
    int rt;
    sleep(0);
    do {
        rt = ssm_wait(ssm, &tv);
        sleep(0);
    } while ( rt > 0);
    if( rt < 0 ) {
        return NA_FAIL;
    } else {
        return NA_SUCCESS;
    }
}


/*---------------------------------------------------------------------------*/
static int
na_ssm_request_free(na_request_t request)
{
    na_ssm_request_t *ssm_request = (na_ssm_request_t*) request;
    int ret = NA_SUCCESS;

    /* Do not want to free the request if another thread is testing it */
    hg_thread_mutex_lock(&request_mutex);

    if (!ssm_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
    } else {
        free(ssm_request);
        ssm_request = NULL;
        /* TODO may need to do extra things here */
    }

    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}

