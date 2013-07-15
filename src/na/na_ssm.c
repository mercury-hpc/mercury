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

#include <ssm/dumb.h>
#include <ssm.h>
#include <ssmptcp.h>

#define DEBUG 1
static int na_ssm_finalize(void);
static int na_ssm_addr_lookup(const char *name, na_addr_t *addr);
static int na_ssm_addr_free(na_addr_t addr);
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

static na_class_t na_ssm_g = {
        na_ssm_finalize,               /* finalize */
        na_ssm_addr_lookup,            /* addr_lookup */
        na_ssm_addr_free,              /* addr_free */
        na_ssm_msg_get_maximum_size,   /* msg_get_maximum_size */
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
    ssm_mr mr;
    ssm_bits matchbits; //XXX delete
} na_ssm_mem_handle_t;


//typedef enum na_ssm_onesided_op {
//    SSM_ONESIDED_PUT,       /* Request a put operation */
//    SSM_ONESIDED_GET        /* Request a get operation */
//} na_ssm_onesided_op_t;

typedef int ssm_size_t;
typedef int ssm_tag_t;
typedef unsigned long ssm_msg_tag_t;

//typedef struct na_ssm_onesided_info {
//    void    *base;         /* Initial address of memory */
//    ssm_size_t disp;       /* Offset from initial address */
//    ssm_size_t count;      /* Number of entries */
//    ssm_onesided_op_t op;  /* Operation requested */
//} na_ssm_onesided_info_t;

/* Used to differentiate Send requests from Recv requests */
typedef enum ssm_req_type {
    SSM_PUT_OP,
    SSM_GET_OP,
    SSM_SEND_OP,
    SSM_RECV_OP
} ssm_req_type_t;

typedef struct na_ssm_request {
    ssm_req_type_t type;
    ssm_bits matchbits;
    void *user_ptr;
    ssm_tx tx;
    ssm_cb_t cb;
    bool completed;
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
#define NA_SSM_UNEXPECTED_SIZE 4096
#define NA_SSM_EXPECTED_SIZE 4096

#define NA_SSM_UNEXPECTED_BUFFERCOUNT 8
char **buf_unexpected;

//#define NA_SSM_ONESIDED_TAG        0x80 /* Default tag used for one-sided over two-sided */
//#define NA_SSM_ONESIDED_DATA_TAG   0x81


#define NA_SSM_TAG_UNEXPECTED_OFFSET 0
#define NA_SSM_TAG_EXPECTED_OFFSET (1<<62)
#define NA_SSM_TAG_RMA_OFFSET (1<<63)

#ifdef NA_HAS_CLIENT_THREAD
static hg_thread_mutex_t finalizing_mutex;
static bool              finalizing;
static hg_thread_t       progress_service;
#endif

/* List for requests */
static hg_thread_mutex_t unexpected_list_mutex;
static hg_thread_cond_t comp_req_cond;

/*---------------------------------------------------------------------------*/

/* Mutex used for tag generation */
/* TODO use atomic increment instead */
static hg_thread_mutex_t tag_mutex;

static hg_thread_mutex_t request_mutex;
static hg_thread_mutex_t testcontext_mutex;
static hg_thread_cond_t  testcontext_cond;
static bool              is_testing_context;

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


static inline int mark_as_completed(na_ssm_request_t *req)
{
    hg_thread_mutex_lock(&request_mutex);
    req->completed = 1;
    hg_thread_mutex_unlock(&request_mutex);
    return 1;
}

void msg_send_cb(void *cbdat, void *evdat) 
{
#if DEBUG
    puts("msg_send_cb()");
#endif
    ssm_result r = evdat;
    (void)cbdat;
#if DEBUG
    printf("        cbdat = %p\n", cbdat);
    printf("ssm_id     id     = %p\n", r->id);
    printf("ssm_me     me     = %p\n", r->me);
    printf("ssm_tx     tx     = %p\n", r->tx);
    printf("ssm_bits   bits   = %lu\n", r->bits);
    printf("ssm_status status = %u\n", r->status);
    printf("         (%s)\n", ssm_status_str(r->status));
    printf("ssm_op     op     = %u\n", r->op);
    printf("         (%s)\n", ssm_op_str(r->op));
    printf("ssm_Haddr  addr   = %p\n", r->addr);
    printf("ssm_mr     mr     = %p\n", r->mr);
    printf("ssm_md     md     = %p\n", r->md);
    printf("uint64_t   bytes  = %lu\n", r->bytes);
#endif
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    ssm_mr_destroy(r->mr); //XXX Error Handling
    if(cbdat!=NULL){
        free(cbdat);
    }
}

void msg_recv_cb(void *cbdat, void *evdat) {
#if DEBUG
    puts("msg_recv_cb()");
#endif
    ssm_result r = evdat;
    (void)cbdat;
    mark_as_completed(cbdat);
    //wake up others
    hg_thread_cond_signal(&comp_req_cond);
    ssm_mr_destroy(r->mr); //XXX Error Handling
    if(cbdat!=NULL){
        free(cbdat);
    }
    if(!DEBUG)      return;
    (void)cbdat;
    printf("        cbdat = %p\n", cbdat);
    printf("ssm_id     id     = %p\n", r->id);
    printf("ssm_me     me     = %p\n", r->me);
    printf("ssm_tx     tx     = %p\n", r->tx);
    printf("ssm_bits   bits   = %lu\n", r->bits);
    printf("ssm_status status = %u\n", r->status);
    printf("         (%s)\n", ssm_status_str(r->status));
    printf("ssm_op     op     = %u\n", r->op);
    printf("         (%s)\n", ssm_op_str(r->op));
    printf("ssm_Haddr  addr   = %p\n", r->addr);
    printf("ssm_mr     mr     = %p\n", r->mr);
    printf("ssm_md     md     = %p\n", r->md);
    printf("uint64_t   bytes  = %lu\n", r->bytes);
}

void unexp_msg_recv_cb(void *cbdat, void *evdat) {
    printf(".");
    fflush(stdout);
    if(!DEBUG)      return;
    puts("----------");
    ssm_result r = evdat;
    (void)cbdat;
    printf("        cbdat = %p\n", cbdat);
    printf("ssm_id     id     = %p\n", r->id);
    printf("ssm_me     me     = %p\n", r->me);
    printf("ssm_tx     tx     = %p\n", r->tx);
    printf("ssm_bits   bits   = %lu\n", r->bits);
    printf("ssm_status status = %u\n", r->status);
    printf("         (%s)\n", ssm_status_str(r->status));
    printf("ssm_op     op     = %u\n", r->op);
    printf("         (%s)\n", ssm_op_str(r->op));
    printf("ssm_Haddr  addr   = %p\n", r->addr);
    printf("ssm_mr     mr     = %p\n", r->mr);
    printf("ssm_md     md     = %p\n", r->md);
    printf("uint64_t   bytes  = %lu\n", r->bytes);
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
}
#endif

/*---------------------------------------------------------------------------
 * Function:    NA_SSM_Init
 *
 * Purpose:     Initialize the network abstraction layer
 *
 *---------------------------------------------------------------------------
 */
na_class_t *NA_SSM_Init(char *proto, int port, int flags)
{
#if DEBUG
    puts("NA_SSM_Init()");
#endif
    if (flags == 0 ){
        flags = SSM_NOF;
    }
#if DEBUG
    printf("Port = %d\n", port);
#endif
    ssmport = port;
    strncpy(c_proto, proto, sizeof(c_proto));
    if (strcmp(proto, "tcp") == 0) {
        itp = ssmptcp_new_tp(port, SSM_NOF);
        if(itp == NULL){
            printf("ssmptcp_new_tp() failed\n");
            return -1;
        }
        ssm = ssm_start(itp, NULL, flags);
        if(ssm == NULL){
            printf("ssm_start() failed\n");
            return -1;
        }
        iaddr = ssm_addr(ssm);
        /* TODO Error handling */
    } else {
        printf("Unknown protocol");
        exit(0);
    }

    /* POST buffers for unexpected recieve */
    
   


    //TODO add is_server (need?)
    //is_server = (flags == BMI_INIT_SERVER) ? 1 : 0;
//
//    /* Automatically free all the values with the hash map */
//    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);
//
    /* Initialize cond variable */
    hg_thread_mutex_init(&unexpected_list_mutex);
//    hg_thread_mutex_init(&request_mutex);
//    hg_thread_mutex_init(&testcontext_mutex);
//    hg_thread_cond_init(&testcontext_cond);
//    is_testing_context = 0;
    hg_thread_mutex_init(&request_mutex);
    hg_thread_cond_init(&comp_req_cond);
//#ifdef NA_HAS_CLIENT_THREAD
//    hg_thread_mutex_init(&finalizing_mutex);
//    if (!is_server) {
//        /* TODO temporary to handle one-sided exchanges with remote server */
//        hg_thread_create(&progress_service, &na_bmi_progress_service, NULL);
//    }
//#endif

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
static int na_ssm_addr_lookup(const char *name, na_addr_t *addr)
{
#if DEBUG
    printf("na_ssm_addr_lookup()\n");
    printf("\tname = %s, addr = %p \n", name, addr);
#endif
    na_ssm_destinfo_t dest;
    addr_parser(name, &dest);
    //
    if(strcmp(dest.proto, c_proto)){
        fprintf(stderr, "ERROR: protocol does not match\n");
        return NA_FAIL;
    }
    if(dest.port != ssmport){
        fprintf(stderr, "ERROR: port does not match\n");
        return NA_FAIL;
    }

    ssmptcp_addrargs_t addrargs = {
        .host = dest.hostname,
        .port = dest.port,
    };

    printf("\tlookup host = %s, port = %d\n", name, ssmport);
    na_ssm_addr_t *ssm_addr = (na_ssm_addr_t *)malloc(sizeof(na_ssm_addr_t));
    //ssm_addr->addrs = ssm_addr(ssm);
    //ssm_addr->addr = ssm_addr_create(ssm, adr);
    ssm_addr->addr = ssm_addr_create(ssm, &addrargs);
    printf("\taddr = %d\n", ssm_addr->addr);
    //ssm_addr->addr = iaddr->create(iaddr, &addrargs);

    if(ssm_addr->addr < 0){
        printf("ERROR: ssm_addr_create() failed\n");
        exit(0);
    }
    *addr = (na_addr_t)ssm_addr;
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
    //free(addr);
    na_ssm_addr_t *paddr = (na_ssm_addr_t *)addr;
    /* SSM addr destroy */
    ssm_addr_destroy(ssm, paddr->addr);
    free(paddr);
    return NA_SUCCESS;
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
    return NA_SSM_EXPECTED_SIZE;
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
    ssm_msg_tag_t t = (0xffffffffffffffff >> 2);
    return t;
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
    ssm_size_t ssm_buf_size = (ssm_size_t) buf_size;
    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) source;
    ssm_msg_tag_t ssm_tag = (ssm_msg_tag_t) tag;
    na_ssm_request_t *ssm_request = NULL;
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    
    ssm_request->type = SSM_RECV_OP;
    ssm_request->matchbits = tag;
    ssm_request->user_ptr = op_arg;

    /* Allocate request */
    /* Register Memory */
    ssm_mr mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    /* Prepare callback function */
    ssm_request->cb.pcb = msg_send_cb;
    ssm_request->cb.cbdata = ssm_request;
    /* Post the BMI recv request */
    ssm_me me = ssm_link(ssm, ssm_tag, 0x0 /* mask */, SSM_POS_HEAD, NULL, &(ssm_request->cb), SSM_NOF);
    ssm_ret = ssm_post(ssm, me, mr, SSM_NOF);

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
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    ssm_request->type = SSM_SEND_OP;
    ssm_request->matchbits = tag + NA_SSM_TAG_EXPECTED_OFFSET;
    ssm_request->user_ptr = op_arg;
    
//    ssm_request_t *bmi_request = NULL;
//
//    /* Allocate request */
//    bmi_request = malloc(sizeof(bmi_request_t));
//    bmi_request->completed = 0;
//    bmi_request->actual_size = 0;
//    bmi_request->user_ptr = op_arg;
//    bmi_request->ack_request = NA_REQUEST_NULL;

//    /* Post the BMI send request */
//    bmi_ret = BMI_post_send(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
//            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);
    
    //na_ssm_mem_handle_t *mem_handle = (na_ssm_mem_handle_t *)malloc(sizeof(na_ssm_mem_handle_t)); //XXX delete
    
#if DEBUG
    printf("na_ssm_msg_send()\n");
    printf("\tbuf = %p, buf_size = %d, dest = %d, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, ssm_peer_addr->addr, tag, request, op_arg);
#endif

    ssm_mr mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    ssm_request->cb.pcb = msg_send_cb;
    ssm_request->cb.cbdata = ssm_request;

    ssm_tx stx; 
    stx = ssm_put(ssm, ssm_peer_addr->addr , mr, NULL, ssm_tag, &(ssm_request->cb), SSM_NOF);
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


//    hg_thread_mutex_lock(&request_mutex);
//    /* Mark request as done if immediate BMI completion detected */
//    bmi_request->completed = bmi_ret ? 1 : 0;
//    *request = (na_request_t) bmi_request;
//    hg_thread_mutex_unlock(&request_mutex);

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
#if DEBUG
    printf("na_ssm_msg_recv()\n");
    printf("\tbuf = %p, buf_size = %d, tag = %d, request = %p, op_arg = %p\n", buf, buf_size, tag, request, op_arg);
#endif
    int ssm_ret, ret = NA_SUCCESS;
    ssm_size_t ssm_buf_size = (ssm_size_t) buf_size;
    na_ssm_addr_t *ssm_peer_addr = (na_ssm_addr_t*) source;
    ssm_msg_tag_t ssm_tag = (ssm_msg_tag_t) tag;
    na_ssm_request_t *ssm_request = NULL;
    ssm_request = (na_ssm_request_t *)malloc(sizeof(na_ssm_request_t));
    memset(ssm_request, 0, sizeof(na_ssm_request_t));
    
    ssm_request->type = SSM_RECV_OP;
    ssm_request->matchbits = tag;
    ssm_request->user_ptr = op_arg;

    /* Allocate request */
    /* Register Memory */
    ssm_mr mr = ssm_mr_create(NULL, (void *)buf, ssm_buf_size);
    /* Prepare callback function */
    ssm_request->cb.pcb = msg_send_cb;
    ssm_request->cb.cbdata = ssm_request;
    /* Post the BMI recv request */
    ssm_me me = ssm_link(ssm, ssm_tag, 0x0 /* mask */, SSM_POS_HEAD, NULL, &(ssm_request->cb), SSM_NOF);
    ssm_ret = ssm_post(ssm, me, mr, SSM_NOF);

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
int na_ssm_mem_register(void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle)
{
    na_ssm_mem_handle_t *pssm_mr;
    ssm_mr mr;
    pssm_mr = (na_ssm_mem_handle_t *)malloc(sizeof(na_ssm_mem_handle_t));
    mr = ssm_mr_create(NULL, buf, buf_size);
    pssm_mr->mr = mr;

    //TODO add this mr to hash table and error handle
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
#if DEBUG
    fprintf(stderr, "na_ssm_msm_handle_serialize()\n");
#endif
    int ret = NA_SUCCESS;
    na_ssm_mem_handle_t *ssm_mem_handle = (na_ssm_mem_handle_t*) mem_handle;

    if (buf_size < sizeof(na_ssm_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, ssm_mem_handle, sizeof(na_ssm_mem_handle_t));
    }
    return ret;
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
    na_ssm_mem_handle_t *ssm_mem_handle;

    if (buf_size < sizeof(na_ssm_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
    } else {
        ssm_mem_handle = malloc(sizeof(na_ssm_mem_handle_t));
        /* Here safe to do a simple memcpy */
        memcpy(ssm_mem_handle, buf, sizeof(na_ssm_mem_handle_t));
        *mem_handle = (na_mem_handle_t) ssm_mem_handle;
    }
    return ret;
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
int na_ssm_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
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
static int na_ssm_wait(na_request_t request, unsigned int timeout,
        na_status_t *status)
{
    hg_time_t t1, t2;
    hg_time_get_current(&t1);
    na_ssm_request_t *req;
    na_ssm_request_t *prequest = (na_ssm_request_t *)request;
    bool request_completed = 0;
#if DEBUG
    printf("ssm_wait()\n\trequest = %p, timeout = %d, status = %p\n", request, timeout, status);
#endif
    struct timeval tv;
    int rt, ret, ssmret;
    rt = 0;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000)*1000;
#if DEBUG
    printf("\ttimeout sec = %d, usec = %d\n", tv.tv_sec, tv.tv_usec);
#endif
    if(prequest == NULL){
        rt = ssm_wait(ssm, &tv);
    } else {
        hg_thread_mutex_lock(&request_mutex);
        request_completed = prequest->completed;
        hg_thread_mutex_unlock(&request_mutex);
        if(request_completed){
            rt = 1;
        } else {
            /* Need to wait the completion */
            /* TODO: need to change tv. should be less than timeout, and
             * repeat this.*/
            ssmret = ssm_wait(ssm, &tv);
            if(ssmret < 0 ){
                NA_ERROR_DEFAULT("ssm_wait() failed");
                rt = -1;
            }
            hg_thread_mutex_lock(&request_mutex);
            request_completed = prequest->completed;
            hg_thread_mutex_unlock(&request_mutex);
            if(request_completed){
                rt = 1;
            }
        }
    }
    if( rt < 0){
#if DEBUG
        fprintf(stderr, "\tssm_wait() failed\n");
#endif
        return NA_FAIL;
    }
    //XXX status->count ??
    if (status && status != NA_STATUS_IGNORE) {
#if DEBUG
        printf("\treturn status code\n");
        fflush(stdout);
#endif
        if (rt > 0){
            status->completed = 1;
            ret = 1;
        } else if (rt == 0){
            status->completed = 0;
            ret = 1;
        } else {
            status->completed = 0;
            ret = -1;
        }
    } else {
#if DEBUG
        printf("\tno return status code\n");
        fflush(stdout);
#endif
        ret = rt;
    }
    return ret;
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

