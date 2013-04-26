/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_bmi.h"
#include "mercury_hash_table.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

static int na_bmi_finalize(void);
static na_size_t na_bmi_get_unexpected_size(void);
static int na_bmi_addr_lookup(const char *name, na_addr_t *addr);
static int na_bmi_addr_free(na_addr_t addr);
static int na_bmi_send_unexpected(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
static int na_bmi_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);
static int na_bmi_mem_register(void *buf, na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle);
static int na_bmi_mem_deregister(na_mem_handle_t mem_handle);
static int na_bmi_mem_handle_serialize(void *buf, na_size_t buf_size, na_mem_handle_t mem_handle);
static int na_bmi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);
static int na_bmi_mem_handle_free(na_mem_handle_t mem_handle);
static int na_bmi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_bmi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
static int na_bmi_wait(na_request_t request, unsigned int timeout, na_status_t *status);

static na_class_t na_bmi_g = {
        na_bmi_finalize,               /* finalize */
        na_bmi_get_unexpected_size,    /* get_unexpected_size */
        na_bmi_addr_lookup,            /* addr_lookup */
        na_bmi_addr_free,              /* addr_free */
        na_bmi_send_unexpected,        /* send_unexpected */
        na_bmi_recv_unexpected,        /* recv_unexpected */
        na_bmi_send,                   /* send */
        na_bmi_recv,                   /* recv */
        na_bmi_mem_register,           /* mem_register */
        na_bmi_mem_deregister,         /* mem_deregister */
        na_bmi_mem_handle_serialize,   /* mem_handle_serialize */
        na_bmi_mem_handle_deserialize, /* mem_handle_deserialize */
        na_bmi_mem_handle_free,        /* mem_handle_free */
        na_bmi_put,                    /* put */
        na_bmi_get,                    /* get */
        na_bmi_wait,                   /* wait */
        NULL                           /* progress */
};

typedef struct bmi_request {
    bmi_op_id_t op_id;       /* BMI op ID */
    bool completed;          /* 1 if operation has completed */
    void *user_ptr;          /* Extra info passed to BMI to identify request */
    bmi_size_t actual_size;  /* Actual buffer size (must only be a pointer if we return it in the receive) */
    bmi_context_id context;  /* Context in which the request has been issued */
} bmi_request_t;

typedef struct bmi_mem_handle {
    void *base;                 /* Initial address of memory */
    bmi_size_t size;            /* Size of memory */
    unsigned long attr;         /* Flag of operation access */
} bmi_mem_handle_t;

typedef enum bmi_onesided_op {
    BMI_ONESIDED_PUT,       /* Request a put operation */
    BMI_ONESIDED_GET,       /* Request a get operation */
    BMI_ONESIDED_END        /* Request end of one-sided operations */
} bmi_onesided_op_t;

typedef struct bmi_onesided_info {
    void    *base;         /* Initial address of memory */
    bmi_size_t disp;       /* Offset from initial address */
    bmi_size_t count;      /* Number of entries */
    bmi_onesided_op_t op;  /* Operation requested */
} bmi_onesided_info_t;

static bool is_server = 0; /* Used in server mode */
static bmi_context_id    bmi_context;
static bmi_context_id    bmi_onesided_context;
static hg_thread_mutex_t request_mutex;
static hg_thread_mutex_t testcontext_mutex;
static hg_thread_mutex_t finalizing_mutex;
static bool              finalizing;
static hg_thread_cond_t  testcontext_cond;
static bool              is_testing_context;
/* Map mem addresses to mem handles */
static hg_hash_table_t  *mem_handle_map = NULL;
static inline int pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}
static inline unsigned int pointer_hash(void *location)
{
    return (unsigned int) (unsigned long) location;
}

#define NA_BMI_UNEXPECTED_SIZE 4096

/* Default tag used for one-sided over two-sided */
#define NA_BMI_ONESIDED_TAG    0x80

hg_thread_t       onesided_service;
hg_thread_mutex_t mem_map_mutex;

/*---------------------------------------------------------------------------
 * Function:    na_bmi_onesided_service
 *
 * Purpose:     Service to emulate one-sided over two-sided
 *
 *---------------------------------------------------------------------------
 */
int na_bmi_onesided_progress(na_addr_t remote_addr, unsigned int timeout)
{
    int ret = NA_SUCCESS, bmi_ret = 0;
    bmi_op_id_t onesided_op_id;
    bmi_onesided_info_t onesided_info;
    int onesided_outcount = 0;
    bmi_size_t onesided_actual_size = 0;
    bmi_error_code_t error_code = 0;

    BMI_addr_t *bmi_remote_addr = (BMI_addr_t*) remote_addr;
    bmi_mem_handle_t *bmi_mem_handle = NULL;
    static bool recv_posted = 0;

    if (!bmi_remote_addr) {
        NA_ERROR_DEFAULT("NULL address");
        ret = NA_FAIL;
        return ret;
    }

    /* Wait for an initial request from client */
    if (!recv_posted) {
        bmi_ret = BMI_post_recv(&onesided_op_id, *bmi_remote_addr,
                &onesided_info, sizeof(bmi_onesided_info_t),
                &onesided_actual_size, BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG,
                NULL, bmi_onesided_context, NULL);
        if (bmi_ret < 0) {
            NA_ERROR_DEFAULT("BMI_post_recv() failed");
            ret = NA_FAIL;
            return ret;
        }
        recv_posted = 1;
    }

    if (!bmi_ret) {
        bmi_ret = BMI_testcontext(1, &onesided_op_id, &onesided_outcount,
                &error_code, &onesided_actual_size, NULL, timeout,
                bmi_onesided_context);

        if (!onesided_outcount) {
            ret = NA_SUCCESS;
            return ret;
        }

        if (bmi_ret < 0 || error_code != 0) {
            NA_ERROR_DEFAULT("Request recv failure (bad state)");
            NA_ERROR_DEFAULT("BMI_testunexpected failed");
            ret = NA_FAIL;
            return ret;
        }

    }
    recv_posted = 0;

    if (onesided_actual_size != sizeof(onesided_info)) {
        NA_ERROR_DEFAULT("recv_buf_size does not match onesided_info");
        ret = NA_FAIL;
        return ret;
    }

//    fprintf(stderr, "onesided_info: base:%lu count: %lu disp: %lu op: %d\n",
//            onesided_info.base, onesided_info.count, onesided_info.disp,
//            onesided_info.op);

    /* Here better to keep the mutex locked the time we operate on
     * bmi_mem_handle since it's a pointer to a mem_handle */
    hg_thread_mutex_lock(&mem_map_mutex);

    bmi_mem_handle = hg_hash_table_lookup(mem_handle_map, onesided_info.base);

    if (!bmi_mem_handle) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        hg_thread_mutex_unlock(&mem_map_mutex);
        ret = NA_FAIL;
        return ret;
    }

    switch (onesided_info.op) {
        onesided_op_id = 0;
        error_code = 0;
        onesided_outcount = 0;
        onesided_actual_size = 0;

        /* Remote wants to do a put so wait in a recv */
        case BMI_ONESIDED_PUT:
            bmi_ret = BMI_post_recv(&onesided_op_id, *bmi_remote_addr,
                    bmi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, &onesided_actual_size,
                    BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG, NULL,
                    bmi_onesided_context, NULL);
            if (bmi_ret < 0) {
                NA_ERROR_DEFAULT("BMI_post_recv() failed");
                break;
            }

            if (!bmi_ret) {
                do {
                    bmi_ret = BMI_testcontext(1, &onesided_op_id,
                            &onesided_outcount, &error_code,
                            &onesided_actual_size, NULL, NA_MAX_IDLE_TIME,
                            bmi_onesided_context);
                } while (bmi_ret == 0 && onesided_outcount == 0);

                if (bmi_ret < 0 || error_code != 0) {
                    NA_ERROR_DEFAULT("Data receive failed");
                }
            }
            /* Send an ack to ensure that the data has been received */
//                MPI_Send(&ack, 1, MPI_UNSIGNED_CHAR, mpi_status.MPI_SOURCE, NA_BMI_ONESIDED_ACK_TAG,
//                        mpi_onesided_comm);
            break;

        /* Remote wants to do a get so do a send */
        case BMI_ONESIDED_GET:
//            fprintf(stderr, "doing a send of: %lu with count: %lu disp: %lu op: %d\n",
//                    bmi_mem_handle->base + onesided_info.disp, onesided_info.count,
//                    onesided_info.op);
            bmi_ret = BMI_post_send(&onesided_op_id, *bmi_remote_addr,
                    bmi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG,
                    NULL, bmi_onesided_context, NULL);
            if (bmi_ret < 0) {
                NA_ERROR_DEFAULT("BMI_post_send() failed");
                ret = NA_FAIL;
                break;
            }

            if (!bmi_ret) {
                do {
                    error_code = 0;
                    bmi_ret = BMI_testcontext(1, &onesided_op_id,
                            &onesided_outcount, &error_code,
                            &onesided_actual_size, NULL, NA_MAX_IDLE_TIME,
                            bmi_onesided_context);
                } while (bmi_ret == 0 && onesided_outcount == 0);

                if (bmi_ret < 0 || error_code != 0) {
                    NA_ERROR_DEFAULT("Data send failed");
                    ret = NA_FAIL;
                    break;
                }
            }
            break;

        default:
            NA_ERROR_DEFAULT("Operation not supported");
            break;
    }

    hg_thread_mutex_unlock(&mem_map_mutex);

    return ret;
}

static void* na_bmi_onesided_service(void *args)
{
    bool service_done = 0;
    na_addr_t remote_addr = (na_addr_t) args;

    while (!service_done) {
        hg_thread_mutex_lock(&finalizing_mutex);
        service_done = (finalizing) ? 1 : 0;
        hg_thread_mutex_unlock(&finalizing_mutex);

        na_bmi_onesided_progress(remote_addr, 1);

        if (service_done) break;
    }

    return NULL;
}

/*---------------------------------------------------------------------------
 * Function:    NA_BMI_Init
 *
 * Purpose:     Initialize the network abstraction layer
 *
 *---------------------------------------------------------------------------
 */
na_class_t *NA_BMI_Init(const char *method_list, const char *listen_addr, int flags)
{
    int bmi_ret;

    /* Initialize BMI */
    bmi_ret = BMI_initialize(method_list, listen_addr, flags);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_initialize() failed");
    }

    is_server = (flags == BMI_INIT_SERVER) ? 1 : 0;

    /* Create a new BMI context */
    bmi_ret = BMI_open_context(&bmi_context);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_open_context() failed");
    }

    /* Create a separate context for onesided_comm */
    bmi_ret = BMI_open_context(&bmi_onesided_context);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_open_context() failed");
    }

    /* Create hash table for memory registration */
    mem_handle_map = hg_hash_table_new(pointer_hash, pointer_equal);
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);

    /* Initialize cond variable */
    hg_thread_mutex_init(&request_mutex);
    hg_thread_mutex_init(&testcontext_mutex);
    hg_thread_cond_init(&testcontext_cond);
    is_testing_context = 0;
    hg_thread_mutex_init(&mem_map_mutex);
    hg_thread_mutex_init(&finalizing_mutex);

    return &na_bmi_g;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_finalize
 *
 * Purpose:     Finalize the network abstraction layer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_finalize(void)
{
    int bmi_ret, ret = NA_SUCCESS;

    if (!is_server) {
        hg_thread_mutex_lock(&finalizing_mutex);
        finalizing = 1;
        hg_thread_mutex_unlock(&finalizing_mutex);
        /* Wait for one-sided thread to complete */
        hg_thread_join(onesided_service);
    }

    /* Close BMI context */
    BMI_close_context(bmi_onesided_context);

    /* Free hash table for memory registration */
    hg_hash_table_free(mem_handle_map);

    /* Close BMI context */
    BMI_close_context(bmi_context);

    /* Finalize BMI */
    bmi_ret = BMI_finalize();

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_finalize() failed");
        ret = NA_FAIL;
    }

    hg_thread_mutex_destroy(&request_mutex);
    hg_thread_mutex_destroy(&testcontext_mutex);
    hg_thread_cond_destroy(&testcontext_cond);
    hg_thread_mutex_destroy(&mem_map_mutex);
    hg_thread_mutex_destroy(&finalizing_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_get_unexpected_size
 *
 * Purpose:     Get the maximum size of an unexpected message
 *
 *---------------------------------------------------------------------------
 */
static na_size_t na_bmi_get_unexpected_size()
{
    na_size_t max_unexpected_size = NA_BMI_UNEXPECTED_SIZE;
    return max_unexpected_size;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_addr_lookup
 *
 * Purpose:     addr_lookup a addr from a peer address/name
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_addr_lookup(const char *name, na_addr_t *addr)
{
    int bmi_ret, ret = NA_SUCCESS;
    BMI_addr_t *bmi_addr = NULL;

    /* Perform an address addr_lookup on the ION */
    bmi_addr = malloc(sizeof(BMI_addr_t));
    bmi_ret = BMI_addr_lookup(bmi_addr, name);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_addr_lookup() failed");
        free(bmi_addr);
        bmi_addr = NULL;
        ret = NA_FAIL;
    } else {
        if (!is_server) {
            /* TODO temporary to handle one-sided exchanges with remote server */
            hg_thread_create(&onesided_service, &na_bmi_onesided_service, (void*)bmi_addr);
        }
        if (addr) *addr = (na_addr_t) bmi_addr;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_addr_free
 *
 * Purpose:     Free the addr from the list of peers
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_addr_free(na_addr_t addr)
{
    BMI_addr_t *bmi_addr = (BMI_addr_t*) addr;
    int ret = NA_SUCCESS;

    /* Cleanup peer_addr */
    if (bmi_addr) {
        free(bmi_addr);
        bmi_addr = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_send_unexpected
 *
 * Purpose:     Send a message to dest (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_send_unexpected(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = op_arg;
    bmi_request->context = bmi_context;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_request->context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_sendunexpected() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
    } else {
        hg_thread_mutex_lock(&request_mutex);
        /* Mark request as done if immediate bmi completion detected */
        bmi_request->completed = bmi_ret ? 1 : 0;
        *request = (na_request_t) bmi_request;
        hg_thread_mutex_unlock(&request_mutex);
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_recv_unexpected
 *
 * Purpose:     Receive a message from source (unexpected asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_recv_unexpected(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg)
{
    int ret = NA_SUCCESS;
    int bmi_ret, outcount = 0;
    struct BMI_unexpected_info request_info;
    bmi_request_t *bmi_request = NULL;

    if (!buf) {
        NA_ERROR_DEFAULT("NULL buffer");
        ret = NA_FAIL;
        return ret;
    }

    bmi_ret = BMI_testunexpected(1, &outcount, &request_info, 0);

    if (!outcount) return ret;

    if (bmi_ret < 0 || request_info.error_code != 0) {
        NA_ERROR_DEFAULT("Request recv failure (bad state)");
        NA_ERROR_DEFAULT("BMI_testunexpected failed");
        ret = NA_FAIL;
        return ret;
    }

    if (request_info.size > (bmi_size_t) buf_size) {
        NA_ERROR_DEFAULT("Buffer too small to recv unexpected data");
        ret = NA_FAIL;
        return ret;
    }

    if (actual_buf_size) *actual_buf_size = (na_size_t) request_info.size;
    if (source) {
        BMI_addr_t **peer_addr = (BMI_addr_t**) source;
        *peer_addr = malloc(sizeof(BMI_addr_t));
        **peer_addr = request_info.addr;
    }
    if (tag) *tag = (na_tag_t) request_info.tag;

    /* Copy buffer and free request_info */
    memcpy(buf, request_info.buffer, request_info.size);

    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->op_id = 0;
    bmi_request->completed = 1;
    bmi_request->actual_size = request_info.size;
    bmi_request->user_ptr = op_arg;
    bmi_request->context = bmi_context;

    BMI_unexpected_free(request_info.addr, request_info.buffer);

    *request = (na_request_t) bmi_request;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_send
 *
 * Purpose:     Send a message to dest (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_send(const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int ret = NA_SUCCESS, bmi_ret;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) dest;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = op_arg;
    bmi_request->context = bmi_context;

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_request->context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_send() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    hg_thread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = bmi_ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_recv
 *
 * Purpose:     Receive a message from source (asynchronous)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_recv(void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    BMI_addr_t *bmi_peer_addr = (BMI_addr_t*) source;
    bmi_msg_tag_t bmi_tag = (bmi_msg_tag_t) tag;
    bmi_request_t *bmi_request = NULL;

    /* Allocate request */
    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0; /* (bmi_size_t*) actual_size; */
    bmi_request->user_ptr = op_arg;
    bmi_request->context = bmi_context;

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            &bmi_request->actual_size, BMI_EXT_ALLOC, bmi_tag, bmi_request,
            bmi_request->context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_recv() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    hg_thread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = bmi_ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_mem_register
 *
 * Purpose:     Register memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_mem_register(void *buf, na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    int ret = NA_SUCCESS;
    void *bmi_buf_base = buf;
    bmi_size_t bmi_buf_size = (bmi_size_t) buf_size;
    bmi_mem_handle_t *bmi_mem_handle;

    bmi_mem_handle = malloc(sizeof(bmi_mem_handle_t));
    bmi_mem_handle->base = bmi_buf_base;
    bmi_mem_handle->size = bmi_buf_size;
    bmi_mem_handle->attr = flags;

    *mem_handle = (na_mem_handle_t) bmi_mem_handle;

    hg_thread_mutex_lock(&mem_map_mutex);

    /* store this handle */
    if (!hg_hash_table_insert(mem_handle_map, bmi_mem_handle->base,
            bmi_mem_handle)) {
        NA_ERROR_DEFAULT("Could not register memory handle");
        ret = NA_FAIL;
    }

    hg_thread_mutex_unlock(&mem_map_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_mem_deregister
 *
 * Purpose:     Deregister memory for RMA operations
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_mem_deregister(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_mem_handle = (bmi_mem_handle_t*) mem_handle;

    hg_thread_mutex_lock(&mem_map_mutex);

    /* remove the handle */
    if (!hg_hash_table_remove(mem_handle_map, bmi_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not deregister memory handle");
        ret = NA_FAIL;
    }

    hg_thread_mutex_unlock(&mem_map_mutex);

    if (bmi_mem_handle) {
        free(bmi_mem_handle);
        bmi_mem_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_mem_handle_serialize
 *
 * Purpose:     Serialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_mem_handle_serialize(void *buf, na_size_t buf_size, na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_mem_handle = (bmi_mem_handle_t*) mem_handle;

    if (buf_size < sizeof(bmi_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bmi_mem_handle, sizeof(bmi_mem_handle_t));
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_mem_handle_deserialize
 *
 * Purpose:     Deserialize memory handle for exchange over the network
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_mem_handle;

    if (buf_size < sizeof(bmi_mem_handle_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
    } else {
        bmi_mem_handle = malloc(sizeof(bmi_mem_handle_t));
        /* Here safe to do a simple memcpy */
        memcpy(bmi_mem_handle, buf, sizeof(bmi_mem_handle_t));
        *mem_handle = (na_mem_handle_t) bmi_mem_handle;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_mem_handle_free
 *
 * Purpose:     Free memory handle created by deserialize
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_mem_handle_free(na_mem_handle_t mem_handle)
{
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_mem_handle = (bmi_mem_handle_t*) mem_handle;

    if (bmi_mem_handle) {
        free(bmi_mem_handle);
        bmi_mem_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_put
 *
 * Purpose:     Put data to remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_local_mem_handle = (bmi_mem_handle_t*) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    bmi_mem_handle_t *bmi_remote_mem_handle = (bmi_mem_handle_t*) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    bmi_size_t bmi_length = (bmi_size_t) length;
    BMI_addr_t *bmi_remote_addr = (BMI_addr_t*) remote_addr;
    bmi_request_t *bmi_request;
    bmi_op_id_t op_id;

    /* TODO check that local memory is registered */
    // ht_lookup(mem_map, mpi_local_mem_handle->base);

    if (bmi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_ERROR_DEFAULT("Registered memory requires write permission");
        ret = NA_FAIL;
        return ret;
    }

    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = NULL;
    bmi_request->context = bmi_onesided_context;

    /* Send to one-sided thread key to access mem_handle */
    bmi_onesided_info_t onesided_info;
    onesided_info.base = bmi_remote_mem_handle->base;
    onesided_info.disp = bmi_remote_offset;
    onesided_info.count = bmi_length;
    onesided_info.op = BMI_ONESIDED_PUT;

    bmi_ret = BMI_post_send(&op_id, *bmi_remote_addr,
            &onesided_info, sizeof(bmi_onesided_info_t),
            BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG, NULL, bmi_onesided_context, NULL);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_sendunexpected() failed");
        ret = NA_FAIL;
        return ret;
    }

    if (!bmi_ret) {
        int outcount = 0;
        bmi_error_code_t error_code = 0;
        bmi_size_t actual_size = 0;

        do {
            bmi_ret = BMI_testcontext(1, &op_id, &outcount,
                    &error_code, &actual_size, NULL, NA_MAX_IDLE_TIME,
                    bmi_onesided_context);
        } while (bmi_ret == 0 && outcount == 0);

        if (bmi_ret < 0 || error_code != 0) {
            NA_ERROR_DEFAULT("Data send failed");
        }
    }

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&bmi_request->op_id, *bmi_remote_addr,
            bmi_local_mem_handle->base + bmi_local_offset, bmi_length,
            BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG, bmi_request, bmi_request->context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_send() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    hg_thread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = bmi_ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    hg_thread_mutex_unlock(&request_mutex);

    /* Pre-post an ack request */
//    mpi_ret = MPI_Irecv(&mpi_request->ack, 1, MPI_UNSIGNED_CHAR, mpi_remote_addr->rank,
//            NA_MPI_ONESIDED_ACK_TAG, mpi_remote_addr->onesided_comm, &mpi_request->ack_request);
//    if (mpi_ret != MPI_SUCCESS) {
//        NA_ERROR_DEFAULT("MPI_Irecv() failed");
//        free(mpi_request);
//        mpi_request = NULL;
//        ret = NA_FAIL;
//    } else {
//        *request = (na_request_t) mpi_request;
//    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_get
 *
 * Purpose:     Get data from remote target
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request)
{
    int bmi_ret, ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_local_mem_handle = (bmi_mem_handle_t*) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    bmi_mem_handle_t *bmi_remote_mem_handle = (bmi_mem_handle_t*) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    bmi_size_t bmi_length = (bmi_size_t) length;
    BMI_addr_t *bmi_remote_addr = (BMI_addr_t*) remote_addr;
    bmi_request_t *bmi_request;
    bmi_op_id_t op_id;

    /* TODO check that local memory is registered */
    // ht_lookup(mem_map, mpi_local_mem_handle->base);

    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->completed = 0;
    bmi_request->actual_size = 0;
    bmi_request->user_ptr = NULL;
    bmi_request->context = bmi_onesided_context;

    /* Send to one-sided thread key to access mem_handle */
    bmi_onesided_info_t onesided_info;
    onesided_info.base = bmi_remote_mem_handle->base;
    onesided_info.disp = bmi_remote_offset;
    onesided_info.count = bmi_length;
    onesided_info.op = BMI_ONESIDED_GET;

    fprintf(stderr, "onesided_info: base:%lu count: %lu disp: %lu op: %d\n",
                    (bmi_size_t)onesided_info.base, onesided_info.count, onesided_info.disp,
                    onesided_info.op);

    bmi_ret = BMI_post_send(&op_id, *bmi_remote_addr,
            &onesided_info, sizeof(bmi_onesided_info_t),
            BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG, NULL, bmi_onesided_context, NULL);
    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_sendunexpected() failed");
        ret = NA_FAIL;
        return ret;
    }

    if (!bmi_ret) {
        int outcount = 0;
        bmi_error_code_t error_code = 0;
        bmi_size_t actual_size = 0;

        do {
            bmi_ret = BMI_testcontext(1, &op_id, &outcount,
                    &error_code, &actual_size, NULL, NA_MAX_IDLE_TIME,
                    bmi_onesided_context);
        } while (bmi_ret == 0 && outcount == 0);

        if (bmi_ret < 0 || error_code != 0) {
            NA_ERROR_DEFAULT("Data send failed");
        }
    }

    /* Simply do an asynchronous recv */
    bmi_ret = BMI_post_recv(&bmi_request->op_id, *bmi_remote_addr,
            bmi_local_mem_handle->base + bmi_local_offset, bmi_length, &bmi_request->actual_size,
            BMI_EXT_ALLOC, NA_BMI_ONESIDED_TAG, bmi_request, bmi_request->context, NULL);

    if (bmi_ret < 0) {
        NA_ERROR_DEFAULT("BMI_post_recv() failed");
        free(bmi_request);
        bmi_request = NULL;
        ret = NA_FAIL;
        return ret;
    }

    hg_thread_mutex_lock(&request_mutex);
    /* Mark request as done if immediate BMI completion detected */
    bmi_request->completed = bmi_ret ? 1 : 0;
    *request = (na_request_t) bmi_request;
    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_wait
 *
 * Purpose:     Wait for a request to complete or until timeout (ms) is reached
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_wait(na_request_t request, unsigned int timeout,
        na_status_t *status)
{
    bmi_request_t *bmi_wait_request = (bmi_request_t*) request;
    unsigned int remaining = timeout;
    int ret = NA_SUCCESS;
    bool wait_request_completed = 0;

    /* Only the thread that has created the request should wait and free that request
     * even if the request may have been marked as completed by other threads */
    if (!bmi_wait_request) {
        NA_ERROR_DEFAULT("NULL request");
        ret = NA_FAIL;
        return ret;
    }

    /* TODO ensure that request is well protected */
    hg_thread_mutex_lock(&request_mutex);
    wait_request_completed = bmi_wait_request->completed;
    hg_thread_mutex_unlock(&request_mutex);

    if (!wait_request_completed)
    do {
        int hg_thread_cond_ret = 0;
        struct timeval t1_wait, t2_wait;

        gettimeofday(&t1_wait, NULL);

        hg_thread_mutex_lock(&testcontext_mutex);

        while (is_testing_context) {
            hg_thread_cond_ret = hg_thread_cond_timedwait(&testcontext_cond, &testcontext_mutex, remaining);
        }
        is_testing_context = 1;

        hg_thread_mutex_unlock(&testcontext_mutex);

        if (hg_thread_cond_ret < 0) {
            ret = NA_FAIL;
            break;
        }

        gettimeofday(&t2_wait, NULL);

        remaining -= (t2_wait.tv_sec - t1_wait.tv_sec) * 1000 +
                (t2_wait.tv_usec - t1_wait.tv_usec) / 1000;

        /* Only one calling thread at a time should reach that point */
        hg_thread_mutex_lock(&testcontext_mutex);

        /* Test again here as request may have completed while waiting */
        hg_thread_mutex_lock(&request_mutex);
        wait_request_completed = bmi_wait_request->completed;
        hg_thread_mutex_unlock(&request_mutex);

        if (!wait_request_completed) {
            int bmi_ret = 0, outcount = 0;
            bmi_error_code_t error_code = 0;
            bmi_op_id_t bmi_op_id = 0;
            bmi_size_t  bmi_actual_size = 0;
            void *bmi_user_ptr = NULL;
            struct timeval t1, t2;

            gettimeofday(&t1, NULL);

            bmi_ret = BMI_testcontext(1, &bmi_op_id, &outcount, &error_code,
                    &bmi_actual_size, &bmi_user_ptr, remaining, bmi_wait_request->context);

            gettimeofday(&t2, NULL);
            remaining -= (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000;

            if (bmi_ret < 0 || error_code != 0) {
                NA_ERROR_DEFAULT("BMI_testcontext failed");
                ret = NA_FAIL;
                return ret;
            }

            if (bmi_user_ptr) {
                bmi_request_t *bmi_request;

                hg_thread_mutex_lock(&request_mutex);
                bmi_request = (bmi_request_t *) bmi_user_ptr;
                assert(bmi_op_id == bmi_request->op_id);
                /* Mark the request as completed */
                bmi_request->completed = 1;
                /* Our request may have been marked as completed as well */
                wait_request_completed = bmi_wait_request->completed;
                /* Only set the actual size if it's a receive request */
                bmi_request->actual_size = bmi_actual_size;
                hg_thread_mutex_unlock(&request_mutex);
            }
        }

        /* Wake up others */
        is_testing_context = 0;
        hg_thread_cond_signal(&testcontext_cond);

        hg_thread_mutex_unlock(&testcontext_mutex);
    } while (!wait_request_completed && remaining > 0);

    hg_thread_mutex_lock(&request_mutex);

    if (status && status != NA_STATUS_IGNORE) {
        status->completed = bmi_wait_request->completed;

        /* Fill status and free request if completed */
        if (bmi_wait_request->completed) {
            status->count = bmi_wait_request->actual_size;
            free(bmi_wait_request);
            bmi_wait_request = NULL;
        }
    }

    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}
