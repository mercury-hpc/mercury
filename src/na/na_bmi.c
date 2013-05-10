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
#include "mercury_list.h"
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
static int na_bmi_addr_lookup(const char *name, na_addr_t *addr);
static int na_bmi_addr_free(na_addr_t addr);
static na_size_t na_bmi_get_unexpected_size(void);
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
static na_size_t na_bmi_mem_handle_get_serialize_size(void);
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
static int na_bmi_progress(unsigned int timeout, na_status_t *status);

static na_class_t na_bmi_g = {
        na_bmi_finalize,               /* finalize */
        na_bmi_addr_lookup,            /* addr_lookup */
        na_bmi_addr_free,              /* addr_free */
        na_bmi_get_unexpected_size,    /* get_unexpected_size */
        na_bmi_send_unexpected,        /* send_unexpected */
        na_bmi_recv_unexpected,        /* recv_unexpected */
        na_bmi_send,                   /* send */
        na_bmi_recv,                   /* recv */
        na_bmi_mem_register,           /* mem_register */
        NULL,                          /* mem_register_segments */
        na_bmi_mem_deregister,         /* mem_deregister */
        na_bmi_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
        na_bmi_mem_handle_serialize,   /* mem_handle_serialize */
        na_bmi_mem_handle_deserialize, /* mem_handle_deserialize */
        na_bmi_mem_handle_free,        /* mem_handle_free */
        na_bmi_put,                    /* put */
        na_bmi_get,                    /* get */
        na_bmi_wait,                   /* wait */
        na_bmi_progress                /* progress */
};

typedef struct bmi_request bmi_request_t;

struct bmi_request {
    bmi_op_id_t op_id;        /* BMI op ID */
    bool completed;           /* 1 if operation has completed */
    void *user_ptr;           /* Extra info passed to BMI to identify request */
    bmi_size_t actual_size;   /* Actual buffer size (must only be a pointer if we return it in the receive) */
    bool ack;                 /* Additional ack for one-sided put request */
    na_request_t ack_request; /* Additional request for one-sided put request */
};

typedef struct bmi_mem_handle {
    void *base;                 /* Initial address of memory */
    bmi_size_t size;            /* Size of memory */
    unsigned long attr;         /* Flag of operation access */
} bmi_mem_handle_t;

typedef enum bmi_onesided_op {
    BMI_ONESIDED_PUT,       /* Request a put operation */
    BMI_ONESIDED_GET        /* Request a get operation */
} bmi_onesided_op_t;

typedef struct bmi_onesided_info {
    void    *base;         /* Initial address of memory */
    bmi_size_t disp;       /* Offset from initial address */
    bmi_size_t count;      /* Number of entries */
    bmi_onesided_op_t op;  /* Operation requested */
} bmi_onesided_info_t;

static bool is_server = 0; /* Used in server mode */
static bmi_context_id    bmi_context;
static hg_list_entry_t  *unexpected_list;
static hg_thread_mutex_t unexpected_list_mutex;

static hg_thread_mutex_t request_mutex;
static hg_thread_mutex_t testcontext_mutex;
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
#define NA_BMI_ONESIDED_TAG        0x80
#define NA_BMI_ONESIDED_DATA_TAG   0x81
#define NA_BMI_ONESIDED_ACK_TAG    0x82

#ifdef NA_HAS_CLIENT_THREAD
static hg_thread_mutex_t finalizing_mutex;
static bool              finalizing;
static hg_thread_t       progress_service;
#endif
static hg_thread_mutex_t mem_map_mutex;

/*---------------------------------------------------------------------------
 * Function:    na_bmi_progress_service
 *
 * Purpose:     One-sided service to emulate one-sided over two-sided
 *
 *---------------------------------------------------------------------------
 */
#ifdef NA_HAS_CLIENT_THREAD
static void* na_bmi_progress_service(void *args)
{
    bool service_done = 0;

    while (!service_done) {
        int na_ret;

        hg_thread_mutex_lock(&finalizing_mutex);
        service_done = (finalizing) ? 1 : 0;
        hg_thread_mutex_unlock(&finalizing_mutex);

        na_ret = na_bmi_progress(0, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            NA_ERROR_DEFAULT("Could not make progress");
            break;
        }

        if (service_done) break;
    }

    return NULL;
}
#endif

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

    /* Create hash table for memory registration */
    mem_handle_map = hg_hash_table_new(pointer_hash, pointer_equal);
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(mem_handle_map, NULL, NULL);

    /* Initialize cond variable */
    hg_thread_mutex_init(&unexpected_list_mutex);
    hg_thread_mutex_init(&request_mutex);
    hg_thread_mutex_init(&testcontext_mutex);
    hg_thread_cond_init(&testcontext_cond);
    is_testing_context = 0;
    hg_thread_mutex_init(&mem_map_mutex);
#ifdef NA_HAS_CLIENT_THREAD
    hg_thread_mutex_init(&finalizing_mutex);
    if (!is_server) {
        /* TODO temporary to handle one-sided exchanges with remote server */
        hg_thread_create(&progress_service, &na_bmi_progress_service, NULL);
    }
#endif

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

#ifdef NA_HAS_CLIENT_THREAD
    if (!is_server) {
        hg_thread_mutex_lock(&finalizing_mutex);
        finalizing = 1;
        hg_thread_mutex_unlock(&finalizing_mutex);
        /* Wait for one-sided thread to complete */
        hg_thread_join(progress_service);
    }
    hg_thread_mutex_destroy(&finalizing_mutex);
#endif

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

    hg_thread_mutex_destroy(&unexpected_list_mutex);
    hg_thread_mutex_destroy(&request_mutex);
    hg_thread_mutex_destroy(&testcontext_mutex);
    hg_thread_cond_destroy(&testcontext_cond);
    hg_thread_mutex_destroy(&mem_map_mutex);

    return ret;
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
    bmi_request->ack_request = NA_REQUEST_NULL;

    /* Post the BMI unexpected send request */
    bmi_ret = BMI_post_sendunexpected(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);

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
    int bmi_ret = 0, outcount = 0;
    struct BMI_unexpected_info *request_info;
    bmi_request_t *bmi_request = NULL;
    hg_list_entry_t *entry = NULL;

    if (!buf) {
        NA_ERROR_DEFAULT("NULL buffer");
        ret = NA_FAIL;
        return ret;
    }

    /* First check if unexpected messages are already arrived */
    hg_thread_mutex_lock(&unexpected_list_mutex);

    if (hg_list_length(unexpected_list)) {
        /* Take the first entry if list not empty */
        entry = unexpected_list;
        request_info = (struct BMI_unexpected_info*) hg_list_data(entry);
    } else {
        /* If no message try to get new message from BMI */
        request_info = malloc(sizeof(struct BMI_unexpected_info));
        bmi_ret = BMI_testunexpected(1, &outcount, request_info, 0);

        if (!outcount) goto done;
    }

    if (bmi_ret < 0 || request_info->error_code != 0) {
        NA_ERROR_DEFAULT("Request recv failure (bad state)");
        NA_ERROR_DEFAULT("BMI_testunexpected failed");
        ret = NA_FAIL;
        goto done;
    }

    if (request_info->size > (bmi_size_t) buf_size) {
        NA_ERROR_DEFAULT("Buffer too small to recv unexpected data");
        ret = NA_FAIL;
        goto done;
    }

    if (actual_buf_size) *actual_buf_size = (na_size_t) request_info->size;
    if (source) {
        BMI_addr_t **peer_addr = (BMI_addr_t**) source;
        *peer_addr = malloc(sizeof(BMI_addr_t));
        **peer_addr = request_info->addr;
    }
    if (tag) *tag = (na_tag_t) request_info->tag;

    /* Copy buffer and free request_info */
    memcpy(buf, request_info->buffer, request_info->size);

    bmi_request = malloc(sizeof(bmi_request_t));
    bmi_request->op_id = 0;
    bmi_request->completed = 1;
    bmi_request->actual_size = request_info->size;
    bmi_request->user_ptr = op_arg;
    bmi_request->ack_request = NA_REQUEST_NULL;

    *request = (na_request_t) bmi_request;

done:

    if (ret != NA_SUCCESS && bmi_request) {
        free(bmi_request);
        bmi_request = NULL;
    }

    if (request_info && (entry || outcount)) {
        BMI_unexpected_free(request_info->addr, request_info->buffer);
    }

    if (entry && !hg_list_remove_entry(&unexpected_list, entry)) {
        NA_ERROR_DEFAULT("Could not remove entry");
    } else {
        free(request_info);
    }

    hg_thread_mutex_unlock(&unexpected_list_mutex);

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
    bmi_request->ack_request = NA_REQUEST_NULL;

    /* Post the BMI send request */
    bmi_ret = BMI_post_send(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            BMI_EXT_ALLOC, bmi_tag, bmi_request, bmi_context, NULL);

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
    bmi_request->ack_request = NA_REQUEST_NULL;

    /* Post the BMI recv request */
    bmi_ret = BMI_post_recv(&bmi_request->op_id, *bmi_peer_addr, buf, bmi_buf_size,
            &bmi_request->actual_size, BMI_EXT_ALLOC, bmi_tag, bmi_request,
            bmi_context, NULL);

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
 * Function:    na_bmi_mem_handle_get_serialize_size
 *
 * Purpose:     Get size required to serialize handle
 *
 *---------------------------------------------------------------------------
 */
static na_size_t na_bmi_mem_handle_get_serialize_size(void)
{
    return sizeof(bmi_mem_handle_t);
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
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_local_mem_handle = (bmi_mem_handle_t*) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    bmi_mem_handle_t *bmi_remote_mem_handle = (bmi_mem_handle_t*) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    bmi_size_t bmi_length = (bmi_size_t) length;
    bmi_request_t *bmi_request;

    bmi_onesided_info_t onesided_info;
    na_request_t onesided_request;
    na_status_t onesided_status;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(mem_handle_map, bmi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }

    if (bmi_remote_mem_handle->attr != NA_MEM_READWRITE) {
        NA_ERROR_DEFAULT("Registered memory requires write permission");
        ret = NA_FAIL;
        return ret;
    }

    onesided_info.base = bmi_remote_mem_handle->base;
    onesided_info.disp = bmi_remote_offset;
    onesided_info.count = bmi_length;
    onesided_info.op = BMI_ONESIDED_PUT;

    /* Send to one-sided thread key to access mem_handle */
    ret = na_bmi_send_unexpected(&onesided_info, sizeof(bmi_onesided_info_t),
            remote_addr, NA_BMI_ONESIDED_TAG, &onesided_request, NULL);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Could not send onesided info");
        ret = NA_FAIL;
        return ret;
    }
    ret = na_bmi_wait(onesided_request, NA_MAX_IDLE_TIME, &onesided_status);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Error during wait");
        ret = NA_FAIL;
        return ret;
    }

    /* Do an asynchronous send */
    ret = na_bmi_send(bmi_local_mem_handle->base + bmi_local_offset, bmi_length,
            remote_addr, NA_BMI_ONESIDED_DATA_TAG, request, NULL);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Could not send data");
        ret = NA_FAIL;
        return ret;
    }

    /* Wrap an ack request around the original request */
    bmi_request = (bmi_request_t *) *request;
    ret = na_bmi_recv(&bmi_request->ack, sizeof(bool),
            remote_addr, NA_BMI_ONESIDED_ACK_TAG, &bmi_request->ack_request, NULL);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Could not recv ack");
        ret = NA_FAIL;
        return ret;
    }

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
    int ret = NA_SUCCESS;
    bmi_mem_handle_t *bmi_local_mem_handle = (bmi_mem_handle_t*) local_mem_handle;
    bmi_size_t bmi_local_offset = (bmi_size_t) local_offset;
    bmi_mem_handle_t *bmi_remote_mem_handle = (bmi_mem_handle_t*) remote_mem_handle;
    bmi_size_t bmi_remote_offset = (bmi_size_t) remote_offset;
    bmi_size_t bmi_length = (bmi_size_t) length;

    bmi_onesided_info_t onesided_info;
    na_request_t onesided_request;
    na_status_t onesided_status;

    /* Check that local memory is registered */
    if (!hg_hash_table_lookup(mem_handle_map, bmi_local_mem_handle->base)) {
        NA_ERROR_DEFAULT("Could not find memory handle, registered?");
        ret = NA_FAIL;
        return ret;
    }

    if (bmi_remote_mem_handle->attr != (NA_MEM_READ_ONLY || NA_MEM_READWRITE)) {
        NA_ERROR_DEFAULT("Registered memory requires read permission");
        ret = NA_FAIL;
        return ret;
    }

    /* Send to one-sided thread key to access mem_handle */
    onesided_info.base = bmi_remote_mem_handle->base;
    onesided_info.disp = bmi_remote_offset;
    onesided_info.count = bmi_length;
    onesided_info.op = BMI_ONESIDED_GET;

    ret = na_bmi_send_unexpected(&onesided_info, sizeof(bmi_onesided_info_t),
            remote_addr, NA_BMI_ONESIDED_TAG, &onesided_request, NULL);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Could not send onesided info");
        ret = NA_FAIL;
        return ret;
    }
    ret = na_bmi_wait(onesided_request, NA_MAX_IDLE_TIME, &onesided_status);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Error during wait");
        ret = NA_FAIL;
        return ret;
    }

    /* Simply do an asynchronous recv */
    ret = na_bmi_recv(bmi_local_mem_handle->base + bmi_local_offset, bmi_length,
            remote_addr, NA_BMI_ONESIDED_DATA_TAG, request, NULL);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_process_unexpected
 *
 * Purpose:     Process unexpected messages when making progress
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_process_unexpected(void)
{
    int outcount;
    struct BMI_unexpected_info *request_info;
    int bmi_ret, ret = NA_SUCCESS;

    hg_thread_mutex_lock(&unexpected_list_mutex);

    do {
        request_info = malloc(sizeof(struct BMI_unexpected_info));
        bmi_ret = BMI_testunexpected(1, &outcount, request_info, 0);
        if (outcount) {
            if (bmi_ret < 0 || request_info->error_code != 0) {
                NA_ERROR_DEFAULT("Request recv failure (bad state)");
                NA_ERROR_DEFAULT("BMI_testunexpected failed");
                ret = NA_FAIL;
                break;
            }
            if (!hg_list_append(&unexpected_list, (hg_list_value_t)request_info)) {
                NA_ERROR_DEFAULT("Could not append handle to list");
                ret = NA_FAIL;
                break;
            }
        } else {
            free(request_info);
        }
    } while (outcount);

    hg_thread_mutex_unlock(&unexpected_list_mutex);

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
    int remaining = timeout;
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
            hg_thread_cond_ret = hg_thread_cond_timedwait(&testcontext_cond,
                    &testcontext_mutex, remaining);
        }
        is_testing_context = 1;

        hg_thread_mutex_unlock(&testcontext_mutex);

        if (hg_thread_cond_ret < 0) {
            NA_ERROR_DEFAULT("hg_thread_cond_timedwait failed");
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

            /* Always try to receive unexpected messages before calling testcontext */
            ret = na_bmi_process_unexpected();
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not process unexpected messages");
                ret = NA_FAIL;
                break;
            }

            bmi_ret = BMI_testcontext(1, &bmi_op_id, &outcount, &error_code,
                    &bmi_actual_size, &bmi_user_ptr, remaining, bmi_context);

            gettimeofday(&t2, NULL);
            remaining -= (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec) / 1000;

            if (bmi_ret < 0 || error_code != 0) {
                NA_ERROR_DEFAULT("BMI_testcontext failed");
                ret = NA_FAIL;
                break;
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
        status->completed = 0;
    }

    if (bmi_wait_request->completed) {
        /* Wait for the ack request too */
        if (bmi_wait_request->ack_request != NA_REQUEST_NULL) {
            na_status_t ack_status;
            hg_thread_mutex_unlock(&request_mutex);
            ret = na_bmi_wait(bmi_wait_request->ack_request, timeout, &ack_status);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not wait for ack request");
                ret = NA_FAIL;
                return ret;
            }
            if (!ack_status.completed) {
                NA_ERROR_DEFAULT("Ack not completed");
                return ret;
            }
            if (!bmi_wait_request->ack) {
                NA_ERROR_DEFAULT("Got wrong ack");
                ret = NA_FAIL;
                return ret;
            }
            hg_thread_mutex_lock(&request_mutex);
        }
        if (status && status != NA_STATUS_IGNORE) {
            status->completed = 1;
            status->count = bmi_wait_request->actual_size;
        }
        free(bmi_wait_request);
        bmi_wait_request = NULL;
    }

    hg_thread_mutex_unlock(&request_mutex);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    na_bmi_progress
 *
 * Purpose:     Track completion of RMA operations and make progress
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
static int na_bmi_progress(unsigned int timeout, na_status_t *status)
{
    int time_remaining = timeout;
    int ret = NA_SUCCESS;
    /* TODO may want to have it dynamically allocated if multiple threads call
     * progress on the client but should that happen? */
    static bmi_onesided_info_t onesided_info;
    static na_size_t onesided_actual_size;
    static na_addr_t remote_addr;
    static na_tag_t remote_tag;
    static na_request_t onesided_request = NA_REQUEST_NULL;

    na_status_t onesided_status;
    bmi_mem_handle_t *bmi_mem_handle = NULL;

    bool ack;
    na_request_t onesided_data_request;
    na_request_t onesided_ack_request;

    /* Wait for an initial request from client */
    if (onesided_request == NA_REQUEST_NULL) {
        do {
            struct timeval t1, t2;
            onesided_actual_size = 0;
            remote_addr = NA_ADDR_NULL;
            remote_tag = 0;

            gettimeofday(&t1, NULL);

            ret = na_bmi_recv_unexpected(&onesided_info, sizeof(bmi_onesided_info_t),
                    &onesided_actual_size, &remote_addr,
                    &remote_tag, &onesided_request, NULL);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not recv buffer");
                ret = NA_FAIL;
                return ret;
            }

            gettimeofday(&t2, NULL);
            time_remaining -= (t2.tv_sec - t1.tv_sec) * 1000 +
                    (t2.tv_usec - t1.tv_usec) / 1000;

        } while (time_remaining > 0 && !onesided_actual_size);
        if (!onesided_actual_size) {
            /* Timeout reached and has still not received anything */
            if (status && status != NA_STATUS_IGNORE) {
                status->completed = 0;
                status->count = 0;
            }
            ret = NA_SUCCESS;
            return ret;
        }
        if (onesided_actual_size != sizeof(onesided_info)) {
            NA_ERROR_DEFAULT("recv_buf_size does not match onesided_info");
            ret = NA_FAIL;
            return ret;
        }
    }

    ret = na_bmi_wait(onesided_request, timeout, &onesided_status);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("Error while waiting");
        ret = NA_FAIL;
        return ret;
    }

    if (!onesided_status.completed) {
        if (status && status != NA_STATUS_IGNORE) {
            status->completed = 0;
            status->count = 0;
        }
        ret = NA_SUCCESS;
        return ret;
    } else {
        onesided_request = NA_REQUEST_NULL;
    }

    if (remote_tag != NA_BMI_ONESIDED_TAG) {
        NA_ERROR_DEFAULT("Bad remote tag");
        ret = NA_FAIL;
        return ret;
    }

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
        /* Remote wants to do a put so wait in a recv */
        case BMI_ONESIDED_PUT:
            ret = na_bmi_recv(bmi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, remote_addr, NA_BMI_ONESIDED_DATA_TAG,
                    &onesided_data_request, NULL);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not recv data");
                ret = NA_FAIL;
                break;
            }
            /* Send an ack to tell the server that the data is here */
            ack = 1;
            ret = na_bmi_send(&ack, sizeof(bool), remote_addr, NA_BMI_ONESIDED_ACK_TAG,
                    &onesided_ack_request, NULL);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not send ack");
                ret = NA_FAIL;
                break;
            }
            ret = na_bmi_wait(onesided_data_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Error while waiting");
                ret = NA_FAIL;
                return ret;
            }
            ret = na_bmi_wait(onesided_ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Error while waiting");
                ret = NA_FAIL;
                return ret;
            }
            break;

        /* Remote wants to do a get so do a send */
        case BMI_ONESIDED_GET:
            ret = na_bmi_send(bmi_mem_handle->base + onesided_info.disp,
                    onesided_info.count, remote_addr, NA_BMI_ONESIDED_DATA_TAG,
                    &onesided_data_request, NULL);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Could not send data");
                ret = NA_FAIL;
                break;
            }
            ret = na_bmi_wait(onesided_data_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (ret != NA_SUCCESS) {
                NA_ERROR_DEFAULT("Error while waiting");
                ret = NA_FAIL;
                return ret;
            }
            break;

        default:
            NA_ERROR_DEFAULT("Operation not supported");
            break;
    }

    hg_thread_mutex_unlock(&mem_map_mutex);

    if (status && status != NA_STATUS_IGNORE) {
        status->completed = 1;
        status->count = onesided_info.count;
    }
    na_bmi_addr_free(remote_addr);
    remote_addr = NA_ADDR_NULL;

    return ret;
}
