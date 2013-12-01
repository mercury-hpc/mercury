/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_handler.h"
#include "mercury_proc_header.h"

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_queue.h"
#include "mercury_thread_mutex.h"
#include "mercury_time.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/


/************************************/
/* Local Type and Struct Definition */
/************************************/
struct hg_handle {
    hg_id_t       id;                  /* Request ID */
    hg_uint32_t   cookie;              /* Cookie unique to every RPC call */

    na_addr_t     addr;                /* Address of the RPC source */
    na_tag_t      tag;                 /* Tag used for request and response */

    void         *recv_buf;            /* Recv buffer for request */
    na_size_t     recv_buf_size;       /* Recv buffer size */
    void         *extra_recv_buf;      /* Extra recv buffer */
    na_size_t     extra_recv_buf_size; /* Extra recv buffer size */

    void         *send_buf;            /* Send buffer for response */
    na_size_t     send_buf_size;       /* Send buffer size */
    void         *extra_send_buf;      /* Extra send buffer (TODO not used) */
    na_size_t     extra_send_buf_size; /* Extra send buffer size (TODO not used) */

    void         *in_struct;           /* Reference to input structure */
};

struct hg_handler_proc_info {
    hg_handler_cb_t callback_routine;
    hg_proc_cb_t dec_routine;
    hg_proc_cb_t enc_routine;
};

/********************/
/* Local Prototypes */
/********************/
/**
 * Create new handle.
 */
static struct hg_handle *hg_handler_new(void);

/**
 * Add handle to completion queue.
 */
static hg_return_t hg_handler_completion_add(struct hg_handle *priv_handle);

/**
 * Remove and free resources from handles in completion queue.
 */
static hg_return_t hg_handler_completion_process(void);

/**
 * Get extra buffer and associate it to handle.
 */
static hg_return_t hg_handler_process_extra_recv_buf(
        struct hg_handle *priv_handle, hg_bulk_t extra_buf_handle);
/**
 * Decode and get request header.
 */
static hg_return_t hg_handler_get_request_header(struct hg_handle *priv_handle,
        struct hg_header_request *header);
/**
 * Set and encode response header.
 */
static hg_return_t hg_handler_set_response_header(struct hg_handle *priv_handle,
        struct hg_header_response header);

/**
 * Recv input callback.
 */
static na_return_t hg_handler_recv_input_cb(
        const struct na_cb_info *callback_info);

/**
 * Send output callback.
 */
static na_return_t hg_handler_send_output_cb(
        const struct na_cb_info *callback_info);

/**
 * Start receiving a new request.
 */
static hg_return_t hg_handler_start_request(void);

/*******************/
/* Local Variables */
/*******************/

/* Pointer to network abstraction class */
static na_class_t *hg_handler_na_class_g = NULL;

/* Local context */
static na_context_t *hg_handler_context_g = NULL;

/* Bulk interface internally initialized */
static hg_bool_t hg_bulk_initialized_internal_g = HG_FALSE;

/* Function map */
static hg_hash_table_t *hg_handler_func_map_g;

/* Completion queue */
static hg_queue_t *hg_handler_completion_queue_g;
static hg_thread_mutex_t hg_handler_completion_queue_mutex_g;

/* Request started */
static hg_bool_t hg_handler_started_request_g = HG_FALSE;
static hg_thread_mutex_t hg_handler_started_request_mutex_g;

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_int_equal(void *vlocation1, void *vlocation2)
{
    int *location1;
    int *location2;

    location1 = (int *) vlocation1;
    location2 = (int *) vlocation2;

    return *location1 == *location2;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE unsigned int
hg_int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
}

/*---------------------------------------------------------------------------*/
static struct hg_handle *
hg_handler_new(void)
{
    struct hg_handle *priv_handle = NULL;

    priv_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (priv_handle) {
        priv_handle->id = 0;
        priv_handle->cookie = 0;

        priv_handle->addr = NA_ADDR_NULL;
        priv_handle->tag = 0;

        priv_handle->recv_buf = NULL;
        priv_handle->recv_buf_size = 0;
        priv_handle->extra_recv_buf = NULL;
        priv_handle->extra_recv_buf_size = 0;

        priv_handle->send_buf = NULL;
        priv_handle->send_buf_size = 0;
        priv_handle->extra_send_buf = NULL;
        priv_handle->extra_send_buf_size = 0;

        priv_handle->in_struct = NULL;
    }

    return priv_handle;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_completion_add(struct hg_handle *priv_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handler_completion_queue_mutex_g);

    if (!hg_queue_push_head(hg_handler_completion_queue_g,
            (hg_queue_value_t) priv_handle)) {
        HG_ERROR_DEFAULT("Could not push handle to completion queue");
        ret = HG_FAIL;
    }

    hg_thread_mutex_unlock(&hg_handler_completion_queue_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_completion_process(void)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handler_completion_queue_mutex_g);

    /* Iterate over entries and test for their completion */
    while (!hg_queue_is_empty(hg_handler_completion_queue_g)) {
        struct hg_handle *priv_handle;

        priv_handle = (struct hg_handle *)
                            hg_queue_pop_tail(hg_handler_completion_queue_g);

        /* Free handle */
        HG_Handler_free(priv_handle);
        priv_handle = NULL;
    }

    hg_thread_mutex_unlock(&hg_handler_completion_queue_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_process_extra_recv_buf(struct hg_handle *priv_handle,
        hg_bulk_t extra_buf_handle)
{
    hg_bulk_block_t extra_buf_block_handle = HG_BULK_BLOCK_NULL;
    hg_bulk_request_t extra_buf_request;
    hg_return_t ret = HG_SUCCESS;

    /* Create a new block handle to read the data */
    priv_handle->extra_recv_buf_size = HG_Bulk_handle_get_size(extra_buf_handle);
    priv_handle->extra_recv_buf = malloc(priv_handle->extra_recv_buf_size);
    if (!priv_handle->extra_recv_buf) {
        HG_ERROR_DEFAULT("Could not allocate extra recv buf");
        ret = HG_FAIL;
        goto done;
    }

    ret = HG_Bulk_block_handle_create(priv_handle->extra_recv_buf,
            priv_handle->extra_recv_buf_size, HG_BULK_READWRITE,
            &extra_buf_block_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create block handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read_all(priv_handle->addr, extra_buf_handle,
            extra_buf_block_handle, &extra_buf_request);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not read bulk data");
        ret = HG_FAIL;
        goto done;
    }

    ret = HG_Bulk_wait(extra_buf_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not complete bulk data read");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (extra_buf_block_handle != HG_BULK_BLOCK_NULL) {
        ret = HG_Bulk_block_handle_free(extra_buf_block_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free block handle");
            ret = HG_FAIL;
        }
        extra_buf_block_handle = HG_BULK_BLOCK_NULL;
    }

    if (extra_buf_handle != HG_BULK_BLOCK_NULL) {
        ret = HG_Bulk_handle_free(extra_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free bulk handle");
            ret = HG_FAIL;
        }
        extra_buf_handle = HG_BULK_NULL;
    }

   return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_get_request_header(struct hg_handle *priv_handle,
        struct hg_header_request *header)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_proc_create(priv_handle->recv_buf, priv_handle->recv_buf_size,
            HG_DECODE, HG_CRC16, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode request header */
    ret = hg_proc_header_request(proc, header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_set_response_header(struct hg_handle *priv_handle,
        struct hg_header_response header)
{
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_proc_create(priv_handle->send_buf, priv_handle->send_buf_size,
            HG_ENCODE, HG_CRC16, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode request header */
    ret = hg_proc_header_response(proc, &header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_handler_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *priv_handle = (struct hg_handle *) callback_info->arg;
    struct hg_handler_proc_info   *proc_info;
    struct hg_header_request request_header;
    hg_return_t ret = HG_SUCCESS; /* TODO embed ret into priv_request */
    na_return_t na_ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    priv_handle->addr = callback_info->info.recv_unexpected.source;
    priv_handle->tag = callback_info->info.recv_unexpected.tag;
    if (callback_info->info.recv_unexpected.actual_buf_size !=
            priv_handle->recv_buf_size) {
        HG_ERROR_DEFAULT("Buffer size and actual transfer size do not match");
        ret = HG_FAIL;
        goto done;
    }

    /* We just received a new request so set started to FALSE (clean later) */
    hg_thread_mutex_lock(&hg_handler_started_request_mutex_g);

    hg_handler_started_request_g = HG_FALSE;

    hg_thread_mutex_unlock(&hg_handler_started_request_mutex_g);

    /* Get request header */
    ret = hg_handler_get_request_header(priv_handle, &request_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get header");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_proc_header_request_verify(request_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not verify header");
        ret = HG_FAIL;
        goto done;
    }

    /* Get operation ID from header */
    priv_handle->id = request_header.id;

    /* Get cookie from header */
    priv_handle->cookie = request_header.cookie;

    /* Get extra payload if necessary */
    if (request_header.flags &&
            (request_header.extra_buf_handle != HG_BULK_NULL)) {
        /* This will make the extra_buf the recv_buf associated to the handle */
        ret = hg_handler_process_extra_recv_buf(priv_handle,
                request_header.extra_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not recv extra buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* Retrieve exe function from function map */
    proc_info = (struct hg_handler_proc_info *)
            hg_hash_table_lookup(hg_handler_func_map_g, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    /* Execute function and fill output parameters */
    proc_info->callback_routine((hg_handle_t) priv_handle);

done:
    return na_ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_handler_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *priv_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Add handle to completion queue */
    hg_handler_completion_add(priv_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_init(na_class_t *na_class)
{
    hg_bool_t bulk_initialized = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_ERROR_DEFAULT("Invalid specified na_class");
        ret = HG_FAIL;
        goto done;
    }

    if (hg_handler_na_class_g) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        goto done;
    }

    hg_handler_na_class_g = na_class;

    /* Create local context */
    hg_handler_context_g = NA_Context_create(hg_handler_na_class_g);
    if (!hg_handler_context_g) {
        HG_ERROR_DEFAULT("Could not create context.");
        ret = HG_FAIL;
        goto done;
    }

    /* Initialize bulk module */
    HG_Bulk_initialized(&bulk_initialized, NULL);
    if (!bulk_initialized) {
        ret = HG_Bulk_init(na_class);
        if (ret != HG_SUCCESS)
        {
            HG_ERROR_DEFAULT("Error initializing bulk module.");
            ret = HG_FAIL;
            goto done;
        }
    }
    hg_bulk_initialized_internal_g = !bulk_initialized;

    /* Create new function map */
    hg_handler_func_map_g = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!hg_handler_func_map_g) {
        HG_ERROR_DEFAULT("Could not create function map");
        ret = HG_FAIL;
        goto done;
    }

    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_handler_func_map_g, free, free);

    /* Create completion queue */
    hg_handler_completion_queue_g = hg_queue_new();

    /* Initialize mutex */
    hg_thread_mutex_init(&hg_handler_completion_queue_mutex_g);
    hg_thread_mutex_init(&hg_handler_started_request_mutex_g);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_handler_na_class_g) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        goto done;
    }

    if (hg_bulk_initialized_internal_g) {
        ret = HG_Bulk_finalize();
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not finalize bulk data interface");
            ret = HG_FAIL;
            goto done;
        }
        hg_bulk_initialized_internal_g = HG_FALSE;
    }

    /* Wait for previous responses to complete */
//    ret = hg_handler_process_response_list(HG_MAX_IDLE_TIME);
//    if (ret != HG_SUCCESS) {
//        HG_ERROR_DEFAULT("Could not process response list");
//        ret = HG_FAIL;
//        goto done;
//    }

    /* Destroy context */
    na_ret = NA_Context_destroy(hg_handler_na_class_g, hg_handler_context_g);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not destroy context.");
        ret = HG_FAIL;
        return ret;
    }

    /* Delete function map */
    hg_hash_table_free(hg_handler_func_map_g);
    hg_handler_func_map_g = NULL;

    hg_handler_na_class_g = NULL;

    /* Destroy mutex */
    hg_thread_mutex_destroy(&hg_handler_completion_queue_mutex_g);
    hg_thread_mutex_destroy(&hg_handler_started_request_mutex_g);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_register(const char *func_name, hg_handler_cb_t callback_routine,
        hg_proc_cb_t dec_routine, hg_proc_cb_t enc_routine)
{
    hg_return_t ret = HG_SUCCESS;
    hg_id_t *id = NULL;
    struct hg_handler_proc_info *proc_info = NULL;

    /* Generate a key from the string */
    id = (hg_id_t*) malloc(sizeof(hg_id_t));
    if (!id) {
        HG_ERROR_DEFAULT("Could not allocate ID");
        ret = HG_FAIL;
        goto done;
    }

    *id = hg_hash_string(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = (struct hg_handler_proc_info *)
            malloc(sizeof(struct hg_handler_proc_info));
    if (!proc_info) {
        HG_ERROR_DEFAULT("Could not allocate proc info");
        ret = HG_FAIL;
        goto done;
    }

    proc_info->callback_routine = callback_routine;
    proc_info->dec_routine = dec_routine;
    proc_info->enc_routine = enc_routine;

    if (!hg_hash_table_insert(hg_handler_func_map_g, id, proc_info)) {
        HG_ERROR_DEFAULT("Could not insert func ID");
        ret = HG_FAIL;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        free(id);
        free(proc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
na_addr_t
HG_Handler_get_addr (hg_handle_t handle)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    na_addr_t ret = NULL;

    if (priv_handle) ret = priv_handle->addr;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_input_buf(hg_handle_t handle, void **in_buf, size_t *in_buf_size)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    void *user_input_buf;
    size_t user_input_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    user_input_buf = (priv_handle->extra_recv_buf) ?
            priv_handle->extra_recv_buf : priv_handle->recv_buf;
    user_input_buf_size = (priv_handle->extra_recv_buf_size) ?
            priv_handle->extra_recv_buf_size : priv_handle->recv_buf_size;
    /* No offset if extra buffer since only the user payload is copied */
    header_offset = (priv_handle->extra_recv_buf) ?
            0 : hg_proc_header_request_get_size();

    /* We don't want the user to mess with the header so don't let him see it */
    if (in_buf) *in_buf = (char*) user_input_buf + header_offset;
    if (in_buf_size) *in_buf_size = user_input_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_output_buf(hg_handle_t handle, void **out_buf,
        size_t *out_buf_size)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    void *user_output_buf;
    size_t user_output_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!priv_handle->send_buf) {
        /* Recv buffer must match the size of unexpected buffer */
        priv_handle->send_buf_size =
                NA_Msg_get_max_expected_size(hg_handler_na_class_g);

        priv_handle->send_buf = hg_proc_buf_alloc(priv_handle->send_buf_size);
        if (!priv_handle->send_buf) {
            HG_ERROR_DEFAULT("Could not allocate send buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    user_output_buf = priv_handle->send_buf;
    user_output_buf_size = priv_handle->send_buf_size;
    header_offset = hg_proc_header_response_get_size();

    /* We don't want the user to mess with the header so don't let him see it */
    if (out_buf) *out_buf = (char*) user_output_buf + header_offset;
    if (out_buf_size) *out_buf_size = user_output_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_process(unsigned int timeout, hg_status_t *status)
{
    double remaining = timeout / 1000; /* Convert timeout in ms into seconds */
    hg_bool_t processed = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    /* Check if previous handles have completed */
    hg_handler_completion_process();

    /* Start a new request if none already started */
    hg_thread_mutex_lock(&hg_handler_started_request_mutex_g);

    if (!hg_handler_started_request_g) {
        ret = hg_handler_start_request();
        hg_handler_started_request_g = HG_TRUE;
    }

    processed = !hg_handler_started_request_g;

    hg_thread_mutex_unlock(&hg_handler_started_request_mutex_g);

    while (!processed) {
        hg_time_t t1, t2;
        na_return_t na_ret;
        int actual_count = 0;

        hg_time_get_current(&t1);

        do {
            na_ret = NA_Trigger(hg_handler_context_g, 0, 1, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&hg_handler_started_request_mutex_g);

        processed = !hg_handler_started_request_g;

        hg_thread_mutex_unlock(&hg_handler_started_request_mutex_g);

        if (processed) break;

        na_ret = NA_Progress(hg_handler_na_class_g, hg_handler_context_g,
                (unsigned int) (remaining * 1000));
        if (na_ret == NA_TIMEOUT) {
            goto done;
        }

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        if (remaining < 0) {
            goto done;
        }
    }

done:
    if (status && (status != HG_STATUS_IGNORE)) {
        *status = processed;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_start_request(void)
{
    struct hg_handle *priv_handle = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Create a new handle */
    priv_handle = (struct hg_handle *) hg_handler_new();
    if (!priv_handle) {
        HG_ERROR_DEFAULT("Could not create new handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Recv buffer must match the size of unexpected buffer */
    priv_handle->recv_buf_size =
            NA_Msg_get_max_unexpected_size(hg_handler_na_class_g);

    /* Allocate a new receive buffer for the unexpected message */
    priv_handle->recv_buf = hg_proc_buf_alloc(priv_handle->recv_buf_size);
    if (!priv_handle->recv_buf) {
        HG_ERROR_DEFAULT("Could not allocate recv buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_handler_na_class_g, hg_handler_context_g,
            &hg_handler_recv_input_cb, priv_handle, priv_handle->recv_buf,
            priv_handle->recv_buf_size, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not post unexpected recv for input buffer");
        ret = HG_FAIL;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_start_response(hg_handle_t handle, void *extra_out_buf,
        size_t extra_out_buf_size)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    /* if get_output has not been called, call it to create to send_buf */
    ret = HG_Handler_get_output_buf(handle, NULL, NULL);
     if (ret != HG_SUCCESS) {
         HG_ERROR_DEFAULT("Could not get output");
         ret = HG_FAIL;
         goto done;
     }

    /* Check out_buf_size, if it's bigger than the size of the pre-posted buffer
     * we need to use an extra buffer again */
    if (extra_out_buf_size > priv_handle->send_buf_size) {
        if (!extra_out_buf) {
            HG_ERROR_DEFAULT("No extra buffer given");
            ret = HG_FAIL;
            goto done;
        }
        priv_handle->extra_send_buf = extra_out_buf;
        priv_handle->extra_send_buf_size = extra_out_buf_size;
    }

    /* Fill the header */
    hg_proc_header_response_init(&response_header);
    response_header.cookie = priv_handle->cookie;

    ret = hg_handler_set_response_header(priv_handle, response_header);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not set header");
        ret = HG_FAIL;
        goto done;
    }

    /* Respond back */
    na_ret = NA_Msg_send_expected(hg_handler_na_class_g, hg_handler_context_g,
            &hg_handler_send_output_cb, priv_handle, priv_handle->send_buf,
            priv_handle->send_buf_size, priv_handle->addr, priv_handle->tag,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not post send for output buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* TODO Also add extra buffer response */

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_free(hg_handle_t handle)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->addr != NA_ADDR_NULL) {
        NA_Addr_free(hg_handler_na_class_g, priv_handle->addr);
        priv_handle->addr = NA_ADDR_NULL;
    }

    if (priv_handle->recv_buf) {
       hg_proc_buf_free(priv_handle->recv_buf);
       priv_handle->recv_buf = NULL;
    }

    if (priv_handle->extra_recv_buf) {
        free(priv_handle->extra_recv_buf);
        priv_handle->extra_recv_buf = NULL;
    }

    if (priv_handle->send_buf) {
        hg_proc_buf_free(priv_handle->send_buf);
        priv_handle->send_buf = NULL;
    }

    if (priv_handle->extra_send_buf) {
        hg_proc_buf_free(priv_handle->extra_send_buf);
        priv_handle->extra_send_buf = NULL;
    }

    free(priv_handle);
    priv_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_input(hg_handle_t handle, void *in_struct)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    void *in_buf;
    size_t in_buf_size;
    struct hg_handler_proc_info *proc_info;
    hg_proc_t proc;

    if (!in_struct) {
        HG_ERROR_DEFAULT("NULL pointer to input struct");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->in_struct) {
        /* TODO Not the first time we call get_input */
    }

    /* Keep reference to in_struct to free decoded params later */
    priv_handle->in_struct = in_struct;

    /* Get input buffer */
    ret = HG_Handler_get_input_buf(handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        return ret;
    }

    /* Retrieve decode function from function map */
    proc_info = (struct hg_handler_proc_info *)
            hg_hash_table_lookup(hg_handler_func_map_g, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        return ret;
    }

    /* Create a new decoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_DECODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        ret = HG_FAIL;
        return ret;
    }

    /* Decode input parameters */
    ret = proc_info->dec_routine(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode input parameters");
        ret = HG_FAIL;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error in proc flush");
        ret = HG_FAIL;
    }

    /* Free proc */
    hg_proc_free(proc);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_start_output(hg_handle_t handle, void *out_struct)
{
    struct hg_handle *priv_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    void *out_buf;
    size_t out_buf_size;
    void *out_extra_buf = NULL;
    size_t out_extra_buf_size = 0;
    struct hg_handler_proc_info *proc_info;
    hg_proc_t proc;

    /* Get output buffer */
    ret = HG_Handler_get_output_buf(handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output buffer");
        ret = HG_FAIL;
        return ret;
    }

    /* Retrieve decode function from function map */
    proc_info = (struct hg_handler_proc_info *)
            hg_hash_table_lookup(hg_handler_func_map_g, &priv_handle->id);
    if (!proc_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        return ret;
    }

    if (out_struct && proc_info->enc_routine) {
        /* Create a new encoding proc */
        ret = hg_proc_create(out_buf, out_buf_size, HG_ENCODE, HG_CRC64, &proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        /* Encode output parameters */
        ret = proc_info->enc_routine(proc, out_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not encode output parameters");
            ret = HG_FAIL;
        }

        /* Get eventual extra buffer */
        if (hg_proc_get_extra_buf(proc)) {
            /* TODO need to do something here */
            out_extra_buf = hg_proc_get_extra_buf(proc);
            out_extra_buf_size = hg_proc_get_extra_size(proc);
            hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);
        }

        /* Flush proc */
        ret = hg_proc_flush(proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Error in proc flush");
            ret = HG_FAIL;
        }

        /* Free proc */
        hg_proc_free(proc);
    }

    if (priv_handle->in_struct && proc_info->dec_routine) {
        /* Create a new free proc */
        ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, &proc);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not create proc");
            ret = HG_FAIL;
            return ret;
        }

        /* Free memory allocated during input decoding */
        ret = proc_info->dec_routine(proc, priv_handle->in_struct);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free allocated parameters");
            ret = HG_FAIL;
        }

        /* Free proc */
        hg_proc_free(proc);
    }

    /* Start sending response back, this should be the last operation called
     * that uses the handle as HG_Handler_process may free the handle as soon
     * as the response completes */
    ret = HG_Handler_start_response(handle, out_extra_buf, out_extra_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not respond");
        ret = HG_FAIL;
        return ret;
    }

    return ret;
}
