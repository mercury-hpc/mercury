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
#include "mercury_proc.h"

#include "mercury_private.h"

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_queue.h"
#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_request.h"
#include "mercury_time.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/


/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

/**
 * Get RPC input buffer from handle.
 */
static hg_return_t hg_handler_get_input_buf(struct hg_handle *hg_handle,
        void **in_buf, size_t *in_buf_size);

/**
 * Get RPC output buffer from handle.
 */
static hg_return_t hg_handler_get_output_buf(struct hg_handle *hg_handle,
        void **out_buf, size_t *out_buf_size);

/**
 * Decode and get input structure.
 */
static hg_return_t hg_handler_get_input(struct hg_handle *hg_handle,
        void *in_struct);

/**
 * Set and encode output structure.
 */
static hg_return_t hg_handler_set_output(struct hg_handle *hg_handle,
        void *out_struct);

/**
 * Free allocated members from input structure.
 */
static hg_return_t hg_handler_free_input(struct hg_handle *hg_handle,
        void *out_struct);

/**
 * Add handle to processing list.
 */
static hg_return_t
hg_handler_processing_list_add(
        struct hg_handle *hg_handle
        );

/**
 * Remove handle from processing list.
 */
static hg_return_t
hg_handler_processing_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Add handle to completion queue.
 */
static hg_return_t
hg_handler_completion_queue_add(
        struct hg_handle *hg_handle
        );

/**
 * Remove and free resources from handles in completion queue.
 */
static hg_return_t
hg_handler_completion_queue_process(void);

/**
 * Mark handle as completed
 */
static hg_return_t
hg_handler_complete(
        struct hg_handle *hg_handle
        );

/**
 * Get extra buffer and associate it to handle.
 */
static hg_return_t
hg_handler_get_extra_input_buf(
        struct hg_handle *hg_handle,
        hg_bulk_t extra_buf_handle
        );

/**
 * Start processing a received request.
 */
hg_return_t
hg_handler_start_processing(struct hg_handle *hg_handle);

/**
 * Recv input callback.
 */
static na_return_t
hg_handler_recv_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Send output callback.
 */
static na_return_t
hg_handler_send_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Start receiving a new request.
 */
static hg_return_t
hg_handler_start_request(void);

/*******************/
/* Local Variables */
/*******************/

/* Pointer to NA class */
extern na_class_t *hg_na_class_g;

/* Local context */
extern na_context_t *hg_context_g;

/* Request class */
extern hg_request_class_t *hg_request_class_g;

/* Function map */
extern hg_hash_table_t *hg_func_map_g;

/* Processing list */
static hg_list_entry_t *hg_handler_processing_list_g;
static hg_thread_mutex_t hg_handler_processing_list_mutex_g;

/* Completion queue */
static hg_queue_t *hg_handler_completion_queue_g;
static hg_thread_mutex_t hg_handler_completion_queue_mutex_g;

/* Handler request started */
static hg_request_object_t *hg_handler_pending_request_g = NULL;
static struct hg_handle *hg_handler_pending_handle_g = NULL;

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_processing_list_add(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;
    hg_list_entry_t *new_entry = NULL;

    hg_thread_mutex_lock(&hg_handler_processing_list_mutex_g);

    new_entry = hg_list_append(&hg_handler_processing_list_g,
            (hg_list_value_t) hg_handle);
    if (!new_entry) {
        HG_ERROR_DEFAULT("Could not append entry");
        ret = HG_FAIL;
    }
    hg_handle->processing_entry = new_entry;

    hg_thread_mutex_unlock(&hg_handler_processing_list_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_processing_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handler_processing_list_mutex_g);

    /* Remove handle from list if not found */
    if (hg_handle->processing_entry && !hg_list_remove_entry(
            &hg_handler_processing_list_g, hg_handle->processing_entry)) {
        HG_ERROR_DEFAULT("Could not remove entry");
        ret = HG_FAIL;
    }
    hg_handle->processing_entry = NULL;

    hg_thread_mutex_unlock(&hg_handler_processing_list_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_completion_queue_add(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handler_completion_queue_mutex_g);

    if (!hg_queue_push_head(hg_handler_completion_queue_g,
            (hg_queue_value_t) hg_handle)) {
        HG_ERROR_DEFAULT("Could not push handle to completion queue");
        ret = HG_FAIL;
    }

    hg_thread_mutex_unlock(&hg_handler_completion_queue_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_completion_queue_process(void)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handler_completion_queue_mutex_g);

    /* Iterate over entries and test for their completion */
    while (!hg_queue_is_empty(hg_handler_completion_queue_g)) {
        struct hg_handle *hg_handle;

        hg_handle = (struct hg_handle *)
                            hg_queue_pop_tail(hg_handler_completion_queue_g);

        /* Free handle */
        hg_handle_free(hg_handle);
        hg_handle = NULL;
    }

    hg_thread_mutex_unlock(&hg_handler_completion_queue_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_complete(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Remove handle from processing list and add handle to completion queue */
    ret = hg_handler_processing_list_remove(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not remove handle from processing list");
        goto done;
    }
    if (!hg_handle->local) {
        ret = hg_handler_completion_queue_add(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not add handle to completion queue");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_get_extra_input_buf(struct hg_handle *hg_handle,
        hg_bulk_t extra_buf_handle)
{
    hg_bulk_t extra_buf_block_handle = HG_BULK_NULL;
    hg_bulk_request_t extra_buf_request;
    hg_return_t ret = HG_SUCCESS;

    /* Create a new block handle to read the data */
    hg_handle->extra_in_buf_size = HG_Bulk_handle_get_size(extra_buf_handle);
    hg_handle->extra_in_buf = malloc(hg_handle->extra_in_buf_size);
    if (!hg_handle->extra_in_buf) {
        HG_ERROR_DEFAULT("Could not allocate extra recv buf");
        ret = HG_FAIL;
        goto done;
    }

    ret = HG_Bulk_handle_create(hg_handle->extra_in_buf,
            hg_handle->extra_in_buf_size, HG_BULK_READWRITE,
            &extra_buf_block_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create block handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read_all(hg_handle->addr, extra_buf_handle,
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
    if (extra_buf_block_handle != HG_BULK_NULL) {
        ret = HG_Bulk_handle_free(extra_buf_block_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not free block handle");
            ret = HG_FAIL;
        }
        extra_buf_block_handle = HG_BULK_NULL;
    }

    if (extra_buf_handle != HG_BULK_NULL) {
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
hg_return_t
hg_handler_start_processing(struct hg_handle *hg_handle)
{
    struct hg_header_request request_header;
    struct hg_info *hg_info;
    hg_return_t ret = HG_SUCCESS;

    /* When a new request is being treated we must enqueue the handle
     * which is then moved to the completion queue once the user is done
     * with it */
    ret = hg_handler_processing_list_add(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not add handle to processing list");
        goto done;
    }

    /* Decode request header */
    ret = hg_proc_header_request(hg_handle->in_buf,
            hg_handle->in_buf_size, &request_header, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode header");
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
    hg_handle->id = request_header.id;

    /* Get cookie from header */
    hg_handle->cookie = request_header.cookie;

    /* Get extra payload if necessary */
    if (request_header.flags &&
            (request_header.extra_buf_handle != HG_BULK_NULL)) {
        /* This will make the extra_buf the recv_buf associated to the handle */
        ret = hg_handler_get_extra_input_buf(hg_handle,
                request_header.extra_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not recv extra buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* Retrieve exe function from function map */
    hg_info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!hg_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_info->rpc_cb) {
        HG_ERROR_DEFAULT("No RPC callback registered");
        ret = HG_FAIL;
        goto done;
    }

    /* Execute function and fill output parameters */
    ret = hg_info->rpc_cb((hg_handle_t) hg_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error while executing RPC callback");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_handler_recv_input_cb(const struct na_cb_info *callback_info)
{
    /* TODO embed ret into priv_request */
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    /* Fill unexpected info */
    hg_handle->addr = callback_info->info.recv_unexpected.source;
    hg_handle->tag = callback_info->info.recv_unexpected.tag;
    if (callback_info->info.recv_unexpected.actual_buf_size !=
            hg_handle->in_buf_size) {
        HG_ERROR_DEFAULT("Buffer size and actual transfer size do not match");
        goto done;
    }

    /* We just received a new request so mark request as completed so that a
     * new request recv can be posted */
    hg_request_complete(hg_handler_pending_request_g);

done:
    return na_ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_handler_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    /* Remove handle from processing list and add handle to completion queue */
    ret = hg_handler_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not complete handle");
        goto done;
    }

 done:
    return na_ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_handler_init(void)
{
    hg_return_t ret = HG_SUCCESS;

    /* Create completion queue */
    hg_handler_completion_queue_g = hg_queue_new();

    /* Initialize mutex */
    hg_thread_mutex_init(&hg_handler_completion_queue_mutex_g);
    hg_thread_mutex_init(&hg_handler_processing_list_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_handler_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;

    /* If request was started, we must cancel it */
    if (hg_handler_pending_request_g != NULL) {
        /* TODO for now print an error message but cancel it in the future
         * if necessary */
        HG_ERROR_DEFAULT("Posted a request which did not complete");
    }

    /* If requests have not finished processing we must ensure that they are
     * moved to the completion queue before we process it */
    /* TODO move that to request emul */
    while (hg_list_length(hg_handler_processing_list_g)) {
        na_return_t na_ret;
        unsigned int actual_count = 0;

        do {
            na_ret = NA_Trigger(hg_context_g, 0, 1, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);

        if (!hg_list_length(hg_handler_processing_list_g)) break;

        NA_Progress(hg_na_class_g, hg_context_g, 10);
    }

    /* Check if any handles have been non completed have been left */
    ret = hg_handler_completion_queue_process();
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not process completed requests");
        ret = HG_FAIL;
        goto done;
    }
    /* Free completion queue */
    hg_queue_free(hg_handler_completion_queue_g);

    /* Destroy mutex */
    hg_thread_mutex_destroy(&hg_handler_completion_queue_mutex_g);
    hg_thread_mutex_destroy(&hg_handler_processing_list_mutex_g);
done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_get_input_buf(struct hg_handle *hg_handle, void **in_buf,
        size_t *in_buf_size)
{
    void *user_input_buf;
    size_t user_input_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* TODO refactor that */
    user_input_buf = (hg_handle->extra_in_buf) ?
            hg_handle->extra_in_buf : hg_handle->in_buf;
    user_input_buf_size = (hg_handle->extra_in_buf_size) ?
            hg_handle->extra_in_buf_size : hg_handle->in_buf_size;
    /* No offset if extra buffer since only the user payload is copied */
    header_offset = (hg_handle->extra_in_buf) ?
            0 : hg_proc_header_request_get_size();

    /* Space left for request header */
    if (in_buf) *in_buf = (char*) user_input_buf + header_offset;
    if (in_buf_size) *in_buf_size = user_input_buf_size - header_offset;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_get_output_buf(struct hg_handle *hg_handle, void **out_buf,
        size_t *out_buf_size)
{
    void *user_output_buf;
    size_t user_output_buf_size;
    size_t header_offset;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle->out_buf) {
        /* Buffer must match the size of unexpected buffer */
        hg_handle->out_buf_size = NA_Msg_get_max_expected_size(hg_na_class_g);

        hg_handle->out_buf = hg_proc_buf_alloc(hg_handle->out_buf_size);
        if (!hg_handle->out_buf) {
            HG_ERROR_DEFAULT("Could not allocate buffer for output");
            ret = HG_FAIL;
            goto done;
        }
    }

    user_output_buf = hg_handle->out_buf;
    user_output_buf_size = hg_handle->out_buf_size;
    header_offset = hg_proc_header_response_get_size();

    /* We don't want the user to mess with the header so don't let him see it */
    if (out_buf) *out_buf = (char*) user_output_buf + header_offset;
    if (out_buf_size) *out_buf_size = user_output_buf_size - header_offset;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_get_input(struct hg_handle *hg_handle, void *in_struct)
{
    void *in_buf;
    size_t in_buf_size;
    struct hg_info *hg_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!in_struct) goto done;

    /* Get input buffer */
    ret = hg_handler_get_input_buf(hg_handle, &in_buf, &in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        goto done;
    }

    /* Retrieve decode function from function map */
    hg_info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!hg_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_info->in_proc_cb) goto done;

    /* Create a new decoding proc */
    ret = hg_proc_create(in_buf, in_buf_size, HG_DECODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Decode input parameters */
    ret = hg_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not decode input parameters");
        goto done;
    }

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_free_input(struct hg_handle *hg_handle, void *in_struct)
{
    struct hg_info *hg_info;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!in_struct) goto done;

    /* Retrieve encoding function from function map */
    hg_info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!hg_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_info->in_proc_cb) goto done;

    /* Create a new free proc */
    ret = hg_proc_create(NULL, 0, HG_FREE, HG_NOHASH, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Free memory allocated during decode operation */
    ret = hg_info->in_proc_cb(proc, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not free allocated parameters");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_set_output(struct hg_handle *hg_handle, void *out_struct)
{
    void *out_buf;
    size_t out_buf_size;
    struct hg_info *hg_info = NULL;
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!out_struct) goto done;

    /* Get output buffer */
    ret = hg_handler_get_output_buf(hg_handle, &out_buf, &out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output buffer");
        goto done;
    }

    /* Retrieve decode function from function map */
    hg_info = (struct hg_info *) hg_hash_table_lookup(hg_func_map_g,
            (hg_hash_table_key_t) &hg_handle->id);
    if (!hg_info) {
        HG_ERROR_DEFAULT("hg_hash_table_lookup failed");
        ret = HG_FAIL;
        goto done;
    }

    if (!hg_info->out_proc_cb) goto done;

    /* Create a new encoding proc */
    ret = hg_proc_create(out_buf, out_buf_size, HG_ENCODE, HG_CRC64, &proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not create proc");
        goto done;
    }

    /* Encode output parameters */
    ret = hg_info->out_proc_cb(proc, out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode output parameters");
        goto done;
    }

#if 0
    /* TODO need to do something here */
    /* Get eventual extra buffer */
    if (hg_proc_get_extra_buf(proc)) {
        void *out_extra_buf = NULL;
        size_t out_extra_buf_size = 0;

        out_extra_buf = hg_proc_get_extra_buf(proc);
        out_extra_buf_size = hg_proc_get_extra_size(proc);
        hg_proc_set_extra_buf_is_mine(proc, HG_TRUE);
    }
#endif

    /* Flush proc */
    ret = hg_proc_flush(proc);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Error in proc flush");
        goto done;
    }

done:
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    return ret;
}

/*---------------------------------------------------------------------------*/
na_addr_t
HG_Handler_get_addr(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    na_addr_t ret = NULL;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        goto done;
    }

    ret = hg_handle->addr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_input_buf(hg_handle_t handle, void **in_buf, size_t *in_buf_size)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_handler_get_input_buf(hg_handle, in_buf, in_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input buffer");
        ret = HG_FAIL;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_output_buf(hg_handle_t handle, void **out_buf,
        size_t *out_buf_size)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_handler_get_output_buf(hg_handle, out_buf, out_buf_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get output buffer");
        ret = HG_FAIL;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_process(unsigned int timeout, hg_status_t *status)
{
    unsigned int flag = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Check if previous handles have completed */
    hg_handler_completion_queue_process();

    /* Start a new request if none already started */
    if (!hg_handler_pending_request_g) {
        ret = hg_handler_start_request();
        if (ret != HG_SUCCESS) goto done;
    }

    if (hg_request_wait(hg_handler_pending_request_g, timeout, &flag)
            != HG_UTIL_SUCCESS) {
        HG_ERROR_DEFAULT("Could not wait on send_request");
        ret = HG_FAIL;
        goto done;
    }

    if (flag) {
        /* Start processing request */
        hg_handler_start_processing(hg_handler_pending_handle_g);
        /* Destroy request */
        hg_request_destroy(hg_handler_pending_request_g);
        hg_handler_pending_request_g = NULL;
    }

done:
    if (status && (status != HG_STATUS_IGNORE)) {
        *status = (hg_status_t) flag;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_handler_start_request(void)
{
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Create a new handle */
    hg_handle = hg_handle_new();
    if (!hg_handle) {
        HG_ERROR_DEFAULT("Could not create new handle");
        ret = HG_FAIL;
        goto done;
    }

    /* Recv buffer must match the size of unexpected buffer */
    hg_handle->in_buf_size =
            NA_Msg_get_max_unexpected_size(hg_na_class_g);

    /* Allocate a new receive buffer for the unexpected message */
    hg_handle->in_buf = hg_proc_buf_alloc(hg_handle->in_buf_size);
    if (!hg_handle->in_buf) {
        HG_ERROR_DEFAULT("Could not allocate input buffer");
        ret = HG_FAIL;
        goto done;
    }

    /* Create a new pending request */
    hg_handler_pending_request_g = hg_request_create(hg_request_class_g);
    hg_handler_pending_handle_g = hg_handle;

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_na_class_g, hg_context_g,
            hg_handler_recv_input_cb, hg_handle, hg_handle->in_buf,
            hg_handle->in_buf_size, NA_OP_ID_IGNORE);
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
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    /* if get_output has not been called, call it to create to send_buf */
    ret = hg_handler_get_output_buf(hg_handle, NULL, NULL);
     if (ret != HG_SUCCESS) {
         HG_ERROR_DEFAULT("Could not get output");
         ret = HG_FAIL;
         goto done;
     }

    /**
     * Check out_buf_size, if it's bigger than the size of the pre-posted buffer
     * we need to use an extra buffer again.
     * TODO not supported for now
     */
    if (extra_out_buf_size > hg_handle->out_buf_size) {
        if (!extra_out_buf) {
            HG_ERROR_DEFAULT("No extra buffer given");
            ret = HG_FAIL;
            goto done;
        }
        hg_handle->extra_out_buf = extra_out_buf;
        hg_handle->extra_out_buf_size = extra_out_buf_size;
    }

    /* Fill the header */
    hg_proc_header_response_init(&response_header);
    response_header.cookie = hg_handle->cookie;

    /* Encode response header */
    ret = hg_proc_header_response(hg_handle->out_buf,
            hg_handle->out_buf_size, &response_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not encode header");
        ret = HG_FAIL;
        goto done;
    }

    if (hg_handle->local) {

        /* Mark handle as completed */
        ret = hg_handler_complete(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Could not complete handle");
            goto done;
        }

        /**
         * In the case of coresident stack signal the waiting thread that
         * the call has been processed
         * TODO should not be necessary anymore when switched to callbacks
         */
        hg_thread_mutex_lock(&hg_handle->processed_mutex);

        hg_handle->processed = HG_TRUE;
        hg_thread_cond_signal(&hg_handle->processed_cond);

        hg_thread_mutex_unlock(&hg_handle->processed_mutex);
    } else {
        /* Respond back */
        na_ret = NA_Msg_send_expected(hg_na_class_g, hg_context_g,
                hg_handler_send_output_cb, hg_handle, hg_handle->out_buf,
                hg_handle->out_buf_size, hg_handle->addr, hg_handle->tag,
                NA_OP_ID_IGNORE);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("Could not post send for output buffer");
            ret = HG_FAIL;
            goto done;
        }
    }

    /* TODO Also add extra buffer response */

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_free(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        return ret;
    }

    hg_handle_free(hg_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_get_input(hg_handle_t handle, void *in_struct)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    if (!in_struct) {
        HG_ERROR_DEFAULT("NULL pointer to input struct");
        ret = HG_FAIL;
        goto done;
    }

// TODO clean up
//    /* Keep reference to in_struct to free decoded params later */
//    hg_handle->in_struct = in_struct;

    ret = hg_handler_get_input(hg_handle, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get input");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_start_output(hg_handle_t handle, void *out_struct)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_handler_set_output(hg_handle, out_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not set output");
        goto done;
    }

// TODO clean up
    /* TODO remove that and make it a separate call */
//    ret = hg_handler_free_input(hg_handle, hg_handle->input_struct);
//    if (ret != HG_SUCCESS) {
//        HG_ERROR_DEFAULT("Could not free input");
//        goto done;
//    }

    /* Start sending response back, this should be the last operation called
     * that uses the handle as HG_Handler_process may free the handle as soon
     * as the response completes */
    ret = HG_Handler_start_response(handle, NULL, 0);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not respond");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Handler_free_input(hg_handle_t handle, void *in_struct)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_ERROR_DEFAULT("NULL handle");
        ret = HG_FAIL;
        goto done;
    }

    ret = hg_handler_free_input(hg_handle, in_struct);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Could not free input");
        goto done;
    }

done:
    return ret;
}
