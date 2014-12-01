/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_core.h"

#include "mercury_proc_header.h"
#include "mercury_proc.h"
#include "mercury_bulk.h"
#include "mercury_error.h"

#include "mercury_hash_table.h"
#include "mercury_hash_string.h"
#include "mercury_atomic.h"
#include "mercury_queue.h"
#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/
#define HG_MAX_UNEXPECTED_RECV 256 /* TODO Variable */

/* Convert value to string */
#define HG_ERROR_STRING_MACRO(def, value, string) \
  if (value == def) string = #def

/* Remove warnings when routine does not use arguments */
#if defined(__cplusplus)
    #define HG_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #define HG_UNUSED __attribute__((unused))
#else
    #define HG_UNUSED
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_class {
    na_class_t *na_class;           /* NA class */
    na_context_t *na_context;       /* NA context */
    hg_bulk_class_t *bulk_class;    /* HG Bulk class */
    hg_bool_t bulk_class_external;  /* Is Bulk class external */
    hg_hash_table_t *func_map;      /* Function map */
    hg_atomic_int32_t request_tag;  /* Atomic used for tag generation */
    na_tag_t request_max_tag;       /* Max value for tag */
};

/* HG context */
struct hg_context {
    hg_class_t *hg_class;
    hg_bulk_context_t *bulk_context;
    hg_queue_t *completion_queue;
    hg_thread_mutex_t completion_queue_mutex;
    hg_thread_cond_t completion_queue_cond;
    hg_list_entry_t *pending_list;
    hg_thread_mutex_t pending_list_mutex;
    hg_list_entry_t *processing_list;
    hg_thread_mutex_t processing_list_mutex;
};

/* Info for function map */
struct hg_rpc_info {
    hg_rpc_cb_t rpc_cb;             /* RPC callback */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
};

/* Info for wrapping callbacks if self addr */
struct hg_self_cb_info {
    hg_cb_t forward_cb;
    void *forward_arg;
    hg_cb_t respond_cb;
    void *respond_arg;
};

/* HG op id */
struct hg_handle {
    struct hg_info hg_info;             /* HG info */
    hg_cb_t callback;                   /* Callback */
    void *arg;                          /* Callback arguments */
    na_tag_t tag;                       /* Tag used for request and response */
    hg_uint32_t cookie;                 /* Cookie unique to every RPC call */
    hg_return_t ret;                    /* Return code associated to handle */
    hg_bool_t addr_mine;                /* NA Addr created by HG */

    void *in_buf;                       /* Input buffer */
    na_size_t in_buf_size;              /* Input buffer size */
    void *out_buf;                      /* Output buffer */
    na_size_t out_buf_size;             /* Output buffer size */

    na_op_id_t na_send_op_id;           /* Operation ID for send */
    na_op_id_t na_recv_op_id;           /* Operation ID for recv */
    hg_atomic_int32_t na_completed_count; /* Number of NA operations completed */

    hg_atomic_int32_t ref_count;        /* Reference count */

    void *extra_in_buf;
    hg_size_t extra_in_buf_size;
    hg_op_id_t extra_in_op_id;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Get extra user payload using bulk transfer.
 * TODO this may be moved to the upper mercury layer.
 */
static hg_return_t
hg_get_extra_input_buf(
        struct hg_handle *hg_handle,
        hg_bulk_t extra_in_handle
        );

/**
 * Bulk transfer callback.
 */
static hg_return_t
hg_get_extra_input_buf_cb(
        const struct hg_bulk_cb_info *callback_info
        );

/**
 * Get request header and verify it.
 */
static hg_return_t
hg_get_header_request(
        struct hg_handle *hg_handle,
        struct hg_header_request *request_header
        );

/**
 * Remove handle from pending list.
 */
static hg_return_t
hg_pending_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Check pending list.
 */
static hg_bool_t
hg_pending_list_check(
        hg_context_t *context
        );

/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_pending_list_cancel(
        hg_context_t *context
        );

/**
 * Add handle to processing list.
 */
static hg_return_t
hg_processing_list_add(
        struct hg_handle *hg_handle
        );

/**
 * Remove handle from processing list.
 */
static hg_return_t
hg_processing_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Wail until processing list is empty.
 */
static hg_return_t
hg_processing_list_wait(
        hg_context_t *context
        );

/**
 * Create handle.
 */
static struct hg_handle *
hg_create(
        hg_class_t *hg_class,
        hg_context_t *context
        );

/**
 * Free handle.
 */
static void
hg_destroy(
        struct hg_handle *hg_handle
        );

/**
 * Send input callback.
 */
static na_return_t
hg_send_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv input callback.
 */
static na_return_t
hg_recv_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Send output callback.
 */
static na_return_t
hg_send_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv output callback.
 */
static na_return_t
hg_recv_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Process handle.
 */
static hg_return_t
hg_process(
        struct hg_handle *hg_handle
        );

/**
 * Complete handle and add to completion queue.
 */
static hg_return_t
hg_complete(
        struct hg_handle *hg_handle
        );

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_listen(
        hg_class_t *hg_class,
        hg_context_t *context
        );

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_progress(
        hg_class_t *hg_class,
        hg_context_t *context,
        unsigned int timeout
        );

/**
 * Cancel handle.
 */
static hg_return_t
hg_cancel(
        struct hg_handle *hg_handle
        );

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
/**
 * Equal function for function map.
 */
static HG_INLINE int
hg_int_equal(void *vlocation1, void *vlocation2)
{
    return *((int *) vlocation1) == *((int *) vlocation2);
}

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_int_hash(void *vlocation)
{
    return *((unsigned int *) vlocation);
}

/*---------------------------------------------------------------------------*/
/**
 * Free function for value in function map.
 */
static HG_INLINE void
hg_func_map_value_free(hg_hash_table_value_t value)
{
    struct hg_rpc_info *hg_rpc_info = (struct hg_rpc_info *) value;

    if (hg_rpc_info->free_callback)
        hg_rpc_info->free_callback(hg_rpc_info->data);
    free(hg_rpc_info);
}

/*---------------------------------------------------------------------------*/
/**
 * Equal function for handle.
 */
static HG_INLINE int
hg_handle_equal(hg_list_value_t value1, hg_list_value_t value2)
{
    return ((struct hg_handle *) value1) == ((struct hg_handle *) value2);
}

/*---------------------------------------------------------------------------*/
/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_gen_request_tag(hg_class_t *hg_class)
{
    na_tag_t tag = 0;

    /* Compare and swap tag if reached max tag */
    if (!hg_atomic_cas32(&hg_class->request_tag, hg_class->request_max_tag, 0)) {
        /* Increment tag */
        tag = hg_atomic_incr32(&hg_class->request_tag);
    }

    return tag;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_get_input_buf(struct hg_handle *hg_handle, void **in_buf,
        hg_size_t *in_buf_size)
{
    /* No offset if extra buffer since only the user payload is copied */
    hg_size_t header_offset = (hg_handle->extra_in_buf) ? 0 :
            hg_proc_header_request_get_size();

    /* Space must be left for request header */
    *in_buf = (char *) ((hg_handle->extra_in_buf) ?
            hg_handle->extra_in_buf : hg_handle->in_buf) + header_offset;
    *in_buf_size = (hg_handle->extra_in_buf_size) ?
            hg_handle->extra_in_buf_size :
            hg_handle->in_buf_size - header_offset;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_get_output_buf(struct hg_handle *hg_handle, void **out_buf,
        hg_size_t *out_buf_size)
{
    hg_size_t header_offset = hg_proc_header_response_get_size();

    /* Space must be left for response header */
    *out_buf = (char *) hg_handle->out_buf + header_offset;
    *out_buf_size = hg_handle->out_buf_size - header_offset;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_input_buf(struct hg_handle *hg_handle, hg_bulk_t extra_in_handle)
{
    hg_bulk_class_t *hg_bulk_class = hg_handle->hg_info.hg_bulk_class;
    hg_bulk_context_t *hg_bulk_context = hg_handle->hg_info.bulk_context;
    hg_bulk_t local_in_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Create a new local handle to read the data */
    hg_handle->extra_in_buf_size = HG_Bulk_get_size(extra_in_handle);
    hg_handle->extra_in_buf = calloc(hg_handle->extra_in_buf_size, sizeof(char));
    if (!hg_handle->extra_in_buf) {
        HG_LOG_ERROR("Could not allocate extra input buffer");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    ret = HG_Bulk_create(hg_bulk_class, 1, &hg_handle->extra_in_buf,
            &hg_handle->extra_in_buf_size, HG_BULK_READWRITE, &local_in_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create HG bulk handle");
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_transfer(hg_bulk_context, hg_get_extra_input_buf_cb,
            hg_handle, HG_BULK_PULL, hg_handle->hg_info.addr, extra_in_handle,
            0, local_in_handle, 0, hg_handle->extra_in_buf_size,
            &hg_handle->extra_in_op_id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not transfer bulk data");
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        HG_Bulk_free(local_in_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_extra_input_buf_cb(const struct hg_bulk_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Free bulk handle */
    ret = HG_Bulk_free(callback_info->local_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free bulk handle");
        goto done;
    }

    /* TODO should be freed with header request proc but clean that up when
     * extra handle is clean
     */
    ret = HG_Bulk_free(callback_info->origin_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free bulk handle");
        goto done;
    }

    /* Now can process the handle */
    ret = hg_process(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_get_header_request(struct hg_handle *hg_handle,
        struct hg_header_request *request_header)
{
    hg_return_t ret = HG_SUCCESS;

    /* Initialize header with default values */
    hg_proc_header_request_init(0, HG_BULK_NULL, request_header);

    /* Decode request header */
    ret = hg_proc_header_request(hg_handle->in_buf, hg_handle->in_buf_size,
            request_header, HG_DECODE, hg_handle->hg_info.hg_bulk_class);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decode header");
        goto done;
    }

    ret = hg_proc_header_request_verify(request_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not verify header");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_pending_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->pending_list_mutex);

    if (!hg_list_remove_data(&hg_handle->hg_info.context->pending_list,
            hg_handle_equal, (hg_list_value_t) hg_handle)) {
        HG_LOG_ERROR("Could not remove entry");
        ret = HG_INVALID_PARAM;
    }

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_bool_t
hg_pending_list_check(hg_context_t *context)
{
    hg_bool_t ret = HG_FALSE;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    ret = hg_list_length(context->pending_list) ? HG_TRUE : HG_FALSE;

    hg_thread_mutex_unlock(&context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_pending_list_cancel(hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    while (hg_list_length(context->pending_list)) {
        hg_list_entry_t *entry = context->pending_list;
        struct hg_handle *hg_handle = (struct hg_handle *) hg_list_data(entry);

        ret = hg_cancel(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not cancel handle");
            break;
        }

        if (!hg_list_remove_entry(&context->pending_list, entry)) {
            HG_LOG_ERROR("Could not remove entry");
            ret = HG_INVALID_PARAM;
            break;
        }
    }

    hg_thread_mutex_unlock(&context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_processing_list_add(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->processing_list_mutex);

    if (!hg_list_append(&hg_handle->hg_info.context->processing_list,
            (hg_list_value_t) hg_handle)) {
        HG_LOG_ERROR("Could not append entry");
        ret = HG_NOMEM_ERROR;
    }

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_processing_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->processing_list_mutex);

    if (!hg_list_remove_data(&hg_handle->hg_info.context->processing_list,
            hg_handle_equal, (hg_list_value_t) hg_handle)) {
        HG_LOG_ERROR("Could not remove entry");
        ret = HG_INVALID_PARAM;
    }

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_processing_list_wait(hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    while (1) {
        unsigned int processing_list_length = 0;
        unsigned int actual_count = 0;
        hg_return_t trigger_ret;

        /* Trigger everything we can from HG */
        do {
            trigger_ret = HG_Trigger(context->hg_class, context, 0, 1,
                    &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&context->processing_list_mutex);

        processing_list_length = hg_list_length(context->processing_list);

        hg_thread_mutex_unlock(&context->processing_list_mutex);

        if (!processing_list_length) break;

        ret = hg_progress(context->hg_class, context, HG_MAX_IDLE_TIME);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not make progress");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_handle *
hg_create(hg_class_t *hg_class, hg_context_t *context)
{
    na_class_t *na_class = hg_class->na_class;
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (!hg_handle) {
        HG_LOG_ERROR("Could not allocate handle");
        goto done;
    }

    hg_handle->hg_info.hg_class = hg_class;
    hg_handle->hg_info.context = context;
    hg_handle->hg_info.hg_bulk_class = hg_class->bulk_class;
    hg_handle->hg_info.bulk_context = context->bulk_context;
    hg_handle->hg_info.addr = NA_ADDR_NULL;
    hg_handle->hg_info.id = 0;
    hg_handle->callback = NULL;
    hg_handle->arg = NULL;
    hg_handle->cookie = 0; /* TODO Generate cookie */
    hg_handle->tag = 0;
    hg_handle->ret = HG_SUCCESS;
    hg_handle->addr_mine = HG_FALSE;

    /* Initialize processing buffers and use unexpected message size */
    hg_handle->in_buf = NULL;
    hg_handle->out_buf = NULL;
    hg_handle->in_buf_size = NA_Msg_get_max_expected_size(na_class);
    hg_handle->out_buf_size = NA_Msg_get_max_expected_size(na_class);

    hg_handle->in_buf = hg_proc_buf_alloc(hg_handle->in_buf_size);
    if (!hg_handle->in_buf) {
        HG_LOG_ERROR("Could not allocate buffer for input");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_handle->out_buf = hg_proc_buf_alloc(hg_handle->out_buf_size);
    if (!hg_handle->out_buf) {
        HG_LOG_ERROR("Could not allocate buffer for output");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    hg_handle->na_send_op_id = NA_OP_ID_NULL;
    hg_handle->na_recv_op_id = NA_OP_ID_NULL;
    hg_atomic_set32(&hg_handle->na_completed_count, 0);

    hg_atomic_set32(&hg_handle->ref_count, 1);

    hg_handle->extra_in_buf = NULL;
    hg_handle->extra_in_buf_size = 0;
    hg_handle->extra_in_op_id = HG_OP_ID_NULL;

done:
    if (ret != HG_SUCCESS) {
        hg_destroy(hg_handle);
    }
    return hg_handle;
}

/*---------------------------------------------------------------------------*/
static void
hg_destroy(struct hg_handle *hg_handle)
{
    if (!hg_handle) goto done;

    if (hg_atomic_decr32(&hg_handle->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Free if mine */
    if (hg_handle->hg_info.addr != NA_ADDR_NULL && hg_handle->addr_mine)
        NA_Addr_free(hg_handle->hg_info.hg_class->na_class,
                hg_handle->hg_info.addr);

    hg_proc_buf_free(hg_handle->in_buf);
    hg_proc_buf_free(hg_handle->out_buf);

    free(hg_handle->extra_in_buf);

    free(hg_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Add handle to completion queue only when send_input and recv_output have
     * completed */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_header_request request_header;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        goto done;
    }

    /* Increment NA completed count */
    hg_atomic_incr32(&hg_handle->na_completed_count);

    /* Fill unexpected info */
    hg_handle->hg_info.addr = callback_info->info.recv_unexpected.source;
    hg_handle->addr_mine = HG_TRUE; /* Address will be freed with handle */
    hg_handle->tag = callback_info->info.recv_unexpected.tag;
    if (callback_info->info.recv_unexpected.actual_buf_size
            != hg_handle->in_buf_size) {
        HG_LOG_ERROR("Buffer size and actual transfer size do not match");
        goto done;
    }

    /* Move handle from pending list to processing list */
    if (hg_pending_list_remove(hg_handle) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not remove handle from pending list");
        goto done;
    }
    if (hg_processing_list_add(hg_handle) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add handle to processing list");
        goto done;
    }

    /* As we removed handle from pending list repost unexpected receives */
    if (NA_Is_listening(hg_handle->hg_info.hg_class->na_class)) {
        hg_listen(hg_handle->hg_info.hg_class, hg_handle->hg_info.context);
    }

    /* Get and verify header */
    if (hg_get_header_request(hg_handle, &request_header) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get request header");
        goto done;
    }

    /* Get operation ID from header */
    hg_handle->hg_info.id = request_header.id;
    hg_handle->cookie = request_header.cookie;

    if (request_header.flags
            && (request_header.extra_in_handle != HG_BULK_NULL)) {
        /* Get extra payload */
        if (hg_get_extra_input_buf(hg_handle, request_header.extra_in_handle)
                != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get extra input buffer");
            goto done;
        }
    } else {
        /* Process handle */
        if (hg_process(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not process handle");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Remove handle from processing list */
    if (hg_processing_list_remove(hg_handle) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not remove handle from processing list");
        goto done;
    }

    /* Mark as completed (sanity check: NA completed count should be 2 here) */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        if (hg_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_header_response response_header;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Initialize header with default values */
    hg_proc_header_response_init(&response_header);

    /* Decode response header */
    if (hg_proc_header_response(hg_handle->out_buf, hg_handle->out_buf_size,
            &response_header, HG_DECODE) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decode header");
        goto done;
    }

    /* Verify header and set return code */
    if (hg_proc_header_response_verify(&response_header) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not verify header");
        goto done;
    }
    hg_handle->ret = (hg_return_t) response_header.ret_code;

    /* Add handle to completion queue only when send_input and recv_output have
     * completed */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_process(struct hg_handle *hg_handle)
{
    hg_class_t *hg_class = hg_handle->hg_info.hg_class;
    struct hg_rpc_info *hg_rpc_info;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve exe function from function map */
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(
            hg_class->func_map, (hg_hash_table_key_t) &hg_handle->hg_info.id);
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_rpc_info->rpc_cb) {
        HG_LOG_ERROR("No RPC callback registered");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Increment ref count here so that a call to HG_Destroy in user's RPC
     * callback does not free the handle but only schedules its completion */
    hg_atomic_incr32(&hg_handle->ref_count);

    /* Execute RPC callback */
    ret = hg_rpc_info->rpc_cb((hg_handle_t) hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error while executing RPC callback");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_complete(struct hg_handle *hg_handle)
{
    hg_context_t *context = hg_handle->hg_info.context;
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&context->completion_queue_mutex);

    /* Add handle to completion queue */
    if (!hg_queue_push_head(context->completion_queue,
            (hg_queue_value_t) hg_handle)) {
        HG_LOG_ERROR("Could not push completion data to completion queue");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Callback is pushed to the completion queue when something completes
     * so wake up anyone waiting in the trigger */
    hg_thread_cond_signal(&context->completion_queue_cond);

done:
    hg_thread_mutex_unlock(&context->completion_queue_mutex);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_listen(hg_class_t *hg_class, hg_context_t *context)
{
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    if (hg_list_length(context->pending_list) > 0) goto done;

    while (hg_list_length(context->pending_list) < HG_MAX_UNEXPECTED_RECV) {
        hg_list_entry_t *new_entry = NULL;

        /* Create a new handle */
        hg_handle = hg_create(hg_class, context);
        if (!hg_handle) {
            HG_LOG_ERROR("Could not create HG handle");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        new_entry = hg_list_append(&context->pending_list,
                (hg_list_value_t) hg_handle);
        if (!new_entry) {
            HG_LOG_ERROR("Could not append handle to pending list");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        /* Post a new unexpected receive */
        na_ret = NA_Msg_recv_unexpected(hg_class->na_class, hg_class->na_context,
                hg_recv_input_cb, hg_handle, hg_handle->in_buf,
                hg_handle->in_buf_size, &hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post unexpected recv for input buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

done:
    hg_thread_mutex_unlock(&context->pending_list_mutex);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_progress(hg_class_t *hg_class, hg_context_t *context, unsigned int timeout)
{
    unsigned int actual_count = 0;
    hg_bool_t completion_queue_empty = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;
    hg_return_t bulk_ret;
    na_return_t na_ret;

    /* Trigger everything we can from NA */
    do {
        na_ret = NA_Trigger(hg_class->na_context, 0, 1, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);

    /* Trigger everything from HG Bulk */
    do {
        bulk_ret = HG_Bulk_trigger(hg_class->bulk_class, context->bulk_context,
                0, 1, &actual_count);
    } while ((bulk_ret == HG_SUCCESS) && actual_count);

    /* Is completion queue empty */
    hg_thread_mutex_lock(&context->completion_queue_mutex);

    completion_queue_empty = (hg_bool_t) hg_queue_is_empty(
            context->completion_queue);

    hg_thread_mutex_unlock(&context->completion_queue_mutex);

    /* If something is in context completion queue just return */
    if (!completion_queue_empty) goto done;

    /* Otherwise try to make progress on NA */
    na_ret = NA_Progress(hg_class->na_class, hg_class->na_context, timeout);
    if (na_ret != NA_SUCCESS) {
        if (na_ret == NA_TIMEOUT)
            ret = HG_TIMEOUT;
        else {
            HG_LOG_ERROR("Could not make NA Progress");
            ret = HG_NA_ERROR;
        }
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_execute_callback(struct hg_handle *hg_handle)
{
    struct hg_cb_info hg_cb_info;

    hg_cb_info.arg = hg_handle->arg;
    hg_cb_info.ret = hg_handle->ret;
    hg_cb_info.hg_class = hg_handle->hg_info.context->hg_class;
    hg_cb_info.context = hg_handle->hg_info.context;
    hg_cb_info.handle = (hg_handle_t) hg_handle;

    /* Execute callback */
    hg_handle->callback(&hg_cb_info);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_self_cb(const struct hg_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->handle;
    struct hg_self_cb_info *hg_self_cb_info =
            (struct hg_self_cb_info *) callback_info->arg;
    hg_return_t ret;

    /* First execute response callback */
    if (hg_self_cb_info->respond_cb) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_self_cb_info->respond_arg;
        hg_cb_info.ret = HG_SUCCESS; /* TODO report failure */
        hg_cb_info.hg_class = hg_handle->hg_info.context->hg_class;
        hg_cb_info.context = hg_handle->hg_info.context;
        hg_cb_info.handle = (hg_handle_t) hg_handle;

        hg_self_cb_info->respond_cb(&hg_cb_info);
    }

    /* Assign forward callback back to handle */
    hg_handle->callback = hg_self_cb_info->forward_cb;
    hg_handle->arg = hg_self_cb_info->forward_arg;

    /* Increment refcount and push handle back to completion queue */
    hg_atomic_incr32(&hg_handle->ref_count);

    ret = hg_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete handle");
        goto done;
    }

    free(hg_self_cb_info);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_cancel(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    hg_return_t ret = HG_SUCCESS;

    /* Cancel all NA operations issued */
    if (hg_handle->na_recv_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_class->na_class, hg_class->na_context,
                hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel recv op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
    if (hg_handle->na_send_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_class->na_class, hg_class->na_context,
                hg_handle->na_send_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel send op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
    /* Free op */
    hg_destroy(hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch)
{
    hg_return_t ret = HG_SUCCESS;

    if (major) *major = HG_VERSION_MAJOR;
    if (minor) *minor = HG_VERSION_MINOR;
    if (patch) *patch = HG_VERSION_PATCH;

    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Error_to_string(hg_return_t errnum)
{
    const char *hg_error_string = "UNDEFINED/UNRECOGNIZED NA ERROR";

    HG_ERROR_STRING_MACRO(HG_SUCCESS, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_TIMEOUT, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_INVALID_PARAM, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_SIZE_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NOMEM_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_PROTOCOL_ERROR, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_NO_MATCH, errnum, hg_error_string);
    HG_ERROR_STRING_MACRO(HG_CHECKSUM_ERROR, errnum, hg_error_string);

    return hg_error_string;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Init(na_class_t *na_class, na_context_t *na_context,
        hg_bulk_class_t *hg_bulk_class)
{
    struct hg_class *hg_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_LOG_ERROR("Invalid specified na_class");
        ret = HG_INVALID_PARAM;
        goto done;

    }
    if (!na_context) {
        HG_LOG_ERROR("Invalid specified na_context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Create new HG class */
    hg_class = (struct hg_class *) malloc(sizeof(struct hg_class));
    if (!hg_class) {
        HG_LOG_ERROR("Could not allocate HG class");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    hg_class->na_class = na_class;
    hg_class->na_context = na_context;
    hg_class->bulk_class = NULL;
    hg_class->func_map = NULL;

    /* Initialize atomic for tags */
    hg_class->request_max_tag = NA_Msg_get_max_tag(na_class);
    hg_atomic_set32(&hg_class->request_tag, 0);

    /* Create new function map */
    hg_class->func_map = hg_hash_table_new(hg_int_hash, hg_int_equal);
    if (!hg_class->func_map) {
        HG_LOG_ERROR("Could not create function map");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_class->func_map, free,
            hg_func_map_value_free);

    if (hg_bulk_class) {
        hg_class->bulk_class_external = HG_TRUE;
        /* Handled by user */
        hg_class->bulk_class = hg_bulk_class;
    } else {
        hg_class->bulk_class_external = HG_FALSE;
        /* If not initialize HG Bulk */
        hg_class->bulk_class = HG_Bulk_init(na_class, na_context);
        if (!hg_class->bulk_class) {
            HG_LOG_ERROR("Could not initialize HG Bulk class");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
    }

done:
    if (ret != HG_SUCCESS) {
        HG_Finalize(hg_class);
    }
    return hg_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Finalize(hg_class_t *hg_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) goto done;

    if (!hg_class->bulk_class_external) {
        /* Finalize bulk class */
        ret = HG_Bulk_finalize(hg_class->bulk_class);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not finalize HG Bulk class");
            goto done;
        }
    }

    /* Delete function map */
    hg_hash_table_free(hg_class->func_map);
    hg_class->func_map = NULL;

    /* Free HG class */
    free(hg_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_context_t *
HG_Context_create(hg_class_t *hg_class)
{
    hg_return_t ret = HG_SUCCESS;
    hg_context_t *context = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context = (hg_context_t *) malloc(sizeof(hg_context_t));
    if (!context) {
        HG_LOG_ERROR("Could not allocate HG context");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    context->hg_class = hg_class;
    context->bulk_context = NULL;
    context->completion_queue = hg_queue_new();
    if (!context->completion_queue) {
        HG_LOG_ERROR("Could not create completion queue");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    context->pending_list = NULL;
    context->processing_list = NULL;

    /* Create bulk context for internal transfer in case of overflow
     * TODO may allow user to pass its own HG Bulk context */
    context->bulk_context = HG_Bulk_context_create(hg_class->bulk_class);
    if (!context->bulk_context) {
        HG_LOG_ERROR("Could not create HG Bulk context");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&context->completion_queue_mutex);
    hg_thread_cond_init(&context->completion_queue_cond);
    hg_thread_mutex_init(&context->pending_list_mutex);
    hg_thread_mutex_init(&context->processing_list_mutex);

done:
    if (ret != HG_SUCCESS && context) {
        hg_queue_free(context->completion_queue);
        HG_Bulk_context_destroy(context->bulk_context);
        free(context);
    }
    return context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Context_destroy(hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) goto done;

    /* Check pending list */
    if (hg_pending_list_check(context) == HG_TRUE) {
        ret = hg_pending_list_cancel(context);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot cancel list of pending entries");
            goto done;
        }
    }

    /* Check that NA operations have completed */
    ret = hg_processing_list_wait(context);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not wait on processing list");
        goto done;
    }

    /* Check that completion queue is empty now */
    hg_thread_mutex_lock(&context->completion_queue_mutex);

    if (!hg_queue_is_empty(context->completion_queue)) {
        HG_LOG_ERROR("Completion queue should be empty");
        ret = HG_PROTOCOL_ERROR;
        hg_thread_mutex_unlock(&context->completion_queue_mutex);
        goto done;
    }

    hg_thread_mutex_unlock(&context->completion_queue_mutex);

    /* Destroy completion queue */
    hg_queue_free(context->completion_queue);
    context->completion_queue = NULL;

    /* Destroy bulk context */
    ret = HG_Bulk_context_destroy(context->bulk_context);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy HG Bulk context");
        goto done;
    }
    context->bulk_context = NULL;

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&context->completion_queue_mutex);
    hg_thread_cond_destroy(&context->completion_queue_cond);
    hg_thread_mutex_destroy(&context->pending_list_mutex);
    hg_thread_mutex_destroy(&context->processing_list_mutex);

    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_id_t
HG_Register_rpc(hg_class_t *hg_class, const char *func_name, hg_rpc_cb_t rpc_cb)
{
    hg_id_t ret = 0;
    hg_id_t *id = NULL;
    struct hg_rpc_info *hg_rpc_info = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    /* Generate a key from the string */
    id = (hg_id_t *) malloc(sizeof(hg_id_t));
    if (!id) {
        HG_LOG_ERROR("Could not allocate ID");
        goto done;
    }

    *id = hg_hash_string(func_name);

    /* Fill info and store it into the function map */
    hg_rpc_info = (struct hg_rpc_info *) malloc(sizeof(struct hg_rpc_info));
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not allocate HG info");
        goto done;
    }

    hg_rpc_info->rpc_cb = rpc_cb;
    hg_rpc_info->data = NULL;
    hg_rpc_info->free_callback = NULL;

    if (!hg_hash_table_insert(hg_class->func_map, (hg_hash_table_key_t) id,
            hg_rpc_info)) {
        HG_LOG_ERROR("Could not insert RPC ID into function map");
        goto done;
    }

    ret = *id;

done:
    if (ret == 0) {
        free(id);
        free(hg_rpc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Registered_rpc(hg_class_t *hg_class, const char *func_name, hg_bool_t *flag,
        hg_id_t *id)
{
    hg_return_t ret = HG_SUCCESS;
    hg_id_t func_id;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!flag) {
        HG_LOG_ERROR("NULL flag");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    func_id = hg_hash_string(func_name);

    *flag = (hg_bool_t) (hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &func_id)
            != HG_HASH_TABLE_NULL);
    if (id) *id = (*flag) ? func_id : 0;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Register_data(hg_class_t *hg_class, hg_id_t id, void *data,
        void (*free_callback)(void *))
{
    struct hg_rpc_info *hg_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id);
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        ret = HG_NO_MATCH;
        goto done;
    }

    hg_rpc_info->data = data;
    hg_rpc_info->free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Registered_data(hg_class_t *hg_class, hg_id_t id)
{
    struct hg_rpc_info *hg_rpc_info = NULL;
    void *data = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id);
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        goto done;
    }

    data = hg_rpc_info->data;

done:
   return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Create(hg_class_t *hg_class, hg_context_t *context, na_addr_t addr,
        hg_id_t id, hg_handle_t *handle)
{
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (context->hg_class != hg_class) {
        HG_LOG_ERROR("Context does not belong to HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (addr == NA_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Create new handle */
    hg_handle = hg_create(hg_class, context);
    if (!hg_handle) {
        HG_LOG_ERROR("Could not create HG handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_handle->hg_info.addr = addr;
    hg_handle->hg_info.id = id;

    *handle = (hg_handle_t) hg_handle;

done:
    if (ret != HG_SUCCESS) {
        hg_destroy(hg_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Destroy(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_destroy(hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
struct hg_info *
HG_Get_info(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    struct hg_info *ret = NULL;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        goto done;
    }

    ret = &hg_handle->hg_info;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_addr_t
HG_Get_addr(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    na_addr_t ret = NULL;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        goto done;
    }

    ret = hg_handle->hg_info.addr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_input_buf(hg_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!in_buf || !in_buf_size) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_get_input_buf(hg_handle, in_buf, in_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Get_output_buf(hg_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!out_buf || !out_buf_size) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_get_output_buf(hg_handle, out_buf, out_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Forward_buf(hg_handle_t handle, hg_cb_t callback, void *arg,
        hg_bulk_t extra_in_handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    struct hg_header_request request_header;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Set callback */
    hg_handle->callback = callback;
    hg_handle->arg = arg;

    /* Increase ref count here so that a call to HG_Destroy does not free the
     * handle but only schedules its completion
     */
    hg_atomic_incr32(&hg_handle->ref_count);

    /* Set header */
    hg_proc_header_request_init(hg_handle->hg_info.id, extra_in_handle,
            &request_header);

    /* Encode request header */
    ret = hg_proc_header_request(hg_handle->in_buf, hg_handle->in_buf_size,
            &request_header, HG_ENCODE, hg_handle->hg_info.hg_bulk_class);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    if (NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
            hg_handle->hg_info.addr)) {
        /* If self, directly process handle */
        ret = hg_process(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not process handle");
            goto done;
        }
    } else {
        /* Forward call */
        hg_class_t *hg_class = hg_handle->hg_info.hg_class;
        na_return_t na_ret;

        /* Generate tag */
        hg_handle->tag = hg_gen_request_tag(hg_handle->hg_info.hg_class);

        /* Pre-post the recv message (output) */
        na_ret = NA_Msg_recv_expected(hg_class->na_class, hg_class->na_context,
                hg_recv_output_cb, hg_handle, hg_handle->out_buf,
                hg_handle->out_buf_size, hg_handle->hg_info.addr,
                hg_handle->tag, &hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post recv for output buffer");
            ret = HG_NA_ERROR;
            goto done;
        }

        /* And post the send message (input) */
        na_ret = NA_Msg_send_unexpected(hg_class->na_class,
                hg_class->na_context, hg_send_input_cb, hg_handle,
                hg_handle->in_buf, hg_handle->in_buf_size,
                hg_handle->hg_info.addr, hg_handle->tag,
                &hg_handle->na_send_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post send for input buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Respond_buf(hg_handle_t handle, hg_cb_t callback, void *arg,
        hg_return_t ret_code)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Fill the header */
    hg_proc_header_response_init(&response_header);
    response_header.cookie = hg_handle->cookie;
    response_header.ret_code = ret_code;

    /* Encode response header */
    ret = hg_proc_header_response(hg_handle->out_buf, hg_handle->out_buf_size,
            &response_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    if (NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
            hg_handle->hg_info.addr)) {
        struct hg_self_cb_info *hg_self_cb_info = NULL;

        /* TODO finish cleaning that up and add condition if no respond cb don't worry with that*/
        hg_self_cb_info = (struct hg_self_cb_info *) malloc(
                sizeof(struct hg_self_cb_info));
        if (!hg_self_cb_info) {
            HG_LOG_ERROR("Could not allocate HG context");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        /* Wrap callback */
        hg_self_cb_info->forward_cb = hg_handle->callback;
        hg_self_cb_info->forward_arg = hg_handle->arg;
        hg_self_cb_info->respond_cb = callback;
        hg_self_cb_info->respond_arg = arg;
        hg_handle->callback = hg_self_cb;
        hg_handle->arg = hg_self_cb_info;

        /* Complete and add to completion queue */
        ret = hg_complete(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete handle");
            goto done;
        }
    } else {
        hg_class_t *hg_class = hg_handle->hg_info.hg_class;
        na_return_t na_ret;

        /* Set callback */
        hg_handle->callback = callback;
        hg_handle->arg = arg;

        /* Respond back */
        na_ret = NA_Msg_send_expected(hg_class->na_class, hg_class->na_context,
                hg_send_output_cb, hg_handle, hg_handle->out_buf,
                hg_handle->out_buf_size, hg_handle->hg_info.addr,
                hg_handle->tag, &hg_handle->na_send_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post send for output buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* TODO Handle extra buffer response */

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Progress(hg_class_t *hg_class, hg_context_t *context, unsigned int timeout)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* If we are listening, try to post unexpected receives and treat incoming
     * RPCs */
    if (NA_Is_listening(hg_class->na_class)) {
        ret = hg_listen(hg_class, context);
    }

    /* Make progress on the HG layer */
    ret = hg_progress(hg_class, context, timeout);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not make progress");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Trigger(hg_class_t *hg_class, hg_context_t *context,
        unsigned int timeout, unsigned int max_count,
        unsigned int *actual_count)
{
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    while (count < max_count) {
        struct hg_handle *hg_handle = NULL;

        hg_thread_mutex_lock(&context->completion_queue_mutex);

        /* Is completion queue empty */
        while (hg_queue_is_empty(context->completion_queue)) {
            if (!timeout) {
                /* Timeout is 0 so leave */
                ret = HG_TIMEOUT;
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                goto done;
            }
            /* Otherwise wait timeout ms */
            if (hg_thread_cond_timedwait(&context->completion_queue_cond,
                    &context->completion_queue_mutex,
                    timeout) != HG_UTIL_SUCCESS) {
                /* Timeout occurred so leave */
                ret = HG_TIMEOUT;
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                goto done;
            }
        }

        /* Completion queue should not be empty now */
        hg_handle = (struct hg_handle *) hg_queue_pop_tail(
                context->completion_queue);
        if (!hg_handle) {
            HG_LOG_ERROR("NULL operation ID");
            ret = HG_INVALID_PARAM;
            hg_thread_mutex_unlock(&context->completion_queue_mutex);
            goto done;
        }

        /* Unlock now so that other threads can eventually add callbacks
         * to the queue while callback gets executed */
        hg_thread_mutex_unlock(&context->completion_queue_mutex);

        /* Execute callback */
        if (hg_handle->callback)
            hg_execute_callback(hg_handle);

        /* Free op */
        hg_destroy(hg_handle);
        count++;
    }

    if (actual_count) *actual_count = count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Cancel(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_cancel(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not cancel handle");
        goto done;
    }

done:
    return ret;
}
