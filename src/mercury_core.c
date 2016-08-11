/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
#include "mercury_private.h"

#include "mercury_queue.h"
#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_condition.h"
#include "mercury_thread_pool.h"
#include "mercury_time.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

#define HG_MAX_UNEXPECTED_RECV 256 /* TODO Variable */
#define HG_MAX_SELF_THREADS 4
#define HG_NA_MIN_TIMEOUT 0

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

/* HG handle list */
struct hg_handle;
LIST_HEAD(hg_handlelist, hg_handle);
typedef struct hg_handlelist hg_handlelist_t;

/* HG completions queue */
TAILQ_HEAD(hg_compqueue, hg_completion_entry);
typedef struct hg_compqueue hg_compqueue_t;

/* HG context */
struct hg_context {
    struct hg_class *hg_class;                    /* HG class */
    hg_compqueue_t completion_queue;              /* Completion queue */
    hg_thread_mutex_t completion_queue_mutex;     /* Completion queue mutex */
    hg_thread_cond_t completion_queue_cond;       /* Completion queue cond */
    hg_handlelist_t pending_list;                 /* List of pending handles */
    hg_bool_t recycle_pending_handles;            /* Recycle pending handles */
    hg_thread_mutex_t pending_list_mutex;         /* Pending list mutex */
    hg_handlelist_t processing_list;              /* List of handles being processed */
    hg_thread_mutex_t processing_list_mutex;      /* Processing list mutex */
    hg_handlelist_t self_processing_list;         /* List of handles being processed */
    hg_thread_mutex_t self_processing_list_mutex; /* Processing list mutex */
    hg_thread_cond_t self_processing_list_cond;   /* Processing list cond */
    hg_thread_pool_t *self_processing_pool;       /* Thread pool for self processing */
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

/* HG addr */
struct hg_addr {
    na_addr_t addr;
};

/* HG handle */
struct hg_handle {
    struct hg_info hg_info;             /* HG info */
    struct hg_completion_entry compent; /* Completion queue */
    LIST_ENTRY(hg_handle) ppl;          /* Pending/processing list linkage */
    hg_cb_t callback;                   /* Callback */
    void *arg;                          /* Callback arguments */
    hg_cb_type_t cb_type;               /* Callback type */
    na_tag_t tag;                       /* Tag used for request and response */
    hg_uint32_t cookie;                 /* Cookie unique to every RPC call */
    hg_return_t ret;                    /* Return code associated to handle */
    hg_bool_t addr_mine;                /* NA Addr created by HG */
    hg_bool_t process_rpc_cb;           /* RPC callback must be processed */
    hg_bool_t recyclable_handle;        /* Can be recycled into pending list */

    hg_cb_t forw_usercb;                /* forw: user callback fn */
    void *forw_extra_in_buf;            /* forw: extra buf (XXX needed?) */
    hg_bulk_t forw_extra_in_handle;     /* forw: extra in bulk handle */

    void *in_buf;                       /* Input buffer */
    na_size_t in_buf_size;              /* Input buffer size */
    na_size_t in_buf_used;              /* Amount of input buffer used */
    void *out_buf;                      /* Output buffer */
    na_size_t out_buf_size;             /* Output buffer size */
    na_size_t out_buf_used;             /* Amount of output buffer used */

    na_op_id_t na_send_prealloc_op_id;  /* Preallocated NA state for sending */
    na_op_id_t na_recv_prealloc_op_id;  /* Preallocated NA state for recving */
    na_op_id_t na_send_op_id;           /* Operation ID for send */
    na_op_id_t na_recv_op_id;           /* Operation ID for recv */
    hg_atomic_int32_t na_completed_count; /* Number of NA operations completed */

    hg_atomic_int32_t ref_count;        /* Reference count */

    void *extra_in_buf;
    hg_size_t extra_in_buf_size;
    hg_op_id_t extra_in_op_id;

    struct hg_rpc_info *hg_rpc_info;    /* Associated RPC info */
    void *private_data;                 /* Private data */
};

/* HG op id */
struct hg_op_info_lookup {
    hg_addr_t addr;                     /* Address */
    na_op_id_t na_lookup_op_id;         /* Operation ID for lookup */
};

struct hg_op_id {
    struct hg_context *context;         /* Context */
    struct hg_completion_entry compent; /* Completion queue */
    hg_cb_type_t type;                  /* Callback type */
    hg_cb_t callback;                   /* Callback */
    void *arg;                          /* Callback arguments */
    hg_atomic_int32_t completed;        /* Operation completed TODO needed ? */
    union {
        struct hg_op_info_lookup lookup;
    } info;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Get extra user payload using bulk transfer.
 * TODO this may be moved to the upper mercury layer.
 */
static hg_return_t
hg_core_get_extra_input(
        struct hg_handle *hg_handle,
        hg_bulk_t extra_in_handle
        );

/**
 * Bulk transfer callback.
 */
static hg_return_t
hg_core_get_extra_input_cb(
        const struct hg_cb_info *callback_info
        );

/**
 * Get request header and verify it.
 */
static hg_return_t
hg_core_get_header_request(
        struct hg_handle *hg_handle,
        struct hg_header_request *request_header
        );

/**
 * Remove handle from pending list.
 */
static hg_return_t
hg_core_pending_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Check pending list.
 */
static hg_bool_t
hg_core_pending_list_check(
        struct hg_context *context
        );

/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_core_pending_list_cancel(
        struct hg_context *context
        );

/**
 * Add handle to processing list.
 */
static hg_return_t
hg_core_processing_list_add(
        struct hg_handle *hg_handle
        );

/**
 * Remove handle from processing list.
 */
static hg_return_t
hg_core_processing_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Wail until processing list is empty.
 */
static hg_return_t
hg_core_processing_list_wait(
        struct hg_context *context
        );

/**
 * Add handle to self processing list.
 */
static hg_return_t
hg_core_self_processing_list_add(
        struct hg_handle *hg_handle
        );

/**
 * Remove handle from self processing list.
 */
static hg_return_t
hg_core_self_processing_list_remove(
        struct hg_handle *hg_handle
        );

/**
 * Check self processing list.
 */
static hg_bool_t
hg_core_self_processing_list_check(
        struct hg_context *context
        );

/**
 * Initialize class.
 */
static struct hg_class *
hg_core_init(
        const char *na_info_string,
        hg_bool_t na_listen,
        na_class_t *na_init_class,
        na_context_t *na_init_context
        );

/**
 * Finalize class.
 */
static hg_return_t
hg_core_finalize(
        struct hg_class *hg_class
        );

/**
 * Lookup addr.
 */
static hg_return_t
hg_core_addr_lookup(
        struct hg_context *context,
        hg_cb_t callback,
        void *arg,
        const char *name,
        hg_op_id_t *op_id
        );

/**
 * Lookup callback.
 */
static na_return_t
hg_core_addr_lookup_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Complete addr lookup.
 */
static hg_return_t
hg_core_addr_lookup_complete(
        struct hg_op_id *hg_op_id
        );

/**
 * Free addr.
 */
static hg_return_t
hg_core_addr_free(
        struct hg_class *hg_class,
        hg_addr_t addr
        );


/**
 * Self addr.
 */
static hg_return_t
hg_core_addr_self(
        struct hg_class *hg_class,
        hg_addr_t *addr
        );

/**
 * Dup addr.
 */
static hg_return_t
hg_core_addr_dup(
        struct hg_class *hg_class,
        hg_addr_t addr,
        hg_addr_t *new_addr
        );

/**
 * Convert addr to string.
 */
static hg_return_t
hg_core_addr_to_string(
        struct hg_class *hg_class,
        char *buf,
        hg_size_t *buf_size,
        hg_addr_t addr
        );

/**
 * Create handle.
 */
static struct hg_handle *
hg_core_create(
        struct hg_context *context,
        hg_bool_t can_recycle
        );

/**
 * Free handle.
 */
static void
hg_core_destroy(
        struct hg_handle *hg_handle
        );

/**
 * Recycle handle back to pending list.
 */
static void
hg_core_recycle_to_pending_or_destroy(
        struct hg_handle *hg_handle
        );

/**
 * Set private data.
 */
void
hg_core_set_private_data(
        struct hg_handle *hg_handle,
        void *private_data
        );

/**
 * Get private data.
 */
void *
hg_core_get_private_data(
        struct hg_handle *hg_handle
        );

/**
 * Forward handle locally.
 */
static hg_return_t
hg_core_forward_self(
        struct hg_handle *hg_handle
        );

/**
 * Forward handle through NA.
 */
static hg_return_t
hg_core_forward_na(
        struct hg_handle *hg_handle
        );

/**
 * Send response locally.
 */
static hg_return_t
hg_core_respond_self(
        struct hg_handle *hg_handle,
        hg_cb_t callback,
        void *arg
        );

/**
 * Send response through NA.
 */
static hg_return_t
hg_core_respond_na(
        struct hg_handle *hg_handle,
        hg_cb_t callback,
        void *arg
        );

/**
 * Send input callback.
 */
static na_return_t
hg_core_send_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv input callback.
 */
static na_return_t
hg_core_recv_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Send output callback.
 */
static na_return_t
hg_core_send_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv output callback.
 */
static na_return_t
hg_core_recv_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Wrapper for local callback execution.
 */
static hg_return_t
hg_core_self_cb(
        const struct hg_cb_info *callback_info
        );

/**
 * Process handle thread (used for self execution).
 */
static HG_THREAD_RETURN_TYPE
hg_core_process_thread(
        void *arg
        );

/**
 * Process handle.
 */
static hg_return_t
hg_core_process(
        struct hg_handle *hg_handle
        );

/**
 * Complete handle and add to completion queue.
 */
static hg_return_t
hg_core_complete(
        struct hg_handle *hg_handle
        );

/**
 * Add entry to completion queue.
 */
hg_return_t
hg_core_completion_add(
        struct hg_context *context,
        struct hg_completion_entry *hg_completion_entry
        );

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_core_listen(
        struct hg_context *context
        );

/**
 * Make progress on local requests.
 */
static hg_return_t
hg_core_progress_self(
        struct hg_context *context,
        unsigned int timeout
        );

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_core_progress_na(
        struct hg_context *context,
        unsigned int timeout
        );

/**
 * Make progress.
 */
static hg_return_t
hg_core_progress(
        struct hg_context *context,
        unsigned int timeout
        );

/**
 * Trigger callbacks.
 */
static hg_return_t
hg_core_trigger(
        struct hg_context *context,
        unsigned int timeout,
        unsigned int max_count,
        unsigned int *actual_count
        );

/**
 * Trigger callback from HG lookup op ID.
 */
static hg_return_t
hg_core_trigger_lookup_entry(
        struct hg_op_id *hg_op_id
        );

/**
 * Trigger callback from HG handle.
 */
static hg_return_t
hg_core_trigger_entry(
        struct hg_handle *hg_handle
        );

/**
 * Trigger callback from HG bulk op ID.
 */
extern hg_return_t
hg_bulk_trigger_entry(
        struct hg_bulk_op_id *hg_bulk_op_id
        );

/**
 * Cancel handle.
 */
static hg_return_t
hg_core_cancel(
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
hg_core_int_equal(void *vlocation1, void *vlocation2)
{
    return *((int *) vlocation1) == *((int *) vlocation2);
}

/*---------------------------------------------------------------------------*/
/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_core_int_hash(void *vlocation)
{
    return *((unsigned int *) vlocation);
}

/*---------------------------------------------------------------------------*/
/**
 * Free function for value in function map.
 */
static HG_INLINE void
hg_core_func_map_value_free(hg_hash_table_value_t value)
{
    struct hg_rpc_info *hg_rpc_info = (struct hg_rpc_info *) value;

    if (hg_rpc_info->free_callback)
        hg_rpc_info->free_callback(hg_rpc_info->data);
    free(hg_rpc_info);
}

/*---------------------------------------------------------------------------*/
/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_core_gen_request_tag(struct hg_class *hg_class)
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
hg_core_get_input(struct hg_handle *hg_handle, void **in_buf,
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
hg_core_get_output(struct hg_handle *hg_handle, void **out_buf,
    hg_size_t *out_buf_size)
{
    hg_size_t header_offset = hg_proc_header_response_get_size();

    /* Space must be left for response header */
    *out_buf = (char *) hg_handle->out_buf + header_offset;
    *out_buf_size = hg_handle->out_buf_size - header_offset;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_get_extra_input(struct hg_handle *hg_handle, hg_bulk_t extra_in_handle)
{
    hg_class_t *hg_class = hg_handle->hg_info.hg_class;
    hg_context_t *hg_context = hg_handle->hg_info.context;
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

    ret = HG_Bulk_create(hg_class, 1, &hg_handle->extra_in_buf,
            &hg_handle->extra_in_buf_size, HG_BULK_READWRITE, &local_in_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not create HG bulk handle");
        goto done;
    }

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_transfer(hg_context, hg_core_get_extra_input_cb,
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
hg_core_get_extra_input_cb(const struct hg_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    /* Free bulk handle */
    ret = HG_Bulk_free(callback_info->info.bulk.local_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free bulk handle");
        goto done;
    }

    /* TODO should be freed with header request proc but clean that up when
     * extra handle is clean
     */
    ret = HG_Bulk_free(callback_info->info.bulk.origin_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free bulk handle");
        goto done;
    }

    /* Now can process the handle */
    hg_handle->process_rpc_cb = HG_TRUE;
    ret = hg_core_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete rpc handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_get_header_request(struct hg_handle *hg_handle,
    struct hg_header_request *request_header)
{
    hg_return_t ret = HG_SUCCESS;
    hg_size_t extra_header_size;

    /* Initialize header with default values */
    hg_proc_header_request_init(0, HG_BULK_NULL, request_header);

    /* Decode request header */
    ret = hg_proc_header_request(hg_handle->in_buf, hg_handle->in_buf_size,
            request_header, HG_DECODE, hg_handle->hg_info.hg_class, &extra_header_size);
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
hg_core_pending_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->pending_list_mutex);

    LIST_REMOVE(hg_handle, ppl);

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_bool_t
hg_core_pending_list_check(struct hg_context *context)
{
    hg_bool_t ret = HG_FALSE;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    ret = (LIST_EMPTY(&context->pending_list)) ? HG_FALSE : HG_TRUE;

    hg_thread_mutex_unlock(&context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_pending_list_cancel(struct hg_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    while (!LIST_EMPTY(&context->pending_list)) {
        struct hg_handle *hg_handle = LIST_FIRST(&context->pending_list);

        ret = hg_core_cancel(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not cancel handle");
            break;
        }

        /* Remove the entries as we go */
        LIST_REMOVE(hg_handle, ppl);
    }

    hg_thread_mutex_unlock(&context->pending_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_processing_list_add(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->processing_list_mutex);

    LIST_INSERT_HEAD(&hg_handle->hg_info.context->processing_list,
                     hg_handle, ppl);

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_processing_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->processing_list_mutex);

    LIST_REMOVE(hg_handle, ppl);

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_processing_list_wait(struct hg_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    while (1) {
        hg_util_bool_t processing_list_empty = HG_UTIL_FALSE;
        unsigned int actual_count = 0;
        hg_return_t trigger_ret;

        /* Trigger everything we can from HG */
        do {
            trigger_ret = hg_core_trigger(context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        hg_thread_mutex_lock(&context->processing_list_mutex);

        processing_list_empty =
            LIST_EMPTY(&context->processing_list) ? HG_TRUE : HG_FALSE;

        hg_thread_mutex_unlock(&context->processing_list_mutex);

        if (processing_list_empty) break;

        ret = hg_core_progress(context, HG_MAX_IDLE_TIME);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not make progress");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_self_processing_list_add(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->self_processing_list_mutex);

    LIST_INSERT_HEAD(&hg_handle->hg_info.context->self_processing_list,
                     hg_handle, ppl);

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->self_processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_self_processing_list_remove(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&hg_handle->hg_info.context->self_processing_list_mutex);
    LIST_REMOVE(hg_handle, ppl);

    hg_thread_cond_signal(&hg_handle->hg_info.context->self_processing_list_cond);

    hg_thread_mutex_unlock(&hg_handle->hg_info.context->self_processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_bool_t
hg_core_self_processing_list_check(struct hg_context *context)
{
    hg_bool_t ret = HG_FALSE;

    hg_thread_mutex_lock(&context->self_processing_list_mutex);

    ret = LIST_EMPTY(&context->self_processing_list) ? HG_FALSE : HG_TRUE;

    hg_thread_mutex_unlock(&context->self_processing_list_mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    na_class_t *na_init_class, na_context_t *na_init_context)
{
    struct hg_class *hg_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Create new HG class */
    hg_class = (struct hg_class *) malloc(sizeof(struct hg_class));
    if (!hg_class) {
        HG_LOG_ERROR("Could not allocate HG class");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_class->na_class = na_init_class;
    hg_class->na_context = na_init_context;
    hg_class->func_map = NULL;
    hg_class->na_ext_init = (na_init_class && na_init_context) ? HG_TRUE : HG_FALSE;

    /* Initialize NA */
    if (!hg_class->na_ext_init) {
        hg_class->na_class = NA_Initialize(na_info_string, na_listen);
        if (!hg_class->na_class) {
            HG_LOG_ERROR("Could not initialize NA class");
            ret = HG_NA_ERROR;
            goto done;
        }

        hg_class->na_context = NA_Context_create(hg_class->na_class);
        if (!hg_class->na_context) {
            HG_LOG_ERROR("Could not create NA context");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* Initialize atomic for tags */
    hg_class->request_max_tag = NA_Msg_get_max_tag(hg_class->na_class);
    hg_atomic_set32(&hg_class->request_tag, 0);

    /* Create new function map */
    hg_class->func_map = hg_hash_table_new(hg_core_int_hash, hg_core_int_equal);
    if (!hg_class->func_map) {
        HG_LOG_ERROR("Could not create function map");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_class->func_map, free,
            hg_core_func_map_value_free);

done:
    if (ret != HG_SUCCESS) {
        hg_core_finalize(hg_class);
        hg_class = NULL;
    }
    return hg_class;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_finalize(struct hg_class *hg_class)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) goto done;

    /* Delete function map */
    hg_hash_table_free(hg_class->func_map);
    hg_class->func_map = NULL;

    /* Destroy context */
    if (!hg_class->na_ext_init) {
        if (hg_class->na_context && NA_Context_destroy(hg_class->na_class,
                hg_class->na_context) != NA_SUCCESS) {
            HG_LOG_ERROR("Could not destroy NA context");
            ret = HG_NA_ERROR;
            goto done;
        }
        hg_class->na_context = NULL;

        /* Finalize interface */
        if (NA_Finalize(hg_class->na_class) != NA_SUCCESS) {
            HG_LOG_ERROR("Could not finalize NA interface");
            ret = HG_NA_ERROR;
            goto done;
        }
        hg_class->na_class = NULL;
    }

done:
    /* Free HG class */
    free(hg_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup(struct hg_context *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    na_class_t *na_class = context->hg_class->na_class;
    na_context_t *na_context = context->hg_class->na_context;
    struct hg_op_id *hg_op_id = NULL;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Allocate op_id */
    hg_op_id = (struct hg_op_id *) malloc(sizeof(struct hg_op_id));
    if (!hg_op_id) {
        HG_LOG_ERROR("Could not allocate HG operation ID");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_op_id->context = context;
    hg_op_id->type = HG_CB_LOOKUP;
    hg_op_id->callback = callback;
    hg_op_id->arg = arg;
    hg_atomic_set32(&hg_op_id->completed, 0);
    hg_op_id->info.lookup.addr = HG_ADDR_NULL;

    na_ret = NA_Addr_lookup(na_class, na_context, hg_core_addr_lookup_cb,
            hg_op_id, name, &hg_op_id->info.lookup.na_lookup_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not start lookup for address %s", name);
        ret = HG_NA_ERROR;
        goto done;
    }

    /* Assign op_id */
    *op_id = (hg_op_id_t) hg_op_id;

done:
    if (ret != HG_SUCCESS) {
        free(hg_op_id);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_core_addr_lookup_cb(const struct na_cb_info *callback_info)
{
    struct hg_op_id *hg_op_id = (struct hg_op_id *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Assign addr */
    hg_op_id->info.lookup.addr = (hg_addr_t) callback_info->info.lookup.addr;

    /* Mark as completed */
    if (hg_core_addr_lookup_complete(hg_op_id) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup_complete(struct hg_op_id *hg_op_id)
{
    hg_context_t *context = hg_op_id->context;
    struct hg_completion_entry *hg_completion_entry = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Mark operation as completed */
    hg_atomic_incr32(&hg_op_id->completed);

    hg_completion_entry = &hg_op_id->compent;
    hg_completion_entry->op_type = HG_ADDR;
    hg_completion_entry->op_id.hg_op_id = hg_op_id;

    ret = hg_core_completion_add(context, hg_completion_entry);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add HG completion entry to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_free(struct hg_class *hg_class, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    na_ret = NA_Addr_free(hg_class->na_class, (na_addr_t)addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not free address");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_self(struct hg_class *hg_class, hg_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    na_ret = NA_Addr_self(hg_class->na_class, (na_addr_t *) addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not get self address");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_dup(struct hg_class *hg_class, hg_addr_t addr, hg_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    na_ret = NA_Addr_dup(hg_class->na_class, (na_addr_t) addr, (na_addr_t *) new_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not duplicate address");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_to_string(struct hg_class *hg_class, char *buf, hg_size_t *buf_size,
    hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    na_ret = NA_Addr_to_string(hg_class->na_class, buf, buf_size, (na_addr_t) addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not convert address to string");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_handle *
hg_core_create(struct hg_context *context, hg_bool_t can_recycle)
{
    na_class_t *na_class = context->hg_class->na_class;
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (!hg_handle) {
        HG_LOG_ERROR("Could not allocate handle");
        goto done;
    }

    hg_handle->hg_info.hg_class = context->hg_class;
    hg_handle->hg_info.context = context;
    hg_handle->hg_info.addr = HG_ADDR_NULL;
    hg_handle->hg_info.id = 0;
    hg_handle->callback = NULL;
    hg_handle->arg = NULL;
    hg_handle->cb_type = 0;
    hg_handle->cookie = 0; /* TODO Generate cookie */
    hg_handle->tag = 0;
    hg_handle->ret = HG_SUCCESS;
    hg_handle->addr_mine = HG_FALSE;
    hg_handle->process_rpc_cb = HG_FALSE;
    hg_handle->recyclable_handle = can_recycle;  /* for pending list */

    /* Initialize processing buffers and use unexpected message size */
    hg_handle->in_buf = NULL;
    hg_handle->out_buf = NULL;
    hg_handle->in_buf_size = NA_Msg_get_max_unexpected_size(na_class);
    hg_handle->out_buf_size = NA_Msg_get_max_expected_size(na_class);
    hg_handle->in_buf_used = 0;
    hg_handle->out_buf_used = 0;

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

    /* ignore prealloc failures, they will set the op_id to NULL */
    NA_Prealloc_op_id(na_class, context->hg_class->na_context,
                      &hg_handle->na_send_prealloc_op_id);
    NA_Prealloc_op_id(na_class, context->hg_class->na_context,
                      &hg_handle->na_recv_prealloc_op_id);

    hg_handle->na_send_op_id = NA_OP_ID_NULL;
    hg_handle->na_recv_op_id = NA_OP_ID_NULL;
    hg_atomic_set32(&hg_handle->na_completed_count, 0);

    hg_atomic_set32(&hg_handle->ref_count, 1);

    hg_handle->extra_in_buf = NULL;
    hg_handle->extra_in_buf_size = 0;
    hg_handle->extra_in_op_id = HG_OP_ID_NULL;

    hg_handle->hg_rpc_info = NULL;
    hg_handle->private_data = NULL;

done:
    if (ret != HG_SUCCESS) {
        hg_core_destroy(hg_handle);
        hg_handle = NULL;
    }
    return hg_handle;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_destroy(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class;
    
    if (!hg_handle) goto done;

    if (hg_atomic_decr32(&hg_handle->ref_count)) {
        /* Cannot free yet */
        goto done;
    }
    hg_class = hg_handle->hg_info.hg_class;

    if (hg_handle->na_send_prealloc_op_id)
        NA_Prealloc_op_id_free(hg_class->na_class, hg_class->na_context,
                               hg_handle->na_send_prealloc_op_id);
    if (hg_handle->na_recv_prealloc_op_id)
        NA_Prealloc_op_id_free(hg_class->na_class, hg_class->na_context,
                               hg_handle->na_recv_prealloc_op_id);
    
    /* Free if mine */
    if (hg_handle->hg_info.addr != HG_ADDR_NULL && hg_handle->addr_mine)
        NA_Addr_free(hg_class->na_class,
                hg_handle->hg_info.addr);

    hg_proc_buf_free(hg_handle->in_buf);
    hg_proc_buf_free(hg_handle->out_buf);

    free(hg_handle->extra_in_buf);

    free(hg_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
/*
 * this will either recycle the handle, or destroy it.
 */
static void
hg_core_recycle_to_pending_or_destroy(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_context *hg_context = hg_handle->hg_info.context;
    na_return_t na_ret;

    /* reset handle */

    /* Free addr if mine */
    if (hg_handle->hg_info.addr != HG_ADDR_NULL && hg_handle->addr_mine) {
        NA_Addr_free(hg_class->na_class, hg_handle->hg_info.addr);
    }
    hg_handle->hg_info.addr = HG_ADDR_NULL;
    hg_handle->callback = NULL;
    hg_handle->ret = HG_SUCCESS;
    hg_handle->addr_mine = HG_FALSE;
    hg_handle->process_rpc_cb = HG_FALSE;
    hg_handle->in_buf_used = 0;
    hg_handle->out_buf_used = 0;
    hg_handle->na_send_op_id = HG_OP_ID_NULL;
    hg_handle->na_recv_op_id = HG_OP_ID_NULL;
    hg_atomic_set32(&hg_handle->na_completed_count, 0);
    if (hg_handle->extra_in_buf)
        free(hg_handle->extra_in_buf);
    hg_handle->extra_in_buf = NULL;
    hg_handle->extra_in_buf_size = 0;
    hg_handle->extra_in_op_id = HG_OP_ID_NULL;
    hg_handle->hg_rpc_info = NULL;
    hg_handle->private_data = NULL;

    hg_thread_mutex_lock(&hg_context->pending_list_mutex);

    LIST_INSERT_HEAD(&hg_context->pending_list, hg_handle, ppl);

    if (hg_context->recycle_pending_handles == HG_FALSE) {

        na_ret = NA_CANCELED;  /* we stopped recycling */

    } else {

        /* Post a new unexpected receive */
        na_ret = NA_Msg_recv_unexpected(hg_class->na_class, hg_class->na_context,
                hg_core_recv_input_cb, hg_handle, hg_handle->in_buf,
                hg_handle->in_buf_size, hg_handle->na_recv_prealloc_op_id,
                &hg_handle->na_recv_op_id);

        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post recycle unexpected recv for input");
        }
    }

    if (na_ret != NA_SUCCESS)
        LIST_REMOVE(hg_handle, ppl);

    hg_thread_mutex_unlock(&hg_context->pending_list_mutex);

    /* if we failed, just destroy it */
    if (na_ret != NA_SUCCESS) {
        hg_handle->recyclable_handle = HG_FALSE;
        hg_core_destroy(hg_handle);
    }

    return;
}

/*---------------------------------------------------------------------------*/
void
hg_core_set_private_data(struct hg_handle *hg_handle, void *private_data)
{
    hg_handle->private_data = private_data;
}

/*---------------------------------------------------------------------------*/
void *
hg_core_get_private_data(struct hg_handle *hg_handle)
{
    void *data;

    if (hg_handle->hg_rpc_info)
        data = hg_handle->hg_rpc_info->data;
    else
        data = hg_handle->private_data;

    return data;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_self(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle->hg_info.context->self_processing_pool)
        hg_thread_pool_init(HG_MAX_SELF_THREADS,
                &hg_handle->hg_info.context->self_processing_pool);

    /* Add handle to self processing list */
    ret = hg_core_self_processing_list_add(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add handle to self processing list");
        goto done;
    }

    /* Post operation to self processing pool */
    hg_thread_pool_post(hg_handle->hg_info.context->self_processing_pool,
            hg_core_process_thread, hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_na(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Generate tag */
    hg_handle->tag = hg_core_gen_request_tag(hg_handle->hg_info.hg_class);

    /* Pre-post the recv message (output) */
    na_ret = NA_Msg_recv_expected(hg_class->na_class, hg_class->na_context,
            hg_core_recv_output_cb, hg_handle, hg_handle->out_buf,
            hg_handle->out_buf_size, hg_handle->hg_info.addr,
            hg_handle->tag, hg_handle->na_recv_prealloc_op_id,
            &hg_handle->na_recv_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post recv for output buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

    /* And post the send message (input) */
    na_ret = NA_Msg_send_unexpected(hg_class->na_class,
            hg_class->na_context, hg_core_send_input_cb, hg_handle,
            hg_handle->in_buf, hg_handle->in_buf_used,
            hg_handle->hg_info.addr, hg_handle->tag,
            hg_handle->na_send_prealloc_op_id,
            &hg_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for input buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_respond_self(struct hg_handle *hg_handle, hg_cb_t callback, void *arg)
{
    struct hg_self_cb_info *hg_self_cb_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_self_cb_info = (struct hg_self_cb_info *) malloc(
            sizeof(struct hg_self_cb_info));
    if (!hg_self_cb_info) {
        HG_LOG_ERROR("Could not allocate HG self cb info");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Wrap callbacks */
    hg_self_cb_info->forward_cb = hg_handle->callback;
    hg_self_cb_info->forward_arg = hg_handle->arg;
    hg_self_cb_info->respond_cb = callback;
    hg_self_cb_info->respond_arg = arg;
    hg_handle->callback = hg_core_self_cb;
    hg_handle->arg = hg_self_cb_info;
    hg_handle->cb_type = HG_CB_RESPOND;

    /* Complete and add to completion queue */
    ret = hg_core_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete handle");
        goto done;
    }

    /* Callback was pushed to the completion queue so wake up anyone waiting
     * in the progress */
    ret = hg_core_self_processing_list_remove(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not remove handle from self processing list");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_respond_na(struct hg_handle *hg_handle, hg_cb_t callback, void *arg)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Set callback */
    hg_handle->callback = callback;
    hg_handle->arg = arg;
    hg_handle->cb_type = HG_CB_RESPOND;

    /* Respond back */
    na_ret = NA_Msg_send_expected(hg_class->na_class, hg_class->na_context,
            hg_core_send_output_cb, hg_handle, hg_handle->out_buf,
            hg_handle->out_buf_used, hg_handle->hg_info.addr,
            hg_handle->tag, hg_handle->na_send_prealloc_op_id,
            &hg_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for output buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

    /* TODO Handle extra buffer response */

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_core_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    /* Reset op ID value */
    hg_handle->na_send_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Add handle to completion queue only when send_input and recv_output have
     * completed */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_core_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_header_request request_header;
    na_return_t ret = NA_SUCCESS;

    /* Reset op ID value */
    hg_handle->na_recv_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;

        /* May only decrement refcount */
        hg_core_destroy(hg_handle);
    } else if (callback_info->ret == NA_SUCCESS) {
        /* Increment NA completed count */
        hg_atomic_incr32(&hg_handle->na_completed_count);

        /* Fill unexpected info */
        hg_handle->hg_info.addr = callback_info->info.recv_unexpected.source;
        hg_handle->addr_mine = HG_TRUE; /* Address will be freed with handle */
        hg_handle->tag = callback_info->info.recv_unexpected.tag;
        if (callback_info->info.recv_unexpected.actual_buf_size
            > hg_handle->in_buf_size) {
            HG_LOG_ERROR(
                "Actual transfer size is too large for unexpected recv");
            goto done;
        }
        hg_handle->in_buf_used =
            callback_info->info.recv_unexpected.actual_buf_size;

        /* Move handle from pending list to processing list */
        if (hg_core_pending_list_remove(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not remove handle from pending list");
            goto done;
        }
        if (hg_core_processing_list_add(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not add handle to processing list");
            goto done;
        }

        /* As we removed handle from pending list repost unexpected receives */
        if (NA_Is_listening(hg_handle->hg_info.hg_class->na_class)) {
            hg_core_listen(hg_handle->hg_info.context);
        }

        /* Get and verify header */
        if (hg_core_get_header_request(hg_handle, &request_header)
            != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get request header");
            goto done;
        }

        /* Get operation ID from header */
        hg_handle->hg_info.id = request_header.id;
        hg_handle->cookie = request_header.cookie;

        if (request_header.flags
            && (request_header.extra_in_handle != HG_BULK_NULL)) {
            /* Get extra payload */
            if (hg_core_get_extra_input(hg_handle,
                request_header.extra_in_handle) != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get extra input buffer");
                goto done;
            }
        } else {
            /* Process handle */
            hg_handle->process_rpc_cb = HG_TRUE;
            if (hg_core_complete(hg_handle) != HG_SUCCESS) {
                HG_LOG_ERROR("Could not complete rpc handle");
                goto done;
            }
        }
    } else {
        HG_LOG_ERROR("Error in NA callback");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_core_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    /* Reset op ID value */
    hg_handle->na_send_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Remove handle from processing list
     * NB. Whichever state we're in, reaching that stage means that the
     * handle was processed. */
    if (hg_core_processing_list_remove(hg_handle) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not remove handle from processing list");
        goto done;
    }

    /* Mark as completed (sanity check: NA completed count should be 2 here) */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
hg_core_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_header_response response_header;
    na_return_t ret = NA_SUCCESS;

    /* Reset op ID value */
    hg_handle->na_recv_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret == NA_SUCCESS) {
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
    } else {
        HG_LOG_ERROR("Error in NA callback");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Add handle to completion queue only when send_input and recv_output have
     * completed */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_self_cb(const struct hg_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->info.respond.handle;
    struct hg_self_cb_info *hg_self_cb_info =
            (struct hg_self_cb_info *) callback_info->arg;
    hg_return_t ret;

    /* First execute response callback */
    if (hg_self_cb_info->respond_cb) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_self_cb_info->respond_arg;
        hg_cb_info.ret = HG_SUCCESS; /* TODO report failure */
        hg_cb_info.type = HG_CB_RESPOND;
        hg_cb_info.info.respond.handle = (hg_handle_t) hg_handle;

        hg_self_cb_info->respond_cb(&hg_cb_info);
    }

    /* TODO response check header */

    /* Assign forward callback back to handle */
    hg_handle->callback = hg_self_cb_info->forward_cb;
    hg_handle->arg = hg_self_cb_info->forward_arg;
    hg_handle->cb_type = HG_CB_INTFORWARD;

    /* Increment refcount and push handle back to completion queue */
    hg_atomic_incr32(&hg_handle->ref_count);

    ret = hg_core_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete handle");
        goto done;
    }

done:
    free(hg_self_cb_info);
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_THREAD_RETURN_TYPE
hg_core_process_thread(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    struct hg_handle *hg_handle = (struct hg_handle *) arg;
    struct hg_header_request request_header;

    /* Get and verify header */
    if (hg_core_get_header_request(hg_handle, &request_header) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get request header");
        goto done;
    }

    /* Check extra arguments */
    if (request_header.flags
            && (request_header.extra_in_handle != HG_BULK_NULL)) {
        /* Get extra payload */
        if (hg_core_get_extra_input(hg_handle, request_header.extra_in_handle)
                != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get extra input buffer");
            goto done;
        }
    } else {
        /* Process handle */
        hg_handle->process_rpc_cb = HG_TRUE;
        if(hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete rpc handle");
            goto done;
        }
    }

done:
    return thread_ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
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

    /* Cache RPC info */
    hg_handle->hg_rpc_info = hg_rpc_info;

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
hg_core_complete(struct hg_handle *hg_handle)
{
    struct hg_context *context = hg_handle->hg_info.context;
    struct hg_completion_entry *hg_completion_entry = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_completion_entry = &hg_handle->compent;
    hg_completion_entry->op_type = HG_RPC;
    hg_completion_entry->op_id.hg_handle = hg_handle;

    ret = hg_core_completion_add(context, hg_completion_entry);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add HG completion entry to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_completion_add(struct hg_context *context,
    struct hg_completion_entry *hg_completion_entry)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&context->completion_queue_mutex);

    /* Add handle to completion queue */
    TAILQ_INSERT_HEAD(&context->completion_queue, hg_completion_entry, q);

    /* Callback is pushed to the completion queue when something completes
     * so wake up anyone waiting in the trigger */
    hg_thread_cond_signal(&context->completion_queue_cond);

    hg_thread_mutex_unlock(&context->completion_queue_mutex);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_listen(struct hg_context *context)
{
    struct hg_class *hg_class = context->hg_class;
    struct hg_handle *hg_handle = NULL;
    unsigned int nentry = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_thread_mutex_lock(&context->pending_list_mutex);

    if (!LIST_EMPTY(&context->pending_list)) goto done;

    /* Create a bunch of handles and post unexpected receives */
    for (nentry = 0; nentry < HG_MAX_UNEXPECTED_RECV; nentry++) {

        /* Create a new handle */
        hg_handle = hg_core_create(context, HG_TRUE);
        if (!hg_handle) {
            HG_LOG_ERROR("Could not create HG handle");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        LIST_INSERT_HEAD(&context->pending_list, hg_handle, ppl);

        /* Post a new unexpected receive */
        na_ret = NA_Msg_recv_unexpected(hg_class->na_class, hg_class->na_context,
                hg_core_recv_input_cb, hg_handle, hg_handle->in_buf,
                hg_handle->in_buf_size, hg_handle->na_recv_prealloc_op_id,
                &hg_handle->na_recv_op_id);
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
hg_core_progress_self(struct hg_context *context, unsigned int timeout)
{
    hg_return_t ret = HG_TIMEOUT;

    hg_thread_mutex_lock(&context->self_processing_list_mutex);

    /* If something is in self processing list, wait timeout ms */
    while (!LIST_EMPTY(&context->self_processing_list)) {
        hg_bool_t completion_queue_empty;

        /* Otherwise wait timeout ms */
        if (timeout && hg_thread_cond_timedwait(
                &context->self_processing_list_cond,
                &context->self_processing_list_mutex, timeout)
                != HG_UTIL_SUCCESS) {
            /* Timeout occurred so leave */
            break;
        }

        /* Is completion queue empty */
        hg_thread_mutex_lock(&context->completion_queue_mutex);

        completion_queue_empty =
            (TAILQ_EMPTY(&context->completion_queue)) ? HG_TRUE : HG_FALSE;

        hg_thread_mutex_unlock(&context->completion_queue_mutex);

        /* If something is in context completion queue just return */
        if (!completion_queue_empty) {
            ret = HG_SUCCESS; /* Progressed */
            break;
        }
        if (!timeout) {
            /* Timeout is 0 so leave */
            break;
        }
    }

    hg_thread_mutex_unlock(&context->self_processing_list_mutex);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_na(struct hg_context *context, unsigned int timeout)
{
    struct hg_class *hg_class = context->hg_class;
    hg_bool_t completion_queue_empty = HG_FALSE;
    unsigned int actual_count = 0;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(hg_class->na_context, 0, 1, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);

    /* Is completion queue empty */
    hg_thread_mutex_lock(&context->completion_queue_mutex);

    completion_queue_empty =
        (TAILQ_EMPTY(&context->completion_queue)) ? HG_TRUE : HG_FALSE;

    hg_thread_mutex_unlock(&context->completion_queue_mutex);

    /* If something is in context completion queue just return */
    if (!completion_queue_empty) goto done;

    /* Otherwise try to make progress on NA */
    na_ret = NA_Progress(hg_class->na_class, hg_class->na_context, timeout);
    switch (na_ret) {
        case NA_SUCCESS:
            /* Progressed */
            break;
        case NA_TIMEOUT:
            ret = HG_TIMEOUT;
            break;
        default:
            HG_LOG_ERROR("Could not make NA Progress");
            ret = HG_NA_ERROR;
            break;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress(struct hg_context *context, unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    hg_return_t ret = HG_SUCCESS;

    do {
        hg_time_t t1, t2, t3;
        unsigned int progress_timeout;
        hg_bool_t do_self_progress = hg_core_self_processing_list_check(context);

        hg_time_get_current(&t1);

        /* Make progress on NA (do not block if something is already in
         * self processing list) */
        if (do_self_progress) {
            ret = hg_core_progress_self(context, HG_NA_MIN_TIMEOUT);
            if (ret == HG_SUCCESS)
                break; /* Progressed */
            else
                if (ret != HG_TIMEOUT) {
                    HG_LOG_ERROR("Could not make progress on local requests");
                    goto done;
                }
        }

        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        if (remaining < 0) {
            /* Give a chance to call progress with timeout of 0 if no progress yet */
            remaining = 0;
        }

        /* Make progress on NA (do not block if something is already in
         * self processing list) */
        progress_timeout = (do_self_progress) ?  HG_NA_MIN_TIMEOUT :
                (unsigned int) (remaining * 1000);
        ret = hg_core_progress_na(context, progress_timeout);
        if (ret == HG_SUCCESS)
            break; /* Progressed */
        else
            if (ret != HG_TIMEOUT) {
                HG_LOG_ERROR("Could not make progress on NA");
                goto done;
            }

        hg_time_get_current(&t3);
        remaining -= hg_time_to_double(hg_time_subtract(t3, t2));
    } while (remaining > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger(struct hg_context *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    while (count < max_count) {
        struct hg_completion_entry *hg_completion_entry = NULL;

        hg_thread_mutex_lock(&context->completion_queue_mutex);

        /* Is completion queue empty */
        while (TAILQ_EMPTY(&context->completion_queue)) {
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
        hg_completion_entry = TAILQ_LAST(&context->completion_queue,
                                         hg_compqueue);
        TAILQ_REMOVE(&context->completion_queue, hg_completion_entry, q);
        if (!hg_completion_entry) {
            HG_LOG_ERROR("NULL completion entry");
            ret = HG_INVALID_PARAM;
            hg_thread_mutex_unlock(&context->completion_queue_mutex);
            goto done;
        }

        /* Unlock now so that other threads can eventually add callbacks
         * to the queue while callback gets executed */
        hg_thread_mutex_unlock(&context->completion_queue_mutex);

        switch(hg_completion_entry->op_type) {
            case HG_ADDR:
                ret = hg_core_trigger_lookup_entry(hg_completion_entry->op_id.hg_op_id);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not trigger completion entry");
                    goto done;
                }
                break;
            case HG_RPC:
                ret = hg_core_trigger_entry(hg_completion_entry->op_id.hg_handle);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not trigger completion entry");
                    goto done;
                }
                break;
            case HG_BULK:
                ret = hg_bulk_trigger_entry(hg_completion_entry->op_id.hg_bulk_op_id);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not trigger completion entry");
                    goto done;
                }
                break;
            default:
                HG_LOG_ERROR("Invalid type of completion entry");
                ret = HG_PROTOCOL_ERROR;
                goto done;

        }

        count++;
    }

    if (actual_count) *actual_count = count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_lookup_entry(struct hg_op_id *hg_op_id)
{
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_op_id->callback) {
        struct hg_cb_info hg_cb_info;

        hg_cb_info.arg = hg_op_id->arg;
        hg_cb_info.ret =  HG_SUCCESS; /* TODO report failure */
        hg_cb_info.type = HG_CB_BULK;
        hg_cb_info.info.lookup.addr = hg_op_id->info.lookup.addr;

        hg_op_id->callback(&hg_cb_info);
    }

    /* Free op */
    free(hg_op_id);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_entry(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if(hg_handle->process_rpc_cb) {
        /* Handle will now be processed */
        hg_handle->process_rpc_cb = HG_FALSE;

        /* Run RPC callback */
        ret = hg_core_process(hg_handle);
        if(ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not process handle");
            goto done;
        }
    } else {
        /* Execute user callback */
        if (hg_handle->callback) {
            struct hg_cb_info hg_cb_info;

            hg_cb_info.arg = hg_handle->arg;
            hg_cb_info.ret = hg_handle->ret;
            hg_cb_info.type = hg_handle->cb_type;
            if (hg_handle->cb_type == HG_CB_INTFORWARD) {
                hg_cb_info.info.intforward.handle = (hg_handle_t) hg_handle;
                hg_cb_info.info.intforward.usercb = hg_handle->forw_usercb;
                hg_cb_info.info.intforward.userarg = hg_handle->arg;
                hg_cb_info.info.intforward.extra_in_handle =
                    hg_handle->forw_extra_in_handle;
                hg_cb_info.info.intforward.extra_in_buf =
                    hg_handle->forw_extra_in_buf;
            } else if (hg_handle->cb_type == HG_CB_FORWARD) {
                hg_cb_info.info.forward.handle = (hg_handle_t) hg_handle;
            } else if (hg_handle->cb_type == HG_CB_RESPOND) {
                hg_cb_info.info.respond.handle = (hg_handle_t) hg_handle;
            }
            
            hg_handle->callback(&hg_cb_info);
        }

        /* recycle or free the handle */
        if (hg_handle->recyclable_handle == HG_TRUE &&
            hg_atomic_get32(&hg_handle->ref_count) == 1) {

            /* this will either recycle it or free it */
            hg_core_recycle_to_pending_or_destroy(hg_handle);

        } else {

            /* free it */
            hg_core_destroy(hg_handle);
        }

    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_cancel(struct hg_handle *hg_handle)
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

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Core_init(const char *na_info_string, hg_bool_t na_listen)
{
    struct hg_class *hg_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!na_info_string) {
        HG_LOG_ERROR("Invalid specified na_info_string");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_class = hg_core_init(na_info_string, na_listen, NULL, NULL);
    if (!hg_class) {
        HG_LOG_ERROR("Cannot initialize HG core layer");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        /* Nothing */
    }
    return hg_class;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Core_init_na(na_class_t *na_class, na_context_t *na_context)
{
    struct hg_class *hg_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_class = hg_core_init(NULL, HG_FALSE, na_class, na_context);
    if (!hg_class) {
        HG_LOG_ERROR("Cannot initialize HG core layer");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        /* Nothing */
    }
    return hg_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_finalize(hg_class_t *hg_class)
{
    hg_return_t ret = HG_SUCCESS;

    ret = hg_core_finalize(hg_class);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot finalize HG core layer");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_name(const hg_class_t *hg_class)
{
    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        return NULL;
    }
    else
        return NA_Get_class_name(hg_class->na_class);
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_protocol(const hg_class_t *hg_class)
{
    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        return NULL;
    }
    else
        return NA_Get_class_protocol(hg_class->na_class);
}

/*---------------------------------------------------------------------------*/
hg_context_t *
HG_Core_context_create(hg_class_t *hg_class)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_context *context = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context = (struct hg_context *) malloc(sizeof(struct hg_context));
    if (!context) {
        HG_LOG_ERROR("Could not allocate HG context");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    context->hg_class = hg_class;
    TAILQ_INIT(&context->completion_queue);

    LIST_INIT(&context->pending_list);
    context->recycle_pending_handles =
        (NA_Is_listening(hg_class->na_class) == NA_TRUE) ? HG_TRUE : HG_FALSE;
    LIST_INIT(&context->processing_list);
    LIST_INIT(&context->self_processing_list);

    context->self_processing_pool = NULL;

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&context->completion_queue_mutex);
    hg_thread_cond_init(&context->completion_queue_cond);
    hg_thread_mutex_init(&context->pending_list_mutex);
    hg_thread_mutex_init(&context->processing_list_mutex);
    hg_thread_mutex_init(&context->self_processing_list_mutex);
    hg_thread_cond_init(&context->self_processing_list_cond);

done:
    if (ret != HG_SUCCESS && context) {
        free(context);
        context = NULL;
    }
    return context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_destroy(hg_context_t *context)
{
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;
    unsigned int actual_count;

    if (!context) goto done;

    /* Disable recycling and its NA unexpected read ops */
    hg_thread_mutex_lock(&context->pending_list_mutex);
    context->recycle_pending_handles = HG_FALSE;
    hg_thread_mutex_unlock(&context->pending_list_mutex);

    /* Check pending list */
    if (hg_core_pending_list_check(context) == HG_TRUE) {
        ret = hg_core_pending_list_cancel(context);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot cancel list of pending entries");
            goto done;
        }
    }

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(context->hg_class->na_context, 0, 1, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);

    /* Check that operations have completed */
    ret = hg_core_processing_list_wait(context);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not wait on processing list");
        goto done;
    }

    /* Check that completion queue is empty now */
    hg_thread_mutex_lock(&context->completion_queue_mutex);

    if (!TAILQ_EMPTY(&context->completion_queue)) {
        HG_LOG_ERROR("Completion queue should be empty");
        ret = HG_PROTOCOL_ERROR;
        hg_thread_mutex_unlock(&context->completion_queue_mutex);
        goto done;
    }

    hg_thread_mutex_unlock(&context->completion_queue_mutex);

    /* Destroy self processing pool if created */
    hg_thread_pool_destroy(context->self_processing_pool);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&context->completion_queue_mutex);
    hg_thread_cond_destroy(&context->completion_queue_cond);
    hg_thread_mutex_destroy(&context->pending_list_mutex);
    hg_thread_mutex_destroy(&context->processing_list_mutex);
    hg_thread_mutex_destroy(&context->self_processing_list_mutex);
    hg_thread_cond_destroy(&context->self_processing_list_cond);

    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Core_context_get_class(hg_context_t *context)
{
    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        return NULL;
    }
    else
        return context->hg_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register(hg_class_t *hg_class, hg_id_t id, hg_rpc_cb_t rpc_cb)
{
    hg_id_t *func_key = NULL;
    struct hg_rpc_info *hg_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Allocate the key */
    func_key = (hg_id_t *) malloc(sizeof(hg_id_t));
    if (!func_key) {
        HG_LOG_ERROR("Could not allocate ID");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    *func_key = id;

    /* Fill info and store it into the function map */
    hg_rpc_info = (struct hg_rpc_info *) malloc(sizeof(struct hg_rpc_info));
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not allocate HG info");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    hg_rpc_info->rpc_cb = rpc_cb;
    hg_rpc_info->data = NULL;
    hg_rpc_info->free_callback = NULL;

    if (!hg_hash_table_insert(hg_class->func_map, (hg_hash_table_key_t) func_key,
            hg_rpc_info)) {
        HG_LOG_ERROR("Could not insert RPC ID into function map (already registered?)");
        ret = HG_INVALID_PARAM;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        free(func_key);
        free(hg_rpc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_registered(hg_class_t *hg_class, hg_id_t id, hg_bool_t *flag)
{
    hg_return_t ret = HG_SUCCESS;

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

    *flag = (hg_bool_t) (hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id) != HG_HASH_TABLE_NULL);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register_data(hg_class_t *hg_class, hg_id_t id, void *data,
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

    if (hg_rpc_info->data)
        HG_LOG_WARNING("Overriding data previously registered");
    hg_rpc_info->data = data;
    hg_rpc_info->free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_registered_data(hg_class_t *hg_class, hg_id_t id)
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
HG_Core_addr_lookup(hg_context_t *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    hg_op_id_t hg_op_id;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!name) {
        HG_LOG_ERROR("NULL lookup name");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_lookup(context, callback, arg, name, &hg_op_id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not lookup address");
        goto done;
    }

    if (op_id && op_id != HG_OP_ID_IGNORE) *op_id = hg_op_id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_free(hg_class_t *hg_class, hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_free(hg_class, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_self(hg_class_t *hg_class, hg_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_self(hg_class, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get self address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_dup(hg_class_t *hg_class, hg_addr_t addr, hg_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!new_addr) {
        HG_LOG_ERROR("NULL pointer to destination address");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_dup(hg_class, addr, new_addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not duplicate address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_to_string(hg_class_t *hg_class, char *buf, hg_size_t *buf_size,
    hg_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_to_string(hg_class, buf, buf_size, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not convert address to string");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_create(hg_context_t *context, hg_addr_t addr, hg_id_t id,
    hg_handle_t *handle)
{
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (addr == HG_ADDR_NULL) {
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
    hg_handle = hg_core_create(context, HG_FALSE);
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
        hg_core_destroy(hg_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_destroy(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_destroy(hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
struct hg_info *
HG_Core_get_info(hg_handle_t handle)
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
hg_return_t
HG_Core_get_input(hg_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
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

    hg_core_get_input(hg_handle, in_buf, in_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_get_output(hg_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
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

    hg_core_get_output(hg_handle, out_buf, out_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_forward(hg_handle_t handle, hg_cb_t callback, hg_cb_t usercb,
                void *userarg, void *extra_in_buf, hg_bulk_t extra_in_handle,
                hg_size_t size_to_send)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    struct hg_header_request request_header;
    hg_return_t (*hg_forward)(struct hg_handle *hg_handle);
    hg_return_t ret = HG_SUCCESS;
    hg_size_t extra_header_size = 0;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Set callback */
    hg_handle->callback = callback;
    hg_handle->arg = userarg;          /* this is arg for usercb */
    hg_handle->forw_usercb = usercb;
    hg_handle->forw_extra_in_buf = extra_in_buf;
    hg_handle->forw_extra_in_handle = extra_in_handle;
    hg_handle->cb_type = HG_CB_INTFORWARD;

    /* Increase ref count here so that a call to HG_Destroy does not free the
     * handle but only schedules its completion
     */
    hg_atomic_incr32(&hg_handle->ref_count);

    /* Set header */
    hg_proc_header_request_init(hg_handle->hg_info.id, extra_in_handle,
            &request_header);

    /* Encode request header */
    ret = hg_proc_header_request(hg_handle->in_buf, hg_handle->in_buf_size,
            &request_header, HG_ENCODE, hg_handle->hg_info.hg_class,
            &extra_header_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    /* set the actual size of the msg that needs to be transmitted */
    hg_handle->in_buf_used = size_to_send + extra_header_size;

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    hg_forward = NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
            hg_handle->hg_info.addr) ? hg_core_forward_self : hg_core_forward_na;
    ret = hg_forward(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward buffer");
        goto done;
    }

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_respond(hg_handle_t handle, hg_cb_t callback, void *arg,
    hg_return_t ret_code, hg_size_t size_to_send)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t (*hg_respond)(struct hg_handle *hg_handle, hg_cb_t callback,
            void *arg);
    struct hg_header_response response_header;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Set error code if any */
    hg_handle->ret = ret_code;

    /* Fill the header */
    hg_proc_header_response_init(&response_header);
    response_header.cookie = hg_handle->cookie;
    response_header.ret_code = hg_handle->ret;

    /* Encode response header */
    ret = hg_proc_header_response(hg_handle->out_buf, hg_handle->out_buf_size,
            &response_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    /* set the actual size of the msg that needs to be transmitted */
    hg_handle->out_buf_used = size_to_send;

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    hg_respond = NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
            hg_handle->hg_info.addr) ? hg_core_respond_self : hg_core_respond_na;
    ret = hg_respond(hg_handle, callback, arg);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not respond");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_progress(hg_context_t *context, unsigned int timeout)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* If we are listening, try to post unexpected receives and treat incoming
     * RPCs */
    if (NA_Is_listening(context->hg_class->na_class)) {
        ret = hg_core_listen(context);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not listen");
            goto done;
        }
    }

    /* Make progress on the HG layer */
    ret = hg_core_progress(context, timeout);
    if (ret != HG_SUCCESS && ret != HG_TIMEOUT) {
        HG_LOG_ERROR("Could not make progress");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_trigger(hg_context_t *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_trigger(context, timeout, max_count, actual_count);
    if (ret != HG_SUCCESS && ret != HG_TIMEOUT) {
        HG_LOG_ERROR("Could not trigger callbacks");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_cancel(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_cancel(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not cancel handle");
        goto done;
    }

done:
    return ret;
}
