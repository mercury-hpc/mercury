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
#include "mercury_private.h"
#include "mercury_error.h"

#include "mercury_hash_table.h"
#include "mercury_atomic.h"
#include "mercury_queue.h"
#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_spin.h"
#include "mercury_thread_condition.h"
#include "mercury_time.h"
#include "mercury_atomic.h"
#include "mercury_poll.h"
#include "mercury_thread_pool.h"
#ifdef HG_HAS_SELF_FORWARD
#include "mercury_event.h"
#endif
#include "mercury_atomic_queue.h"

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

#define HG_CORE_MAX_SELF_THREADS    4
#define HG_CORE_MASK_NBITS          8
#define HG_CORE_ATOMIC_QUEUE_SIZE   1024
#define HG_CORE_PENDING_INCR        256

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

/* Private callback type for HG layer */
typedef hg_return_t (*handle_create_cb_t)(hg_class_t *, hg_handle_t);

/* HG class */
struct hg_class {
    na_class_t *na_class;               /* NA class */
    hg_hash_table_t *func_map;          /* Function map */
    hg_thread_spin_t func_map_lock;     /* Function map mutex */
    hg_atomic_int32_t request_tag;      /* Atomic used for tag generation */
    na_tag_t request_max_tag;           /* Max value for tag */
    unsigned int na_max_tag_msb;        /* MSB of NA max tag */
    hg_bool_t use_tag_mask;             /* Can use tag masking or not */
    hg_bool_t na_ext_init;              /* NA externally initialized */
    handle_create_cb_t handle_create_callback; /* Callback executed on hg_core_create */
#ifdef HG_HAS_SELF_FORWARD
    hg_thread_pool_t *self_processing_pool; /* Thread pool for self processing */
#endif
    hg_atomic_int32_t n_contexts;       /* Atomic used for number of contexts */
    hg_atomic_int32_t n_addrs;          /* Atomic used for number of addrs */
};

/* HG context */
struct hg_context {
    struct hg_class *hg_class;                    /* HG class */
    na_context_t *na_context;                     /* NA context */
    hg_uint8_t id;                                /* Context ID */
    na_tag_t request_mask;                        /* Request tag mask */
    struct hg_poll_set *poll_set;                 /* Context poll set */
    /* Pointer to function used for making progress */
    hg_return_t (*progress)(struct hg_context *context, unsigned int timeout);
    struct hg_atomic_queue *completion_queue;     /* Default completion queue */
    HG_QUEUE_HEAD(hg_completion_entry) backfill_queue; /* Backfill completion queue */
    hg_atomic_int32_t backfill_queue_count;       /* Backfill queue count */
    hg_thread_mutex_t completion_queue_mutex;     /* Completion queue mutex */
    hg_thread_cond_t  completion_queue_cond;      /* Completion queue cond */
    hg_atomic_int32_t trigger_waiting;            /* Waiting in trigger */
    HG_LIST_HEAD(hg_handle) pending_list;         /* List of pending handles */
    hg_thread_spin_t pending_list_lock;           /* Pending list lock */
    HG_LIST_HEAD(hg_handle) processing_list;      /* List of handles being processed */
    hg_thread_spin_t processing_list_lock;        /* Processing list lock */
#ifdef HG_HAS_SELF_FORWARD
    int completion_queue_notify;                  /* Self notification */
    HG_LIST_HEAD(hg_handle) self_processing_list; /* List of handles being processed */
    hg_thread_spin_t self_processing_list_lock;   /* Processing list lock */
#endif
    hg_bool_t finalizing;                         /* Prevent reposts */
    hg_atomic_int32_t n_handles;                  /* Atomic used for number of handles */
};

/* Info for function map */
struct hg_rpc_info {
    hg_rpc_cb_t rpc_cb;             /* RPC callback */
    hg_bool_t no_response;          /* RPC response not expected */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
};

#ifdef HG_HAS_SELF_FORWARD
/* Info for wrapping callbacks if self addr */
struct hg_self_cb_info {
    hg_cb_t forward_cb;
    void *forward_arg;
    hg_cb_t respond_cb;
    void *respond_arg;
};
#endif

/* HG addr */
struct hg_addr {
    na_addr_t na_addr;                  /* Underlying NA address */
    hg_bool_t local;                    /* Address is local */
    hg_bool_t is_mine;                  /* Created internally or not */
    hg_atomic_int32_t ref_count;        /* Reference count */
};

/* HG handle */
struct hg_handle {
    struct hg_info hg_info;             /* HG info */
    hg_cb_t callback;                   /* Callback */
    void *arg;                          /* Callback arguments */
    hg_cb_type_t cb_type;               /* Callback type */
    na_tag_t tag;                       /* Tag used for request and response */
    hg_uint32_t cookie;                 /* Cookie unique to every RPC call */
    hg_return_t ret;                    /* Return code associated to handle */
    HG_LIST_ENTRY(hg_handle) entry;     /* Entry in pending / processing lists */
    struct hg_completion_entry hg_completion_entry; /* Entry in completion queue */
    hg_bool_t repost;                   /* Repost handle on completion (listen) */
    hg_bool_t process_rpc_cb;           /* RPC callback must be processed */
    hg_bool_t is_self;                  /* Handle self processed */

    void *in_buf;                       /* Input buffer */
    void *in_buf_plugin_data;           /* Input buffer NA plugin data */
    na_size_t in_buf_size;              /* Input buffer size */
    na_size_t na_in_header_offset;      /* Input NA header offset */
    na_size_t in_buf_used;              /* Amount of input buffer used */
    void *out_buf;                      /* Output buffer */
    void *out_buf_plugin_data;          /* Output buffer NA plugin data */
    na_size_t out_buf_size;             /* Output buffer size */
    na_size_t na_out_header_offset;     /* Output NA header offset */
    na_size_t out_buf_used;             /* Amount of output buffer used */

    na_op_id_t na_send_op_id;           /* Operation ID for send */
    na_op_id_t na_recv_op_id;           /* Operation ID for recv */
    hg_atomic_int32_t na_completed_count; /* Number of NA operations completed */
    hg_bool_t na_op_id_mine;            /* Operation ID created by HG */

    hg_atomic_int32_t ref_count;        /* Reference count */

    void *extra_in_buf;
    hg_size_t extra_in_buf_size;
    hg_op_id_t extra_in_op_id;

    struct hg_header_request in_header; /* Input header */
    struct hg_header_response out_header; /* Output header */

    struct hg_rpc_info *hg_rpc_info;    /* Associated RPC info */
    hg_bool_t no_response;              /* Require response or not */
    void *private_data;                 /* Private data */
    void (*private_free_callback)(void *); /* Private data free callback */

    struct hg_thread_work thread_work;  /* Used for self processing and testing */
};

/* HG op id */
struct hg_op_info_lookup {
    struct hg_addr *hg_addr;            /* Address */
    na_op_id_t na_lookup_op_id;         /* Operation ID for lookup */
};

struct hg_op_id {
    struct hg_context *context;         /* Context */
    hg_cb_type_t type;                  /* Callback type */
    hg_cb_t callback;                   /* Callback */
    void *arg;                          /* Callback arguments */
    hg_atomic_int32_t completed;        /* Operation completed TODO needed ? */
    union {
        struct hg_op_info_lookup lookup;
    } info;
    struct hg_completion_entry hg_completion_entry; /* Entry in completion queue */
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
 * Proc request header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_request(
        struct hg_handle *hg_handle,
        struct hg_header_request *request_header,
        hg_proc_op_t op,
        hg_size_t *extra_header_size
        );

/**
 * Proc response header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_response(
        struct hg_handle *hg_handle,
        struct hg_header_response *response_header,
        hg_proc_op_t op
        );

/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_core_pending_list_cancel(
        struct hg_context *context
        );

/**
 * Wail until processing list is empty.
 */
static hg_return_t
hg_core_processing_list_wait(
        struct hg_context *context
        );

/**
 * Initialize class.
 */
static struct hg_class *
hg_core_init(
        const char *na_info_string,
        hg_bool_t na_listen,
        na_class_t *na_init_class
        );

/**
 * Finalize class.
 */
static hg_return_t
hg_core_finalize(
        struct hg_class *hg_class
        );

/**
 * Set handle create callback.
 */
void
hg_core_set_handle_create_callback(
        struct hg_class *hg_class,
        handle_create_cb_t handle_create_callback
        );

/**
 * Get NA context.
 */
na_context_t *
hg_core_get_na_context(
        struct hg_context *context
        );

/**
 * Create addr.
 */
static struct hg_addr *
hg_core_addr_create(
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
static int
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
        struct hg_addr *hg_addr
        );


/**
 * Self addr.
 */
static hg_return_t
hg_core_addr_self(
        struct hg_class *hg_class,
        struct hg_addr **self_addr
        );

/**
 * Dup addr.
 */
static hg_return_t
hg_core_addr_dup(
        struct hg_class *hg_class,
        struct hg_addr *hg_addr,
        struct hg_addr **hg_new_addr
        );

/**
 * Convert addr to string.
 */
static hg_return_t
hg_core_addr_to_string(
        struct hg_class *hg_class,
        char *buf,
        hg_size_t *buf_size,
        struct hg_addr *hg_addr
        );

/**
 * Create handle.
 */
static struct hg_handle *
hg_core_create(
        struct hg_context *context
        );

/**
 * Free handle.
 */
static void
hg_core_destroy(
        struct hg_handle *hg_handle
        );

/**
 * Reset handle.
 */
static hg_return_t
hg_core_reset(
        struct hg_handle *hg_handle,
        hg_bool_t reset_info
        );

/**
 * Set target addr / RPC ID
 */
static hg_return_t
hg_core_set_rpc(
        struct hg_handle *hg_handle,
        hg_addr_t addr,
        hg_id_t id
        );

/**
 * Set private data.
 */
void
hg_core_set_private_data(
        struct hg_handle *hg_handle,
        void *private_data,
        void (*private_free_callback)(void *)
        );

/**
 * Get private data.
 */
void *
hg_core_get_private_data(
        struct hg_handle *hg_handle
        );

/**
 * Get RPC registered data.
 */
void *
hg_core_get_rpc_data(
        struct hg_handle *hg_handle
        );

/**
 * Get thread work (TODO internal use but could provide some hooks).
 */
struct hg_thread_work *
hg_core_get_thread_work(
        hg_handle_t handle
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Forward handle locally.
 */
static hg_return_t
hg_core_forward_self(
        struct hg_handle *hg_handle
        );
#endif

/**
 * Forward handle through NA.
 */
static hg_return_t
hg_core_forward_na(
        struct hg_handle *hg_handle
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Send response locally.
 */
static hg_return_t
hg_core_respond_self(
        struct hg_handle *hg_handle,
        hg_cb_t callback,
        void *arg
        );
#endif

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
static int
hg_core_send_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv input callback.
 */
static int
hg_core_recv_input_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Send output callback.
 */
static int
hg_core_send_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv output callback.
 */
static int
hg_core_recv_output_cb(
        const struct na_cb_info *callback_info
        );

#ifdef HG_HAS_SELF_FORWARD
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
#endif

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
        struct hg_completion_entry *hg_completion_entry,
        hg_bool_t self_notify
        );

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_core_context_post(
        struct hg_context *context,
        unsigned int request_count,
        hg_bool_t repost
        );

/**
 * Post handle and add it to pending list.
 */
static hg_return_t
hg_core_post(
        struct hg_handle *hg_handle
        );

/**
 * Reset handle and re-post it.
 */
static hg_return_t
hg_core_reset_post(
        struct hg_handle *hg_handle
        );

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_core_progress_na(
        struct hg_context *context,
        unsigned int timeout
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Completion queue notification callback.
 */
static int
hg_core_completion_queue_notify_cb(
        void *arg,
        unsigned int timeout,
        hg_util_bool_t *progressed
        );
#endif

/**
 * Progress callback on NA layer when hg_core_progress_poll() is used.
 */
static int
hg_core_progress_na_cb(
        void *arg,
        unsigned int timeout,
        hg_util_bool_t *progressed
        );

/**
 * Callback for HG poll progress that determines when it is safe to block.
 */
static HG_INLINE hg_util_bool_t
hg_core_poll_try_wait_cb(
        void *arg
        );

/**
 * Make progress.
 */
static hg_return_t
hg_core_progress_poll(
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
 * Find tag most significant bit.
 */
static HG_INLINE unsigned int
hg_core_tag_msb(na_tag_t tag)
{
    unsigned int ret = 0;

    while (tag >>= 1)
        ret++;

    return ret;
}

/*---------------------------------------------------------------------------*/
/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_core_gen_request_tag(struct hg_class *hg_class,
    struct hg_handle *hg_handle)
{
    na_tag_t tag = 0;
    na_tag_t request_tag = 0;

    /* Compare and swap tag if reached max tag */
    if (!hg_atomic_cas32(&hg_class->request_tag,
        (hg_util_int32_t) hg_class->request_max_tag, 0)) {
        /* Increment tag */
        request_tag = (na_tag_t) hg_atomic_incr32(&hg_class->request_tag);
    }

    /* Use handle target ID if tag mask is enabled */
    tag = (hg_handle->hg_info.target_id && hg_class->use_tag_mask) ?
        (na_tag_t) (hg_handle->hg_info.target_id << (hg_class->na_max_tag_msb
            + 1 - HG_CORE_MASK_NBITS)) | request_tag
        : request_tag;

    return tag;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_core_get_input(struct hg_handle *hg_handle, void **in_buf,
    hg_size_t *in_buf_size)
{
    hg_size_t header_offset = hg_proc_header_request_get_size() +
        hg_handle->na_in_header_offset;

    /* Space must be left for request header, no offset if extra buffer since
     * only the user payload is copied */
    *in_buf =
        (hg_handle->extra_in_buf) ? hg_handle->extra_in_buf :
            ((char *) hg_handle->in_buf + header_offset);
    *in_buf_size =
        (hg_handle->extra_in_buf_size) ? hg_handle->extra_in_buf_size :
            (hg_handle->in_buf_size - header_offset);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_core_get_output(struct hg_handle *hg_handle, void **out_buf,
    hg_size_t *out_buf_size)
{
    hg_size_t header_offset = hg_proc_header_response_get_size() +
        hg_handle->na_out_header_offset;

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
    HG_Bulk_free(local_in_handle);
    HG_Bulk_free(extra_in_handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_get_extra_input_cb(const struct hg_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

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
static HG_INLINE hg_return_t
hg_core_proc_header_request(struct hg_handle *hg_handle,
    struct hg_header_request *request_header, hg_proc_op_t op,
    hg_size_t *extra_header_size)
{
    char *header_buf = (char *) hg_handle->in_buf +
        hg_handle->na_in_header_offset;
    size_t header_buf_size = hg_handle->in_buf_size -
        hg_handle->na_in_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc request header */
    ret = hg_proc_header_request(header_buf, header_buf_size,
        request_header, op, hg_handle->hg_info.hg_class, extra_header_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process request header");
        goto done;
    }

    if (op == HG_DECODE) {
        ret = hg_proc_header_request_verify(request_header);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not verify request header");
            goto done;
        }
    }

done:
    return ret;
}


/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_proc_header_response(struct hg_handle *hg_handle,
    struct hg_header_response *response_header, hg_proc_op_t op)
{
    char *header_buf = (char *) hg_handle->out_buf +
        hg_handle->na_out_header_offset;
    size_t header_buf_size = hg_handle->out_buf_size -
        hg_handle->na_out_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc response header */
    ret = hg_proc_header_response(header_buf, header_buf_size,
        response_header, op);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process response header");
        goto done;
    }

    if (op == HG_DECODE) {
        ret = hg_proc_header_response_verify(response_header);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not verify response header");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_pending_list_cancel(struct hg_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_spin_lock(&context->pending_list_lock);

    while (!HG_LIST_IS_EMPTY(&context->pending_list)) {
        struct hg_handle *hg_handle = HG_LIST_FIRST(&context->pending_list);
        HG_LIST_REMOVE(hg_handle, entry);

        /* Prevent reposts */
        hg_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not cancel handle");
            break;
        }
    }

    hg_thread_spin_unlock(&context->pending_list_lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_processing_list_wait(struct hg_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    for (;;) {
        hg_util_bool_t processing_list_empty = HG_UTIL_FALSE;
        unsigned int actual_count = 0;
        hg_return_t trigger_ret;

        /* Trigger everything we can from HG */
        do {
            trigger_ret = hg_core_trigger(context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        hg_thread_spin_lock(&context->processing_list_lock);

        processing_list_empty = HG_LIST_IS_EMPTY(&context->processing_list);

        hg_thread_spin_unlock(&context->processing_list_lock);

        if (processing_list_empty) break;

        ret = context->progress(context, HG_MAX_IDLE_TIME);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not make progress");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    na_class_t *na_init_class)
{
    struct hg_class *hg_class = NULL;
    na_tag_t na_max_tag;
    hg_return_t ret = HG_SUCCESS;

    /* Create new HG class */
    hg_class = (struct hg_class *) malloc(sizeof(struct hg_class));
    if (!hg_class) {
        HG_LOG_ERROR("Could not allocate HG class");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    memset(hg_class, 0, sizeof(struct hg_class));
    hg_class->na_class = na_init_class;
    hg_class->na_ext_init = (na_init_class) ? HG_TRUE : HG_FALSE;

    /* Initialize NA */
    if (!hg_class->na_ext_init) {
        hg_class->na_class = NA_Initialize(na_info_string, na_listen);
        if (!hg_class->na_class) {
            HG_LOG_ERROR("Could not initialize NA class");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* Compute max request tag */
    na_max_tag = NA_Msg_get_max_tag(hg_class->na_class);
    if (!na_max_tag) {
        HG_LOG_ERROR("NA Max tag is not defined");
        ret = HG_NA_ERROR;
        goto done;
    }
    hg_class->use_tag_mask = NA_Check_feature(hg_class->na_class,
        NA_HAS_TAG_MASK);
    hg_class->request_max_tag =
        (hg_class->use_tag_mask) ? na_max_tag >> HG_CORE_MASK_NBITS :
            na_max_tag;

    /* Find MSB of na_max_tag */
    hg_class->na_max_tag_msb = hg_core_tag_msb(na_max_tag);

    /* Initialize atomic for tags */
    hg_atomic_init32(&hg_class->request_tag, 0);

    /* No context created yet */
    hg_atomic_init32(&hg_class->n_contexts, 0);

    /* No addr created yet */
    hg_atomic_init32(&hg_class->n_addrs, 0);

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

    /* Initialize mutex */
    hg_thread_spin_init(&hg_class->func_map_lock);

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
    hg_util_int32_t n_addrs, n_contexts;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) goto done;

    n_contexts = hg_atomic_get32(&hg_class->n_contexts);
    if (n_contexts != 0) {
        HG_LOG_ERROR("HG contexts must be destroyed before finalizing HG"
            " (%d remaining)", n_contexts);
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    n_addrs = hg_atomic_get32(&hg_class->n_addrs);
    if (n_addrs != 0) {
        HG_LOG_ERROR("HG addrs must be freed before finalizing HG"
            " (%d remaining)", n_addrs);
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

#ifdef HG_HAS_SELF_FORWARD
    /* Destroy self processing pool if created */
    hg_thread_pool_destroy(hg_class->self_processing_pool);
#endif

    /* Delete function map */
    if(hg_class->func_map)
        hg_hash_table_free(hg_class->func_map);
    hg_class->func_map = NULL;

    /* Destroy mutex */
    hg_thread_spin_destroy(&hg_class->func_map_lock);

    if (!hg_class->na_ext_init) {
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
void
hg_core_set_handle_create_callback(struct hg_class *hg_class,
    handle_create_cb_t handle_create_callback)
{
    hg_class->handle_create_callback = handle_create_callback;
}

/*---------------------------------------------------------------------------*/
na_context_t *
hg_core_get_na_context(struct hg_context *context)
{
    return context->na_context;
}

/*---------------------------------------------------------------------------*/
static struct hg_addr *
hg_core_addr_create(struct hg_class *hg_class)
{
    struct hg_addr *hg_addr = NULL;

    hg_addr = (struct hg_addr *) malloc(sizeof(struct hg_addr));
    if (!hg_addr) {
        HG_LOG_ERROR("Could not allocate HG addr");
        goto done;
    }
    memset(hg_addr, 0, sizeof(struct hg_addr));
    hg_addr->na_addr = NA_ADDR_NULL;
    hg_atomic_init32(&hg_addr->ref_count, 1);

    /* Increment N addrs from HG class */
    hg_atomic_incr32(&hg_class->n_addrs);

done:
    return hg_addr;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup(struct hg_context *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    na_class_t *na_class = context->hg_class->na_class;
    na_context_t *na_context = context->na_context;
    struct hg_op_id *hg_op_id = NULL;
    struct hg_addr *hg_addr = NULL;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS, progress_ret;

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
    hg_atomic_init32(&hg_op_id->completed, 0);
    hg_op_id->info.lookup.hg_addr = NULL;
    hg_op_id->info.lookup.na_lookup_op_id = NA_OP_ID_NULL;

    /* Allocate addr */
    hg_addr = hg_core_addr_create(context->hg_class);
    if (!hg_addr) {
        HG_LOG_ERROR("Could not create HG addr");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_op_id->info.lookup.hg_addr = hg_addr;

    /* Assign op_id */
    if (op_id && op_id != HG_OP_ID_IGNORE)
        *op_id = (hg_op_id_t) hg_op_id;

    na_ret = NA_Addr_lookup(na_class, na_context, hg_core_addr_lookup_cb,
            hg_op_id, name, &hg_op_id->info.lookup.na_lookup_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not start lookup for address %s", name);
        ret = HG_NA_ERROR;
        goto done;
    }

    /* TODO to avoid blocking after lookup make progress on the HG layer with
     * timeout of 0 */
    progress_ret = context->progress(context, 0);
    if (progress_ret != HG_SUCCESS && progress_ret != HG_TIMEOUT) {
        HG_LOG_ERROR("Could not make progress");
        ret = progress_ret;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        free(hg_op_id);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_addr_lookup_cb(const struct na_cb_info *callback_info)
{
    struct hg_op_id *hg_op_id = (struct hg_op_id *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Assign addr */
    hg_op_id->info.lookup.hg_addr->na_addr = callback_info->info.lookup.addr;

    /* TODO could determine here if address is local */
//    hg_op_id->info.lookup.addr->local = HG_FALSE;

    /* Mark as completed */
    if (hg_core_addr_lookup_complete(hg_op_id) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        goto done;
    }
    ret++;

done:
    (void) na_ret;
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup_complete(struct hg_op_id *hg_op_id)
{
    hg_context_t *context = hg_op_id->context;
    struct hg_completion_entry *hg_completion_entry =
        &hg_op_id->hg_completion_entry;
    hg_return_t ret = HG_SUCCESS;

    /* Mark operation as completed */
    hg_atomic_incr32(&hg_op_id->completed);

    hg_completion_entry->op_type = HG_ADDR;
    hg_completion_entry->op_id.hg_op_id = hg_op_id;

    ret = hg_core_completion_add(context, hg_completion_entry, HG_FALSE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add HG completion entry to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_free(struct hg_class *hg_class, struct hg_addr *hg_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_addr) goto done;

    if (hg_atomic_decr32(&hg_addr->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Decrement N addrs from HG class */
    hg_atomic_decr32(&hg_class->n_addrs);

    na_ret = NA_Addr_free(hg_class->na_class, hg_addr->na_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not free address");
        ret = HG_NA_ERROR;
        goto done;
    }
    free(hg_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_self(struct hg_class *hg_class, struct hg_addr **self_addr)
{
    struct hg_addr *hg_addr = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_addr = hg_core_addr_create(hg_class);
    if (!hg_addr) {
        HG_LOG_ERROR("Could not create HG addr");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    na_ret = NA_Addr_self(hg_class->na_class, &hg_addr->na_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not get self address");
        ret = HG_NA_ERROR;
        goto done;
    }

    *self_addr = hg_addr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_dup(struct hg_class *hg_class, struct hg_addr *hg_addr,
    struct hg_addr **hg_new_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /**
     * If address is internal, create a new copy to prevent repost
     * operations to modify underlying NA address, otherwise simply increment
     * refcount of original address.
     */
    if (hg_addr->is_mine) {
        struct hg_addr *dup = NULL;

        dup = hg_core_addr_create(hg_class);
        if (!dup) {
            HG_LOG_ERROR("Could not create HG addr");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        na_ret = NA_Addr_dup(hg_class->na_class, hg_addr->na_addr,
            &dup->na_addr);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not duplicate address");
            ret = HG_NA_ERROR;
            goto done;
        }
        dup->local = hg_addr->local;
        *hg_new_addr = dup;
    } else {
        hg_atomic_incr32(&hg_addr->ref_count);
        *hg_new_addr = hg_addr;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_to_string(struct hg_class *hg_class, char *buf, hg_size_t *buf_size,
    struct hg_addr *hg_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    na_ret = NA_Addr_to_string(hg_class->na_class, buf, buf_size,
        hg_addr->na_addr);
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
hg_core_create(struct hg_context *context)
{
    na_class_t *na_class = context->hg_class->na_class;
    struct hg_handle *hg_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (!hg_handle) {
        HG_LOG_ERROR("Could not allocate handle");
        goto done;
    }
    memset(hg_handle, 0, sizeof(struct hg_handle));

    hg_handle->hg_info.hg_class = context->hg_class;
    hg_handle->hg_info.context = context;
    hg_handle->hg_info.addr = HG_ADDR_NULL;
    hg_handle->hg_info.id = 0;
    hg_handle->hg_info.target_id = 0;
    hg_handle->ret = HG_SUCCESS;

    /* Initialize processing buffers and use unexpected message size */
    hg_handle->in_buf_size = NA_Msg_get_max_unexpected_size(na_class);
    hg_handle->out_buf_size = NA_Msg_get_max_expected_size(na_class);
    hg_handle->na_in_header_offset = NA_Msg_get_unexpected_header_size(na_class);
    hg_handle->na_out_header_offset = NA_Msg_get_expected_header_size(na_class);

    hg_handle->in_buf = NA_Msg_buf_alloc(na_class, hg_handle->in_buf_size,
        &hg_handle->in_buf_plugin_data);
    if (!hg_handle->in_buf) {
        HG_LOG_ERROR("Could not allocate buffer for input");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    NA_Msg_init_unexpected(na_class, hg_handle->in_buf, hg_handle->in_buf_size);

    hg_handle->out_buf = NA_Msg_buf_alloc(na_class, hg_handle->out_buf_size,
        &hg_handle->out_buf_plugin_data);
    if (!hg_handle->out_buf) {
        HG_LOG_ERROR("Could not allocate buffer for output");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    NA_Msg_init_expected(na_class, hg_handle->out_buf, hg_handle->out_buf_size);

    /* Init in/out header */
    hg_proc_header_request_init(&hg_handle->in_header);
    hg_proc_header_response_init(&hg_handle->out_header);

    /* Create NA operation IDs */
    hg_handle->na_send_op_id = NA_Op_create(na_class);
    hg_handle->na_recv_op_id = NA_Op_create(na_class);
    if (hg_handle->na_recv_op_id || hg_handle->na_send_op_id) {
        if ((hg_handle->na_recv_op_id == NA_OP_ID_NULL)
            || (hg_handle->na_send_op_id == NA_OP_ID_NULL)) {
            HG_LOG_ERROR("NULL operation ID");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        hg_handle->na_op_id_mine = HG_TRUE;
    }
    hg_atomic_init32(&hg_handle->na_completed_count, 0);

    /* Set refcount to 1 */
    hg_atomic_init32(&hg_handle->ref_count, 1);

    /* Increment N handles from HG context */
    hg_atomic_incr32(&context->n_handles);

    /* Execute context callback on handle, this allows upper layers to allocate
     * private data on handle creation */
    if (context->hg_class->handle_create_callback) {
        ret = context->hg_class->handle_create_callback(context->hg_class,
            (hg_handle_t) hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in HG handle create callback");
            goto done;
        }
    }

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
    na_return_t na_ret;

    if (!hg_handle) goto done;

    if (hg_atomic_decr32(&hg_handle->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Decrement N handles from HG context */
    hg_atomic_decr32(&hg_handle->hg_info.context->n_handles);

    /* Remove reference to HG addr */
    hg_core_addr_free(hg_handle->hg_info.hg_class, hg_handle->hg_info.addr);

    na_ret = NA_Op_destroy(hg_handle->hg_info.hg_class->na_class,
        hg_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA op ID");
    NA_Op_destroy(hg_handle->hg_info.hg_class->na_class,
        hg_handle->na_recv_op_id);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA op ID");

    hg_proc_header_request_finalize(&hg_handle->in_header);
    hg_proc_header_response_finalize(&hg_handle->out_header);

    na_ret = NA_Msg_buf_free(hg_handle->hg_info.hg_class->na_class,
        hg_handle->in_buf, hg_handle->in_buf_plugin_data);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA input msg buffer");
    na_ret = NA_Msg_buf_free(hg_handle->hg_info.hg_class->na_class,
        hg_handle->out_buf, hg_handle->out_buf_plugin_data);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA output msg buffer");

    free(hg_handle->extra_in_buf);

    if (hg_handle->private_free_callback)
        hg_handle->private_free_callback(hg_handle->private_data);

    free(hg_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_reset(struct hg_handle *hg_handle, hg_bool_t reset_info)
{
    /* Reset source address */
    if (reset_info) {
        if (hg_handle->hg_info.addr != HG_ADDR_NULL
            && hg_handle->hg_info.addr->na_addr != NA_ADDR_NULL) {
            NA_Addr_free(hg_handle->hg_info.hg_class->na_class,
                hg_handle->hg_info.addr->na_addr);
            hg_handle->hg_info.addr->na_addr = NA_ADDR_NULL;
        }
        hg_handle->hg_info.id = 0;
        hg_handle->hg_info.target_id = 0;
    }
    hg_handle->callback = NULL;
    hg_handle->arg = NULL;
    hg_handle->cb_type = 0;
    hg_handle->tag = 0;
    hg_handle->cookie = 0;
    hg_handle->ret = HG_SUCCESS;
    hg_handle->in_buf_used = 0;
    hg_handle->out_buf_used = 0;
    hg_atomic_set32(&hg_handle->na_completed_count, 0);
    if (hg_handle->extra_in_buf) {
        free(hg_handle->extra_in_buf);
        hg_handle->extra_in_buf = NULL;
    }
    hg_handle->extra_in_buf_size = 0;
    hg_handle->extra_in_op_id = HG_OP_ID_NULL;

    hg_proc_header_request_reset(&hg_handle->in_header);
    hg_proc_header_response_reset(&hg_handle->out_header);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_set_rpc(struct hg_handle *hg_handle, hg_addr_t addr, hg_id_t id)
{
    hg_return_t ret = HG_SUCCESS;

    /* We allow for NULL addr to be passed at creation time, this allows
     * for pool of handles to be created and later re-used after a call to
     * HG_Core_reset() */
    if (addr != HG_ADDR_NULL && hg_handle->hg_info.addr != addr) {
        if (hg_handle->hg_info.addr != HG_ADDR_NULL)
             hg_core_addr_free(hg_handle->hg_info.hg_class,
                               hg_handle->hg_info.addr);
        hg_handle->hg_info.addr = addr;
        hg_atomic_incr32(&addr->ref_count); /* Increase ref to addr */
    }

    /* We also allow for NULL RPC id to be passed (same reason as above) */
    if (id && hg_handle->hg_info.id != id) {
        struct hg_rpc_info *hg_rpc_info;
        hg_context_t *context = hg_handle->hg_info.context;
        hg_handle->hg_info.id = id;

        /* Retrieve ID function from function map */
        hg_thread_spin_lock(&context->hg_class->func_map_lock);
        hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(
            context->hg_class->func_map, (hg_hash_table_key_t) &id);
        hg_thread_spin_unlock(&context->hg_class->func_map_lock);
        if (!hg_rpc_info) {
            HG_LOG_ERROR("Could not find RPC ID in function map");
            ret = HG_NO_MATCH;
            goto done;
        }

        /* Cache RPC info */
        hg_handle->hg_rpc_info = hg_rpc_info;

        /* Copy no response flag */
        hg_handle->no_response = hg_rpc_info->no_response;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
hg_core_set_private_data(struct hg_handle *hg_handle, void *private_data,
    void (*private_free_callback)(void *))
{
    hg_handle->private_data = private_data;
    hg_handle->private_free_callback = private_free_callback;
}

/*---------------------------------------------------------------------------*/
void *
hg_core_get_private_data(struct hg_handle *hg_handle)
{
    return hg_handle->private_data;
}

/*---------------------------------------------------------------------------*/
void *
hg_core_get_rpc_data(struct hg_handle *hg_handle)
{
    void *data = NULL;

    if (hg_handle->hg_rpc_info)
        data = hg_handle->hg_rpc_info->data;

    return data;
}

/*---------------------------------------------------------------------------*/
struct hg_thread_work *
hg_core_get_thread_work(hg_handle_t handle)
{
    return &((struct hg_handle *) handle)->thread_work;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_forward_self(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Initialize thread pool if not initialized yet */
    if (!hg_handle->hg_info.hg_class->self_processing_pool) {
        hg_thread_pool_init(HG_CORE_MAX_SELF_THREADS,
            &hg_handle->hg_info.hg_class->self_processing_pool);
    }

    /* Add handle to self processing list */
    hg_thread_spin_lock(&hg_handle->hg_info.context->self_processing_list_lock);
    HG_LIST_INSERT_HEAD(&hg_handle->hg_info.context->self_processing_list,
        hg_handle, entry);
    hg_thread_spin_unlock(
        &hg_handle->hg_info.context->self_processing_list_lock);

    /* Post operation to self processing pool */
    hg_handle->thread_work.func = hg_core_process_thread;
    hg_handle->thread_work.args = hg_handle;
    hg_thread_pool_post(hg_handle->hg_info.hg_class->self_processing_pool,
        &hg_handle->thread_work);

    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_na(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_context *hg_context = hg_handle->hg_info.context;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Generate tag */
    hg_handle->tag = hg_core_gen_request_tag(hg_class, hg_handle);

    /* Pre-post the recv message (output) if response is expected */
    if (!hg_handle->hg_rpc_info->no_response) {
        na_ret = NA_Msg_recv_expected(hg_class->na_class, hg_context->na_context,
            hg_core_recv_output_cb, hg_handle, hg_handle->out_buf,
            hg_handle->out_buf_size, hg_handle->out_buf_plugin_data,
            hg_handle->hg_info.addr->na_addr, hg_handle->tag,
            &hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post recv for output buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* And post the send message (input) */
    na_ret = NA_Msg_send_unexpected(hg_class->na_class,
            hg_context->na_context, hg_core_send_input_cb, hg_handle,
            hg_handle->in_buf, hg_handle->in_buf_used,
            hg_handle->in_buf_plugin_data, hg_handle->hg_info.addr->na_addr,
            hg_handle->tag, &hg_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for input buffer");
        /* cancel the above posted recv op */
        na_ret = NA_Cancel(hg_class->na_class, hg_context->na_context,
                           hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel recv op id");
        }
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
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

    /* Remove handle from processing list */
    hg_thread_spin_lock(&hg_handle->hg_info.context->self_processing_list_lock);
    HG_LIST_REMOVE(hg_handle, entry);
    hg_thread_spin_unlock(&hg_handle->hg_info.context->self_processing_list_lock);

    /* Complete and add to completion queue */
    ret = hg_core_complete(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete handle");
        goto done;
    }

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_respond_na(struct hg_handle *hg_handle, hg_cb_t callback, void *arg)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_context *hg_context = hg_handle->hg_info.context;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Set callback */
    hg_handle->callback = callback;
    hg_handle->arg = arg;
    hg_handle->cb_type = HG_CB_RESPOND;

    /* Respond back */
    na_ret = NA_Msg_send_expected(hg_class->na_class, hg_context->na_context,
            hg_core_send_output_cb, hg_handle, hg_handle->out_buf,
            hg_handle->out_buf_used, hg_handle->out_buf_plugin_data,
            hg_handle->hg_info.addr->na_addr, hg_handle->tag,
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
static int
hg_core_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    /* If we expect a response, there needs to be 2 NA operations in total */
    int completed_count = hg_handle->no_response ? 1 : 2;
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    /* Reset op ID value */
    if (!hg_handle->na_op_id_mine)
        hg_handle->na_send_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Add handle to completion queue only when send_input and recv_output have
     * completed */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == completed_count) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
        /* Increment number of entries added to completion queue */
        ret++;
    }

done:
    (void) na_ret;
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    struct hg_context *hg_context = hg_handle->hg_info.context;
#ifndef HG_HAS_POST_LIMIT
    hg_bool_t pending_empty = NA_FALSE;
#endif
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    /* Reset op ID value */
    if (!hg_handle->na_op_id_mine)
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
        hg_handle->hg_info.addr->na_addr =
            callback_info->info.recv_unexpected.source;

        /* TODO determine if addr is local */
//        hg_handle->hg_info.addr->local = HG_FALSE;

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
        hg_thread_spin_lock(&hg_context->pending_list_lock);
        HG_LIST_REMOVE(hg_handle, entry);
#ifndef HG_HAS_POST_LIMIT
        pending_empty = HG_LIST_IS_EMPTY(&hg_context->pending_list);
#endif
        hg_thread_spin_unlock(&hg_context->pending_list_lock);

        hg_thread_spin_lock(&hg_context->processing_list_lock);
        HG_LIST_INSERT_HEAD(&hg_context->processing_list, hg_handle, entry);
        hg_thread_spin_unlock(&hg_context->processing_list_lock);

#ifndef HG_HAS_POST_LIMIT
        /* If pending list is empty, post more handles */
        if (pending_empty
            && hg_core_context_post(hg_context, HG_CORE_PENDING_INCR,
                hg_handle->repost) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not post additional handles");
            goto done;
        }
#endif

        /* Get and verify header */
        if (hg_core_proc_header_request(hg_handle, &hg_handle->in_header,
            HG_DECODE, NULL) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get request header");
            goto done;
        }

        /* Get operation ID from header */
        hg_handle->hg_info.id = hg_handle->in_header.id;
        hg_handle->cookie = hg_handle->in_header.cookie;
        /* TODO assign target ID from cookie directly for now */
        hg_handle->hg_info.target_id = hg_handle->cookie & 0xff;
        hg_handle->no_response = (hg_handle->in_header.flags
            & HG_PROC_HEADER_NO_RESPONSE) ? HG_TRUE : HG_FALSE;

        /* Get extra payload if flag HG_PROC_HEADER_BULK is set */
        if ((hg_handle->in_header.flags & HG_PROC_HEADER_BULK_EXTRA)
            && (hg_handle->in_header.extra_in_handle != HG_BULK_NULL)) {
            if (hg_core_get_extra_input(hg_handle,
                hg_handle->in_header.extra_in_handle) != HG_SUCCESS) {
                HG_LOG_ERROR("Could not get extra input buffer");
                goto done;
            }
        } else {
            /* Otherwise, mark handle ready for processing */
            hg_handle->process_rpc_cb = HG_TRUE;
            if (hg_core_complete(hg_handle) != HG_SUCCESS) {
                HG_LOG_ERROR("Could not complete rpc handle");
                goto done;
            }
            /* Increment number of entries added to completion queue */
            ret++;
        }
    } else {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret;
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    /* Reset op ID value */
    if (!hg_handle->na_op_id_mine)
        hg_handle->na_send_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Remove handle from processing list
     * NB. Whichever state we're in, reaching that stage means that the
     * handle was processed. */
    hg_thread_spin_lock(&hg_handle->hg_info.context->processing_list_lock);
    HG_LIST_REMOVE(hg_handle, entry);
    hg_thread_spin_unlock(&hg_handle->hg_info.context->processing_list_lock);

    /* Mark as completed (sanity check: NA completed count should be 2 here) */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
        /* Increment number of entries added to completion queue */
        ret++;
    }

done:
    (void) na_ret;
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_handle *hg_handle = (struct hg_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    /* Reset op ID value */
    if (!hg_handle->na_op_id_mine)
        hg_handle->na_recv_op_id = NA_OP_ID_NULL;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_handle->ret = HG_CANCELED;
    } else if (callback_info->ret == NA_SUCCESS) {
        /* Decode response header */
        if (hg_core_proc_header_response(hg_handle, &hg_handle->out_header,
            HG_DECODE) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not decode header");
            goto done;
        }
        hg_handle->ret = (hg_return_t) hg_handle->out_header.ret_code;
    } else {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Add handle to completion queue only when send_input and recv_output have
     * completed, 2 NA operations in total */
    if (hg_atomic_incr32(&hg_handle->na_completed_count) == 2) {
        /* Reset completed count */
        hg_atomic_set32(&hg_handle->na_completed_count, 0);

        /* Mark as completed */
        if (hg_core_complete(hg_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
        /* Increment number of entries added to completion queue */
        ret++;
    }

done:
    (void) na_ret;
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_self_cb(const struct hg_cb_info *callback_info)
{
    struct hg_handle *hg_handle =
        (struct hg_handle *) callback_info->info.respond.handle;
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
    hg_handle->cb_type = HG_CB_FORWARD;

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

    /* Get and verify header */
    if (hg_core_proc_header_request(hg_handle, &hg_handle->in_header,
        HG_DECODE, NULL) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get request header");
        goto done;
    }

    /* Check extra arguments */
    if ((hg_handle->in_header.flags & HG_PROC_HEADER_BULK_EXTRA)
            && (hg_handle->in_header.extra_in_handle != HG_BULK_NULL)) {
        /* Get extra payload */
        if (hg_core_get_extra_input(hg_handle, hg_handle->in_header.extra_in_handle)
                != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get extra input buffer");
            goto done;
        }
    } else {
        hg_return_t ret;

        /* Process handle */
        hg_handle->process_rpc_cb = HG_TRUE;
        ret = hg_core_complete(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete rpc handle");
            goto done;
        }
    }

done:
    return thread_ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_rpc_info *hg_rpc_info;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve exe function from function map */
    hg_thread_spin_lock(&hg_class->func_map_lock);
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(
            hg_class->func_map, (hg_hash_table_key_t) &hg_handle->hg_info.id);
    hg_thread_spin_unlock(&hg_class->func_map_lock);
    if (!hg_rpc_info) {
        HG_LOG_WARNING("Could not find RPC ID in function map");
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
    struct hg_completion_entry *hg_completion_entry =
        &hg_handle->hg_completion_entry;
    hg_return_t ret = HG_SUCCESS;

    hg_completion_entry->op_type = HG_RPC;
    hg_completion_entry->op_id.hg_handle = hg_handle;

    ret = hg_core_completion_add(context, hg_completion_entry,
        hg_handle->is_self);
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
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_atomic_queue_push(context->completion_queue, hg_completion_entry)
        != HG_UTIL_SUCCESS) {
        /* Queue is full */
        hg_thread_mutex_lock(&context->completion_queue_mutex);
        HG_QUEUE_PUSH_TAIL(&context->backfill_queue, hg_completion_entry,
            entry);
        hg_atomic_incr32(&context->backfill_queue_count);
        hg_thread_mutex_unlock(&context->completion_queue_mutex);
    }

    if (hg_atomic_get32(&context->trigger_waiting)) {
        hg_thread_mutex_lock(&context->completion_queue_mutex);
        /* Callback is pushed to the completion queue when something completes
         * so wake up anyone waiting in the trigger */
        hg_thread_cond_signal(&context->completion_queue_cond);
        hg_thread_mutex_unlock(&context->completion_queue_mutex);
    }

#ifdef HG_HAS_SELF_FORWARD
    /* TODO could prevent from self notifying if hg_poll_wait() not entered */
    if (self_notify && context->completion_queue_notify
        && hg_event_set(context->completion_queue_notify) != HG_UTIL_SUCCESS) {
        HG_LOG_ERROR("Could not signal completion queue");
        ret = HG_PROTOCOL_ERROR;
    }
#else
    (void) self_notify;
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_post(struct hg_context *context, unsigned int request_count,
    hg_bool_t repost)
{
    unsigned int nentry = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Create a bunch of handles and post unexpected receives */
    for (nentry = 0; nentry < request_count; nentry++) {
        struct hg_handle *hg_handle = NULL;
        struct hg_addr *hg_addr = NULL;

        /* Create a new handle */
        hg_handle = hg_core_create(context);
        if (!hg_handle) {
            HG_LOG_ERROR("Could not create HG handle");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        /* Create internal addresses */
        hg_addr = hg_core_addr_create(context->hg_class);
        if (!hg_addr) {
            HG_LOG_ERROR("Could not create HG addr");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        /* To safely repost handle and prevent externally referenced address */
        hg_addr->is_mine = HG_TRUE;
        hg_handle->hg_info.addr = hg_addr;

        /* Repost handle on completion if told so */
        hg_handle->repost = repost;

        ret = hg_core_post(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot post handle");
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_post(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_context *context = hg_handle->hg_info.context;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    hg_thread_spin_lock(&context->pending_list_lock);
    HG_LIST_INSERT_HEAD(&context->pending_list, hg_handle, entry);
    hg_thread_spin_unlock(&context->pending_list_lock);

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_class->na_class, context->na_context,
            hg_core_recv_input_cb, hg_handle, hg_handle->in_buf,
            hg_handle->in_buf_size, hg_handle->in_buf_plugin_data,
            context->request_mask, &hg_handle->na_recv_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post unexpected recv for input buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_reset_post(struct hg_handle *hg_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_atomic_decr32(&hg_handle->ref_count))
        goto done;

    ret = hg_core_reset(hg_handle, HG_TRUE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot reset handle");
        goto done;
    }
    /* Also reset additional handle parameters */
    hg_atomic_set32(&hg_handle->ref_count, 1);
    hg_handle->hg_rpc_info = NULL;
    hg_handle->no_response = HG_FALSE;


    /* Safe to repost */
    ret = hg_core_post(hg_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Cannot post handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static int
hg_core_completion_queue_notify_cb(void *arg, unsigned int timeout,
    hg_util_bool_t *progressed)
{
    struct hg_context *context = (struct hg_context *) arg;
    hg_util_bool_t notified = HG_UTIL_FALSE;
    int ret = HG_UTIL_SUCCESS;

    if (timeout && hg_event_get(context->completion_queue_notify,
        &notified) != HG_UTIL_SUCCESS) {
        HG_LOG_ERROR("Could not get completion notification");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    if (notified || !hg_atomic_queue_is_empty(context->completion_queue)
        || hg_atomic_get32(&context->backfill_queue_count)) {
        *progressed = HG_UTIL_TRUE; /* Progressed */
        goto done;
    }

    *progressed = HG_UTIL_FALSE;

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static int
hg_core_progress_na_cb(void *arg, unsigned int timeout,
    hg_util_bool_t *progressed)
{
    struct hg_context *context = (struct hg_context *) arg;
    struct hg_class *hg_class = context->hg_class;
    unsigned int actual_count = 0;
    na_return_t na_ret;
    unsigned int completed_count = 0;
    int cb_ret[1] = {0};
    int ret = HG_UTIL_SUCCESS;

    /* Check progress on NA (no need to call try_wait here) */
    na_ret = NA_Progress(hg_class->na_class, context->na_context, timeout);
    if (na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT) {
        HG_LOG_ERROR("Could not make progress on NA");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (na_ret != NA_SUCCESS) {
        /* Nothing progressed */
        *progressed = HG_UTIL_FALSE;
        goto done;
    }

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(context->na_context, 0, 1, cb_ret, &actual_count);

        /* Return value of callback is completion count */
        completed_count += (unsigned int) cb_ret[0];
    } while ((na_ret == NA_SUCCESS) && actual_count);

    /* We can't only verify that the completion queue is not empty, we need
     * to check what was added to the completion queue, as the completion queue
     * may have been concurrently emptied */
    if (!completed_count && hg_atomic_queue_is_empty(context->completion_queue)
        && !hg_atomic_get32(&context->backfill_queue_count)) {
        /* Nothing progressed */
        *progressed = HG_UTIL_FALSE;
        goto done;
    }

    *progressed = HG_UTIL_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_na(struct hg_context *context, unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    hg_return_t ret = HG_TIMEOUT;

    for (;;) {
        struct hg_class *hg_class = context->hg_class;
        unsigned int actual_count = 0;
        int cb_ret[1] = {0};
        unsigned int completed_count = 0;
        unsigned int progress_timeout;
        na_return_t na_ret;
        hg_time_t t1, t2;

        /* Trigger everything we can from NA, if something completed it will
         * be moved to the HG context completion queue */
        do {
            na_ret = NA_Trigger(context->na_context, 0, 1, cb_ret,
                &actual_count);

            /* Return value of callback is completion count */
            completed_count += (unsigned int)cb_ret[0];
        } while ((na_ret == NA_SUCCESS) && actual_count);

        /* We can't only verify that the completion queue is not empty, we need
         * to check what was added to the completion queue, as the completion
         * queue may have been concurrently emptied */
        if (completed_count
            || !hg_atomic_queue_is_empty(context->completion_queue)
            || hg_atomic_get32(&context->backfill_queue_count)) {
            ret = HG_SUCCESS; /* Progressed */
            break;
        }

        if (remaining < 0)
            break;

        if (timeout)
            hg_time_get_current(&t1);

        /* Make sure that it is safe to block */
        if (timeout &&
            NA_Poll_try_wait(hg_class->na_class, context->na_context))
            progress_timeout = (unsigned int) (remaining * 1000.0);
        else
            progress_timeout = 0;

        /* Otherwise try to make progress on NA */
        na_ret = NA_Progress(hg_class->na_class, context->na_context,
            progress_timeout);

        if (timeout) {
            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        }

        if (na_ret == NA_SUCCESS) {
            /* Trigger NA callbacks and check whether we completed something */
            continue;
        } else if (na_ret == NA_TIMEOUT) {
            break;
        } else {
            HG_LOG_ERROR("Could not make NA Progress");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_util_bool_t
hg_core_poll_try_wait_cb(void *arg)
{
    struct hg_context *hg_context = (struct hg_context *) arg;

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(hg_context->completion_queue) ||
        hg_atomic_get32(&hg_context->backfill_queue_count)) {
        return NA_FALSE;
    }

    return NA_Poll_try_wait(hg_context->hg_class->na_class,
        hg_context->na_context);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_poll(struct hg_context *context, unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    hg_return_t ret = HG_TIMEOUT;

    do {
        hg_time_t t1, t2;
        hg_util_bool_t progressed;

        if (timeout)
            hg_time_get_current(&t1);

        /* Will call hg_core_poll_try_wait_cb if timeout is not 0 */
        if (hg_poll_wait(context->poll_set, (unsigned int)(remaining * 1000.0),
            &progressed) != HG_UTIL_SUCCESS) {
            HG_LOG_ERROR("hg_poll_wait() failed");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }

        /* We progressed, return success */
        if (progressed) {
            ret = HG_SUCCESS;
            break;
        }

        if (timeout) {
            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        }
    } while ((int)(remaining * 1000.0) > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger(struct hg_context *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    while (count < max_count) {
        struct hg_completion_entry *hg_completion_entry = NULL;

        hg_completion_entry =
            hg_atomic_queue_pop_mc(context->completion_queue);
        if (!hg_completion_entry) {
            /* Check backfill queue */
            if (hg_atomic_get32(&context->backfill_queue_count)) {
                hg_thread_mutex_lock(&context->completion_queue_mutex);
                hg_completion_entry = HG_QUEUE_FIRST(&context->backfill_queue);
                HG_QUEUE_POP_HEAD(&context->backfill_queue, entry);
                hg_atomic_decr32(&context->backfill_queue_count);
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                if (!hg_completion_entry)
                    continue; /* Give another change to grab it */
            } else {
                hg_time_t t1, t2;

                /* If something was already processed leave */
                if (count)
                    break;

                /* Timeout is 0 so leave */
                if ((int)(remaining * 1000.0) <= 0) {
                    ret = HG_TIMEOUT;
                    break;
                }

                hg_time_get_current(&t1);

                hg_atomic_incr32(&context->trigger_waiting);
                hg_thread_mutex_lock(&context->completion_queue_mutex);
                /* Otherwise wait timeout ms */
                while (hg_atomic_queue_is_empty(context->completion_queue) &&
                    !hg_atomic_get32(&context->backfill_queue_count)) {
                    if (hg_thread_cond_timedwait(&context->completion_queue_cond,
                        &context->completion_queue_mutex, timeout)
                        != HG_UTIL_SUCCESS) {
                        /* Timeout occurred so leave */
                        ret = HG_TIMEOUT;
                        break;
                    }
                }
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                hg_atomic_decr32(&context->trigger_waiting);
                if (ret == HG_TIMEOUT)
                    break;

                hg_time_get_current(&t2);
                remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
                continue; /* Give another change to grab it */
            }
        }

        /* Completion queue should not be empty now */
        if (!hg_completion_entry) {
            HG_LOG_ERROR("NULL completion entry");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }

        /* Trigger entry */
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

done:
    if ((ret == HG_SUCCESS || ret == HG_TIMEOUT) && actual_count)
        *actual_count = count;
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
        hg_cb_info.type = HG_CB_LOOKUP;
        hg_cb_info.info.lookup.addr = hg_op_id->info.lookup.hg_addr;

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

    if (hg_handle->process_rpc_cb) {
        /* Handle will now be processed */
        hg_handle->process_rpc_cb = HG_FALSE;

        /* Run RPC callback */
        ret = hg_core_process(hg_handle);
        if (ret != HG_SUCCESS && !hg_handle->no_response) {
            hg_size_t header_size = hg_proc_header_response_get_size() +
                hg_handle->na_out_header_offset;

            /* Respond in case of error */
            ret = HG_Core_respond(hg_handle, NULL, NULL, ret, header_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not respond");
                goto done;
            }
        }

        /* Complete handle if no response required */
        if (hg_handle->no_response) {
            /* Remove handle from processing list
             * NB. Whichever state we're in, reaching that stage means that the
             * handle was processed. */
            hg_thread_spin_lock(&hg_handle->hg_info.context->processing_list_lock);
            HG_LIST_REMOVE(hg_handle, entry);
            hg_thread_spin_unlock(&hg_handle->hg_info.context->processing_list_lock);

            if (hg_core_complete(hg_handle) != HG_SUCCESS) {
                HG_LOG_ERROR("Could not complete operation");
                goto done;
            }
        }
    } else {
        /* Execute user callback */
        if (hg_handle->callback) {
            struct hg_cb_info hg_cb_info;

            hg_cb_info.arg = hg_handle->arg;
            hg_cb_info.ret = hg_handle->ret;
            hg_cb_info.type = hg_handle->cb_type;
            if (hg_handle->cb_type == HG_CB_FORWARD)
                hg_cb_info.info.forward.handle = (hg_handle_t) hg_handle;
            else if (hg_handle->cb_type == HG_CB_RESPOND)
                hg_cb_info.info.respond.handle = (hg_handle_t) hg_handle;
            hg_handle->callback(&hg_cb_info);
        }

        /* Repost handle if we were listening, otherwise destroy it */
        if (hg_handle->repost && !hg_handle->hg_info.context->finalizing) {
            /* Repost handle */
            ret = hg_core_reset_post(hg_handle);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Cannot repost handle");
                goto done;
            }
        } else
            hg_core_destroy(hg_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_cancel(struct hg_handle *hg_handle)
{
    struct hg_class *hg_class = hg_handle->hg_info.hg_class;
    struct hg_context *hg_context = hg_handle->hg_info.context;
    hg_return_t ret = HG_SUCCESS;

    /* Cancel all NA operations issued */
    if (hg_handle->na_recv_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_class->na_class, hg_context->na_context,
                hg_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel recv op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    if (hg_handle->na_send_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_class->na_class, hg_context->na_context,
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

    hg_class = hg_core_init(na_info_string, na_listen, NULL);
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
HG_Core_init_na(na_class_t *na_class)
{
    struct hg_class *hg_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!na_class) {
        HG_LOG_ERROR("NULL NA class");
        goto done;
    }

    hg_class = hg_core_init(NULL, HG_FALSE, na_class);
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
void
HG_Core_cleanup(void)
{
    NA_Cleanup();
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_name(const hg_class_t *hg_class)
{
    const char *ret = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    ret = NA_Get_class_name(hg_class->na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_protocol(const hg_class_t *hg_class)
{
    const char *ret = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    ret = NA_Get_class_protocol(hg_class->na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_class_t *
HG_Core_class_get_na(const hg_class_t *hg_class)
{
    na_class_t *ret = NULL;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    ret = hg_class->na_class;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Core_class_get_input_eager_size(const hg_class_t *hg_class)
{
    hg_size_t ret = 0, unexp, header;

    if (hg_class == NULL) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    unexp  = NA_Msg_get_max_unexpected_size(hg_class->na_class);
    header = hg_proc_header_request_get_size() +
        NA_Msg_get_unexpected_header_size(hg_class->na_class);
    if (unexp > header)
        ret = unexp - header;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Core_class_get_output_eager_size(const hg_class_t *hg_class)
{
    hg_size_t ret = 0, exp, header;

    if (hg_class == NULL) {
        HG_LOG_ERROR("NULL HG class");
        goto done;
    }

    exp    = NA_Msg_get_max_expected_size(hg_class->na_class);
    header = hg_proc_header_response_get_size() +
        NA_Msg_get_expected_header_size(hg_class->na_class);
    if (exp > header)
        ret = exp - header;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_context_t *
HG_Core_context_create(hg_class_t *hg_class)
{
    hg_return_t ret = HG_SUCCESS;
    struct hg_context *context = NULL;
    int na_poll_fd;
#ifdef HG_HAS_SELF_FORWARD
    int fd;
#endif

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
    memset(context, 0, sizeof(struct hg_context));
    context->hg_class = hg_class;
    context->completion_queue =
        hg_atomic_queue_alloc(HG_CORE_ATOMIC_QUEUE_SIZE);
    if (!context->completion_queue) {
        HG_LOG_ERROR("Could not allocate queue");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    HG_QUEUE_INIT(&context->backfill_queue);
    hg_atomic_init32(&context->backfill_queue_count, 0);
    HG_LIST_INIT(&context->pending_list);
    HG_LIST_INIT(&context->processing_list);
#ifdef HG_HAS_SELF_FORWARD
    HG_LIST_INIT(&context->self_processing_list);
#endif

    /* No handle created yet */
    hg_atomic_init32(&context->n_handles, 0);

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&context->completion_queue_mutex);
    hg_thread_cond_init(&context->completion_queue_cond);
    hg_atomic_init32(&context->trigger_waiting, 0);

    hg_thread_spin_init(&context->pending_list_lock);
    hg_thread_spin_init(&context->processing_list_lock);
#ifdef HG_HAS_SELF_FORWARD
    hg_thread_spin_init(&context->self_processing_list_lock);
#endif

    context->na_context = NA_Context_create(hg_class->na_class);
    if (!context->na_context) {
        HG_LOG_ERROR("Could not create NA context");
        ret = HG_NA_ERROR;
        goto done;
    }

    /* Create poll set */
    context->poll_set = hg_poll_create();
    if (!context->poll_set) {
        HG_LOG_ERROR("Could not create poll set");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

#ifdef HG_HAS_SELF_FORWARD
    /* Create event for completion queue notification */
    fd = hg_event_create();
    if (fd < 0) {
        HG_LOG_ERROR("Could not create event");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    context->completion_queue_notify = fd;

    /* Add event to context poll set */
    hg_poll_add(context->poll_set, fd, HG_POLLIN,
        hg_core_completion_queue_notify_cb, context);
#endif

    /* If NA plugin exposes fd, add it to poll set and use appropriate
     * progress function */
    na_poll_fd = NA_Poll_get_fd(hg_class->na_class, context->na_context);
    if (na_poll_fd > 0) {
        hg_poll_add(context->poll_set, na_poll_fd, HG_POLLIN,
            hg_core_progress_na_cb, context);
        hg_poll_set_try_wait(context->poll_set, hg_core_poll_try_wait_cb,
            context);
        context->progress = hg_core_progress_poll;
    } else {
        context->progress = hg_core_progress_na;
    }

    /* Increment context count of parent class */
    hg_atomic_incr32(&hg_class->n_contexts);

done:
    if (ret != HG_SUCCESS && context) {
        HG_Core_context_destroy(context);
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
    int na_poll_fd;
    hg_util_int32_t n_handles;

    if (!context) goto done;

    /* Prevent repost of handles */
    context->finalizing = HG_TRUE;

    /* Check pending list and cancel posted handles */
    if (!HG_LIST_IS_EMPTY(&context->pending_list)) {
        ret = hg_core_pending_list_cancel(context);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot cancel list of pending entries");
            goto done;
        }
    }

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(context->na_context, 0, 1, NULL, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);

    /* Check that operations have completed */
    ret = hg_core_processing_list_wait(context);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not wait on processing list");
        goto done;
    }

    /* Number of handles for that context should be 0 */
    n_handles = hg_atomic_get32(&context->n_handles);
    if (n_handles != 0) {
        HG_LOG_ERROR("HG handles must be freed before destroying context "
            "(%d remaining)", n_handles);
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Check that completion queue is empty now */
    if (!hg_atomic_queue_is_empty(context->completion_queue)) {
        HG_LOG_ERROR("Completion queue should be empty");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    hg_atomic_queue_free(context->completion_queue);

    /* Check that completion queue is empty now */
    hg_thread_mutex_lock(&context->completion_queue_mutex);
    if (!HG_QUEUE_IS_EMPTY(&context->backfill_queue)) {
        HG_LOG_ERROR("Completion queue should be empty");
        ret = HG_PROTOCOL_ERROR;
        hg_thread_mutex_unlock(&context->completion_queue_mutex);
        goto done;
    }
    hg_thread_mutex_unlock(&context->completion_queue_mutex);

#ifdef HG_HAS_SELF_FORWARD
    if (context->completion_queue_notify > 0) {
        if (hg_poll_remove(context->poll_set, context->completion_queue_notify)
            != HG_UTIL_SUCCESS) {
            HG_LOG_ERROR("Could not remove self processing event from poll set");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        if (hg_event_destroy(context->completion_queue_notify) != HG_UTIL_SUCCESS) {
            HG_LOG_ERROR("Could not destroy self processing event");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }
#endif

    /* If NA plugin exposes fd, remove it from poll set */
    na_poll_fd = NA_Poll_get_fd(context->hg_class->na_class,
        context->na_context);
    if ((na_poll_fd > 0)
        && (hg_poll_remove(context->poll_set, na_poll_fd) != HG_UTIL_SUCCESS)) {
        HG_LOG_ERROR("Could not remove NA poll descriptor from poll set");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Destroy poll set */
    if (hg_poll_destroy(context->poll_set) != HG_UTIL_SUCCESS) {
        HG_LOG_ERROR("Could not destroy poll set");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Destroy NA context */
    if (context->na_context && NA_Context_destroy(context->hg_class->na_class,
            context->na_context) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not destroy NA context");
        ret = HG_NA_ERROR;
        goto done;
    }

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&context->completion_queue_mutex);
    hg_thread_cond_destroy(&context->completion_queue_cond);
    hg_thread_spin_destroy(&context->pending_list_lock);
    hg_thread_spin_destroy(&context->processing_list_lock);
#ifdef HG_HAS_SELF_FORWARD
    hg_thread_spin_destroy(&context->self_processing_list_lock);
#endif

    /* Decrement context count of parent class */
    hg_atomic_decr32(&context->hg_class->n_contexts);

    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_class_t *
HG_Core_context_get_class(const hg_context_t *context)
{
    hg_class_t *ret = NULL;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        goto done;
    }

    ret = context->hg_class;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_set_id(hg_context_t *context, hg_uint8_t id)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context->id = id;
    context->request_mask = (id && context->hg_class->use_tag_mask) ?
        (na_tag_t) (id << (context->hg_class->na_max_tag_msb
            + 1 - HG_CORE_MASK_NBITS)) : 0;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_uint8_t
HG_Core_context_get_id(const hg_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = context->id;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_post(hg_context_t *context, unsigned int request_count,
    hg_bool_t repost)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!request_count) {
        HG_LOG_ERROR("Request count must be greater than 0");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_context_post(context, request_count, repost);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not post requests on context");
        goto done;
    }

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register(hg_class_t *hg_class, hg_id_t id, hg_rpc_cb_t rpc_cb)
{
    hg_id_t *func_key = NULL;
    struct hg_rpc_info *hg_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;
    int hash_ret;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Check if registered and set RPC CB */
    hg_thread_spin_lock(&hg_class->func_map_lock);
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(
            hg_class->func_map, (hg_hash_table_key_t) &id);
    if (hg_rpc_info && rpc_cb)
        hg_rpc_info->rpc_cb = rpc_cb;
    hg_thread_spin_unlock(&hg_class->func_map_lock);

    if (!hg_rpc_info) {
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
        hg_rpc_info->no_response = HG_FALSE;
        hg_rpc_info->data = NULL;
        hg_rpc_info->free_callback = NULL;

        hg_thread_spin_lock(&hg_class->func_map_lock);
        hash_ret = hg_hash_table_insert(hg_class->func_map,
            (hg_hash_table_key_t) func_key, hg_rpc_info);
        hg_thread_spin_unlock(&hg_class->func_map_lock);
        if (!hash_ret) {
            HG_LOG_ERROR("Could not insert RPC ID into function map (already registered?)");
            ret = HG_INVALID_PARAM;
            goto done;
        }
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

    hg_thread_spin_lock(&hg_class->func_map_lock);
    *flag = (hg_bool_t) (hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id) != HG_HASH_TABLE_NULL);
    hg_thread_spin_unlock(&hg_class->func_map_lock);

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

    hg_thread_spin_lock(&hg_class->func_map_lock);
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_class->func_map_lock);
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

    hg_thread_spin_lock(&hg_class->func_map_lock);
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(hg_class->func_map,
            (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_class->func_map_lock);
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
HG_Core_registered_disable_response(hg_class_t *hg_class, hg_id_t id,
    hg_bool_t disable)
{
    struct hg_rpc_info *hg_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_class) {
        HG_LOG_ERROR("NULL HG class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&hg_class->func_map_lock);
    hg_rpc_info = (struct hg_rpc_info *) hg_hash_table_lookup(
        hg_class->func_map, (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_class->func_map_lock);
    if (!hg_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        goto done;
    }
    hg_rpc_info->no_response = disable;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_lookup(hg_context_t *context, hg_cb_t callback, void *arg,
    const char *name, hg_op_id_t *op_id)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!callback) {
        HG_LOG_ERROR("NULL callback");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!name) {
        HG_LOG_ERROR("NULL lookup name");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_lookup(context, callback, arg, name, op_id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not lookup address");
        goto done;
    }

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
na_addr_t
HG_Core_addr_get_na(hg_addr_t addr)
{
    na_addr_t ret = NA_ADDR_NULL;

    if (addr == HG_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
        goto done;
    }

    ret = addr->na_addr;

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
    if (!addr) {
        HG_LOG_ERROR("NULL pointer to address");
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
    if (addr == HG_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
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
    if (!handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Create new handle */
    hg_handle = hg_core_create(context);
    if (!hg_handle) {
        HG_LOG_ERROR("Could not create HG handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_handle, addr, id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set rpc to handle");
        goto done;
    }

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

    /* Repost handle if we were listening, otherwise destroy it */
    if (hg_handle->repost && !hg_handle->hg_info.context->finalizing) {
        /* Repost handle */
        ret = hg_core_reset_post(hg_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot repost handle");
            goto done;
        }
    } else
        hg_core_destroy(hg_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_reset(hg_handle_t handle, hg_addr_t addr, hg_id_t id)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (hg_atomic_get32(&hg_handle->ref_count) > 1) {
        /* Not safe to reset
         * TODO could add the ability to defer the reset operation */
        HG_LOG_ERROR("Cannot reset HG handle, handle is still in use, "
            "refcount: %d", hg_atomic_get32(&hg_handle->ref_count));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    ret = hg_core_reset(hg_handle, HG_FALSE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not reset HG handle");
        goto done;
    }

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_handle, addr, id);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not set rpc to handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_ref_incr(hg_handle_t handle)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL pointer to HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_atomic_incr32(&hg_handle->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const struct hg_info *
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
HG_Core_set_target_id(hg_handle_t handle, hg_uint8_t target_id)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_handle->hg_info.target_id = target_id;

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

    /* Cannot respond if no_response flag set */
    if (hg_handle->no_response) {
        HG_LOG_ERROR("No output was produced on that RPC (no response)");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    hg_core_get_output(hg_handle, out_buf, out_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_forward(hg_handle_t handle, hg_cb_t callback, void *arg,
    hg_bulk_t extra_in_handle, hg_size_t size_to_send)
{
    struct hg_handle *hg_handle = (struct hg_handle *) handle;
#ifdef HG_HAS_SELF_FORWARD
    hg_return_t (*hg_forward)(struct hg_handle *hg_handle);
#endif
    hg_return_t ret = HG_SUCCESS;
    hg_size_t header_size;
    hg_size_t extra_header_size = 0;
    hg_uint8_t flags = 0;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (hg_handle->hg_info.addr == HG_ADDR_NULL) {
        HG_LOG_ERROR("NULL target addr");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!hg_handle->hg_info.id) {
        HG_LOG_ERROR("NULL RPC ID");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#ifndef HG_HAS_SELF_FORWARD
    if (NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
        hg_handle->hg_info.addr->na_addr)) {
        HG_LOG_ERROR("Not enabled, please enable HG_USE_SELF_FORWARD");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#endif

    /* Set callback */
    hg_handle->callback = callback;
    hg_handle->arg = arg;
    hg_handle->cb_type = HG_CB_FORWARD;

    /* Increase ref count here so that a call to HG_Destroy does not free the
     * handle but only schedules its completion
     */
    hg_atomic_incr32(&hg_handle->ref_count);

    /* Set header */
    header_size = hg_proc_header_request_get_size() +
        hg_handle->na_in_header_offset;
    hg_handle->in_header.id = hg_handle->hg_info.id;
    hg_handle->in_header.cookie = hg_handle->hg_info.target_id;
    hg_handle->in_header.extra_in_handle = extra_in_handle;
    flags = (extra_in_handle != HG_BULK_NULL) ? HG_PROC_HEADER_BULK_EXTRA : 0;
    hg_handle->in_header.flags |= flags;
    flags = (hg_handle->no_response) ? HG_PROC_HEADER_NO_RESPONSE : 0;
    hg_handle->in_header.flags |= flags;

    /* Encode request header */
    ret = hg_core_proc_header_request(hg_handle, &hg_handle->in_header,
        HG_ENCODE, &extra_header_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        /* rollback ref_count taken above */
        hg_atomic_decr32(&hg_handle->ref_count);
        goto done;
    }
    header_size += extra_header_size;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_handle->in_buf_used = header_size + size_to_send;

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
#ifdef HG_HAS_SELF_FORWARD
    hg_handle->is_self = NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
        hg_handle->hg_info.addr->na_addr);
    hg_forward =  hg_handle->is_self ? hg_core_forward_self :
        hg_core_forward_na;
    ret = hg_forward(hg_handle);
#else
    ret = hg_core_forward_na(hg_handle);
#endif
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward buffer");
        /* rollback ref_count taken above */
        hg_atomic_decr32(&hg_handle->ref_count);
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
#ifdef HG_HAS_SELF_FORWARD
    hg_return_t (*hg_respond)(struct hg_handle *hg_handle, hg_cb_t callback,
            void *arg);
#endif
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#ifndef HG_HAS_SELF_FORWARD
    if (NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
        hg_handle->hg_info.addr->na_addr)) {
        HG_LOG_ERROR("Not enabled, please enable HG_USE_SELF_FORWARD");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#endif
    /* Cannot respond if no_response flag set */
    if (hg_handle->no_response) {
        HG_LOG_ERROR("Sending response was disabled on that RPC");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Set error code if any */
    hg_handle->ret = ret_code;

    /* Set header size */
    header_size = hg_proc_header_response_get_size() +
        hg_handle->na_out_header_offset;

    /* Fill the header */
    hg_handle->out_header.cookie = hg_handle->cookie;
    hg_handle->out_header.ret_code = hg_handle->ret;

    /* Encode response header */
    ret = hg_core_proc_header_response(hg_handle, &hg_handle->out_header,
        HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    /* Set the actual size of the msg that needs to be transmitted */
    hg_handle->out_buf_used = header_size + size_to_send;

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
#ifdef HG_HAS_SELF_FORWARD
    hg_respond = NA_Addr_is_self(hg_handle->hg_info.hg_class->na_class,
            hg_handle->hg_info.addr->na_addr) ? hg_core_respond_self :
            hg_core_respond_na;
    ret = hg_respond(hg_handle, callback, arg);
#else
    ret = hg_core_respond_na(hg_handle, callback, arg);
#endif
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

    /* Make progress on the HG layer */
    ret = context->progress(context, timeout);
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
