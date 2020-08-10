/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_core.h"
#include "mercury_private.h"

#include "mercury_atomic_queue.h"
#ifdef HG_HAS_SELF_FORWARD
#    include "mercury_event.h"
#endif
#include "mercury_error.h"
#include "mercury_hash_table.h"
#include "mercury_list.h"
#include "mercury_mem.h"
#include "mercury_poll.h"
#include "mercury_queue.h"
#include "mercury_thread_condition.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_pool.h"
#include "mercury_thread_spin.h"
#include "mercury_time.h"

#ifdef HG_HAS_SM_ROUTING
#    include <na_sm.h>
#endif

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_CORE_ATOMIC_QUEUE_SIZE 1024
#define HG_CORE_PENDING_INCR      256
#define HG_CORE_CLEANUP_TIMEOUT   1000
#define HG_CORE_MAX_EVENTS        1
#define HG_CORE_MAX_TRIGGER_COUNT 1
#ifdef HG_HAS_SM_ROUTING
#    define HG_CORE_ADDR_MAX_SIZE   256
#    define HG_CORE_PROTO_DELIMITER ":"
#    define HG_CORE_ADDR_DELIMITER  "#"
#    define HG_CORE_MIN(a, b)       (a < b) ? a : b /* Min macro */
#endif

/* Remove warnings when routine does not use arguments */
#if defined(__cplusplus)
#    define HG_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#    define HG_UNUSED __attribute__((unused))
#else
#    define HG_UNUSED
#endif

/* Map stat type to either 32-bit atomic or 64-bit */
#ifdef HG_HAS_COLLECT_STATS
#    ifndef HG_UTIL_HAS_OPA_PRIMITIVES_H
typedef hg_atomic_int64_t hg_core_stat_t;
#        define hg_core_stat_incr hg_atomic_incr64
#        define hg_core_stat_get  hg_atomic_get64
#    else
typedef hg_atomic_int32_t hg_core_stat_t;
#        define hg_core_stat_incr hg_atomic_incr32
#        define hg_core_stat_get  hg_atomic_get32
#    endif
#    define HG_CORE_STAT_INIT HG_ATOMIC_VAR_INIT
#endif

#define HG_CORE_CONTEXT_CLASS(context)                                         \
    ((struct hg_core_private_class *) (context->core_context.core_class))

#define HG_CORE_HANDLE_CLASS(handle)                                           \
    ((struct hg_core_private_class *) (handle->core_handle.info.core_class))
#define HG_CORE_HANDLE_CONTEXT(handle)                                         \
    ((struct hg_core_private_context *) (handle->core_handle.info.context))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_core_private_class {
    struct hg_core_class core_class; /* Must remain as first field */
#ifdef HG_HAS_SM_ROUTING
    na_sm_id_t host_id; /* Host ID for local identification */
#endif
    hg_hash_table_t *func_map; /* Function map */
    hg_return_t (*more_data_acquire)(hg_core_handle_t, hg_op_t,
        hg_return_t (*done_callback)(hg_core_handle_t)); /* more_data_acquire */
    void (*more_data_release)(hg_core_handle_t);         /* more_data_release */
    na_tag_t request_max_tag;                            /* Max value for tag */
    hg_atomic_int32_t n_contexts;   /* Atomic used for number of contexts */
    hg_atomic_int32_t n_addrs;      /* Atomic used for number of addrs */
    hg_atomic_int32_t request_tag;  /* Atomic used for tag generation */
    hg_thread_spin_t func_map_lock; /* Function map lock */
    na_uint32_t progress_mode;      /* NA progress mode */
    hg_bool_t na_ext_init;          /* NA externally initialized */
#ifdef HG_HAS_COLLECT_STATS
    hg_bool_t stats; /* (Debug) Print stats at exit */
#endif
};

/* Poll type */
typedef enum hg_core_poll_type {
    HG_CORE_POLL_LOOPBACK = 1,
#ifdef HG_HAS_SM_ROUTING
    HG_CORE_POLL_SM,
#endif
    HG_CORE_POLL_NA
} hg_core_poll_type_t;

/* HG context */
struct hg_core_private_context {
    struct hg_core_context core_context;      /* Must remain as first field */
    hg_thread_cond_t completion_queue_cond;   /* Completion queue cond */
    hg_thread_mutex_t completion_queue_mutex; /* Completion queue mutex */
    hg_thread_mutex_t completion_queue_notify_mutex; /* Notify mutex */
    HG_QUEUE_HEAD(hg_completion_entry)
    backfill_queue;                           /* Backfill completion queue */
    struct hg_atomic_queue *completion_queue; /* Default completion queue */
    HG_LIST_HEAD(hg_core_private_handle)
    created_list; /* List of handles for that context */
    HG_LIST_HEAD(hg_core_private_handle)
    pending_list; /* List of pending handles */
#ifdef HG_HAS_SM_ROUTING
    HG_LIST_HEAD(hg_core_private_handle)
    sm_pending_list; /* List of SM pending handles */
#endif
    hg_return_t (*handle_create)(hg_core_handle_t, void *); /* handle_create */
    void *handle_create_arg;      /* handle_create arg */
    struct hg_poll_set *poll_set; /* Context poll set */
    struct hg_poll_event
        poll_events[HG_CORE_MAX_EVENTS]; /* Context poll events */
    hg_atomic_int32_t
        completion_queue_must_notify; /* Notify of completion queue events */
    hg_atomic_int32_t backfill_queue_count; /* Backfill queue count */
    hg_atomic_int32_t trigger_waiting;      /* Waiting in trigger */
    hg_atomic_int32_t n_handles;        /* Atomic used for number of handles */
    hg_thread_spin_t created_list_lock; /* Handle list lock */
    hg_thread_spin_t pending_list_lock; /* Pending list lock */
#ifdef HG_HAS_SELF_FORWARD
    int completion_queue_notify; /* Self notification */
#endif
    hg_bool_t finalizing; /* Prevent reposts */
};

#ifdef HG_HAS_SELF_FORWARD
/* Info for wrapping callbacks if self addr */
struct hg_core_self_cb_info {
    hg_core_cb_t forward_cb;
    void *forward_arg;
    hg_core_cb_t respond_cb;
    void *respond_arg;
};
#endif

/* HG addr */
struct hg_core_private_addr {
    struct hg_core_addr core_addr; /* Must remain as first field */
#ifdef HG_HAS_SM_ROUTING
    na_sm_id_t host_id; /* NA SM Host ID */
#endif
    hg_atomic_int32_t ref_count; /* Reference count */
    hg_bool_t is_mine;           /* Created internally or not */
};

/* HG core op type */
typedef enum {
    HG_CORE_FORWARD,    /*!< Forward completion */
    HG_CORE_RESPOND,    /*!< Respond completion */
    HG_CORE_NO_RESPOND, /*!< No response completion */
#ifdef HG_HAS_SELF_FORWARD
    HG_CORE_FORWARD_SELF, /*!< Self forward completion */
    HG_CORE_RESPOND_SELF, /*!< Self respond completion */
#endif
    HG_CORE_PROCESS /*!< Process completion */
} hg_core_op_type_t;

/* HG core handle */
struct hg_core_private_handle {
    struct hg_core_handle core_handle; /* Must remain as first field */
    struct hg_completion_entry
        hg_completion_entry; /* Entry in completion queue */
    HG_LIST_ENTRY(hg_core_private_handle) created; /* Created list entry */
    HG_LIST_ENTRY(hg_core_private_handle) pending; /* Pending list entry */
    struct hg_core_header in_header;               /* Input header */
    struct hg_core_header out_header;              /* Output header */
    na_class_t *na_class;                          /* NA class */
    na_context_t *na_context;                      /* NA context */
    hg_core_cb_t request_callback;                 /* Request callback */
    void *request_arg;              /* Request callback arguments */
    hg_core_cb_t response_callback; /* Response callback */
    void *response_arg;             /* Response callback arguments */
    hg_return_t (*forward)(
        struct hg_core_private_handle *hg_core_handle); /* forward */
    hg_return_t (*respond)(
        struct hg_core_private_handle *hg_core_handle); /* respond */
    hg_return_t (*no_respond)(
        struct hg_core_private_handle *hg_core_handle); /* no_respond */
    void *ack_buf;             /* Ack buf for more data */
    void *in_buf_plugin_data;  /* Input buffer NA plugin data */
    void *out_buf_plugin_data; /* Output buffer NA plugin data */
    void *ack_buf_plugin_data; /* Ack plugin data */
    na_op_id_t na_send_op_id;  /* Operation ID for send */
    na_op_id_t na_recv_op_id;  /* Operation ID for recv */
    na_op_id_t na_ack_op_id;   /* Operation ID for ack */
    na_size_t in_buf_used;     /* Amount of input buffer used */
    na_size_t out_buf_used;    /* Amount of output buffer used */
    na_tag_t tag;              /* Tag used for request and response */
    hg_atomic_int32_t
        na_op_completed_count;   /* Number of NA operations completed */
    hg_atomic_int32_t in_use;    /* Is in use */
    hg_atomic_int32_t ref_count; /* Reference count */
    hg_atomic_int32_t posted;    /* Handle has been posted */
    hg_atomic_int32_t canceling; /* Handle is being canceled */
    unsigned int na_op_count;    /* Number of ongoing operations */
    hg_core_op_type_t op_type;   /* Core operation type */
    hg_return_t ret;             /* Return code associated to handle */
    hg_uint8_t cookie;           /* Cookie */
    hg_bool_t repost;            /* Repost handle on completion (listen) */
    hg_bool_t is_self;           /* Self processed */
    hg_bool_t no_response;       /* Require response or not */
};

/* HG op id */
struct hg_core_op_info_lookup {
    struct hg_core_private_addr *hg_core_addr; /* Address */
};

struct hg_core_op_id {
    struct hg_completion_entry
        hg_completion_entry; /* Entry in completion queue */
    union {
        struct hg_core_op_info_lookup lookup;
    } info;
    struct hg_core_private_context *context; /* Context */
    hg_core_cb_t callback;                   /* Callback */
    void *arg;                               /* Callback arguments */
    hg_cb_type_t type;                       /* Callback type */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Equal function for function map.
 */
static HG_INLINE int
hg_core_int_equal(void *vlocation1, void *vlocation2);

/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_core_int_hash(void *vlocation);

/**
 * Free function for value in function map.
 */
static void
hg_core_func_map_value_free(hg_hash_table_value_t value);

/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_core_gen_request_tag(struct hg_core_private_class *hg_core_class);

/**
 * Proc request header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_request(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op);

/**
 * Proc response header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_response(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op);

/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_core_pending_list_cancel(struct hg_core_private_context *context);

/**
 * Wail until handle lists are empty.
 */
static hg_return_t
hg_core_context_lists_wait(struct hg_core_private_context *context);

/**
 * Initialize class.
 */
static struct hg_core_private_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info);

/**
 * Finalize class.
 */
static hg_return_t
hg_core_finalize(struct hg_core_private_class *hg_core_class);

/**
 * Create addr.
 */
static struct hg_core_private_addr *
hg_core_addr_create(
    struct hg_core_private_class *hg_core_class, na_class_t *na_class);

/**
 * Lookup addr.
 */
static hg_return_t
hg_core_addr_lookup(struct hg_core_private_class *hg_core_class,
    const char *name, struct hg_core_private_addr **addr);

/**
 * Free addr.
 */
static hg_return_t
hg_core_addr_free(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr *hg_core_addr);

/**
 * Self addr.
 */
static hg_return_t
hg_core_addr_self(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr **self_addr);

/**
 * Dup addr.
 */
static hg_return_t
hg_core_addr_dup(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr *hg_core_addr,
    struct hg_core_private_addr **hg_new_addr);

/**
 * Convert addr to string.
 */
static hg_return_t
hg_core_addr_to_string(struct hg_core_private_class *hg_core_class, char *buf,
    hg_size_t *buf_size, struct hg_core_private_addr *hg_core_addr);

/**
 * Create handle.
 */
static struct hg_core_private_handle *
hg_core_create(struct hg_core_private_context *context, hg_bool_t use_sm);

/**
 * Free handle.
 */
static void
hg_core_destroy(struct hg_core_private_handle *hg_core_handle);

/**
 * Allocate NA resources.
 */
static hg_return_t
hg_core_alloc_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t use_sm);

/**
 * Freee NA resources.
 */
static void
hg_core_free_na(struct hg_core_private_handle *hg_core_handle);

/**
 * Reset handle.
 */
static void
hg_core_reset(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t reset_info);

/**
 * Set target addr / RPC ID
 */
static hg_return_t
hg_core_set_rpc(struct hg_core_private_handle *hg_core_handle,
    struct hg_core_private_addr *addr, hg_id_t id);

#ifdef HG_HAS_SELF_FORWARD
/**
 * Forward handle locally.
 */
static hg_return_t
hg_core_forward_self(struct hg_core_private_handle *hg_core_handle);
#endif

/**
 * Forward handle through NA.
 */
static hg_return_t
hg_core_forward_na(struct hg_core_private_handle *hg_core_handle);

#ifdef HG_HAS_SELF_FORWARD
/**
 * Send response locally.
 */
static HG_INLINE hg_return_t
hg_core_respond_self(struct hg_core_private_handle *hg_core_handle);

/**
 * Do not send response locally.
 */
static HG_INLINE hg_return_t
hg_core_no_respond_self(struct hg_core_private_handle *hg_core_handle);
#endif

/**
 * Send response through NA.
 */
static hg_return_t
hg_core_respond_na(struct hg_core_private_handle *hg_core_handle);

/**
 * Do not send response through NA.
 */
static HG_INLINE hg_return_t
hg_core_no_respond_na(struct hg_core_private_handle *hg_core_handle);

/**
 * Send input callback.
 */
static HG_INLINE int
hg_core_send_input_cb(const struct na_cb_info *callback_info);

/**
 * Recv input callback.
 */
static int
hg_core_recv_input_cb(const struct na_cb_info *callback_info);

/**
 * Process input.
 */
static hg_return_t
hg_core_process_input(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed);

/**
 * Send output callback.
 */
static HG_INLINE int
hg_core_send_output_cb(const struct na_cb_info *callback_info);

/**
 * Recv output callback.
 */
static HG_INLINE int
hg_core_recv_output_cb(const struct na_cb_info *callback_info);

/**
 * Process output.
 */
static hg_return_t
hg_core_process_output(struct hg_core_private_handle *hg_core_handle,
    hg_bool_t *completed, hg_return_t (*done_callback)(hg_core_handle_t));

/**
 * Send ack for HG_CORE_MORE_DATA flag on output.
 */
static hg_return_t
hg_core_send_ack(hg_core_handle_t handle);

/**
 * Send ack callback. (HG_CORE_MORE_DATA flag on output)
 */
static HG_INLINE int
hg_core_send_ack_cb(const struct na_cb_info *callback_info);

/**
 * Recv ack callback. (HG_CORE_MORE_DATA flag on output)
 */
static HG_INLINE int
hg_core_recv_ack_cb(const struct na_cb_info *callback_info);

#ifdef HG_HAS_SELF_FORWARD
/**
 * Wrapper for local callback execution.
 */
static hg_return_t
hg_core_self_cb(const struct hg_core_cb_info *callback_info);

/**
 * Process handle (used for self execution).
 */
static hg_return_t
hg_core_process_self(struct hg_core_private_handle *hg_core_handle);
#endif

/**
 * Process handle.
 */
static hg_return_t
hg_core_process(struct hg_core_private_handle *hg_core_handle);

/**
 * Complete handle and NA operation.
 */
static HG_INLINE hg_return_t
hg_core_complete_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed);

/**
 * Complete handle and add to completion queue.
 */
static HG_INLINE hg_return_t
hg_core_complete(hg_core_handle_t handle);

/**
 * Add entry to completion queue.
 */
hg_return_t
hg_core_completion_add(struct hg_core_context *context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify);

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_core_context_post(struct hg_core_private_context *context,
    unsigned int request_count, hg_bool_t repost, hg_bool_t use_sm);

/**
 * Post handle and add it to pending list.
 */
static hg_return_t
hg_core_post(struct hg_core_private_handle *hg_core_handle);

/**
 * Reset handle and re-post it.
 */
static hg_return_t
hg_core_reset_post(struct hg_core_private_handle *hg_core_handle);

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_core_progress_na(
    na_class_t *na_class, na_context_t *na_context, unsigned int timeout);

#ifdef HG_HAS_SELF_FORWARD
/**
 * Completion queue notification callback.
 */
static HG_INLINE hg_return_t
hg_core_progress_loopback_notify(struct hg_core_private_context *context);
#endif

/**
 * Determines when it is safe to block.
 */
static HG_INLINE hg_bool_t
hg_core_poll_try_wait(struct hg_core_private_context *context);

/**
 * Make progress.
 */
static hg_return_t
hg_core_progress(struct hg_core_private_context *context, unsigned int timeout);

/**
 * Trigger callbacks.
 */
static hg_return_t
hg_core_trigger(struct hg_core_private_context *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count);

/**
 * Trigger callback from HG lookup op ID.
 */
static hg_return_t
hg_core_trigger_lookup_entry(struct hg_core_op_id *hg_core_op_id);

/**
 * Trigger callback from HG core handle.
 */
static hg_return_t
hg_core_trigger_entry(struct hg_core_private_handle *hg_core_handle);

/**
 * Trigger callback from HG bulk op ID.
 */
extern hg_return_t
hg_bulk_trigger_entry(struct hg_bulk_op_id *hg_bulk_op_id);

/**
 * Cancel handle.
 */
static hg_return_t
hg_core_cancel(struct hg_core_private_handle *hg_core_handle);

#ifdef HG_HAS_COLLECT_STATS
/**
 * Print stats.
 */
static void
hg_core_print_stats(void);
#endif

/*******************/
/* Local Variables */
/*******************/

#ifdef HG_HAS_COLLECT_STATS
static hg_bool_t hg_core_print_stats_registered_g = HG_FALSE;
static hg_core_stat_t hg_core_rpc_count_g = HG_CORE_STAT_INIT(0);
static hg_core_stat_t hg_core_rpc_extra_count_g = HG_CORE_STAT_INIT(0);
static hg_core_stat_t hg_core_bulk_count_g = HG_CORE_STAT_INIT(0);
#endif

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_COLLECT_STATS
static void
hg_core_print_stats(void)
{
    printf("\n================================================================="
           "\n");
    printf("Mercury stat report\n");
    printf("-------------------\n");
    printf("RPC count:            %lu\n",
        (unsigned long) hg_core_stat_get(&hg_core_rpc_count_g));
    printf("RPC count (overflow): %lu\n",
        (unsigned long) hg_core_stat_get(&hg_core_rpc_extra_count_g));
    printf("Bulk transfer count:  %lu\n",
        (unsigned long) hg_core_stat_get(&hg_core_bulk_count_g));
}
#endif

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_int_equal(void *vlocation1, void *vlocation2)
{
    return *((int *) vlocation1) == *((int *) vlocation2);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE unsigned int
hg_core_int_hash(void *vlocation)
{
    return *((unsigned int *) vlocation);
}

/*---------------------------------------------------------------------------*/
static void
hg_core_func_map_value_free(hg_hash_table_value_t value)
{
    struct hg_core_rpc_info *hg_core_rpc_info =
        (struct hg_core_rpc_info *) value;

    if (hg_core_rpc_info->free_callback)
        hg_core_rpc_info->free_callback(hg_core_rpc_info->data);
    free(hg_core_rpc_info);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE na_tag_t
hg_core_gen_request_tag(struct hg_core_private_class *hg_core_class)
{
    na_tag_t request_tag = 0;

    /* Compare and swap tag if reached max tag */
    if (!hg_atomic_cas32(&hg_core_class->request_tag,
            (hg_util_int32_t) hg_core_class->request_max_tag, 0)) {
        /* Increment tag */
        request_tag = (na_tag_t) hg_atomic_incr32(&hg_core_class->request_tag);
    }

    return request_tag;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_proc_header_request(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op)
{
    char *header_buf =
        (char *) hg_core_handle->in_buf + hg_core_handle->na_in_header_offset;
    size_t header_buf_size =
        hg_core_handle->in_buf_size - hg_core_handle->na_in_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc request header */
    ret = hg_core_header_request_proc(
        op, header_buf, header_buf_size, hg_core_header);
    HG_CHECK_HG_ERROR(done, ret, "Could not process request header");

    if (op == HG_DECODE) {
        ret = hg_core_header_request_verify(hg_core_header);
        HG_CHECK_HG_ERROR(done, ret, "Could not verify request header");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_proc_header_response(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op)
{
    char *header_buf =
        (char *) hg_core_handle->out_buf + hg_core_handle->na_out_header_offset;
    size_t header_buf_size =
        hg_core_handle->out_buf_size - hg_core_handle->na_out_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc response header */
    ret = hg_core_header_response_proc(
        op, header_buf, header_buf_size, hg_core_header);
    HG_CHECK_HG_ERROR(done, ret, "Could not process response header");

    if (op == HG_DECODE) {
        ret = hg_core_header_response_verify(hg_core_header);
        HG_CHECK_HG_ERROR(done, ret, "Could not verify response header");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_pending_list_cancel(struct hg_core_private_context *context)
{
    struct hg_core_private_handle *hg_core_handle;
    hg_return_t ret = HG_SUCCESS;

    hg_thread_spin_lock(&context->pending_list_lock);

    HG_QUEUE_FOREACH (hg_core_handle, &context->pending_list, pending) {
        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not cancel handle");
    }

#ifdef HG_HAS_SM_ROUTING
    HG_QUEUE_FOREACH (hg_core_handle, &context->sm_pending_list, pending) {
        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not cancel handle");
    }
#endif

done:
    hg_thread_spin_unlock(&context->pending_list_lock);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_lists_wait(struct hg_core_private_context *context)
{
    hg_util_bool_t created_list_empty = HG_UTIL_FALSE;
    hg_util_bool_t pending_list_empty = HG_UTIL_FALSE;
#ifdef HG_HAS_SM_ROUTING
    hg_util_bool_t sm_pending_list_empty = HG_UTIL_FALSE;
#else
    hg_util_bool_t sm_pending_list_empty = HG_UTIL_TRUE;
#endif
    /* Convert timeout in ms into seconds */
    double remaining = HG_CORE_CLEANUP_TIMEOUT / 1000.0;
    hg_return_t ret = HG_SUCCESS;

    do {
        unsigned int actual_count = 0;
        hg_time_t t1, t2;
        hg_return_t trigger_ret, progress_ret;

        hg_time_get_current_ms(&t1);

        /* Trigger everything we can from HG */
        do {
            trigger_ret = hg_core_trigger(context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);
        HG_CHECK_ERROR(trigger_ret != HG_SUCCESS && trigger_ret != HG_TIMEOUT,
            done, ret, trigger_ret, "Could not trigger entry");

        hg_thread_spin_lock(&context->created_list_lock);
        created_list_empty = HG_LIST_IS_EMPTY(&context->created_list);
        hg_thread_spin_unlock(&context->created_list_lock);

        hg_thread_spin_lock(&context->pending_list_lock);
        pending_list_empty = HG_LIST_IS_EMPTY(&context->pending_list);
#ifdef HG_HAS_SM_ROUTING
        sm_pending_list_empty = HG_LIST_IS_EMPTY(&context->sm_pending_list);
#endif
        hg_thread_spin_unlock(&context->pending_list_lock);

        if (created_list_empty && pending_list_empty && sm_pending_list_empty)
            break;

        progress_ret =
            hg_core_progress(context, (unsigned int) (remaining * 1000.0));
        HG_CHECK_ERROR(progress_ret != HG_SUCCESS && progress_ret != HG_TIMEOUT,
            done, ret, progress_ret, "Could not make progress");
        hg_time_get_current_ms(&t2);
        remaining -= hg_time_diff(t2, t1);
        if (remaining < 0)
            remaining = 0;
    } while (remaining > 0 || !pending_list_empty || !sm_pending_list_empty);

    HG_LOG_DEBUG("Remaining %lf, Context list status: %d, %d, %d", remaining,
        created_list_empty, pending_list_empty, sm_pending_list_empty);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_private_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_core_private_class *hg_core_class = NULL;
    na_tag_t na_max_tag;
#ifdef HG_HAS_SM_ROUTING
    na_tag_t na_sm_max_tag;
    hg_bool_t auto_sm = HG_FALSE;
#endif
    hg_return_t ret = HG_SUCCESS;

    /* Create new HG class */
    hg_core_class = (struct hg_core_private_class *) malloc(
        sizeof(struct hg_core_private_class));
    HG_CHECK_ERROR(hg_core_class == NULL, error, ret, HG_NOMEM,
        "Could not allocate HG class");
    memset(hg_core_class, 0, sizeof(struct hg_core_private_class));

    /* Parse options */
    if (hg_init_info) {
        /* External NA class */
        if (hg_init_info->na_class) {
            hg_core_class->core_class.na_class = hg_init_info->na_class;
            hg_core_class->na_ext_init = HG_TRUE;
        }
        hg_core_class->progress_mode = hg_init_info->na_init_info.progress_mode;
#ifdef HG_HAS_SM_ROUTING
        auto_sm = hg_init_info->auto_sm;
#else
        HG_CHECK_WARNING(hg_init_info->auto_sm,
            "Auto SM requested but not enabled, "
            "please turn ON MERCURY_USE_SM_ROUTING in CMake options");
#endif
#ifdef HG_HAS_COLLECT_STATS
        hg_core_class->stats = hg_init_info->stats;
        if (hg_core_class->stats && !hg_core_print_stats_registered_g) {
            int rc = atexit(hg_core_print_stats);
            HG_CHECK_ERROR(rc != 0, error, ret, HG_PROTOCOL_ERROR,
                "Could not register hg_core_print_stats");
            hg_core_print_stats_registered_g = HG_TRUE;
        }
#endif
    }

    /* Initialize NA if not provided externally */
    if (!hg_core_class->na_ext_init) {
        hg_core_class->core_class.na_class = NA_Initialize_opt(
            na_info_string, na_listen, &hg_init_info->na_init_info);
        HG_CHECK_ERROR(hg_core_class->core_class.na_class == NULL, error, ret,
            HG_NA_ERROR, "Could not initialize NA class");
    }

#ifdef HG_HAS_SM_ROUTING
    /* Initialize SM plugin */
    if (auto_sm) {
        na_return_t na_ret;

        HG_CHECK_ERROR(
            strcmp(NA_Get_class_name(hg_core_class->core_class.na_class),
                "na") == 0,
            error, ret, HG_PROTONOSUPPORT,
            "Cannot use auto SM mode if initialized "
            "NA class is already using SM");

        /* Initialize NA SM first so that tmp directories are created */
        hg_core_class->core_class.na_sm_class =
            NA_Initialize_opt("na+sm", na_listen, &hg_init_info->na_init_info);
        HG_CHECK_ERROR(hg_core_class->core_class.na_sm_class == NULL, error,
            ret, HG_NA_ERROR, "Could not initialize NA SM class");

        /* Get SM host ID */
        na_ret = NA_SM_Host_id_get(&hg_core_class->host_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "NA_SM_Host_id_get() failed (%s)", NA_Error_to_string(na_ret));
    }
#endif

    /* Compute max request tag */
    na_max_tag = NA_Msg_get_max_tag(hg_core_class->core_class.na_class);
    HG_CHECK_ERROR(
        na_max_tag == 0, error, ret, HG_NA_ERROR, "NA Max tag is not defined");
    hg_core_class->request_max_tag = na_max_tag;

#ifdef HG_HAS_SM_ROUTING
    if (auto_sm) {
        na_sm_max_tag =
            NA_Msg_get_max_tag(hg_core_class->core_class.na_sm_class);
        HG_CHECK_ERROR(na_sm_max_tag == 0, error, ret, HG_NA_ERROR,
            "NA Max tag is not defined");
        hg_core_class->request_max_tag =
            HG_CORE_MIN(hg_core_class->request_max_tag, na_sm_max_tag);
    }
#endif

    /* Initialize atomic for tags */
    hg_atomic_init32(&hg_core_class->request_tag, 0);

    /* No context created yet */
    hg_atomic_init32(&hg_core_class->n_contexts, 0);

    /* No addr created yet */
    hg_atomic_init32(&hg_core_class->n_addrs, 0);

    /* Create new function map */
    hg_core_class->func_map =
        hg_hash_table_new(hg_core_int_hash, hg_core_int_equal);
    HG_CHECK_ERROR(hg_core_class->func_map == NULL, error, ret, HG_NOMEM,
        "Could not create function map");

    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(
        hg_core_class->func_map, free, hg_core_func_map_value_free);

    /* Initialize mutex */
    hg_thread_spin_init(&hg_core_class->func_map_lock);

    // TODO
    (void) ret;
    return hg_core_class;

error:
    hg_core_finalize(hg_core_class);
    return NULL;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_finalize(struct hg_core_private_class *hg_core_class)
{
    hg_util_int32_t n_addrs, n_contexts;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_core_class)
        goto done;

    n_contexts = hg_atomic_get32(&hg_core_class->n_contexts);
    HG_CHECK_ERROR(n_contexts != 0, done, ret, HG_BUSY,
        "HG contexts must be destroyed before finalizing HG (%d remaining)",
        n_contexts);

    n_addrs = hg_atomic_get32(&hg_core_class->n_addrs);
    HG_CHECK_ERROR(n_addrs != 0, done, ret, HG_BUSY,
        "HG addrs must be freed before finalizing HG (%d remaining)", n_addrs);

    /* Delete function map */
    if (hg_core_class->func_map)
        hg_hash_table_free(hg_core_class->func_map);
    hg_core_class->func_map = NULL;

    /* Free user data */
    if (hg_core_class->core_class.data_free_callback)
        hg_core_class->core_class.data_free_callback(
            hg_core_class->core_class.data);

    /* Destroy mutex */
    hg_thread_spin_destroy(&hg_core_class->func_map_lock);

    if (!hg_core_class->na_ext_init) {
        /* Finalize interface */
        na_ret = NA_Finalize(hg_core_class->core_class.na_class);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not finalize NA interface (%s)", NA_Error_to_string(na_ret));
        hg_core_class->core_class.na_class = NULL;
    }

#ifdef HG_HAS_SM_ROUTING
    /* Finalize SM interface */
    na_ret = NA_Finalize(hg_core_class->core_class.na_sm_class);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not finalize NA SM interface (%s)", NA_Error_to_string(na_ret));
#endif

    /* Free HG class */
    free(hg_core_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_private_addr *
hg_core_addr_create(
    struct hg_core_private_class *hg_core_class, na_class_t *na_class)
{
    struct hg_core_private_addr *hg_core_addr = NULL;

    hg_core_addr = (struct hg_core_private_addr *) malloc(
        sizeof(struct hg_core_private_addr));
    HG_CHECK_ERROR_NORET(
        hg_core_addr == NULL, done, "Could not allocate HG addr");

    memset(hg_core_addr, 0, sizeof(struct hg_core_private_addr));
    hg_core_addr->core_addr.na_class = na_class;
    hg_core_addr->core_addr.na_addr = NA_ADDR_NULL;
#ifdef HG_HAS_SM_ROUTING
    hg_core_addr->core_addr.na_sm_addr = NA_ADDR_NULL;
#endif
    hg_atomic_init32(&hg_core_addr->ref_count, 1);

    /* Increment N addrs from HG class */
    hg_atomic_incr32(&hg_core_class->n_addrs);

done:
    return hg_core_addr;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup(struct hg_core_private_class *hg_core_class,
    const char *name, struct hg_core_private_addr **addr)
{
    na_class_t *na_class = hg_core_class->core_class.na_class;
    struct hg_core_private_addr *hg_core_addr = NULL;
    na_return_t na_ret;
#ifdef HG_HAS_SM_ROUTING
    char lookup_name[HG_CORE_ADDR_MAX_SIZE] = {'\0'};
#endif
    const char *name_str = name;
    hg_return_t ret = HG_SUCCESS;

    /* Allocate addr */
    hg_core_addr = hg_core_addr_create(hg_core_class, NULL);
    HG_CHECK_ERROR(
        hg_core_addr == NULL, error, ret, HG_NOMEM, "Could not create HG addr");

#ifdef HG_HAS_SM_ROUTING
    /* Parse name string */
    if (strstr(name, HG_CORE_ADDR_DELIMITER)) {
        char *lookup_names, *local_id_str;
        char *remote_name, *local_name;

        strcpy(lookup_name, name);

        /* Get first part of address string with host ID */
        strtok_r(lookup_name, HG_CORE_ADDR_DELIMITER, &lookup_names);

        HG_CHECK_ERROR(strstr(name, HG_CORE_PROTO_DELIMITER) == NULL, error,
            ret, HG_PROTOCOL_ERROR, "Malformed address format");

        /* Get address SM host ID */
        strtok_r(lookup_name, HG_CORE_PROTO_DELIMITER, &local_id_str);
        na_ret =
            NA_SM_String_to_host_id(local_id_str + 2, &hg_core_addr->host_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "NA_SM_String_to_host_id() failed (%s)",
            NA_Error_to_string(na_ret));

        /* Separate remaining two parts */
        strtok_r(lookup_names, HG_CORE_ADDR_DELIMITER, &remote_name);
        local_name = lookup_names;

        /* Compare IDs, if they match it's local address */
        if (hg_core_class->core_class.na_sm_class &&
            NA_SM_Host_id_cmp(hg_core_addr->host_id, hg_core_class->host_id)) {
            HG_LOG_DEBUG("This is a local address");
            name_str = local_name;
            na_class = hg_core_class->core_class.na_sm_class;
        } else {
            /* Remote lookup */
            name_str = remote_name;
        }
    }
#endif
    /* Assign corresponding NA class */
    hg_core_addr->core_addr.na_class = na_class;

    /* Lookup adress */
    na_ret =
        NA_Addr_lookup(na_class, name_str, &hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not lookup address %s (%s)", name_str,
        NA_Error_to_string(na_ret));

    *addr = hg_core_addr;

    return ret;

error:
    hg_core_addr_free(hg_core_class, hg_core_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_free(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr *hg_core_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_core_addr)
        goto done;

    if (hg_atomic_decr32(&hg_core_addr->ref_count))
        /* Cannot free yet */
        goto done;

    /* Decrement N addrs from HG class */
    hg_atomic_decr32(&hg_core_class->n_addrs);

#ifdef HG_HAS_SM_ROUTING
    /* Self address case with SM */
    if (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_ret = NA_Addr_free(hg_core_class->core_class.na_sm_class,
            hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not free NA SM address (%s)", NA_Error_to_string(na_ret));
    }
#endif

    /* Free NA address */
    na_ret = NA_Addr_free(
        hg_core_addr->core_addr.na_class, hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not free NA address (%s)", NA_Error_to_string(na_ret));

    free(hg_core_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_self(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr **self_addr)
{
    struct hg_core_private_addr *hg_core_addr = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_core_addr =
        hg_core_addr_create(hg_core_class, hg_core_class->core_class.na_class);
    HG_CHECK_ERROR(
        hg_core_addr == NULL, done, ret, HG_NOMEM, "Could not create HG addr");

    na_ret = NA_Addr_self(
        hg_core_class->core_class.na_class, &hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not get self address (%s)", NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_class->core_class.na_sm_class) {
        /* Get SM address */
        na_ret = NA_Addr_self(hg_core_class->core_class.na_sm_class,
            &hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not get self SM address (%s)", NA_Error_to_string(na_ret));

        /* Copy local host ID */
        NA_SM_Host_id_copy(&hg_core_addr->host_id, hg_core_class->host_id);
    }
#endif

    *self_addr = hg_core_addr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_dup(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr *hg_core_addr,
    struct hg_core_private_addr **hg_new_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /**
     * If address is internal, create a new copy to prevent repost
     * operations to modify underlying NA address, otherwise simply increment
     * refcount of original address.
     */
    if (hg_core_addr->is_mine) {
        struct hg_core_private_addr *dup = NULL;

        dup = hg_core_addr_create(
            hg_core_class, hg_core_addr->core_addr.na_class);
        HG_CHECK_ERROR(
            dup == NULL, done, ret, HG_NOMEM, "Could not create dup HG addr");

        na_ret = NA_Addr_dup(hg_core_addr->core_addr.na_class,
            hg_core_addr->core_addr.na_addr, &dup->core_addr.na_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not duplicate address (%s)", NA_Error_to_string(na_ret));

        *hg_new_addr = dup;
    } else {
        hg_atomic_incr32(&hg_core_addr->ref_count);
        *hg_new_addr = hg_core_addr;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_to_string(struct hg_core_private_class *hg_core_class, char *buf,
    hg_size_t *buf_size, struct hg_core_private_addr *hg_core_addr)
{
    char *buf_ptr = buf;
    hg_size_t new_buf_size = 0, buf_size_used = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    new_buf_size = *buf_size;

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr->core_addr.na_sm_addr) {
        char addr_str[HG_CORE_ADDR_MAX_SIZE];
        char uuid_str[NA_SM_HOST_ID_LEN + 1];
        int desc_len;

        /* Convert host ID to string and generate addr string */
        na_ret = NA_SM_Host_id_to_string(hg_core_addr->host_id, uuid_str);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "NA_SM_Host_id_to_string() failed (%s)",
            NA_Error_to_string(na_ret));

        desc_len = snprintf(addr_str, HG_CORE_ADDR_MAX_SIZE,
            "uid://%s" HG_CORE_ADDR_DELIMITER, uuid_str);
        HG_CHECK_ERROR(desc_len > HG_CORE_ADDR_MAX_SIZE, done, ret, HG_OVERFLOW,
            "Exceeding max addr name");

        if (buf_ptr) {
            strcpy(buf_ptr, addr_str);
            buf_ptr += desc_len;
        }
        buf_size_used += (hg_size_t) desc_len;
        if (*buf_size > (unsigned int) desc_len)
            new_buf_size = *buf_size - (hg_size_t) desc_len;

        /* Get NA SM address string */
        na_ret = NA_Addr_to_string(hg_core_class->core_class.na_sm_class,
            buf_ptr, &new_buf_size, hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not convert SM address to string (%s)",
            NA_Error_to_string(na_ret));

        if (buf_ptr) {
            buf_ptr[new_buf_size - 1] = *HG_CORE_ADDR_DELIMITER;
            buf_ptr += new_buf_size;
        }
        buf_size_used += new_buf_size;
        if (*buf_size > new_buf_size)
            new_buf_size = *buf_size - new_buf_size;
    }
#endif

    /* Get NA address string */
    na_ret = NA_Addr_to_string(hg_core_addr->core_addr.na_class, buf_ptr,
        &new_buf_size, hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not convert address to string (%s)", NA_Error_to_string(na_ret));

    *buf_size = new_buf_size + buf_size_used;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_private_handle *
hg_core_create(struct hg_core_private_context *context, hg_bool_t use_sm)
{
    struct hg_core_private_handle *hg_core_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_core_handle = (struct hg_core_private_handle *) malloc(
        sizeof(struct hg_core_private_handle));
    HG_CHECK_ERROR_NORET(
        hg_core_handle == NULL, error, "Could not allocate handle");

    memset(hg_core_handle, 0, sizeof(struct hg_core_private_handle));

    hg_core_handle->op_type = HG_CORE_PROCESS; /* Default */
    hg_core_handle->core_handle.info.core_class =
        context->core_context.core_class;
    hg_core_handle->core_handle.info.context = &context->core_context;
    hg_core_handle->core_handle.info.addr = HG_CORE_ADDR_NULL;
    hg_core_handle->core_handle.info.id = 0;
    hg_core_handle->core_handle.info.context_id = 0;

    /* Default return code */
    hg_core_handle->ret = HG_SUCCESS;

    /* Add handle to handle list so that we can track it */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);
    HG_LIST_INSERT_HEAD(&HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list,
        hg_core_handle, created);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);

    /* Handle is not in use */
    hg_atomic_init32(&hg_core_handle->in_use, HG_FALSE);

    /* Handle has not been posted */
    hg_atomic_init32(&hg_core_handle->posted, HG_FALSE);

    /* Handle is not being canceled */
    hg_atomic_init32(&hg_core_handle->canceling, HG_FALSE);

    /* Init in/out header */
    hg_core_header_request_init(&hg_core_handle->in_header);
    hg_core_header_response_init(&hg_core_handle->out_header);

    /* Set refcount to 1 */
    hg_atomic_init32(&hg_core_handle->ref_count, 1);

    /* Increment N handles from HG context */
    hg_atomic_incr32(&context->n_handles);

    /* Alloc/init NA resources */
    ret = hg_core_alloc_na(hg_core_handle, use_sm);
    HG_CHECK_HG_ERROR(error, ret, "Could not allocate NA handle ops");

    return hg_core_handle;

error:
    hg_core_destroy(hg_core_handle);
    return NULL;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_destroy(struct hg_core_private_handle *hg_core_handle)
{
    if (!hg_core_handle)
        goto done;

    if (hg_atomic_decr32(&hg_core_handle->ref_count))
        goto done; /* Cannot free yet */

    /* Remove handle from list */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);
    HG_LIST_REMOVE(hg_core_handle, created);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);

    /* Decrement N handles from HG context */
    hg_atomic_decr32(&HG_CORE_HANDLE_CONTEXT(hg_core_handle)->n_handles);

    /* Remove reference to HG addr */
    hg_core_addr_free(HG_CORE_HANDLE_CLASS(hg_core_handle),
        (struct hg_core_private_addr *) hg_core_handle->core_handle.info.addr);

    hg_core_header_request_finalize(&hg_core_handle->in_header);
    hg_core_header_response_finalize(&hg_core_handle->out_header);

    /* Free extra data here if needed */
    if (HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_release)
        HG_CORE_HANDLE_CLASS(hg_core_handle)
            ->more_data_release((hg_core_handle_t) hg_core_handle);

    /* Free user data */
    if (hg_core_handle->core_handle.data_free_callback)
        hg_core_handle->core_handle.data_free_callback(
            hg_core_handle->core_handle.data);

    /* Free NA resources */
    hg_core_free_na(hg_core_handle);

    free(hg_core_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_alloc_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t HG_UNUSED use_sm)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Set handle NA class/context */
    hg_core_handle->na_class =
#ifdef HG_HAS_SM_ROUTING
        (use_sm) ? HG_CORE_HANDLE_CLASS(hg_core_handle)->core_class.na_sm_class
                 :
#endif
                 HG_CORE_HANDLE_CLASS(hg_core_handle)->core_class.na_class;
    hg_core_handle->na_context =
#ifdef HG_HAS_SM_ROUTING
        (use_sm)
            ? HG_CORE_HANDLE_CONTEXT(hg_core_handle)->core_context.na_sm_context
            :
#endif
            HG_CORE_HANDLE_CONTEXT(hg_core_handle)->core_context.na_context;

    /* Initialize in/out buffers and use unexpected message size */
    hg_core_handle->core_handle.in_buf_size =
        NA_Msg_get_max_unexpected_size(hg_core_handle->na_class);
    hg_core_handle->core_handle.out_buf_size =
        NA_Msg_get_max_expected_size(hg_core_handle->na_class);
    hg_core_handle->core_handle.na_in_header_offset =
        NA_Msg_get_unexpected_header_size(hg_core_handle->na_class);
    hg_core_handle->core_handle.na_out_header_offset =
        NA_Msg_get_expected_header_size(hg_core_handle->na_class);

    hg_core_handle->core_handle.in_buf = NA_Msg_buf_alloc(
        hg_core_handle->na_class, hg_core_handle->core_handle.in_buf_size,
        &hg_core_handle->in_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->core_handle.in_buf == NULL, error, ret,
        HG_NOMEM, "Could not allocate buffer for input");

    na_ret = NA_Msg_init_unexpected(hg_core_handle->na_class,
        hg_core_handle->core_handle.in_buf,
        hg_core_handle->core_handle.in_buf_size);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize input buffer (%s)", NA_Error_to_string(na_ret));

    hg_core_handle->core_handle.out_buf = NA_Msg_buf_alloc(
        hg_core_handle->na_class, hg_core_handle->core_handle.out_buf_size,
        &hg_core_handle->out_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->core_handle.out_buf == NULL, error, ret,
        HG_NOMEM, "Could not allocate buffer for output");

    na_ret = NA_Msg_init_expected(hg_core_handle->na_class,
        hg_core_handle->core_handle.out_buf,
        hg_core_handle->core_handle.out_buf_size);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize output buffer (%s)", NA_Error_to_string(na_ret));

    /* Create NA operation IDs */
    hg_core_handle->na_send_op_id = NA_Op_create(hg_core_handle->na_class);
    HG_CHECK_ERROR(hg_core_handle->na_send_op_id == NA_OP_ID_NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");
    hg_core_handle->na_recv_op_id = NA_Op_create(hg_core_handle->na_class);
    HG_CHECK_ERROR(hg_core_handle->na_recv_op_id == NA_OP_ID_NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");
    hg_core_handle->na_ack_op_id = NA_Op_create(hg_core_handle->na_class);
    HG_CHECK_ERROR(hg_core_handle->na_ack_op_id == NA_OP_ID_NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");

    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_init32(&hg_core_handle->na_op_completed_count, 0);

    return ret;

error:
    hg_core_free_na(hg_core_handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_free_na(struct hg_core_private_handle *hg_core_handle)
{
    na_return_t na_ret;

    /* Destroy NA op IDs */
    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_send_op_id);
    HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
        "Could not destroy send op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_send_op_id = NA_OP_ID_NULL;

    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_recv_op_id);
    HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
        "Could not destroy recv op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_recv_op_id = NA_OP_ID_NULL;

    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_ack_op_id);
    HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
        "Could not destroy ack op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_ack_op_id = NA_OP_ID_NULL;

    /* Free buffers */
    na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
        hg_core_handle->core_handle.in_buf, hg_core_handle->in_buf_plugin_data);
    HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
        "Could not free input buffer (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->core_handle.in_buf = NULL;
    hg_core_handle->in_buf_plugin_data = NULL;

    na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
        hg_core_handle->core_handle.out_buf,
        hg_core_handle->out_buf_plugin_data);
    HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
        "Could not free output buffer (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->core_handle.out_buf = NULL;
    hg_core_handle->out_buf_plugin_data = NULL;

    if (hg_core_handle->ack_buf) {
        na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
            hg_core_handle->ack_buf, hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
            "Could not free ack buffer (%s)", NA_Error_to_string(na_ret));
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }

done:
    return;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_reset(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t reset_info)
{
    /* Reset source address */
    if (reset_info) {
        if (hg_core_handle->core_handle.info.addr != HG_CORE_ADDR_NULL &&
            hg_core_handle->core_handle.info.addr->na_addr != NA_ADDR_NULL) {
            na_return_t na_ret =
                NA_Addr_free(hg_core_handle->core_handle.info.addr->na_class,
                    hg_core_handle->core_handle.info.addr->na_addr);
            HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
                "Could not free NA address (%s)", NA_Error_to_string(na_ret));
            hg_core_handle->core_handle.info.addr->na_addr = NA_ADDR_NULL;
        }
        hg_core_handle->core_handle.info.id = 0;
    }
    hg_core_handle->core_handle.info.context_id = 0;
    hg_core_handle->request_callback = NULL;
    hg_core_handle->request_arg = NULL;
    hg_core_handle->response_callback = NULL;
    hg_core_handle->response_arg = NULL;
    hg_core_handle->op_type = HG_CORE_PROCESS; /* Default */
    hg_core_handle->tag = 0;
    hg_core_handle->cookie = 0;
    hg_core_handle->ret = HG_SUCCESS;
    hg_core_handle->in_buf_used = 0;
    hg_core_handle->out_buf_used = 0;
    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_set32(&hg_core_handle->na_op_completed_count, 0);
    hg_core_handle->no_response = HG_FALSE;

    /* Free extra data here if needed */
    if (HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_release)
        HG_CORE_HANDLE_CLASS(hg_core_handle)
            ->more_data_release((hg_core_handle_t) hg_core_handle);
    if (hg_core_handle->ack_buf) {
        na_return_t na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
            hg_core_handle->ack_buf, hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR_NORET(na_ret != NA_SUCCESS, done,
            "Could not free ack buffer (%s)", NA_Error_to_string(na_ret));
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }

    hg_core_header_request_reset(&hg_core_handle->in_header);
    hg_core_header_response_reset(&hg_core_handle->out_header);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_set_rpc(struct hg_core_private_handle *hg_core_handle,
    struct hg_core_private_addr *addr, hg_id_t id)
{
    struct hg_core_private_addr **handle_addr =
        (struct hg_core_private_addr **) &hg_core_handle->core_handle.info.addr;
    hg_return_t ret = HG_SUCCESS;

    /* We allow for NULL addr to be passed at creation time, this allows
     * for pool of handles to be created and later re-used after a call to
     * HG_Core_reset() */
    if (addr && *handle_addr != addr) {
        if (*handle_addr)
            hg_core_addr_free(
                HG_CORE_HANDLE_CLASS(hg_core_handle), *handle_addr);
        *handle_addr = addr;
        hg_atomic_incr32(&(*addr).ref_count); /* Increase ref to addr */

        /* Set forward call depending on address self */
        hg_core_handle->is_self =
            NA_Addr_is_self((*handle_addr)->core_addr.na_class,
                (*handle_addr)->core_addr.na_addr);
#ifdef HG_HAS_SELF_FORWARD
        hg_core_handle->forward =
            hg_core_handle->is_self ? hg_core_forward_self : hg_core_forward_na;
#else
        hg_core_handle->forward = hg_core_forward_na;
#endif
    }

    /* We also allow for NULL RPC id to be passed (same reason as above) */
    if (id && hg_core_handle->core_handle.info.id != id) {
        struct hg_core_rpc_info *hg_core_rpc_info;

        /* Retrieve ID function from function map */
        hg_thread_spin_lock(
            &HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map_lock);
        hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
            HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map,
            (hg_hash_table_key_t) &id);
        hg_thread_spin_unlock(
            &HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map_lock);
        if (!hg_core_rpc_info)
            HG_GOTO_DONE(done, ret, HG_NOENTRY);

        hg_core_handle->core_handle.info.id = id;

        /* Cache RPC info */
        hg_core_handle->core_handle.rpc_info = hg_core_rpc_info;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_forward_self(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Post operation to self processing pool */
    ret = hg_core_process_self(hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not self process handle");

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_na(struct hg_core_private_handle *hg_core_handle)
{
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD;

    /* Generate tag */
    hg_core_handle->tag =
        hg_core_gen_request_tag(HG_CORE_HANDLE_CLASS(hg_core_handle));

    /* Pre-post recv (output) if response is expected */
    if (!hg_core_handle->no_response) {
        na_ret = NA_Msg_recv_expected(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_recv_output_cb, hg_core_handle,
            hg_core_handle->core_handle.out_buf,
            hg_core_handle->core_handle.out_buf_size,
            hg_core_handle->out_buf_plugin_data,
            hg_core_handle->core_handle.info.addr->na_addr,
            hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
            &hg_core_handle->na_recv_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not post recv for output buffer (%s)",
            NA_Error_to_string(na_ret));

        /* Increment number of expected NA operations */
        hg_core_handle->na_op_count++;

        /* Take reference to make sure the handle does not get freed */
        hg_atomic_incr32(&hg_core_handle->ref_count);
    }

    /* Mark handle as posted */
    hg_atomic_set32(&hg_core_handle->posted, HG_TRUE);

    /* Post send (input) */
    na_ret = NA_Msg_send_unexpected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_input_cb, hg_core_handle,
        hg_core_handle->core_handle.in_buf, hg_core_handle->in_buf_used,
        hg_core_handle->in_buf_plugin_data,
        hg_core_handle->core_handle.info.addr->na_addr,
        hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
        &hg_core_handle->na_send_op_id);
    if (na_ret == NA_AGAIN)
        /* Silently return on NA_AGAIN error so that users can manually retry */
        HG_GOTO_DONE(cancel, ret, HG_AGAIN);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, cancel, ret, (hg_return_t) na_ret,
        "Could not post send for input buffer (%s)",
        NA_Error_to_string(na_ret));

done:
    return ret;

cancel:
    if (!hg_core_handle->no_response)
        hg_core_handle->na_op_count--;

    /* Handle is no longer posted and being canceled*/
    hg_atomic_set32(&hg_core_handle->posted, HG_FALSE);
    hg_atomic_set32(&hg_core_handle->canceling, HG_TRUE);

    /* Cancel the above posted recv op */
    na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
        hg_core_handle->na_recv_op_id);
    HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
        "Could not cancel recv op id (%s)", NA_Error_to_string(na_ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static HG_INLINE hg_return_t
hg_core_respond_self(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_RESPOND_SELF;

    /* Complete and add to completion queue */
    ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_no_respond_self(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Complete and add to completion queue */
    ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete handle");

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_respond_na(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    hg_bool_t ack_recv_posted = HG_FALSE;

    /* Increment number of expected NA operations */
    hg_core_handle->na_op_count++;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_RESPOND;

    /* More data on output requires an ack once it is processed */
    if (hg_core_handle->out_header.msg.response.flags & HG_CORE_MORE_DATA) {
        /* Increment number of expected NA operations */
        hg_core_handle->na_op_count++;

        hg_core_handle->ack_buf = NA_Msg_buf_alloc(hg_core_handle->na_class,
            sizeof(hg_uint8_t), &hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR(hg_core_handle->ack_buf == NULL, error, ret, HG_NA_ERROR,
            "Could not allocate buffer for ack");

        na_ret = NA_Msg_init_expected(hg_core_handle->na_class,
            hg_core_handle->ack_buf, sizeof(hg_uint8_t));
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not initialize ack buffer (%s)", NA_Error_to_string(na_ret));

        /* Pre-post recv (ack) if more data is expected */
        na_ret = NA_Msg_recv_expected(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_recv_ack_cb, hg_core_handle,
            hg_core_handle->ack_buf, sizeof(hg_uint8_t),
            hg_core_handle->ack_buf_plugin_data,
            hg_core_handle->core_handle.info.addr->na_addr,
            hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
            &hg_core_handle->na_ack_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not post recv for ack buffer (%s)",
            NA_Error_to_string(na_ret));
        ack_recv_posted = HG_TRUE;
    }

    /* Post expected send (output) */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_output_cb, hg_core_handle,
        hg_core_handle->core_handle.out_buf, hg_core_handle->out_buf_used,
        hg_core_handle->out_buf_plugin_data,
        hg_core_handle->core_handle.info.addr->na_addr,
        hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
        &hg_core_handle->na_send_op_id);
    /* Expected sends should always succeed after retry */
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post send for output buffer (%s)",
        NA_Error_to_string(na_ret));

    return ret;

error:
    if (ack_recv_posted) {
        /* Cancel the above posted recv ack op */
        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_ack_op_id);
        HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
            "Could not cancel ack op id (%s)", NA_Error_to_string(na_ret));
    }
    if (hg_core_handle->ack_buf) {
        na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
            hg_core_handle->ack_buf, hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
            "Could not free ack buffer (%s)", NA_Error_to_string(na_ret));
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_no_respond_na(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_NO_RESPOND;

    ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED)
        hg_core_handle->ret = HG_CANCELED;
    else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_WARNING("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));
        hg_core_handle->ret = HG_NA_ERROR;

        if (!hg_core_handle->no_response) {
            /* Cancel posted recv for response */
            na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
                hg_core_handle->na_context, hg_core_handle->na_recv_op_id);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t) na_ret, "Could not cancel recv op id (%s)",
                NA_Error_to_string(na_ret));
        }
    }

    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    const struct na_cb_info_recv_unexpected *na_cb_info_recv_unexpected =
        &callback_info->info.recv_unexpected;
#ifndef HG_HAS_POST_LIMIT
    hg_bool_t pending_empty = HG_FALSE;
    hg_bool_t use_sm = HG_FALSE;
#endif
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* Remove handle from pending list */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    HG_LIST_REMOVE(hg_core_handle, pending);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED) {
        hg_core_handle->ret = HG_CANCELED;
        /* Only decrement refcount and exit */
        hg_core_destroy(hg_core_handle);
        goto done;
    } else
        HG_CHECK_ERROR_NORET(callback_info->ret != NA_SUCCESS, done,
            "Error in NA callback (s)", NA_Error_to_string(callback_info->ret));

    /* Reset ret value */
    hg_core_handle->ret = HG_SUCCESS;

    /* Fill unexpected info */
    hg_core_handle->core_handle.info.addr->na_addr =
        na_cb_info_recv_unexpected->source;
    hg_core_handle->tag = na_cb_info_recv_unexpected->tag;
    HG_CHECK_ERROR_NORET(na_cb_info_recv_unexpected->actual_buf_size >
                             hg_core_handle->core_handle.in_buf_size,
        done, "Actual transfer size is too large for unexpected recv");
    hg_core_handle->in_buf_used = na_cb_info_recv_unexpected->actual_buf_size;

#ifndef HG_HAS_POST_LIMIT
    /* Check if we need more handles */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);

#    ifdef HG_HAS_SM_ROUTING
    if (hg_core_handle->na_class ==
        hg_core_handle->core_handle.info.core_class->na_sm_class) {
        pending_empty = HG_LIST_IS_EMPTY(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->sm_pending_list);
        use_sm = HG_TRUE;
    } else
#    endif
        pending_empty = HG_LIST_IS_EMPTY(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list);

    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);

    /* If pending list is empty, post more handles */
    if (pending_empty) {
        ret = hg_core_context_post(HG_CORE_HANDLE_CONTEXT(hg_core_handle),
            HG_CORE_PENDING_INCR, hg_core_handle->repost, use_sm);
        HG_CHECK_HG_ERROR(done, ret, "Could not post additional handles");
    }
#endif

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_PROCESS;

    /* Process input information */
    ret = hg_core_process_input(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not process input");

    /* Complete operation */
    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process_input(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed)
{
    hg_return_t ret = HG_SUCCESS;

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    hg_core_stat_incr(&hg_core_rpc_count_g);
#endif

    /* Get and verify input header */
    ret = hg_core_proc_header_request(
        &hg_core_handle->core_handle, &hg_core_handle->in_header, HG_DECODE);
    HG_CHECK_HG_ERROR(done, ret, "Could not get request header");

    /* Get operation ID from header */
    hg_core_handle->core_handle.info.id =
        hg_core_handle->in_header.msg.request.id;
    hg_core_handle->cookie = hg_core_handle->in_header.msg.request.cookie;
    /* TODO assign target ID from cookie directly for now */
    hg_core_handle->core_handle.info.context_id = hg_core_handle->cookie;

    /* Parse flags */
    hg_core_handle->no_response =
        hg_core_handle->in_header.msg.request.flags & HG_CORE_NO_RESPONSE;
#ifdef HG_HAS_SELF_FORWARD
    hg_core_handle->respond =
        hg_core_handle->in_header.msg.request.flags & HG_CORE_SELF_FORWARD
            ? hg_core_respond_self
            : hg_core_respond_na;
    hg_core_handle->no_respond =
        hg_core_handle->in_header.msg.request.flags & HG_CORE_SELF_FORWARD
            ? hg_core_no_respond_self
            : hg_core_no_respond_na;
#else
    hg_core_handle->respond = hg_core_respond_na;
    hg_core_handle->no_respond = hg_core_no_respond_na;
#endif

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->in_header.msg.request.flags & HG_CORE_MORE_DATA) {
        HG_CHECK_ERROR(!HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_acquire,
            done, ret, HG_OPNOTSUPPORTED,
            "No callback defined for acquiring more data");
#ifdef HG_HAS_COLLECT_STATS
        /* Increment counter */
        hg_core_stat_incr(&hg_core_rpc_extra_count_g);
#endif
        ret = HG_CORE_HANDLE_CLASS(hg_core_handle)
                  ->more_data_acquire((hg_core_handle_t) hg_core_handle,
                      HG_INPUT, hg_core_complete);
        HG_CHECK_HG_ERROR(
            done, ret, "Error in HG core handle more data acquire callback");
        *completed = HG_FALSE;
    } else
        *completed = HG_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_send_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED)
        hg_core_handle->ret = HG_CANCELED;
    else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_WARNING("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));
        hg_core_handle->ret = HG_NA_ERROR;
    }

    /* Complete operation */
    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED) {
        /* Do not overwrite ret value if other callback has set error */
        if (hg_core_handle->ret == HG_SUCCESS)
            hg_core_handle->ret = HG_CANCELED;

        /* Do not add handle to completion queue if it was not posted */
        if (hg_atomic_get32(&hg_core_handle->posted))
            goto complete;
        else {
            /* Cancelation has been processed */
            hg_atomic_set32(&hg_core_handle->canceling, HG_FALSE);
            goto done;
        }
    } else
        HG_CHECK_ERROR_NORET(callback_info->ret != NA_SUCCESS, done,
            "Error in NA callback (s)", NA_Error_to_string(callback_info->ret));

    /* Process output information */
    ret = hg_core_process_output(hg_core_handle, &completed, hg_core_send_ack);
    HG_CHECK_HG_ERROR(done, ret, "Could not process output");

complete:
    /* Complete operation */
    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    /* Only decrement refcount and exit */
    hg_core_destroy(hg_core_handle);
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process_output(struct hg_core_private_handle *hg_core_handle,
    hg_bool_t *completed, hg_return_t (*done_callback)(hg_core_handle_t))
{
    hg_return_t ret = HG_SUCCESS;

    /* Get and verify output header */
    ret = hg_core_proc_header_response(
        &hg_core_handle->core_handle, &hg_core_handle->out_header, HG_DECODE);
    HG_CHECK_HG_ERROR(done, ret, "Could not decode header");

    /* Get return code from header */
    hg_core_handle->ret =
        (hg_return_t) hg_core_handle->out_header.msg.response.ret_code;

    /* Parse flags */

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->out_header.msg.response.flags & HG_CORE_MORE_DATA) {
        HG_CHECK_ERROR(!HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_acquire,
            done, ret, HG_OPNOTSUPPORTED,
            "No callback defined for acquiring more data");

        ret = HG_CORE_HANDLE_CLASS(hg_core_handle)
                  ->more_data_acquire((hg_core_handle_t) hg_core_handle,
                      HG_OUTPUT, done_callback);
        HG_CHECK_HG_ERROR(
            done, ret, "Error in HG core handle more data acquire callback");
        *completed = HG_FALSE;
    } else
        *completed = HG_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_send_ack(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Increment number of expected NA operations */
    hg_core_handle->na_op_count++;

    /* Allocate buffer for ack */
    hg_core_handle->ack_buf = NA_Msg_buf_alloc(hg_core_handle->na_class,
        sizeof(hg_uint8_t), &hg_core_handle->ack_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->ack_buf == NULL, error, ret, HG_NA_ERROR,
        "Could not allocate buffer for ack");

    na_ret = NA_Msg_init_expected(
        hg_core_handle->na_class, hg_core_handle->ack_buf, sizeof(hg_uint8_t));
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize ack buffer (%s)", NA_Error_to_string(na_ret));

    /* Post expected send (ack) */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_ack_cb, hg_core_handle,
        hg_core_handle->ack_buf, sizeof(hg_uint8_t),
        hg_core_handle->ack_buf_plugin_data,
        hg_core_handle->core_handle.info.addr->na_addr,
        hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
        &hg_core_handle->na_ack_op_id);
    /* Expected sends should always succeed after retry */
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post send for ack buffer (%s)", NA_Error_to_string(na_ret));

    return ret;

error:
    if (hg_core_handle->ack_buf) {
        na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
            hg_core_handle->ack_buf, hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
            "Could not free ack buffer (%s)", NA_Error_to_string(na_ret));
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_send_ack_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED)
        hg_core_handle->ret = HG_CANCELED;
    else
        HG_CHECK_ERROR_NORET(callback_info->ret != NA_SUCCESS, done,
            "Error in NA callback (s)", NA_Error_to_string(callback_info->ret));

    /* Complete operation */
    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_recv_ack_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED)
        hg_core_handle->ret = HG_CANCELED;
    else
        HG_CHECK_ERROR_NORET(callback_info->ret != NA_SUCCESS, done,
            "Error in NA callback (s)", NA_Error_to_string(callback_info->ret));

    /* Complete operation */
    ret = hg_core_complete_na(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

done:
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_self_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->info.respond.handle;
    hg_return_t ret;
    hg_bool_t completed = HG_TRUE;

    /* First execute response callback */
    if (hg_core_handle->response_callback) {
        struct hg_core_cb_info hg_core_cb_info;

        hg_core_cb_info.arg = hg_core_handle->response_arg;
        hg_core_cb_info.ret = HG_SUCCESS; /* TODO report failure */
        hg_core_cb_info.type = HG_CB_RESPOND;
        hg_core_cb_info.info.respond.handle = (hg_core_handle_t) hg_core_handle;

        hg_core_handle->response_callback(&hg_core_cb_info);
    }

    /* Assign forward callback back to handle */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Increment refcount and push handle back to completion queue */
    hg_atomic_incr32(&hg_core_handle->ref_count);

    /* Process output */
    ret = hg_core_process_output(hg_core_handle, &completed, hg_core_complete);
    HG_CHECK_HG_ERROR(done, ret, "Could not process output");

    /* Mark as completed */
    if (completed) {
        ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process_self(struct hg_core_private_handle *hg_core_handle)
{
    hg_bool_t completed = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_PROCESS;

    /* Process input */
    ret = hg_core_process_input(hg_core_handle, &completed);
    HG_CHECK_HG_ERROR(done, ret, "Could not process input");

    /* Mark as completed */
    if (completed) {
        ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");
    }

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process(struct hg_core_private_handle *hg_core_handle)
{
    struct hg_core_rpc_info *hg_core_rpc_info;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve exe function from function map */
    hg_thread_spin_lock(&HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
        HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map,
        (hg_hash_table_key_t) &hg_core_handle->core_handle.info.id);
    hg_thread_spin_unlock(&HG_CORE_HANDLE_CLASS(hg_core_handle)->func_map_lock);
    if (!hg_core_rpc_info) {
        HG_LOG_WARNING("Could not find RPC ID in function map");
        ret = HG_NOENTRY;
        goto done;
    }

    HG_CHECK_ERROR(hg_core_rpc_info->rpc_cb == NULL, done, ret, HG_INVALID_ARG,
        "No RPC callback registered");

    /* Cache RPC info */
    hg_core_handle->core_handle.rpc_info = hg_core_rpc_info;

    /* Increment ref count here so that a call to HG_Destroy in user's RPC
     * callback does not free the handle but only schedules its completion */
    hg_atomic_incr32(&hg_core_handle->ref_count);

    /* Execute RPC callback */
    ret = hg_core_rpc_info->rpc_cb((hg_core_handle_t) hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Error while executing RPC callback");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_complete_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed)
{
    hg_return_t ret = HG_SUCCESS;

    /* Add handle to completion queue when expected operations have completed */
    if (hg_atomic_incr32(&hg_core_handle->na_op_completed_count) ==
            (hg_util_int32_t) hg_core_handle->na_op_count &&
        *completed) {
        /* Handle is no longer posted */
        hg_atomic_set32(&hg_core_handle->posted, HG_FALSE);

        /* Mark as completed */
        ret = hg_core_complete((hg_core_handle_t) hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not complete operation");

        /* Increment number of entries added to completion queue */
        *completed = HG_TRUE;
    } else
        *completed = HG_FALSE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_complete(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    struct hg_core_context *context = hg_core_handle->core_handle.info.context;
    struct hg_completion_entry *hg_completion_entry =
        &hg_core_handle->hg_completion_entry;
    hg_return_t ret = HG_SUCCESS;

    hg_completion_entry->op_type = HG_RPC;
    hg_completion_entry->op_id.hg_core_handle = handle;

    ret = hg_core_completion_add(
        context, hg_completion_entry, hg_core_handle->is_self);
    HG_CHECK_HG_ERROR(
        done, ret, "Could not add HG completion entry to completion queue");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_completion_add(struct hg_core_context *context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    hg_return_t ret = HG_SUCCESS;

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    if (hg_completion_entry->op_type == HG_BULK)
        hg_core_stat_incr(&hg_core_bulk_count_g);
#endif

    if (hg_atomic_queue_push(private_context->completion_queue,
            hg_completion_entry) != HG_UTIL_SUCCESS) {
        /* Queue is full */
        hg_thread_mutex_lock(&private_context->completion_queue_mutex);
        HG_QUEUE_PUSH_TAIL(
            &private_context->backfill_queue, hg_completion_entry, entry);
        hg_atomic_incr32(&private_context->backfill_queue_count);
        hg_thread_mutex_unlock(&private_context->completion_queue_mutex);
    }

    if (hg_atomic_get32(&private_context->trigger_waiting)) {
        hg_thread_mutex_lock(&private_context->completion_queue_mutex);
        /* Callback is pushed to the completion queue when something completes
         * so wake up anyone waiting in the trigger */
        hg_thread_cond_signal(&private_context->completion_queue_cond);
        hg_thread_mutex_unlock(&private_context->completion_queue_mutex);
    }

#ifdef HG_HAS_SELF_FORWARD
    if (!(HG_CORE_CONTEXT_CLASS(private_context)->progress_mode &
            NA_NO_BLOCK) &&
        self_notify && (private_context->completion_queue_notify > 0)) {
        hg_thread_mutex_lock(&private_context->completion_queue_notify_mutex);
        /* Do not bother notifying if it's not needed as any event call will
         * increase latency */
        if (hg_atomic_get32(&private_context->completion_queue_must_notify)) {
            int rc = hg_event_set(private_context->completion_queue_notify);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_FAULT,
                "Could not signal completion queue");
        }
        hg_thread_mutex_unlock(&private_context->completion_queue_notify_mutex);
    }
#else
    (void) self_notify;
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_post(struct hg_core_private_context *context,
    unsigned int request_count, hg_bool_t repost, hg_bool_t use_sm)
{
    unsigned int nentry = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Create a bunch of handles and post unexpected receives */
    for (nentry = 0; nentry < request_count; nentry++) {
        struct hg_core_private_handle *hg_core_handle = NULL;
        struct hg_core_private_addr *hg_core_addr = NULL;

        /* Create a new handle */
        // TODO
        hg_core_handle = hg_core_create(context, use_sm);
        HG_CHECK_ERROR(hg_core_handle == NULL, error, ret, HG_NOMEM,
            "Could not create HG core handle");

        /* Execute class callback on handle, this allows upper layers to
         * allocate private data on handle creation */
        if (context->handle_create) {
            ret = context->handle_create(
                (hg_core_handle_t) hg_core_handle, context->handle_create_arg);
            HG_CHECK_HG_ERROR(
                error, ret, "Error in HG core handle create callback");
        }

        /* Create internal addresses */
        // TODO
        hg_core_addr = hg_core_addr_create(
            HG_CORE_CONTEXT_CLASS(context), hg_core_handle->na_class);
        HG_CHECK_ERROR(hg_core_addr == NULL, error, ret, HG_NOMEM,
            "Could not create HG addr");

        /* To safely repost handle and prevent externally referenced address */
        hg_core_addr->is_mine = HG_TRUE;
        hg_core_handle->core_handle.info.addr = (hg_core_addr_t) hg_core_addr;

        /* Repost handle on completion if told so */
        hg_core_handle->repost = repost;

        ret = hg_core_post(hg_core_handle);
        HG_CHECK_HG_ERROR(error, ret, "Cannot post handle");
    }

    return ret;

error:
    /* TODO */
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_post(struct hg_core_private_handle *hg_core_handle)
{
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Handle is now in use */
    hg_atomic_set32(&hg_core_handle->in_use, HG_TRUE);

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_handle->na_class ==
        hg_core_handle->core_handle.info.core_class->na_sm_class) {
        hg_thread_spin_lock(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
        HG_LIST_INSERT_HEAD(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->sm_pending_list,
            hg_core_handle, pending);
        hg_thread_spin_unlock(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    } else {
#endif
        hg_thread_spin_lock(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
        HG_LIST_INSERT_HEAD(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list,
            hg_core_handle, pending);
        hg_thread_spin_unlock(
            &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
#ifdef HG_HAS_SM_ROUTING
    }
#endif

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_recv_input_cb, hg_core_handle,
        hg_core_handle->core_handle.in_buf,
        hg_core_handle->core_handle.in_buf_size,
        hg_core_handle->in_buf_plugin_data, &hg_core_handle->na_recv_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post unexpected recv for input buffer (%s)",
        NA_Error_to_string(na_ret));

    return ret;

error:
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    HG_LIST_REMOVE(hg_core_handle, pending);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_reset_post(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_atomic_decr32(&hg_core_handle->ref_count))
        goto done;

    /* Reset the handle */
    hg_core_reset(hg_core_handle, HG_TRUE);

    /* Also reset additional handle parameters */
    hg_atomic_set32(&hg_core_handle->ref_count, 1);
    hg_core_handle->core_handle.rpc_info = NULL;

    /* Safe to repost */
    ret = hg_core_post(hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Cannot post handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_na(
    na_class_t *na_class, na_context_t *na_context, unsigned int timeout)
{
    double remaining =
        timeout / 1000.0; /* Convert timeout in ms into seconds */
    unsigned int completed_count = 0;
    hg_return_t ret = HG_TIMEOUT;

    for (;;) {
        unsigned int actual_count = 0;
        unsigned int progress_timeout;
        na_return_t na_ret;
        hg_time_t t1, t2;

        /* Trigger everything we can from NA, if something completed it will
         * be moved to the HG context completion queue */
        do {
            int cb_ret[HG_CORE_MAX_TRIGGER_COUNT] = {0};
            unsigned int i;

            na_ret = NA_Trigger(na_context, 0, HG_CORE_MAX_TRIGGER_COUNT,
                cb_ret, &actual_count);

            /* Return value of callback is completion count */
            for (i = 0; i < actual_count; i++)
                completed_count += (unsigned int) cb_ret[i];
        } while ((na_ret == NA_SUCCESS) && actual_count);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
            (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
            NA_Error_to_string(na_ret));

        /* Progressed */
        if (completed_count) {
            ret = HG_SUCCESS;
            break;
        }

        if (remaining < 0)
            break;

        if (timeout)
            hg_time_get_current_ms(&t1);

        /* Make sure that it is safe to block */
        if (timeout && NA_Poll_try_wait(na_class, na_context))
            progress_timeout = (unsigned int) (remaining * 1000.0);
        else
            progress_timeout = 0;

        /* Otherwise try to make progress on NA */
        na_ret = NA_Progress(na_class, na_context, progress_timeout);
        if (na_ret == NA_TIMEOUT && (remaining <= 0))
            break;
        else
            HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done,
                ret, (hg_return_t) na_ret, "Could not make progress on NA (%s)",
                NA_Error_to_string(na_ret));

        if (timeout) {
            hg_time_get_current_ms(&t2);
            remaining -= hg_time_diff(t2, t1);
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static HG_INLINE hg_return_t
hg_core_progress_loopback_notify(struct hg_core_private_context *context)
{
    hg_util_bool_t progressed = HG_UTIL_FALSE;
    hg_return_t ret = HG_AGAIN;
    int rc;

    rc = hg_event_get(context->completion_queue_notify, &progressed);
    if (progressed)
        ret = HG_SUCCESS;
    else
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_PROTOCOL_ERROR,
            "Could not get completion notification");

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_bool_t
hg_core_poll_try_wait(struct hg_core_private_context *context)
{
    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(context->completion_queue) ||
        (hg_atomic_get32(&context->backfill_queue_count) > 0))
        return HG_FALSE;

#ifdef HG_HAS_SM_ROUTING
    if (context->core_context.core_class->na_sm_class &&
        !NA_Poll_try_wait(context->core_context.core_class->na_sm_class,
            context->core_context.na_sm_context))
        return HG_FALSE;
#endif

    if (!NA_Poll_try_wait(context->core_context.core_class->na_class,
            context->core_context.na_context))
        return HG_FALSE;

    return HG_TRUE;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress(struct hg_core_private_context *context, unsigned int timeout)
{
    double remaining =
        timeout / 1000.0; /* Convert timeout in ms into seconds */
    hg_return_t ret = HG_TIMEOUT;

    do {
        hg_time_t t1, t2;
        hg_bool_t safe_wait = HG_FALSE;

        if (timeout)
            hg_time_get_current_ms(&t1);

        if (!(HG_CORE_CONTEXT_CLASS(context)->progress_mode & NA_NO_BLOCK) &&
            timeout) {
            hg_thread_mutex_lock(&context->completion_queue_notify_mutex);

            if (hg_core_poll_try_wait(context)) {
                safe_wait = HG_TRUE;
                hg_atomic_set32(&context->completion_queue_must_notify, 1);
            }

            hg_thread_mutex_unlock(&context->completion_queue_notify_mutex);
        }

        /* Only enter blocking wait if it is safe to */
        if (context->poll_set && safe_wait) {
            unsigned int i, nevents;
            int rc;

            rc = hg_poll_wait(context->poll_set,
                (unsigned int) (remaining * 1000.0), HG_CORE_MAX_EVENTS,
                context->poll_events, &nevents);
            hg_atomic_set32(&context->completion_queue_must_notify, 0);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_PROTOCOL_ERROR,
                "hg_poll_wait() failed");

            for (i = 0; i < nevents; i++) {
                switch (context->poll_events[i].data.u32) {
#ifdef HG_HAS_SELF_FORWARD
                    case HG_CORE_POLL_LOOPBACK:
                        HG_LOG_DEBUG("HG_CORE_POLL_LOOPBACK event");
                        ret = hg_core_progress_loopback_notify(context);
                        HG_CHECK_HG_ERROR(done, ret,
                            "hg_core_progress_loopback_notify() failed");
                        break;
#endif
#ifdef HG_HAS_SM_ROUTING
                    case HG_CORE_POLL_SM:
                        HG_LOG_DEBUG("HG_CORE_POLL_SM event");
                        ret = hg_core_progress_na(HG_CORE_CONTEXT_CLASS(context)
                                                      ->core_class.na_sm_class,
                            context->core_context.na_sm_context, 0);
                        if (ret != HG_TIMEOUT)
                            HG_CHECK_HG_ERROR(
                                done, ret, "hg_core_progress_na() failed");
                        break;
#endif
                    case HG_CORE_POLL_NA:
                        HG_LOG_DEBUG("HG_CORE_POLL_NA event");
                        ret = hg_core_progress_na(
                            HG_CORE_CONTEXT_CLASS(context)->core_class.na_class,
                            context->core_context.na_context, 0);
                        if (ret != HG_TIMEOUT)
                            HG_CHECK_HG_ERROR(
                                done, ret, "hg_core_progress_na() failed");
                        break;
                    default:
                        HG_GOTO_ERROR(done, ret, HG_INVALID_ARG,
                            "Invalid type of poll event (%d)",
                            (int) context->poll_events[i].data.u32);
                }
            }

            /* We progressed, will return success */
            if (nevents > 0) {
                ret = HG_SUCCESS;
                goto done;
            }
        } else {
            hg_bool_t progressed = HG_FALSE;
            unsigned int progress_timeout;
#ifdef HG_HAS_SM_ROUTING
            if (context->core_context.na_sm_context) {
                progress_timeout = 0;

                ret = hg_core_progress_na(
                    HG_CORE_CONTEXT_CLASS(context)->core_class.na_sm_class,
                    context->core_context.na_sm_context, progress_timeout);
                if (ret == HG_SUCCESS)
                    progressed |= HG_TRUE;
                else if (ret != HG_TIMEOUT)
                    HG_CHECK_HG_ERROR(
                        done, ret, "hg_core_progress_na() failed");
            } else {
#else
            progress_timeout =
                safe_wait ? (unsigned int) (remaining * 1000.0) : 0;
#endif
#ifdef HG_HAS_SM_ROUTING
            }
#endif

            ret = hg_core_progress_na(
                HG_CORE_CONTEXT_CLASS(context)->core_class.na_class,
                context->core_context.na_context, progress_timeout);
            if (ret == HG_SUCCESS)
                progressed |= HG_TRUE;
            else if (ret != HG_TIMEOUT)
                HG_CHECK_HG_ERROR(done, ret, "hg_core_progress_na() failed");

            /* We progressed, return success */
            if (progressed) {
                ret = HG_SUCCESS;
                break;
            }
        }

        /* There is stuff in the queues to process */
        if (!hg_atomic_queue_is_empty(context->completion_queue) ||
            (hg_atomic_get32(&context->backfill_queue_count) > 0)) {
            ret = HG_SUCCESS;
            break;
        }

        if (timeout) {
            hg_time_get_current_ms(&t2);
            remaining -= hg_time_diff(t2, t1);
        }
    } while ((int) (remaining * 1000.0) > 0);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger(struct hg_core_private_context *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    double remaining =
        timeout / 1000.0; /* Convert timeout in ms into seconds */
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    while (count < max_count) {
        struct hg_completion_entry *hg_completion_entry = NULL;

        hg_completion_entry = hg_atomic_queue_pop_mc(context->completion_queue);
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
                if ((int) (remaining * 1000.0) <= 0) {
                    ret = HG_TIMEOUT;
                    break;
                }

                hg_time_get_current_ms(&t1);

                hg_atomic_incr32(&context->trigger_waiting);
                hg_thread_mutex_lock(&context->completion_queue_mutex);
                /* Otherwise wait timeout ms */
                while (hg_atomic_queue_is_empty(context->completion_queue) &&
                       !hg_atomic_get32(&context->backfill_queue_count)) {
                    if (hg_thread_cond_timedwait(
                            &context->completion_queue_cond,
                            &context->completion_queue_mutex,
                            timeout) != HG_UTIL_SUCCESS) {
                        /* Timeout occurred so leave */
                        ret = HG_TIMEOUT;
                        break;
                    }
                }
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                hg_atomic_decr32(&context->trigger_waiting);
                if (ret == HG_TIMEOUT)
                    break;

                hg_time_get_current_ms(&t2);
                remaining -= hg_time_diff(t2, t1);
                continue; /* Give another change to grab it */
            }
        }

        /* Completion queue should not be empty now */
        HG_CHECK_ERROR(hg_completion_entry == NULL, done, ret, HG_FAULT,
            "NULL completion entry");

        /* Trigger entry */
        switch (hg_completion_entry->op_type) {
            case HG_ADDR:
                ret = hg_core_trigger_lookup_entry(
                    hg_completion_entry->op_id.hg_core_op_id);
                HG_CHECK_HG_ERROR(
                    done, ret, "Could not trigger addr completion entry");
                break;
            case HG_RPC:
                ret = hg_core_trigger_entry(
                    (struct hg_core_private_handle *)
                        hg_completion_entry->op_id.hg_core_handle);
                HG_CHECK_HG_ERROR(
                    done, ret, "Could not trigger RPC completion entry");
                break;
            case HG_BULK:
                ret = hg_bulk_trigger_entry(
                    hg_completion_entry->op_id.hg_bulk_op_id);
                HG_CHECK_HG_ERROR(
                    done, ret, "Could not trigger bulk completion entry");
                break;
            default:
                HG_GOTO_ERROR(done, ret, HG_INVALID_ARG,
                    "Invalid type of completion entry (%d)",
                    (int) hg_completion_entry->op_type);
        }

        count++;
    }

    if (actual_count)
        *actual_count = count;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_lookup_entry(struct hg_core_op_id *hg_core_op_id)
{
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_core_op_id->callback) {
        struct hg_core_cb_info hg_core_cb_info;

        hg_core_cb_info.arg = hg_core_op_id->arg;
        hg_core_cb_info.ret = HG_SUCCESS;
        hg_core_cb_info.type = HG_CB_LOOKUP;
        hg_core_cb_info.info.lookup.addr =
            (hg_core_addr_t) hg_core_op_id->info.lookup.hg_core_addr;

        hg_core_op_id->callback(&hg_core_cb_info);
    }

    free(hg_core_op_id);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_entry(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_core_handle->op_type == HG_CORE_PROCESS) {
        /* Take another reference to make sure the handle does not get freed */
        hg_atomic_incr32(&hg_core_handle->ref_count);

        /* Run RPC callback */
        ret = hg_core_process(hg_core_handle);
        if (ret != HG_SUCCESS && !hg_core_handle->no_response) {
            hg_size_t header_size =
                hg_core_header_response_get_size() +
                hg_core_handle->core_handle.na_out_header_offset;

            /* Respond in case of error */
            hg_core_handle->ret = ret;
            ret = HG_Core_respond(
                (hg_core_handle_t) hg_core_handle, NULL, NULL, 0, header_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not respond");
        }

        /* No response callback */
        if (hg_core_handle->no_response) {
            ret = hg_core_handle->no_respond(hg_core_handle);
            HG_CHECK_HG_ERROR(done, ret, "Could not complete handle");
        }
    } else {
        hg_core_cb_t hg_cb = NULL;
        struct hg_core_cb_info hg_core_cb_info;

        /* Handle is no longer in use (safe to reset) */
        hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);

        hg_core_cb_info.ret = hg_core_handle->ret;
        switch (hg_core_handle->op_type) {
#ifdef HG_HAS_SELF_FORWARD
            case HG_CORE_FORWARD_SELF:
                HG_FALLTHROUGH();
#endif
            case HG_CORE_FORWARD:
                hg_cb = hg_core_handle->request_callback;
                hg_core_cb_info.arg = hg_core_handle->request_arg;
                hg_core_cb_info.type = HG_CB_FORWARD;
                hg_core_cb_info.info.forward.handle =
                    (hg_core_handle_t) hg_core_handle;
                break;
            case HG_CORE_RESPOND:
                hg_cb = hg_core_handle->response_callback;
                hg_core_cb_info.arg = hg_core_handle->response_arg;
                hg_core_cb_info.type = HG_CB_RESPOND;
                hg_core_cb_info.info.respond.handle =
                    (hg_core_handle_t) hg_core_handle;
                break;
#ifdef HG_HAS_SELF_FORWARD
            case HG_CORE_RESPOND_SELF:
                hg_cb = hg_core_self_cb;
                hg_core_cb_info.arg = hg_core_handle->response_arg;
                hg_core_cb_info.type = HG_CB_RESPOND;
                hg_core_cb_info.info.respond.handle =
                    (hg_core_handle_t) hg_core_handle;
                break;
#endif
            case HG_CORE_NO_RESPOND:
                /* Nothing */
                break;
            case HG_CORE_PROCESS:
            default:
                HG_GOTO_ERROR(done, ret, HG_OPNOTSUPPORTED,
                    "Invalid core operation type");
        }

        /* Execute user callback */
        if (hg_cb)
            hg_cb(&hg_core_cb_info);
    }

    /* Repost handle if we were listening, otherwise destroy it */
    if (hg_core_handle->repost &&
        !HG_CORE_HANDLE_CONTEXT(hg_core_handle)->finalizing) {
        /* Repost handle */
        ret = hg_core_reset_post(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Cannot repost handle");
    } else
        hg_core_destroy(hg_core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_cancel(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_core_handle->is_self, done, ret, HG_OPNOTSUPPORTED,
        "Local cancellation is not supported");

    /* Cancel all NA operations issued */
    if (hg_core_handle->na_recv_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_handle->na_recv_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not cancel recv op id (%s)", NA_Error_to_string(na_ret));
    }

    if (hg_core_handle->na_send_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_handle->na_send_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not cancel send op id (%s)", NA_Error_to_string(na_ret));
    }

    if (hg_core_handle->na_ack_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_handle->na_ack_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not cancel ack op id (%s)", NA_Error_to_string(na_ret));
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_core_class_t *
HG_Core_init(const char *na_info_string, hg_bool_t na_listen)
{
    return HG_Core_init_opt(na_info_string, na_listen, NULL);
}

/*---------------------------------------------------------------------------*/
hg_core_class_t *
HG_Core_init_opt(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_core_private_class *hg_core_class = NULL;

    hg_core_class = hg_core_init(na_info_string, na_listen, hg_init_info);
    HG_CHECK_ERROR_NORET(
        hg_core_class == NULL, done, "Cannot initialize HG core layer");

done:
    return (hg_core_class_t *) hg_core_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_finalize(hg_core_class_t *hg_core_class)
{
    hg_return_t ret;

    ret = hg_core_finalize((struct hg_core_private_class *) hg_core_class);
    HG_CHECK_HG_ERROR(done, ret, "Cannot finalize HG core layer");

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
hg_return_t
HG_Core_set_more_data_callback(struct hg_core_class *hg_core_class,
    hg_return_t (*more_data_acquire_callback)(hg_core_handle_t, hg_op_t,
        hg_return_t (*done_callback)(hg_core_handle_t)),
    void (*more_data_release_callback)(hg_core_handle_t))
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");

    private_class->more_data_acquire = more_data_acquire_callback;
    private_class->more_data_release = more_data_release_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_core_context_t *
HG_Core_context_create(hg_core_class_t *hg_core_class)
{
    return HG_Core_context_create_id(hg_core_class, 0);
}

/*---------------------------------------------------------------------------*/
hg_core_context_t *
HG_Core_context_create_id(hg_core_class_t *hg_core_class, hg_uint8_t id)
{
    struct hg_core_private_context *context = NULL;
    int na_poll_fd;

    HG_CHECK_ERROR_NORET(hg_core_class == NULL, error, "NULL HG core class");

    context = (struct hg_core_private_context *) malloc(
        sizeof(struct hg_core_private_context));
    HG_CHECK_ERROR_NORET(
        context == NULL, error, "Could not allocate HG context");

    memset(context, 0, sizeof(struct hg_core_private_context));
    context->core_context.core_class = hg_core_class;
    context->completion_queue =
        hg_atomic_queue_alloc(HG_CORE_ATOMIC_QUEUE_SIZE);
    HG_CHECK_ERROR_NORET(
        context->completion_queue == NULL, error, "Could not allocate queue");

    HG_QUEUE_INIT(&context->backfill_queue);
    hg_atomic_init32(&context->backfill_queue_count, 0);
    HG_LIST_INIT(&context->pending_list);
#ifdef HG_HAS_SM_ROUTING
    HG_LIST_INIT(&context->sm_pending_list);
#endif
    HG_LIST_INIT(&context->created_list);

    /* No handle created yet */
    hg_atomic_init32(&context->n_handles, 0);

    /* Notifications of completion queue events */
    hg_atomic_init32(&context->completion_queue_must_notify, 0);
    hg_thread_mutex_init(&context->completion_queue_notify_mutex);

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&context->completion_queue_mutex);
    hg_thread_cond_init(&context->completion_queue_cond);
    hg_atomic_init32(&context->trigger_waiting, 0);

    hg_thread_spin_init(&context->pending_list_lock);
    hg_thread_spin_init(&context->created_list_lock);

    context->core_context.na_context =
        NA_Context_create_id(hg_core_class->na_class, id);
    HG_CHECK_ERROR_NORET(context->core_context.na_context == NULL, error,
        "Could not create NA context");

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_class->na_sm_class) {
        context->core_context.na_sm_context =
            NA_Context_create(hg_core_class->na_sm_class);
        HG_CHECK_ERROR_NORET(context->core_context.na_sm_context == NULL, error,
            "Could not create NA SM context");
    }
#endif

    /* If NA plugin exposes fd, we will use poll set and use appropriate
     * progress function */
    na_poll_fd = NA_Poll_get_fd(
        hg_core_class->na_class, context->core_context.na_context);

    if (!(HG_CORE_CONTEXT_CLASS(context)->progress_mode & NA_NO_BLOCK) &&
        (na_poll_fd > 0)) {
        struct hg_poll_event event = {.events = HG_POLLIN, .data.u64 = 0};
        int rc;

        /* Create poll set */
        context->poll_set = hg_poll_create();
        HG_CHECK_ERROR_NORET(
            context->poll_set == NULL, error, "Could not create poll set");

        event.data.u32 = (hg_util_uint32_t) HG_CORE_POLL_NA;
        rc = hg_poll_add(context->poll_set, na_poll_fd, &event);
        HG_CHECK_ERROR_NORET(
            rc != HG_UTIL_SUCCESS, error, "hg_poll_add() failed");

#ifdef HG_HAS_SM_ROUTING
        if (context->core_context.na_sm_context) {
            na_poll_fd = NA_Poll_get_fd(hg_core_class->na_sm_class,
                context->core_context.na_sm_context);
            HG_CHECK_ERROR_NORET(
                na_poll_fd < 0, error, "Could not get NA SM poll fd");

            event.data.u32 = (hg_util_uint32_t) HG_CORE_POLL_SM;
            rc = hg_poll_add(context->poll_set, na_poll_fd, &event);
            HG_CHECK_ERROR_NORET(
                rc != HG_UTIL_SUCCESS, error, "hg_poll_add() failed");
        }
#endif

#ifdef HG_HAS_SELF_FORWARD
        /* Create event for completion queue notification */
        context->completion_queue_notify = hg_event_create();
        HG_CHECK_ERROR_NORET(context->completion_queue_notify < 0, error,
            "Could not create event");

        /* Add event to context poll set */
        event.data.u32 = (hg_util_uint32_t) HG_CORE_POLL_LOOPBACK;
        rc = hg_poll_add(
            context->poll_set, context->completion_queue_notify, &event);
        HG_CHECK_ERROR_NORET(
            rc != HG_UTIL_SUCCESS, error, "hg_poll_add() failed");
#endif
    }

    /* Assign context ID */
    context->core_context.id = id;

    /* Increment context count of parent class */
    hg_atomic_incr32(&HG_CORE_CONTEXT_CLASS(context)->n_contexts);

    return (hg_core_context_t *) context;

error:
    HG_Core_context_destroy((hg_core_context_t *) context);
    return NULL;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_destroy(hg_core_context_t *context)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    unsigned int actual_count;
    hg_util_int32_t n_handles;
    hg_bool_t empty;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;
    int rc;

    if (!context)
        goto done;

    /* Prevent repost of handles */
    private_context->finalizing = HG_TRUE;

    /* Check pending list and cancel posted handles */
    ret = hg_core_pending_list_cancel(private_context);
    HG_CHECK_HG_ERROR(done, ret, "Cannot cancel list of pending entries");

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(context->na_context, 0, 1, NULL, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
        (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
        NA_Error_to_string(na_ret));

#ifdef HG_HAS_SM_ROUTING
    if (context->na_sm_context) {
        do {
            na_ret =
                NA_Trigger(context->na_sm_context, 0, 1, NULL, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
            (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
            NA_Error_to_string(na_ret));
    }
#endif

    /* Check that operations have completed */
    ret = hg_core_context_lists_wait(private_context);
    HG_CHECK_HG_ERROR(done, ret, "Could not wait on HG core handle list");

    /* Number of handles for that context should be 0 */
    n_handles = hg_atomic_get32(&private_context->n_handles);
    if (n_handles != 0) {
        struct hg_core_private_handle *hg_core_handle = NULL;
        HG_LOG_ERROR("HG core handles must be freed before destroying context "
                     "(%d remaining)",
            n_handles);
        hg_thread_spin_lock(&private_context->created_list_lock);
        HG_LIST_FOREACH (
            hg_core_handle, &private_context->created_list, created) {
            HG_LOG_ERROR("HG core handle at address %p was not destroyed",
                hg_core_handle);
        }
        hg_thread_spin_unlock(&private_context->created_list_lock);
        ret = HG_BUSY;
        goto done;
    }

    /* Check that completion queue is empty now */
    HG_CHECK_ERROR(!hg_atomic_queue_is_empty(private_context->completion_queue),
        done, ret, HG_BUSY, "Completion queue should be empty");
    hg_atomic_queue_free(private_context->completion_queue);

    /* Check that completion queue is empty now */
    hg_thread_mutex_lock(&private_context->completion_queue_mutex);
    empty = HG_QUEUE_IS_EMPTY(&private_context->backfill_queue);
    hg_thread_mutex_unlock(&private_context->completion_queue_mutex);
    HG_CHECK_ERROR(
        !empty, done, ret, HG_BUSY, "Completion queue should be empty");

#ifdef HG_HAS_SELF_FORWARD
    if (private_context->completion_queue_notify > 0) {
        rc = hg_poll_remove(private_context->poll_set,
            private_context->completion_queue_notify);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
            "Could not remove self processing event from poll set");

        rc = hg_event_destroy(private_context->completion_queue_notify);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
            "Could not destroy self processing event");
    }
#endif

    if (private_context->poll_set) {
        /* If NA plugin exposes fd, remove it from poll set */
        int na_poll_fd =
            NA_Poll_get_fd(context->core_class->na_class, context->na_context);
        if (na_poll_fd > 0) {
            rc = hg_poll_remove(private_context->poll_set, na_poll_fd);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
                "Could not remove NA poll descriptor from poll set");
        }
    }

#ifdef HG_HAS_SM_ROUTING
    if (context->na_sm_context && private_context->poll_set) {
        /* If NA plugin exposes fd, remove it from poll set */
        int na_poll_fd = NA_Poll_get_fd(
            context->core_class->na_sm_class, context->na_sm_context);
        if (na_poll_fd > 0) {
            rc = hg_poll_remove(private_context->poll_set, na_poll_fd);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
                "Could not remove NA poll descriptor from poll set");
        }
    }
#endif

    /* Destroy poll set */
    if (private_context->poll_set) {
        rc = hg_poll_destroy(private_context->poll_set);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_FAULT,
            "Could not destroy poll set");
    }

    /* Destroy NA context */
    if (context->na_context) {
        na_ret = NA_Context_destroy(
            context->core_class->na_class, context->na_context);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not destroy NA context (%s)", NA_Error_to_string(na_ret));
    }

#ifdef HG_HAS_SM_ROUTING
    /* Destroy NA SM context */
    if (context->na_sm_context) {
        na_ret = NA_Context_destroy(
            context->core_class->na_sm_class, context->na_sm_context);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not destroy NA SM context");
    }
#endif

    /* Free user data */
    if (context->data_free_callback)
        context->data_free_callback(context->data);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&private_context->completion_queue_notify_mutex);
    hg_thread_mutex_destroy(&private_context->completion_queue_mutex);
    hg_thread_cond_destroy(&private_context->completion_queue_cond);
    hg_thread_spin_destroy(&private_context->pending_list_lock);
    hg_thread_spin_destroy(&private_context->created_list_lock);

    /* Decrement context count of parent class */
    hg_atomic_decr32(&HG_CORE_CONTEXT_CLASS(private_context)->n_contexts);

    free(private_context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_set_handle_create_callback(hg_core_context_t *context,
    hg_return_t (*callback)(hg_core_handle_t, void *), void *arg)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");

    private_context->handle_create = callback;
    private_context->handle_create_arg = arg;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_post(
    hg_core_context_t *context, unsigned int request_count, hg_bool_t repost)
{
    hg_bool_t use_sm = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");
    HG_CHECK_ERROR(request_count == 0, done, ret, HG_INVALID_ARG,
        "Request count must be greater than 0");

#ifdef HG_HAS_SM_ROUTING
    do {
#endif
        ret = hg_core_context_post((struct hg_core_private_context *) context,
            request_count, repost, use_sm);
        HG_CHECK_HG_ERROR(done, ret, "Could not post requests on context");

#ifdef HG_HAS_SM_ROUTING
        if (context->na_sm_context)
            use_sm = !use_sm;
    } while (use_sm);
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register(
    hg_core_class_t *hg_core_class, hg_id_t id, hg_core_rpc_cb_t rpc_cb)
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    hg_id_t *func_key = NULL;
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;
    int hash_ret;

    HG_CHECK_ERROR(hg_core_class == NULL, error, ret, HG_INVALID_ARG,
        "NULL HG core class");

    /* Check if registered and set RPC CB */
    hg_thread_spin_lock(&private_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
        private_class->func_map, (hg_hash_table_key_t) &id);
    if (hg_core_rpc_info && rpc_cb)
        hg_core_rpc_info->rpc_cb = rpc_cb;
    hg_thread_spin_unlock(&private_class->func_map_lock);

    if (!hg_core_rpc_info) {
        /* Allocate the key */
        func_key = (hg_id_t *) malloc(sizeof(hg_id_t));
        HG_CHECK_ERROR(func_key == NULL, error, ret, HG_NOMEM,
            "Could not allocate ID key");
        *func_key = id;

        /* Fill info and store it into the function map */
        hg_core_rpc_info =
            (struct hg_core_rpc_info *) malloc(sizeof(struct hg_core_rpc_info));
        HG_CHECK_ERROR(hg_core_rpc_info == NULL, error, ret, HG_NOMEM,
            "Could not allocate HG info");

        hg_core_rpc_info->rpc_cb = rpc_cb;
        hg_core_rpc_info->data = NULL;
        hg_core_rpc_info->free_callback = NULL;

        hg_thread_spin_lock(&private_class->func_map_lock);
        hash_ret = hg_hash_table_insert(private_class->func_map,
            (hg_hash_table_key_t) func_key, hg_core_rpc_info);
        hg_thread_spin_unlock(&private_class->func_map_lock);
        HG_CHECK_ERROR(hash_ret == 0, error, ret, HG_INVALID_ARG,
            "Could not insert RPC ID into function map (already registered?)");
    }

    return ret;

error:
    free(func_key);
    free(hg_core_rpc_info);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_deregister(hg_core_class_t *hg_core_class, hg_id_t id)
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    hg_return_t ret = HG_SUCCESS;
    int hash_ret;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");

    hg_thread_spin_lock(&private_class->func_map_lock);
    hash_ret = hg_hash_table_remove(
        private_class->func_map, (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&private_class->func_map_lock);
    HG_CHECK_ERROR(hash_ret == 0, done, ret, HG_NOENTRY,
        "Could not deregister RPC ID from function map");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_registered(hg_core_class_t *hg_core_class, hg_id_t id, hg_bool_t *flag)
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(flag == NULL, done, ret, HG_INVALID_ARG, "NULL flag");

    hg_thread_spin_lock(&private_class->func_map_lock);
    *flag = (hg_bool_t)(hg_hash_table_lookup(private_class->func_map,
                            (hg_hash_table_key_t) &id) != HG_HASH_TABLE_NULL);
    hg_thread_spin_unlock(&private_class->func_map_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register_data(hg_core_class_t *hg_core_class, hg_id_t id, void *data,
    void (*free_callback)(void *))
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");

    hg_thread_spin_lock(&private_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
        private_class->func_map, (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&private_class->func_map_lock);
    HG_CHECK_ERROR(hg_core_rpc_info == NULL, done, ret, HG_NOENTRY,
        "Could not find RPC ID in function map");

    HG_CHECK_WARNING(
        hg_core_rpc_info->data, "Overriding data previously registered");
    hg_core_rpc_info->data = data;
    hg_core_rpc_info->free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_registered_data(hg_core_class_t *hg_core_class, hg_id_t id)
{
    struct hg_core_private_class *private_class =
        (struct hg_core_private_class *) hg_core_class;
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    void *data = NULL;

    HG_CHECK_ERROR_NORET(hg_core_class == NULL, done, "NULL HG core class");

    hg_thread_spin_lock(&private_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
        private_class->func_map, (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&private_class->func_map_lock);
    HG_CHECK_ERROR_NORET(hg_core_rpc_info == NULL, done,
        "Could not find RPC ID in function map");

    data = hg_core_rpc_info->data;

done:
    return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_create(hg_core_class_t *hg_core_class, hg_core_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(
        addr == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to address");

    *addr = (hg_core_addr_t) hg_core_addr_create(
        (struct hg_core_private_class *) hg_core_class,
        hg_core_class->na_class);
    HG_CHECK_ERROR(*addr == HG_CORE_ADDR_NULL, done, ret, HG_NOMEM,
        "Could not create address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_lookup1(hg_core_context_t *context, hg_core_cb_t callback,
    void *arg, const char *name, hg_core_op_id_t *op_id)
{
    struct hg_core_op_id *hg_core_op_id = NULL;
    struct hg_completion_entry *hg_completion_entry = NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");
    HG_CHECK_ERROR(
        callback == NULL, done, ret, HG_INVALID_ARG, "NULL callback");
    HG_CHECK_ERROR(name == NULL, done, ret, HG_INVALID_ARG, "NULL lookup");
    (void) op_id;

    /* Allocate op_id */
    hg_core_op_id =
        (struct hg_core_op_id *) malloc(sizeof(struct hg_core_op_id));
    HG_CHECK_ERROR(hg_core_op_id == NULL, error, ret, HG_NOMEM,
        "Could not allocate HG operation ID");

    hg_core_op_id->context = (struct hg_core_private_context *) context;
    hg_core_op_id->type = HG_CB_LOOKUP;
    hg_core_op_id->callback = callback;
    hg_core_op_id->arg = arg;
    hg_core_op_id->info.lookup.hg_core_addr = NULL;

    ret = hg_core_addr_lookup(
        (struct hg_core_private_class *) context->core_class, name,
        &hg_core_op_id->info.lookup.hg_core_addr);
    HG_CHECK_HG_ERROR(error, ret, "Could not lookup address");

    /* Add callback to completion queue */
    hg_completion_entry = &hg_core_op_id->hg_completion_entry;
    hg_completion_entry->op_type = HG_ADDR;
    hg_completion_entry->op_id.hg_core_op_id = hg_core_op_id;

    ret = hg_core_completion_add(context, hg_completion_entry, HG_TRUE);
    HG_CHECK_HG_ERROR(
        error, ret, "Could not add HG completion entry to completion queue");

done:
    return ret;

error:
    if (hg_core_op_id) {
        hg_core_addr_free((struct hg_core_private_class *) context->core_class,
            hg_core_op_id->info.lookup.hg_core_addr);
        free(hg_core_op_id);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_lookup2(
    hg_core_class_t *hg_core_class, const char *name, hg_core_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(name == NULL, done, ret, HG_INVALID_ARG, "NULL lookup");
    HG_CHECK_ERROR(
        addr == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to address");

    ret = hg_core_addr_lookup((struct hg_core_private_class *) hg_core_class,
        name, (struct hg_core_private_addr **) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not lookup address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_free(hg_core_class_t *hg_core_class, hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");

    ret = hg_core_addr_free((struct hg_core_private_class *) hg_core_class,
        (struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_set_remove(hg_core_class_t *hg_core_class, hg_core_addr_t addr)
{
    struct hg_core_private_addr *hg_core_addr =
        (struct hg_core_private_addr *) addr;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");

    na_ret = NA_Addr_set_remove(
        hg_core_addr->core_addr.na_class, hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not set address to be removed (%s)", NA_Error_to_string(na_ret));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_self(hg_core_class_t *hg_core_class, hg_core_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(
        addr == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to address");

    ret = hg_core_addr_self((struct hg_core_private_class *) hg_core_class,
        (struct hg_core_private_addr **) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not get self address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_dup(hg_core_class_t *hg_core_class, hg_core_addr_t addr,
    hg_core_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(
        addr == HG_CORE_ADDR_NULL, done, ret, HG_INVALID_ARG, "NULL addr");
    HG_CHECK_ERROR(new_addr == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to dup addr");

    ret = hg_core_addr_dup((struct hg_core_private_class *) hg_core_class,
        (struct hg_core_private_addr *) addr,
        (struct hg_core_private_addr **) new_addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not duplicate address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_bool_t
HG_Core_addr_cmp(
    hg_core_class_t *hg_core_class, hg_core_addr_t addr1, hg_core_addr_t addr2)
{
    hg_bool_t ret = HG_FALSE;

    HG_CHECK_ERROR_NORET(hg_core_class == NULL, done, "NULL HG core class");

    if (addr1 == HG_CORE_ADDR_NULL && addr2 == HG_CORE_ADDR_NULL)
        HG_GOTO_DONE(done, ret, HG_TRUE);

    if (addr1 == HG_CORE_ADDR_NULL || addr2 == HG_CORE_ADDR_NULL)
        HG_GOTO_DONE(done, ret, HG_FALSE);

    ret =
        NA_Addr_cmp(((struct hg_core_private_addr *) addr1)->core_addr.na_class,
            ((struct hg_core_private_addr *) addr1)->core_addr.na_addr,
            ((struct hg_core_private_addr *) addr2)->core_addr.na_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_to_string(hg_core_class_t *hg_core_class, char *buf,
    hg_size_t *buf_size, hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(buf_size == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to buffer size");

    ret = hg_core_addr_to_string((struct hg_core_private_class *) hg_core_class,
        buf, buf_size, (struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not convert address to string");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_create(hg_core_context_t *context, hg_core_addr_t addr, hg_id_t id,
    hg_core_handle_t *handle)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    struct hg_core_private_handle *hg_core_handle = NULL;
    struct hg_core_private_addr *private_addr =
        (struct hg_core_private_addr *) addr;
    hg_bool_t use_sm = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, error, ret, HG_INVALID_ARG, "NULL HG core context");
    HG_CHECK_ERROR(handle == NULL, error, ret, HG_INVALID_ARG,
        "NULL pointer to HG core handle");

#ifdef HG_HAS_SM_ROUTING
    if (private_addr &&
        (private_addr->core_addr.na_class == context->core_class->na_sm_class))
        use_sm = HG_TRUE;
#endif

    /* Create new handle */
    hg_core_handle = hg_core_create(private_context, use_sm);
    HG_CHECK_ERROR(hg_core_handle == NULL, error, ret, HG_NOMEM,
        "Could not create HG core handle");

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, private_addr, id);
    if (ret == HG_NOENTRY)
        goto error;
    HG_CHECK_HG_ERROR(error, ret, "Could not set rpc to handle");

    /* Execute class callback on handle, this allows upper layers to
     * allocate private data on handle creation */
    if (private_context->handle_create) {
        ret = private_context->handle_create((hg_core_handle_t) hg_core_handle,
            private_context->handle_create_arg);
        HG_CHECK_HG_ERROR(error, ret, "Error in HG handle create callback");
    }

    *handle = (hg_core_handle_t) hg_core_handle;

    return ret;

error:
    hg_core_destroy(hg_core_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_destroy(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (hg_core_handle == NULL)
        goto done;

    /* Repost handle if we were listening, otherwise destroy it */
    if (hg_core_handle->repost &&
        !HG_CORE_HANDLE_CONTEXT(hg_core_handle)->finalizing) {
        /* Repost handle */
        ret = hg_core_reset_post(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Cannot repost handle");
    } else
        hg_core_destroy(hg_core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_reset(hg_core_handle_t handle, hg_core_addr_t addr, hg_id_t id)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    struct hg_core_private_addr *hg_core_addr =
        (struct hg_core_private_addr *) addr;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_core_handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");

    /* Not safe to reset
     * TODO could add the ability to defer the reset operation */
    HG_CHECK_ERROR(hg_atomic_get32(&hg_core_handle->in_use), done, ret, HG_BUSY,
        "Cannot reset HG core handle, still in use, "
        "refcount: %d",
        hg_atomic_get32(&hg_core_handle->ref_count));

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr &&
        (hg_core_addr->core_addr.na_class != hg_core_handle->na_class)) {
        struct hg_core_private_context *private_context =
            (struct hg_core_private_context *)
                hg_core_handle->core_handle.info.context;
        hg_bool_t use_sm =
            (private_context->core_context.core_class->na_sm_class ==
                hg_core_addr->core_addr.na_class);
        /* In that case, we must free and re-allocate NA resources */
        hg_core_free_na(hg_core_handle);
        ret = hg_core_alloc_na(hg_core_handle, use_sm);
        HG_CHECK_HG_ERROR(done, ret, "Could not re-allocate NA resources");
    }
#endif

    /* Reset handle */
    hg_core_reset(hg_core_handle, HG_FALSE);

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, hg_core_addr, id);
    if (ret == HG_NOENTRY)
        goto done;
    HG_CHECK_HG_ERROR(done, ret, "Could not set rpc to handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_ref_incr(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_core_handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");
    hg_atomic_incr32(&hg_core_handle->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_int32_t
HG_Core_ref_get(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_int32_t ret;

    HG_CHECK_ERROR(
        hg_core_handle == NULL, done, ret, -1, "NULL HG core handle");
    ret = (hg_int32_t) hg_atomic_get32(&hg_core_handle->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_forward(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    hg_uint8_t flags, hg_size_t payload_size)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_size_t header_size;
    hg_bool_t in_use;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_core_handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");
    HG_CHECK_ERROR(hg_core_handle->core_handle.info.addr == HG_CORE_ADDR_NULL,
        done, ret, HG_INVALID_ARG, "NULL target addr");
    HG_CHECK_ERROR(hg_core_handle->core_handle.info.id == 0, done, ret,
        HG_INVALID_ARG, "NULL RPC ID");

#ifndef HG_HAS_SELF_FORWARD
    HG_CHECK_ERROR(hg_core_handle->is_self, done, ret, HG_INVALID_PARAM,
        "Forward to self not enabled, please enable HG_USE_SELF_FORWARD");
#endif
    in_use = (hg_atomic_cas32(&hg_core_handle->in_use, HG_FALSE, HG_TRUE) !=
              HG_UTIL_TRUE);
    /* Not safe to reset
     * TODO could add the ability to defer the reset operation */
    HG_CHECK_ERROR(in_use, done, ret, HG_BUSY,
        "Not safe to use HG core handle, handle is still in use, refcount: %d",
        hg_atomic_get32(&hg_core_handle->ref_count));

    /* Make sure any cancelation has been processed on this handle before
     * re-using it */
    while (hg_atomic_get32(&hg_core_handle->canceling)) {
        int cb_ret[HG_CORE_MAX_TRIGGER_COUNT] = {0};
        unsigned int trigger_count = 0;
        na_return_t na_ret;

        na_ret = NA_Trigger(hg_core_handle->na_context, 0,
            HG_CORE_MAX_TRIGGER_COUNT, cb_ret, &trigger_count);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
            (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
            NA_Error_to_string(na_ret));
    }

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    hg_core_stat_incr(&hg_core_rpc_count_g);
#endif

    /* Reset op counts */
    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_set32(&hg_core_handle->na_op_completed_count, 0);

    /* Reset handle ret */
    hg_core_handle->ret = HG_SUCCESS;

    /* Increase ref count here so that a call to HG_Destroy does not free the
     * handle but only schedules its completion
     */
    hg_atomic_incr32(&hg_core_handle->ref_count);

    /* Set header size */
    header_size = hg_core_header_request_get_size() +
                  hg_core_handle->core_handle.na_in_header_offset;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_core_handle->in_buf_used = header_size + payload_size;
    HG_CHECK_ERROR(
        hg_core_handle->in_buf_used > hg_core_handle->core_handle.in_buf_size,
        error, ret, HG_MSGSIZE, "Exceeding input buffer size");

    /* Parse flags */
    if (flags & HG_CORE_NO_RESPONSE)
        hg_core_handle->no_response = HG_TRUE;
    if (hg_core_handle->is_self)
        flags |= HG_CORE_SELF_FORWARD;

    /* Set callback, keep request and response callbacks separate so that
     * they do not get overwritten when forwarding to ourself */
    hg_core_handle->request_callback = callback;
    hg_core_handle->request_arg = arg;

    /* Set header */
    hg_core_handle->in_header.msg.request.id =
        hg_core_handle->core_handle.info.id;
    hg_core_handle->in_header.msg.request.flags = flags;
    /* Set the cookie as origin context ID, so that when the cookie is unpacked
     * by the target and assigned to HG info context_id, the NA layer knows
     * which context ID it needs to send the response to. */
    hg_core_handle->in_header.msg.request.cookie =
        hg_core_handle->core_handle.info.context->id;

    /* Encode request header */
    ret = hg_core_proc_header_request(
        &hg_core_handle->core_handle, &hg_core_handle->in_header, HG_ENCODE);
    HG_CHECK_HG_ERROR(error, ret, "Could not encode header");

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    ret = hg_core_handle->forward(hg_core_handle);
    if (ret == HG_AGAIN)
        goto error;

    HG_CHECK_HG_ERROR(error, ret, "Could not forward buffer");

done:
    return ret;

error:
    /* Handle is no longer in use */
    hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);
    /* Rollback ref_count taken above */
    hg_atomic_decr32(&hg_core_handle->ref_count);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_respond(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    hg_uint8_t flags, hg_size_t payload_size)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(hg_core_handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");

    /* Cannot respond if no_response flag set */
    HG_CHECK_ERROR(hg_core_handle->no_response, done, ret, HG_OPNOTSUPPORTED,
        "Sending response was disabled on that RPC");

    /* Set header size */
    header_size = hg_core_header_response_get_size() +
                  hg_core_handle->core_handle.na_out_header_offset;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_core_handle->out_buf_used = header_size + payload_size;
    HG_CHECK_ERROR(
        hg_core_handle->out_buf_used > hg_core_handle->core_handle.out_buf_size,
        done, ret, HG_MSGSIZE, "Exceeding output buffer size");

    /* Set callback, keep request and response callbacks separate so that
     * they do not get overwritten when forwarding to ourself */
    hg_core_handle->response_callback = callback;
    hg_core_handle->response_arg = arg;

    /* Set header */
    hg_core_handle->out_header.msg.response.ret_code = hg_core_handle->ret;
    hg_core_handle->out_header.msg.response.flags = flags;
    hg_core_handle->out_header.msg.response.cookie = hg_core_handle->cookie;

    /* Encode response header */
    ret = hg_core_proc_header_response(
        &hg_core_handle->core_handle, &hg_core_handle->out_header, HG_ENCODE);
    HG_CHECK_HG_ERROR(done, ret, "Could not encode header");

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    ret = hg_core_handle->respond(hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not respond");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_progress(hg_core_context_t *context, unsigned int timeout)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");

    /* Make progress on the HG layer */
    ret = hg_core_progress(private_context, timeout);
    HG_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        "Could not make progress");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_trigger(hg_core_context_t *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");

    ret = hg_core_trigger((struct hg_core_private_context *) context, timeout,
        max_count, actual_count);
    HG_CHECK_ERROR_NORET(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        "Could not trigger callbacks");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_cancel(hg_core_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(handle == HG_CORE_HANDLE_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");

    ret = hg_core_cancel((struct hg_core_private_handle *) handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not cancel handle");

done:
    return ret;
}
