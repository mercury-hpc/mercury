/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
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
#include "mercury_error.h"
#include "mercury_event.h"
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

#ifdef NA_HAS_SM
#    include <na_sm.h>
#endif

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/* Private flags */
#define HG_CORE_SELF_FORWARD (1 << 3) /* Forward to self */

/* Size of comletion queue used for holding completed requests */
#define HG_CORE_ATOMIC_QUEUE_SIZE (1024)

/* Pre-posted requests and op IDs */
#define HG_CORE_POST_INIT          (256)
#define HG_CORE_POST_INCR          (256)
#define HG_CORE_BULK_OP_INIT_COUNT (256)

/* Timeout on finalize */
#define HG_CORE_CLEANUP_TIMEOUT (1000)

/* Max number of events for progress */
#define HG_CORE_MAX_EVENTS        (1)
#define HG_CORE_MAX_TRIGGER_COUNT (1)

#ifdef NA_HAS_SM
/* Addr string format */
#    define HG_CORE_ADDR_MAX_SIZE   (256)
#    define HG_CORE_PROTO_DELIMITER ":"
#    define HG_CORE_ADDR_DELIMITER  "#"

/* Min macro */
#    define HG_CORE_MIN(a, b) (a < b) ? a : b
#endif

/* Op status bits */
#define HG_CORE_OP_COMPLETED (1 << 0)
#define HG_CORE_OP_CANCELED  (1 << 1)
#define HG_CORE_OP_POSTED    (1 << 2)
#define HG_CORE_OP_ERRORED   (1 << 3)
#define HG_CORE_OP_QUEUED    (1 << 4)

/* Encode type */
#define HG_CORE_TYPE_ENCODE(label, ret, buf_ptr, buf_size_left, data, size)    \
    do {                                                                       \
        HG_CHECK_ERROR(buf_size_left < size, label, ret, HG_OVERFLOW,          \
            "Buffer size too small (%" PRIu64 ")", buf_size_left);             \
        memcpy(buf_ptr, data, size);                                           \
        buf_ptr += size;                                                       \
        buf_size_left -= size;                                                 \
    } while (0)

#define HG_CORE_ENCODE(label, ret, buf_ptr, buf_size_left, data, type)         \
    HG_CORE_TYPE_ENCODE(label, ret, buf_ptr, buf_size_left, data, sizeof(type))

/* Decode type */
#define HG_CORE_TYPE_DECODE(label, ret, buf_ptr, buf_size_left, data, size)    \
    do {                                                                       \
        HG_CHECK_ERROR(buf_size_left < size, label, ret, HG_OVERFLOW,          \
            "Buffer size too small (%" PRIu64 ")", buf_size_left);             \
        memcpy(data, buf_ptr, size);                                           \
        buf_ptr += size;                                                       \
        buf_size_left -= size;                                                 \
    } while (0)

#define HG_CORE_DECODE(label, ret, buf_ptr, buf_size_left, data, type)         \
    HG_CORE_TYPE_DECODE(label, ret, buf_ptr, buf_size_left, data, sizeof(type))

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

/* Private accessors */
#define HG_CORE_CONTEXT_CLASS(context)                                         \
    ((struct hg_core_private_class *) (context->core_context.core_class))

#define HG_CORE_HANDLE_CLASS(handle)                                           \
    ((struct hg_core_private_class *) (handle->core_handle.info.core_class))
#define HG_CORE_HANDLE_CONTEXT(handle)                                         \
    ((struct hg_core_private_context *) (handle->core_handle.info.context))

#define HG_CORE_ADDR_CLASS(addr)                                               \
    ((struct hg_core_private_class *) (addr->core_addr.core_class))

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_core_private_class {
    struct hg_core_class core_class; /* Must remain as first field */
#ifdef NA_HAS_SM
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
    hg_uint32_t request_post_init;  /* Init count of posted requests */
    hg_uint32_t request_post_incr;  /* Incr count of posted requests */
    hg_bool_t na_ext_init;          /* NA externally initialized */
    hg_bool_t loopback;             /* Able to self forward */
#ifdef HG_HAS_COLLECT_STATS
    hg_bool_t stats; /* (Debug) Print stats at exit */
#endif
};

/* Poll type */
typedef enum hg_core_poll_type {
    HG_CORE_POLL_LOOPBACK = 1,
#ifdef NA_HAS_SM
    HG_CORE_POLL_SM,
#endif
    HG_CORE_POLL_NA
} hg_core_poll_type_t;

/* HG context */
struct hg_core_private_context {
    struct hg_core_context core_context;      /* Must remain as first field */
    hg_thread_cond_t completion_queue_cond;   /* Completion queue cond */
    hg_thread_mutex_t completion_queue_mutex; /* Completion queue mutex */
    hg_thread_mutex_t completion_queue_notify_mutex;   /* Notify mutex */
    HG_QUEUE_HEAD(hg_completion_entry) backfill_queue; /* Backfill queue */
    struct hg_atomic_queue *completion_queue;          /* Default queue */
    HG_LIST_HEAD(hg_core_private_handle) created_list; /* Created handle list */
    HG_LIST_HEAD(hg_core_private_handle) pending_list; /* Pending handle list */
#ifdef NA_HAS_SM
    HG_LIST_HEAD(hg_core_private_handle) sm_pending_list; /* Pending handles */
#endif
    hg_return_t (*handle_create)(hg_core_handle_t, void *); /* Create cb */
    void *handle_create_arg;                                /* Create args */
    struct hg_bulk_op_pool *hg_bulk_op_pool;                /* Pool of op IDs */
    struct hg_poll_set *poll_set;                           /* Poll set */
    struct hg_poll_event poll_events[HG_CORE_MAX_EVENTS];   /* Poll events */
    hg_atomic_int32_t completion_queue_must_notify; /* Will notify if set */
    hg_atomic_int32_t backfill_queue_count;         /* Backfill queue count */
    hg_atomic_int32_t n_handles;                    /* Number of handles */
    hg_thread_spin_t created_list_lock;             /* Handle list lock */
    hg_thread_spin_t pending_list_lock;             /* Pending list lock */
    int completion_queue_notify;                    /* Self notification */
    hg_bool_t finalizing;                           /* Prevent reposts */
};

/* Info for wrapping callbacks if self addr */
struct hg_core_self_cb_info {
    hg_core_cb_t forward_cb;
    void *forward_arg;
    hg_core_cb_t respond_cb;
    void *respond_arg;
};

/* HG addr */
struct hg_core_private_addr {
    struct hg_core_addr core_addr;    /* Must remain as first field */
    na_size_t na_addr_serialize_size; /* Cached serialization size */
#ifdef NA_HAS_SM
    na_size_t na_sm_addr_serialize_size; /* Cached serialization size */
    na_sm_id_t host_id;                  /* NA SM Host ID */
#endif
    hg_atomic_int32_t ref_count; /* Reference count */
};

/* HG core op type */
typedef enum {
    HG_CORE_FORWARD,      /*!< Forward completion */
    HG_CORE_RESPOND,      /*!< Respond completion */
    HG_CORE_NO_RESPOND,   /*!< No response completion */
    HG_CORE_FORWARD_SELF, /*!< Self forward completion */
    HG_CORE_RESPOND_SELF, /*!< Self respond completion */
    HG_CORE_PROCESS       /*!< Process completion */
} hg_core_op_type_t;

/* HG core handle */
struct hg_core_private_handle {
    struct hg_core_handle core_handle; /* Must remain as first field */
    struct hg_completion_entry hg_completion_entry; /* Completion queue entry */
    HG_LIST_ENTRY(hg_core_private_handle) created;  /* Created list entry */
    HG_LIST_ENTRY(hg_core_private_handle) pending;  /* Pending list entry */
    struct hg_core_header in_header;                /* Input header */
    struct hg_core_header out_header;               /* Output header */
    na_class_t *na_class;                           /* NA class */
    na_context_t *na_context;                       /* NA context */
    na_addr_t na_addr;                              /* NA addr */
    hg_core_cb_t request_callback;                  /* Request callback */
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
    na_op_id_t *na_send_op_id; /* Operation ID for send */
    na_op_id_t *na_recv_op_id; /* Operation ID for recv */
    na_op_id_t *na_ack_op_id;  /* Operation ID for ack */
    na_size_t in_buf_used;     /* Amount of input buffer used */
    na_size_t out_buf_used;    /* Amount of output buffer used */
    na_tag_t tag;              /* Tag used for request and response */
    hg_atomic_int32_t na_op_completed_count; /* Completed NA operation count */
    hg_atomic_int32_t ref_count;             /* Reference count */
    hg_atomic_int32_t status;                /* Handle status */
    unsigned int na_op_count;                /* Expected NA operation count */
    hg_core_op_type_t op_type;               /* Core operation type */
    hg_return_t ret;       /* Return code associated to handle */
    hg_uint8_t cookie;     /* Cookie */
    hg_bool_t repost;      /* Repost handle on completion (listen) */
    hg_bool_t is_self;     /* Self processed */
    hg_bool_t no_response; /* Require response or not */
};

/* HG op id */
struct hg_core_op_info_lookup {
    struct hg_core_private_addr *hg_core_addr; /* Address */
};

struct hg_core_op_id {
    struct hg_completion_entry hg_completion_entry; /* Completion queue entry */
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
 * Create context.
 */
static hg_return_t
hg_core_context_create(hg_core_class_t *hg_core_class, hg_uint8_t id,
    struct hg_core_private_context **context_ptr);

/**
 * Destroy context.
 */
static hg_return_t
hg_core_context_destroy(struct hg_core_private_context *context);

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_core_context_post(struct hg_core_private_context *context,
    na_class_t *na_class, na_context_t *na_context, unsigned int request_count);

/**
 * Cancel posted requests.
 */
static hg_return_t
hg_core_context_unpost(struct hg_core_private_context *context);

/**
 * Check pending list and repost batch of requests as needed.
 */
static hg_return_t
hg_core_context_check_pending(struct hg_core_private_context *context,
    na_class_t *na_class, na_context_t *na_context, unsigned int request_count);

/**
 * Wail until handle lists are empty.
 */
static hg_return_t
hg_core_context_lists_wait(struct hg_core_private_context *context);

/**
 * Lookup addr.
 */
static hg_return_t
hg_core_addr_lookup(struct hg_core_private_class *hg_core_class,
    const char *name, struct hg_core_private_addr **addr);

/**
 * Create addr.
 */
static struct hg_core_private_addr *
hg_core_addr_create(struct hg_core_private_class *hg_core_class);

/**
 * Free addr.
 */
static hg_return_t
hg_core_addr_free(struct hg_core_private_addr *hg_core_addr);

/**
 * Free NA addr.
 */
static hg_return_t
hg_core_addr_free_na(struct hg_core_private_addr *hg_core_addr);

/**
 * Set addr to be removed.
 */
static hg_return_t
hg_core_addr_set_remove(struct hg_core_private_addr *hg_core_addr);

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
hg_core_addr_dup(struct hg_core_private_addr *hg_core_addr,
    struct hg_core_private_addr **hg_new_addr_ptr);

/**
 * Compare two addresses.
 */
static hg_bool_t
hg_core_addr_cmp(
    struct hg_core_private_addr *addr1, struct hg_core_private_addr *addr2);

/**
 * Convert addr to string.
 */
static hg_return_t
hg_core_addr_to_string(
    char *buf, hg_size_t *buf_size, struct hg_core_private_addr *hg_core_addr);

/**
 * Get serialize size.
 */
static hg_size_t
hg_core_addr_get_serialize_size(
    struct hg_core_private_addr *hg_core_addr, hg_uint8_t flags);

/**
 * Serialize core address.
 */
static hg_return_t
hg_core_addr_serialize(void *buf, hg_size_t buf_size, hg_uint8_t flags,
    struct hg_core_private_addr *hg_core_addr);

/**
 * Deserialize core address.
 */
static hg_return_t
hg_core_addr_deserialize(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr **hg_core_addr_ptr, const void *buf,
    hg_size_t buf_size);

/**
 * Create handle.
 */
static hg_return_t
hg_core_create(struct hg_core_private_context *context, na_class_t *na_class,
    na_context_t *na_context,
    struct hg_core_private_handle **hg_core_handle_ptr);

/**
 * Free handle.
 */
static hg_return_t
hg_core_destroy(struct hg_core_private_handle *hg_core_handle);

/**
 * Allocate new handle.
 */
static struct hg_core_private_handle *
hg_core_alloc(struct hg_core_private_context *context);

/**
 * Free handle.
 */
static hg_return_t
hg_core_free(struct hg_core_private_handle *hg_core_handle);

/**
 * Allocate NA resources.
 */
static hg_return_t
hg_core_alloc_na(struct hg_core_private_handle *hg_core_handle,
    na_class_t *na_class, na_context_t *na_context);

/**
 * Freee NA resources.
 */
static hg_return_t
hg_core_free_na(struct hg_core_private_handle *hg_core_handle);

/**
 * Reset handle.
 */
static void
hg_core_reset(struct hg_core_private_handle *hg_core_handle);

/**
 * Reset handle and re-post it.
 */
static hg_return_t
hg_core_reset_post(struct hg_core_private_handle *hg_core_handle);

/**
 * Set target addr / RPC ID
 */
static hg_return_t
hg_core_set_rpc(struct hg_core_private_handle *hg_core_handle,
    struct hg_core_private_addr *hg_core_addr, na_addr_t na_addr, hg_id_t id);

/**
 * Post handle and add it to pending list.
 */
static hg_return_t
hg_core_post(struct hg_core_private_handle *hg_core_handle);

/**
 * Forward handle.
 */
static hg_return_t
hg_core_forward(struct hg_core_private_handle *hg_core_handle,
    hg_core_cb_t callback, void *arg, hg_uint8_t flags, hg_size_t payload_size);

/**
 * Forward handle locally.
 */
static hg_return_t
hg_core_forward_self(struct hg_core_private_handle *hg_core_handle);

/**
 * Forward handle through NA.
 */
static hg_return_t
hg_core_forward_na(struct hg_core_private_handle *hg_core_handle);

/**
 * Send response.
 */
static hg_return_t
hg_core_respond(struct hg_core_private_handle *hg_core_handle,
    hg_core_cb_t callback, void *arg, hg_uint8_t flags, hg_size_t payload_size,
    hg_return_t ret_code);

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
 * Callback for HG_CORE_MORE_DATA operation.
 */
static HG_INLINE hg_return_t
hg_core_more_data_complete(hg_core_handle_t handle);

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

/**
 * Process handle.
 */
static hg_return_t
hg_core_process(struct hg_core_private_handle *hg_core_handle);

/**
 * Complete handle and NA operation.
 */
static HG_INLINE void
hg_core_complete_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed);

/**
 * Complete handle and add to completion queue.
 */
static HG_INLINE void
hg_core_complete(hg_core_handle_t handle);

/**
 * Make progress.
 */
static hg_return_t
hg_core_progress(
    struct hg_core_private_context *context, unsigned int timeout_ms);

/**
 * Determines when it is safe to block.
 */
static HG_INLINE hg_bool_t
hg_core_poll_try_wait(struct hg_core_private_context *context);

/**
 * Poll for timeout ms on context.
 */
static hg_return_t
hg_core_poll_wait(struct hg_core_private_context *context,
    unsigned int timeout_ms, hg_bool_t *progressed_ptr);

/**
 * Poll context without blocking.
 */
static hg_return_t
hg_core_poll(struct hg_core_private_context *context, unsigned int timeout_ms,
    hg_bool_t *progressed_ptr);

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_core_progress_na(na_class_t *na_class, na_context_t *na_context,
    unsigned int timeout_ms, hg_bool_t *progressed_ptr);

/**
 * Completion queue notification callback.
 */
static HG_INLINE hg_return_t
hg_core_progress_loopback_notify(
    struct hg_core_private_context *context, hg_bool_t *progressed_ptr);

/**
 * Trigger callbacks.
 */
static hg_return_t
hg_core_trigger(struct hg_core_private_context *context,
    unsigned int timeout_ms, unsigned int max_count,
    unsigned int *actual_count);

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
            (int32_t) hg_core_class->request_max_tag, 0)) {
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
static struct hg_core_private_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_core_private_class *hg_core_class = NULL;
    na_tag_t na_max_tag;
#ifdef NA_HAS_SM
    na_tag_t na_sm_max_tag;
    const char *na_class_name;
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
        /* request_post_incr is used only if request_post_init is non-zero */
        if (hg_init_info->request_post_init == 0) {
            hg_core_class->request_post_init = HG_CORE_POST_INIT;
            hg_core_class->request_post_incr = HG_CORE_POST_INCR;
        } else {
            hg_core_class->request_post_init = hg_init_info->request_post_init;
            hg_core_class->request_post_incr = hg_init_info->request_post_incr;
        }
        hg_core_class->progress_mode = hg_init_info->na_init_info.progress_mode;
#ifdef NA_HAS_SM
        auto_sm = hg_init_info->auto_sm;
#else
        HG_CHECK_WARNING(hg_init_info->auto_sm,
            "Option auto_sm requested but NA SM pluging was not compiled, "
            "please turn ON NA_USE_SM in CMake options");
#endif
        hg_core_class->loopback = !hg_init_info->no_loopback;
#ifdef HG_HAS_COLLECT_STATS
        hg_core_class->stats = hg_init_info->stats;
        if (hg_core_class->stats && !hg_core_print_stats_registered_g) {
            int rc = atexit(hg_core_print_stats);
            HG_CHECK_ERROR(rc != 0, error, ret, HG_PROTOCOL_ERROR,
                "Could not register hg_core_print_stats");
            hg_core_print_stats_registered_g = HG_TRUE;
        }
#endif
    } else {
        hg_core_class->request_post_init = HG_CORE_POST_INIT;
        hg_core_class->request_post_incr = HG_CORE_POST_INCR;
        hg_core_class->loopback = HG_TRUE;
    }

    /* Initialize NA if not provided externally */
    if (!hg_core_class->na_ext_init) {
        hg_core_class->core_class.na_class = NA_Initialize_opt(
            na_info_string, na_listen, &hg_init_info->na_init_info);
        HG_CHECK_ERROR(hg_core_class->core_class.na_class == NULL, error, ret,
            HG_NA_ERROR, "Could not initialize NA class");
    }

#ifdef NA_HAS_SM
    /* Retrieve NA class name */
    na_class_name = NA_Get_class_name(hg_core_class->core_class.na_class);

    /* Check for compatibility with SM */
    if (auto_sm && strcmp(na_class_name, "mpi") == 0) {
        HG_LOG_WARNING(
            "Auto SM mode is not compatible with MPI NA class, disabling");
        auto_sm = HG_FALSE;
    }
    if (auto_sm && strcmp(na_class_name, "na") == 0) {
        HG_LOG_WARNING(
            "Auto SM mode is set but NA class is already SM, ignoring");
        auto_sm = HG_FALSE;
    }

    /* Initialize SM plugin */
    if (auto_sm) {
        char info_string[HG_CORE_ADDR_MAX_SIZE], *info_string_p;
        na_return_t na_ret;

        if (hg_init_info && hg_init_info->sm_info_string) {
            int rc = snprintf(info_string, HG_CORE_ADDR_MAX_SIZE, "na+sm://%s",
                hg_init_info->sm_info_string);
            HG_CHECK_ERROR(rc < 0 || rc > HG_CORE_ADDR_MAX_SIZE, error, ret,
                HG_OVERFLOW, "snprintf() failed, rc: %d", rc);
            info_string_p = info_string;
        } else
            info_string_p = "na+sm";

        /* Initialize NA SM first so that tmp directories are created */
        hg_core_class->core_class.na_sm_class = NA_Initialize_opt(
            info_string_p, na_listen, &hg_init_info->na_init_info);
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

#ifdef NA_HAS_SM
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

    // TODO return error code
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
    int32_t n_addrs, n_contexts;
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

#ifdef NA_HAS_SM
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
static hg_return_t
hg_core_context_create(hg_core_class_t *hg_core_class, hg_uint8_t id,
    struct hg_core_private_context **context_ptr)
{
    struct hg_core_private_context *context = NULL;
    hg_return_t ret = HG_SUCCESS;
    int na_poll_fd;

    context = (struct hg_core_private_context *) malloc(
        sizeof(struct hg_core_private_context));
    HG_CHECK_ERROR(
        context == NULL, error, ret, HG_NOMEM, "Could not allocate HG context");

    memset(context, 0, sizeof(struct hg_core_private_context));
    context->core_context.core_class = hg_core_class;
    context->completion_queue =
        hg_atomic_queue_alloc(HG_CORE_ATOMIC_QUEUE_SIZE);
    HG_CHECK_ERROR(context->completion_queue == NULL, error, ret, HG_NOMEM,
        "Could not allocate queue");

    HG_QUEUE_INIT(&context->backfill_queue);
    hg_atomic_init32(&context->backfill_queue_count, 0);
    HG_LIST_INIT(&context->pending_list);
#ifdef NA_HAS_SM
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

    hg_thread_spin_init(&context->pending_list_lock);
    hg_thread_spin_init(&context->created_list_lock);

    /* Create NA context */
    context->core_context.na_context =
        NA_Context_create_id(hg_core_class->na_class, id);
    HG_CHECK_ERROR(context->core_context.na_context == NULL, error, ret,
        HG_NOMEM, "Could not create NA context");

#ifdef NA_HAS_SM
    if (hg_core_class->na_sm_class) {
        context->core_context.na_sm_context =
            NA_Context_create(hg_core_class->na_sm_class);
        HG_CHECK_ERROR(context->core_context.na_sm_context == NULL, error, ret,
            HG_NOMEM, "Could not create NA SM context");
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
        HG_CHECK_ERROR(context->poll_set == NULL, error, ret, HG_NOMEM,
            "Could not create poll set");

        event.data.u32 = (uint32_t) HG_CORE_POLL_NA;
        rc = hg_poll_add(context->poll_set, na_poll_fd, &event);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_NOMEM,
            "hg_poll_add() failed (na_poll_fd=%d)", na_poll_fd);

#ifdef NA_HAS_SM
        if (hg_core_class->na_sm_class && context->core_context.na_sm_context) {
            na_poll_fd = NA_Poll_get_fd(hg_core_class->na_sm_class,
                context->core_context.na_sm_context);
            HG_CHECK_ERROR(na_poll_fd < 0, error, ret, HG_PROTOCOL_ERROR,
                "Could not get NA SM poll fd");

            event.data.u32 = (uint32_t) HG_CORE_POLL_SM;
            rc = hg_poll_add(context->poll_set, na_poll_fd, &event);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_NOMEM,
                "hg_poll_add() failed (na_poll_fd=%d)", na_poll_fd);
        }
#endif

        if (HG_CORE_CONTEXT_CLASS(context)->loopback) {
            /* Create event for completion queue notification */
            context->completion_queue_notify = hg_event_create();
            HG_CHECK_ERROR(context->completion_queue_notify < 0, error, ret,
                HG_NOMEM, "Could not create event");

            /* Add event to context poll set */
            event.data.u32 = (uint32_t) HG_CORE_POLL_LOOPBACK;
            rc = hg_poll_add(
                context->poll_set, context->completion_queue_notify, &event);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_NOMEM,
                "hg_poll_add() failed (na_poll_fd=%d)", na_poll_fd);
        }
    }

    /* Assign context ID */
    context->core_context.id = id;

    /* Create pool of bulk op IDs */
    ret = hg_bulk_op_pool_create((hg_core_context_t *) context,
        HG_CORE_BULK_OP_INIT_COUNT, &context->hg_bulk_op_pool);
    HG_CHECK_HG_ERROR(error, ret, "Could not create bulk op pool");

    /* Increment context count of parent class */
    hg_atomic_incr32(&HG_CORE_CONTEXT_CLASS(context)->n_contexts);

    *context_ptr = context;

    return ret;

error:
    hg_core_context_destroy(context);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_destroy(struct hg_core_private_context *context)
{
    int32_t n_handles;
    hg_bool_t empty;
    hg_return_t ret = HG_SUCCESS;
    int rc;

    if (!context)
        goto done;

    /* Unpost requests */
    ret = hg_core_context_unpost(context);
    HG_CHECK_HG_ERROR(done, ret, "Could not unpost requests");

    /* Number of handles for that context should be 0 */
    n_handles = hg_atomic_get32(&context->n_handles);
    if (n_handles != 0) {
        struct hg_core_private_handle *hg_core_handle = NULL;

        HG_LOG_ERROR("HG core handles must be freed before destroying context "
                     "(%d remaining)",
            n_handles);
        hg_thread_spin_lock(&context->created_list_lock);
        HG_LIST_FOREACH (hg_core_handle, &context->created_list, created) {
            /* TODO ideally we'd want the upper layer to print that */
            if (hg_core_handle->core_handle.data)
                HG_LOG_ERROR("Handle (%p) was not destroyed",
                    hg_core_handle->core_handle.data);
            HG_LOG_DEBUG(
                "Core handle (%p) was not destroyed", (void *) hg_core_handle);
        }
        hg_thread_spin_unlock(&context->created_list_lock);

        hg_thread_spin_lock(&context->pending_list_lock);
        HG_LIST_FOREACH (hg_core_handle, &context->pending_list, pending) {
            /* TODO ideally we'd want the upper layer to print that */
            if (hg_core_handle->core_handle.data)
                HG_LOG_ERROR("Handle (%p) was not destroyed",
                    hg_core_handle->core_handle.data);
            HG_LOG_DEBUG(
                "Core handle (%p) was not destroyed", (void *) hg_core_handle);
        }
        hg_thread_spin_unlock(&context->pending_list_lock);
        ret = HG_BUSY;
        goto done;
    }

    /* Check that atomic completion queue is empty now */
    HG_CHECK_ERROR(!hg_atomic_queue_is_empty(context->completion_queue), done,
        ret, HG_BUSY, "Completion queue should be empty");
    hg_atomic_queue_free(context->completion_queue);

    /* Check that backfill completion queue is empty now */
    hg_thread_mutex_lock(&context->completion_queue_mutex);
    empty = HG_QUEUE_IS_EMPTY(&context->backfill_queue);
    hg_thread_mutex_unlock(&context->completion_queue_mutex);
    HG_CHECK_ERROR(
        !empty, done, ret, HG_BUSY, "Completion queue should be empty");

    /* Destroy pool of bulk op IDs */
    if (context->hg_bulk_op_pool) {
        ret = hg_bulk_op_pool_destroy(context->hg_bulk_op_pool);
        HG_CHECK_HG_ERROR(done, ret, "Could not destroy bulk op pool");
    }

    /* Stop listening for events */
    if (context->completion_queue_notify > 0) {
        rc =
            hg_poll_remove(context->poll_set, context->completion_queue_notify);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
            "Could not remove self processing event from poll set");

        rc = hg_event_destroy(context->completion_queue_notify);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
            "Could not destroy self processing event");
    }

    if (context->poll_set) {
        /* If NA plugin exposes fd, remove it from poll set */
        int na_poll_fd =
            NA_Poll_get_fd(context->core_context.core_class->na_class,
                context->core_context.na_context);
        if (na_poll_fd > 0) {
            rc = hg_poll_remove(context->poll_set, na_poll_fd);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
                "Could not remove NA poll descriptor from poll set");
        }
    }

#ifdef NA_HAS_SM
    if (context->core_context.na_sm_context && context->poll_set) {
        /* If NA plugin exposes fd, remove it from poll set */
        int na_poll_fd =
            NA_Poll_get_fd(context->core_context.core_class->na_sm_class,
                context->core_context.na_sm_context);
        if (na_poll_fd > 0) {
            rc = hg_poll_remove(context->poll_set, na_poll_fd);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_NOENTRY,
                "Could not remove NA poll descriptor from poll set");
        }
    }
#endif

    /* Destroy poll set */
    if (context->poll_set) {
        rc = hg_poll_destroy(context->poll_set);
        HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_FAULT,
            "Could not destroy poll set");
    }

    /* Destroy NA context */
    if (context->core_context.na_context) {
        na_return_t na_ret =
            NA_Context_destroy(context->core_context.core_class->na_class,
                context->core_context.na_context);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not destroy NA context (%s)", NA_Error_to_string(na_ret));
    }

#ifdef NA_HAS_SM
    /* Destroy NA SM context */
    if (context->core_context.na_sm_context) {
        na_return_t na_ret =
            NA_Context_destroy(context->core_context.core_class->na_sm_class,
                context->core_context.na_sm_context);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not destroy NA SM context");
    }
#endif

    /* Free user data */
    if (context->core_context.data_free_callback)
        context->core_context.data_free_callback(context->core_context.data);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&context->completion_queue_notify_mutex);
    hg_thread_mutex_destroy(&context->completion_queue_mutex);
    hg_thread_cond_destroy(&context->completion_queue_cond);
    hg_thread_spin_destroy(&context->pending_list_lock);
    hg_thread_spin_destroy(&context->created_list_lock);

    /* Decrement context count of parent class */
    hg_atomic_decr32(&HG_CORE_CONTEXT_CLASS(context)->n_contexts);

    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_post(struct hg_core_private_context *context,
    na_class_t *na_class, na_context_t *na_context, unsigned int request_count)
{
    hg_return_t ret = HG_SUCCESS;
    unsigned int nentry = 0;

    /* Create a bunch of handles and post unexpected receives */
    for (nentry = 0; nentry < request_count; nentry++) {
        struct hg_core_private_handle *hg_core_handle = NULL;
        struct hg_core_private_addr *hg_core_addr = NULL;

        /* Create new handle */
        ret = hg_core_create(context, na_class, na_context, &hg_core_handle);
        HG_CHECK_HG_ERROR(error, ret, "Could not create HG core handle");

        /* Reset status */
        hg_atomic_set32(&hg_core_handle->status, 0);

        /* Create new (empty) source addresses */
        hg_core_addr = hg_core_addr_create(HG_CORE_CONTEXT_CLASS(context));
        HG_CHECK_ERROR(hg_core_addr == NULL, error, ret, HG_NOMEM,
            "Could not create HG addr");
        hg_core_handle->core_handle.info.addr = (hg_core_addr_t) hg_core_addr;

        /* Repost handle on completion */
        hg_core_handle->repost = HG_TRUE;

        /* Post handle */
        ret = hg_core_post(hg_core_handle);
        HG_CHECK_HG_ERROR(error, ret, "Cannot post handle");
    }

    return ret;

error:
    hg_core_context_unpost(context);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_unpost(struct hg_core_private_context *context)
{
    struct hg_core_private_handle *hg_core_handle;
    unsigned int actual_count;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Prevent repost of handles */
    context->finalizing = HG_TRUE;

    /* Check pending list and cancel posted handles */
    hg_thread_spin_lock(&context->pending_list_lock);
    HG_LIST_FOREACH (hg_core_handle, &context->pending_list, pending) {
        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        HG_CHECK_HG_ERROR(error, ret, "Could not cancel handle");
    }

#ifdef NA_HAS_SM
    HG_LIST_FOREACH (hg_core_handle, &context->sm_pending_list, pending) {
        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        HG_CHECK_HG_ERROR(error, ret, "Could not cancel handle");
    }
#endif
    hg_thread_spin_unlock(&context->pending_list_lock);

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(
            context->core_context.na_context, 0, 1, NULL, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
        (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
        NA_Error_to_string(na_ret));

#ifdef NA_HAS_SM
    if (context->core_context.na_sm_context) {
        do {
            na_ret = NA_Trigger(
                context->core_context.na_sm_context, 0, 1, NULL, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT, done, ret,
            (hg_return_t) na_ret, "Could not trigger NA callback (%s)",
            NA_Error_to_string(na_ret));
    }
#endif

    /* Check that operations have completed */
    ret = hg_core_context_lists_wait(context);
    HG_CHECK_HG_ERROR(done, ret, "Could not wait on HG core handle list");

done:
    return ret;

error:
    hg_thread_spin_unlock(&context->pending_list_lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_check_pending(struct hg_core_private_context *context,
    na_class_t *na_class, na_context_t *na_context, unsigned int request_count)
{
    hg_bool_t pending_empty = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    /* Check if we need more handles */
    hg_thread_spin_lock(&context->pending_list_lock);

#ifdef NA_HAS_SM
    if (na_class == context->core_context.core_class->na_sm_class) {
        pending_empty = HG_LIST_IS_EMPTY(&context->sm_pending_list);
    } else
#endif
        pending_empty = HG_LIST_IS_EMPTY(&context->pending_list);

    hg_thread_spin_unlock(&context->pending_list_lock);

    /* If pending list is empty, post more handles */
    if (pending_empty) {
        ret =
            hg_core_context_post(context, na_class, na_context, request_count);
        HG_CHECK_HG_ERROR(done, ret, "Could not post additional handles");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_context_lists_wait(struct hg_core_private_context *context)
{
    bool created_list_empty = false;
    bool pending_list_empty = false;
#ifdef NA_HAS_SM
    bool sm_pending_list_empty = false;
#else
    bool sm_pending_list_empty = true;
#endif
    /* Convert timeout in ms into seconds */
    hg_time_t deadline, now;
    hg_return_t ret = HG_SUCCESS;

    hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(HG_CORE_CLEANUP_TIMEOUT));

    do {
        unsigned int actual_count = 0;
        hg_return_t trigger_ret, progress_ret;

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
#ifdef NA_HAS_SM
        sm_pending_list_empty = HG_LIST_IS_EMPTY(&context->sm_pending_list);
#endif
        hg_thread_spin_unlock(&context->pending_list_lock);

        if (created_list_empty && pending_list_empty && sm_pending_list_empty)
            break;

        progress_ret = hg_core_progress(
            context, hg_time_to_ms(hg_time_subtract(deadline, now)));
        HG_CHECK_ERROR(progress_ret != HG_SUCCESS && progress_ret != HG_TIMEOUT,
            done, ret, progress_ret, "Could not make progress");

        hg_time_get_current_ms(&now);
    } while (hg_time_less(now, deadline) || !pending_list_empty ||
             !sm_pending_list_empty);

    HG_LOG_DEBUG("Context list status: %d, %d, %d", created_list_empty,
        pending_list_empty, sm_pending_list_empty);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
struct hg_bulk_op_pool *
hg_core_context_get_bulk_op_pool(struct hg_core_context *core_context)
{
    return ((struct hg_core_private_context *) core_context)->hg_bulk_op_pool;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup(struct hg_core_private_class *hg_core_class,
    const char *name, struct hg_core_private_addr **addr)
{
    struct hg_core_private_addr *hg_core_addr = NULL;
    na_class_t **na_class_ptr = NULL;
    na_addr_t *na_addr_ptr = NULL;
    na_size_t *na_addr_serialize_size_ptr = NULL;
    na_return_t na_ret;
#ifdef NA_HAS_SM
    char lookup_name[HG_CORE_ADDR_MAX_SIZE] = {'\0'};
#endif
    const char *name_str = name;
    hg_return_t ret = HG_SUCCESS;

    /* Allocate addr */
    hg_core_addr = hg_core_addr_create(hg_core_class);
    HG_CHECK_ERROR(
        hg_core_addr == NULL, error, ret, HG_NOMEM, "Could not create HG addr");

    /* TODO lookup could also create self addresses */

#ifdef NA_HAS_SM
    /* Parse name string */
    if (hg_core_class->core_class.na_sm_class &&
        strstr(name, HG_CORE_ADDR_DELIMITER)) {
        char *lookup_names, *local_id_str;
        char *remote_name, *local_name;
        char *(*tok)(char *str, const char *delim, char **saveptr) = strtok_r;

        strcpy(lookup_name, name);

        /* Get first part of address string with host ID */
        (*tok)(lookup_name, HG_CORE_ADDR_DELIMITER, &lookup_names);

        HG_CHECK_ERROR(strstr(name, HG_CORE_PROTO_DELIMITER) == NULL, error,
            ret, HG_PROTOCOL_ERROR, "Malformed address format");

        /* Get address SM host ID */
        (*tok)(lookup_name, HG_CORE_PROTO_DELIMITER, &local_id_str);
        na_ret =
            NA_SM_String_to_host_id(local_id_str + 2, &hg_core_addr->host_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "NA_SM_String_to_host_id() failed (%s)",
            NA_Error_to_string(na_ret));

        /* Separate remaining two parts */
        (*tok)(lookup_names, HG_CORE_ADDR_DELIMITER, &remote_name);
        local_name = lookup_names;

        /* Compare IDs, if they match it's local address */
        if (NA_SM_Host_id_cmp(hg_core_addr->host_id, hg_core_class->host_id)) {
            HG_LOG_DEBUG("This is a local address");
            name_str = local_name;
            na_class_ptr = &hg_core_addr->core_addr.core_class->na_sm_class;
            na_addr_ptr = &hg_core_addr->core_addr.na_sm_addr;
            na_addr_serialize_size_ptr =
                &hg_core_addr->na_sm_addr_serialize_size;
        } else {
            /* Remote lookup */
            name_str = remote_name;
            na_class_ptr = &hg_core_addr->core_addr.core_class->na_class;
            na_addr_ptr = &hg_core_addr->core_addr.na_addr;
            na_addr_serialize_size_ptr = &hg_core_addr->na_addr_serialize_size;
        }
    } else {
#endif
        /* Remote lookup */
        na_class_ptr = &hg_core_addr->core_addr.core_class->na_class;
        na_addr_ptr = &hg_core_addr->core_addr.na_addr;
        na_addr_serialize_size_ptr = &hg_core_addr->na_addr_serialize_size;
#ifdef NA_HAS_SM
    }
#endif

    /* Lookup adress */
    na_ret = NA_Addr_lookup(*na_class_ptr, name_str, na_addr_ptr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not lookup address %s (%s)", name_str,
        NA_Error_to_string(na_ret));

    /* Cache serialize size */
    *na_addr_serialize_size_ptr =
        NA_Addr_get_serialize_size(*na_class_ptr, *na_addr_ptr);

    *addr = hg_core_addr;

    return ret;

error:
    hg_core_addr_free(hg_core_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_private_addr *
hg_core_addr_create(struct hg_core_private_class *hg_core_class)
{
    struct hg_core_private_addr *hg_core_addr = NULL;

    hg_core_addr = (struct hg_core_private_addr *) malloc(
        sizeof(struct hg_core_private_addr));
    HG_CHECK_ERROR_NORET(
        hg_core_addr == NULL, done, "Could not allocate HG addr");

    memset(hg_core_addr, 0, sizeof(struct hg_core_private_addr));
    hg_core_addr->core_addr.core_class = (hg_core_class_t *) hg_core_class;
    hg_core_addr->core_addr.na_addr = NA_ADDR_NULL;
#ifdef NA_HAS_SM
    hg_core_addr->core_addr.na_sm_addr = NA_ADDR_NULL;
#endif
    hg_core_addr->core_addr.is_self = HG_FALSE;
    hg_atomic_init32(&hg_core_addr->ref_count, 1);

    /* Increment N addrs from HG class */
    hg_atomic_incr32(&hg_core_class->n_addrs);

done:
    return hg_core_addr;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_free(struct hg_core_private_addr *hg_core_addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_addr)
        goto done;

    if (hg_atomic_decr32(&hg_core_addr->ref_count))
        /* Cannot free yet */
        goto done;

    /* Decrement N addrs from HG class */
    hg_atomic_decr32(&HG_CORE_ADDR_CLASS(hg_core_addr)->n_addrs);

    /* Free NA addresses */
    ret = hg_core_addr_free_na(hg_core_addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free NA addresses");

    free(hg_core_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_free_na(struct hg_core_private_addr *hg_core_addr)
{
    hg_return_t ret = HG_SUCCESS;

    /* Free NA address */
    if (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL) {
        na_return_t na_ret =
            NA_Addr_free(hg_core_addr->core_addr.core_class->na_class,
                hg_core_addr->core_addr.na_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not free NA address (%s)", NA_Error_to_string(na_ret));
        hg_core_addr->core_addr.na_addr = NA_ADDR_NULL;
        hg_core_addr->na_addr_serialize_size = 0;
    }

#ifdef NA_HAS_SM
    /* Free NA SM address */
    if (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_return_t na_ret =
            NA_Addr_free(hg_core_addr->core_addr.core_class->na_sm_class,
                hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not free NA SM address (%s)", NA_Error_to_string(na_ret));
        hg_core_addr->core_addr.na_sm_addr = NA_ADDR_NULL;
        hg_core_addr->na_sm_addr_serialize_size = 0;
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_set_remove(struct hg_core_private_addr *hg_core_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL) {
        na_ret =
            NA_Addr_set_remove(hg_core_addr->core_addr.core_class->na_class,
                hg_core_addr->core_addr.na_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "NA_Addr_set_remove() failed (%s)", NA_Error_to_string(na_ret));
    }

#ifdef NA_HAS_SM
    if (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_ret =
            NA_Addr_set_remove(hg_core_addr->core_addr.core_class->na_sm_class,
                hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "NA_Addr_set_remove() failed (%s)", NA_Error_to_string(na_ret));
    }
#endif

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

    hg_core_addr = hg_core_addr_create(hg_core_class);
    HG_CHECK_ERROR(
        hg_core_addr == NULL, error, ret, HG_NOMEM, "Could not create HG addr");
    hg_core_addr->core_addr.is_self = HG_TRUE;

    /* Get NA address */
    na_ret = NA_Addr_self(
        hg_core_class->core_class.na_class, &hg_core_addr->core_addr.na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not get self address (%s)", NA_Error_to_string(na_ret));

    /* Cache serialize size */
    hg_core_addr->na_addr_serialize_size = NA_Addr_get_serialize_size(
        hg_core_class->core_class.na_class, hg_core_addr->core_addr.na_addr);

#ifdef NA_HAS_SM
    if (hg_core_class->core_class.na_sm_class) {
        /* Get SM address */
        na_ret = NA_Addr_self(hg_core_class->core_class.na_sm_class,
            &hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not get self SM address (%s)", NA_Error_to_string(na_ret));

        /* Cache serialize size */
        hg_core_addr->na_sm_addr_serialize_size =
            NA_Addr_get_serialize_size(hg_core_class->core_class.na_sm_class,
                hg_core_addr->core_addr.na_sm_addr);

        /* Copy local host ID */
        NA_SM_Host_id_copy(&hg_core_addr->host_id, hg_core_class->host_id);
    }
#endif

    *self_addr = hg_core_addr;

    return ret;

error:
    hg_core_addr_free(hg_core_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_dup(struct hg_core_private_addr *hg_core_addr,
    struct hg_core_private_addr **hg_new_addr_ptr)
{
    struct hg_core_private_addr *hg_new_addr = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_new_addr = hg_core_addr_create(HG_CORE_ADDR_CLASS(hg_core_addr));
    HG_CHECK_ERROR(hg_new_addr == NULL, error, ret, HG_NOMEM,
        "Could not create dup HG addr");
    hg_new_addr->core_addr.is_self = hg_core_addr->core_addr.is_self;

    if (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL) {
        na_ret = NA_Addr_dup(hg_core_addr->core_addr.core_class->na_class,
            hg_core_addr->core_addr.na_addr, &hg_new_addr->core_addr.na_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not duplicate address (%s)", NA_Error_to_string(na_ret));

        /* Copy serialize size */
        hg_new_addr->na_addr_serialize_size =
            hg_core_addr->na_addr_serialize_size;
    }

#ifdef NA_HAS_SM
    if (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_ret = NA_Addr_dup(hg_core_addr->core_addr.core_class->na_sm_class,
            hg_core_addr->core_addr.na_sm_addr,
            &hg_new_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not duplicate address (%s)", NA_Error_to_string(na_ret));

        /* Copy serialize size */
        hg_new_addr->na_sm_addr_serialize_size =
            hg_core_addr->na_sm_addr_serialize_size;

        /* Copy local host ID */
        NA_SM_Host_id_copy(&hg_new_addr->host_id, hg_core_addr->host_id);
    }
#endif

    *hg_new_addr_ptr = hg_new_addr;

    return ret;

error:
    hg_core_addr_free(hg_new_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_bool_t
hg_core_addr_cmp(
    struct hg_core_private_addr *addr1, struct hg_core_private_addr *addr2)
{
    hg_bool_t ret = HG_TRUE;

    /* Cannot be separate classes */
    if (addr1->core_addr.core_class != addr2->core_addr.core_class)
        return HG_FALSE;

    /* Self addresses are always equal */
    if (addr1->core_addr.is_self && addr2->core_addr.is_self)
        return HG_TRUE;

    /* Compare NA addresses */
    ret &= (hg_bool_t) NA_Addr_cmp(addr1->core_addr.core_class->na_class,
        addr1->core_addr.na_addr, addr2->core_addr.na_addr);

#ifdef NA_HAS_SM
    /* Compare NA SM addresses */
    if (addr1->core_addr.core_class->na_sm_class)
        ret &= (hg_bool_t) NA_Addr_cmp(addr1->core_addr.core_class->na_sm_class,
            addr1->core_addr.na_sm_addr, addr2->core_addr.na_sm_addr);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_to_string(
    char *buf, hg_size_t *buf_size, struct hg_core_private_addr *hg_core_addr)
{
    na_class_t *na_class = hg_core_addr->core_addr.core_class->na_class;
    na_addr_t na_addr = hg_core_addr->core_addr.na_addr;
    char *buf_ptr = buf;
    hg_size_t new_buf_size = 0, buf_size_used = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    new_buf_size = *buf_size;

#ifdef NA_HAS_SM
    /* When we have local and remote addresses */
    if ((hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) &&
        (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL)) {
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
        na_ret =
            NA_Addr_to_string(hg_core_addr->core_addr.core_class->na_sm_class,
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
    } else if (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_class = hg_core_addr->core_addr.core_class->na_sm_class;
        na_addr = hg_core_addr->core_addr.na_sm_addr;
    }
#endif

    /* Get NA address string */
    na_ret = NA_Addr_to_string(na_class, buf_ptr, &new_buf_size, na_addr);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not convert address to string (%s)", NA_Error_to_string(na_ret));

    *buf_size = new_buf_size + buf_size_used;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_size_t
hg_core_addr_get_serialize_size(
    struct hg_core_private_addr *hg_core_addr, hg_uint8_t flags)
{
    hg_size_t ret = sizeof(na_size_t);

    if (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL) {
        if (hg_core_addr->na_addr_serialize_size == 0) {
            /* Cache serialize size */
            hg_core_addr->na_addr_serialize_size = NA_Addr_get_serialize_size(
                hg_core_addr->core_addr.core_class->na_class,
                hg_core_addr->core_addr.na_addr);
        }

        ret += hg_core_addr->na_addr_serialize_size;
    }

#ifdef NA_HAS_SM
    ret += sizeof(na_size_t);

    if ((flags & HG_CORE_SM) &&
        hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        if (hg_core_addr->na_sm_addr_serialize_size == 0) {
            /* Cache serialize size */
            hg_core_addr->na_sm_addr_serialize_size =
                NA_Addr_get_serialize_size(
                    hg_core_addr->core_addr.core_class->na_sm_class,
                    hg_core_addr->core_addr.na_sm_addr);
        }

        ret += hg_core_addr->na_sm_addr_serialize_size +
               sizeof(hg_core_addr->host_id);
    }
#else
    (void) flags;
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_serialize(void *buf, hg_size_t buf_size, hg_uint8_t flags,
    struct hg_core_private_addr *hg_core_addr)
{
    char *buf_ptr = (char *) buf;
    hg_size_t buf_size_left = buf_size;
    hg_return_t ret = HG_SUCCESS;

    if (hg_core_addr->core_addr.na_addr != NA_ADDR_NULL) {
        na_return_t na_ret;

        HG_CORE_ENCODE(done, ret, buf_ptr, buf_size_left,
            &hg_core_addr->na_addr_serialize_size, na_size_t);

        na_ret = NA_Addr_serialize(hg_core_addr->core_addr.core_class->na_class,
            buf_ptr, buf_size_left, hg_core_addr->core_addr.na_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not serialize NA address (%s)", NA_Error_to_string(na_ret));
        buf_ptr += hg_core_addr->na_addr_serialize_size;
        buf_size_left -= hg_core_addr->na_addr_serialize_size;
    } else {
        na_size_t na_sm_addr_serialize_size = 0;

        /* Encode a 0 instead of flag */
        HG_CORE_ENCODE(done, ret, buf_ptr, buf_size_left,
            &na_sm_addr_serialize_size, na_size_t);
    }

#ifdef NA_HAS_SM
    if ((flags & HG_CORE_SM) &&
        hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL) {
        na_return_t na_ret;

        HG_CORE_ENCODE(done, ret, buf_ptr, buf_size_left,
            &hg_core_addr->na_sm_addr_serialize_size, na_size_t);

        na_ret =
            NA_Addr_serialize(hg_core_addr->core_addr.core_class->na_sm_class,
                buf_ptr, buf_size_left, hg_core_addr->core_addr.na_sm_addr);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not serialize NA SM address (%s)",
            NA_Error_to_string(na_ret));
        /*
        buf_ptr += hg_core_addr->na_sm_addr_serialize_size;
        buf_size_left -= hg_core_addr->na_sm_addr_serialize_size;
*/
    } else {
        na_size_t na_sm_addr_serialize_size = 0;

        /* Encode a 0 instead of flag */
        HG_CORE_ENCODE(done, ret, buf_ptr, buf_size_left,
            &na_sm_addr_serialize_size, na_size_t);
    }
#else
    (void) flags;
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_deserialize(struct hg_core_private_class *hg_core_class,
    struct hg_core_private_addr **hg_core_addr_ptr, const void *buf,
    hg_size_t buf_size)
{
    struct hg_core_private_addr *hg_core_addr = NULL;
    const char *buf_ptr = (const char *) buf;
    hg_size_t buf_size_left = buf_size;
    hg_bool_t is_self = HG_TRUE;
    hg_return_t ret = HG_SUCCESS;

    /* Create new address */
    hg_core_addr = hg_core_addr_create(hg_core_class);
    HG_CHECK_ERROR(hg_core_addr == NULL, error, ret, HG_NOMEM,
        "Could not create deserialized HG addr");

    HG_CORE_DECODE(error, ret, buf_ptr, buf_size_left,
        &hg_core_addr->na_addr_serialize_size, na_size_t);

    if (hg_core_addr->na_addr_serialize_size != 0) {
        na_return_t na_ret =
            NA_Addr_deserialize(hg_core_class->core_class.na_class,
                &hg_core_addr->core_addr.na_addr, buf_ptr, buf_size_left);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not deserialize NA address (%s)",
            NA_Error_to_string(na_ret));
        buf_ptr += hg_core_addr->na_addr_serialize_size;
        buf_size_left -= hg_core_addr->na_addr_serialize_size;

        is_self &= NA_Addr_is_self(hg_core_class->core_class.na_class,
            hg_core_addr->core_addr.na_addr);
    }

#ifdef NA_HAS_SM
    HG_CORE_DECODE(error, ret, buf_ptr, buf_size_left,
        &hg_core_addr->na_sm_addr_serialize_size, na_size_t);

    if (hg_core_addr->na_sm_addr_serialize_size != 0) {
        na_return_t na_ret =
            NA_Addr_deserialize(hg_core_class->core_class.na_sm_class,
                &hg_core_addr->core_addr.na_sm_addr, buf_ptr, buf_size_left);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not deserialize NA SM address (%s)",
            NA_Error_to_string(na_ret));
        /*
        buf_ptr += hg_core_addr->na_sm_addr_serialize_size;
        buf_size_left -= hg_core_addr->na_sm_addr_serialize_size;
        */
        is_self &= NA_Addr_is_self(hg_core_class->core_class.na_class,
            hg_core_addr->core_addr.na_addr);
    }
#endif
    hg_core_addr->core_addr.is_self = is_self;

    *hg_core_addr_ptr = hg_core_addr;

    return ret;

error:
    hg_core_addr_free(hg_core_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_create(struct hg_core_private_context *context, na_class_t *na_class,
    na_context_t *na_context,
    struct hg_core_private_handle **hg_core_handle_ptr)
{
    struct hg_core_private_handle *hg_core_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    /* Allocate new handle */
    hg_core_handle = hg_core_alloc(context);
    HG_CHECK_ERROR(hg_core_handle == NULL, error, ret, HG_NOMEM,
        "Could not allocate handle");

    /* Alloc/init NA resources */
    ret = hg_core_alloc_na(hg_core_handle, na_class, na_context);
    HG_CHECK_HG_ERROR(error, ret, "Could not allocate NA handle ops");

    /* Execute class callback on handle, this allows upper layers to
     * allocate private data on handle creation */
    if (context->handle_create) {
        ret = context->handle_create(
            (hg_core_handle_t) hg_core_handle, context->handle_create_arg);
        HG_CHECK_HG_ERROR(error, ret, "Error in HG handle create callback");
    }

    HG_LOG_DEBUG("Created new handle (%p)", (void *) hg_core_handle);

    *hg_core_handle_ptr = hg_core_handle;

    return ret;

error:
    hg_core_destroy(hg_core_handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_destroy(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle)
        goto done;

    if (hg_atomic_decr32(&hg_core_handle->ref_count))
        goto done; /* Cannot free yet */

    /* Repost handle if we were listening, otherwise destroy it */
    if (hg_core_handle->repost &&
        !HG_CORE_HANDLE_CONTEXT(hg_core_handle)->finalizing) {
        HG_LOG_DEBUG("Reposting handle (%p)", (void *) hg_core_handle);

        /* Repost handle */
        ret = hg_core_reset_post(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Cannot repost handle");

        /* TODO handle error */
    } else {
        HG_LOG_DEBUG("Freeing handle (%p)", (void *) hg_core_handle);

        /* Free extra data here if needed */
        if (HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_release)
            HG_CORE_HANDLE_CLASS(hg_core_handle)
                ->more_data_release((hg_core_handle_t) hg_core_handle);

        /* Free user data */
        if (hg_core_handle->core_handle.data_free_callback)
            hg_core_handle->core_handle.data_free_callback(
                hg_core_handle->core_handle.data);

        /* Free NA resources */
        if (hg_core_handle->na_class) {
            ret = hg_core_free_na(hg_core_handle);
            HG_CHECK_HG_ERROR(done, ret, "Could not free NA ressources");
        }

        /* Free handle */
        hg_core_free(hg_core_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_private_handle *
hg_core_alloc(struct hg_core_private_context *context)
{
    struct hg_core_private_handle *hg_core_handle = NULL;

    hg_core_handle = (struct hg_core_private_handle *) malloc(
        sizeof(struct hg_core_private_handle));
    HG_CHECK_ERROR_NORET(
        hg_core_handle == NULL, done, "Could not allocate handle");

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

    /* Completed by default */
    hg_atomic_init32(&hg_core_handle->status, HG_CORE_OP_COMPLETED);

    /* Init in/out header */
    hg_core_header_request_init(&hg_core_handle->in_header);
    hg_core_header_response_init(&hg_core_handle->out_header);

    /* Set refcount to 1 */
    hg_atomic_init32(&hg_core_handle->ref_count, 1);

    /* Increment N handles from HG context */
    hg_atomic_incr32(&context->n_handles);

done:
    return hg_core_handle;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_free(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Remove reference to HG addr */
    ret = hg_core_addr_free(
        (struct hg_core_private_addr *) hg_core_handle->core_handle.info.addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free address");

    /* Remove handle from list */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);
    HG_LIST_REMOVE(hg_core_handle, created);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->created_list_lock);

    /* Decrement N handles from HG context */
    hg_atomic_decr32(&HG_CORE_HANDLE_CONTEXT(hg_core_handle)->n_handles);

    hg_core_header_request_finalize(&hg_core_handle->in_header);
    hg_core_header_response_finalize(&hg_core_handle->out_header);

    free(hg_core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_alloc_na(struct hg_core_private_handle *hg_core_handle,
    na_class_t *na_class, na_context_t *na_context)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Set NA class / context */
    hg_core_handle->na_class = na_class;
    hg_core_handle->na_context = na_context;

    /* Initialize in/out buffers and use unexpected message size */
    hg_core_handle->core_handle.in_buf_size =
        NA_Msg_get_max_unexpected_size(na_class);
    hg_core_handle->core_handle.out_buf_size =
        NA_Msg_get_max_expected_size(na_class);
    hg_core_handle->core_handle.na_in_header_offset =
        NA_Msg_get_unexpected_header_size(na_class);
    hg_core_handle->core_handle.na_out_header_offset =
        NA_Msg_get_expected_header_size(na_class);

    hg_core_handle->core_handle.in_buf =
        NA_Msg_buf_alloc(na_class, hg_core_handle->core_handle.in_buf_size,
            &hg_core_handle->in_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->core_handle.in_buf == NULL, error, ret,
        HG_NOMEM, "Could not allocate buffer for input");

    na_ret =
        NA_Msg_init_unexpected(na_class, hg_core_handle->core_handle.in_buf,
            hg_core_handle->core_handle.in_buf_size);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize input buffer (%s)", NA_Error_to_string(na_ret));

    hg_core_handle->core_handle.out_buf =
        NA_Msg_buf_alloc(na_class, hg_core_handle->core_handle.out_buf_size,
            &hg_core_handle->out_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->core_handle.out_buf == NULL, error, ret,
        HG_NOMEM, "Could not allocate buffer for output");

    na_ret = NA_Msg_init_expected(na_class, hg_core_handle->core_handle.out_buf,
        hg_core_handle->core_handle.out_buf_size);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize output buffer (%s)", NA_Error_to_string(na_ret));

    /* Create NA operation IDs */
    hg_core_handle->na_send_op_id = NA_Op_create(na_class);
    HG_CHECK_ERROR(hg_core_handle->na_send_op_id == NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");
    hg_core_handle->na_recv_op_id = NA_Op_create(na_class);
    HG_CHECK_ERROR(hg_core_handle->na_recv_op_id == NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");
    hg_core_handle->na_ack_op_id = NA_Op_create(na_class);
    HG_CHECK_ERROR(hg_core_handle->na_ack_op_id == NULL, error, ret,
        HG_NA_ERROR, "Could not create NA op ID");

    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_init32(&hg_core_handle->na_op_completed_count, 0);

    return ret;

error:
    hg_core_free_na(hg_core_handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_free_na(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Destroy NA op IDs */
    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_send_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not destroy send op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_send_op_id = NULL;

    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_recv_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not destroy recv op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_recv_op_id = NULL;

    na_ret =
        NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_ack_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not destroy ack op ID (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->na_ack_op_id = NULL;

    /* Free buffers */
    na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
        hg_core_handle->core_handle.in_buf, hg_core_handle->in_buf_plugin_data);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not free input buffer (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->core_handle.in_buf = NULL;
    hg_core_handle->in_buf_plugin_data = NULL;

    na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
        hg_core_handle->core_handle.out_buf,
        hg_core_handle->out_buf_plugin_data);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
        "Could not free output buffer (%s)", NA_Error_to_string(na_ret));
    hg_core_handle->core_handle.out_buf = NULL;
    hg_core_handle->out_buf_plugin_data = NULL;

    if (hg_core_handle->ack_buf) {
        na_ret = NA_Msg_buf_free(hg_core_handle->na_class,
            hg_core_handle->ack_buf, hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not free ack buffer (%s)", NA_Error_to_string(na_ret));
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }

    hg_core_handle->na_class = NULL;
    hg_core_handle->na_context = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_reset(struct hg_core_private_handle *hg_core_handle)
{
    /* TODO context ID must always be reset as it is not passed along with the
     * addr */
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
hg_core_reset_post(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Reset handle info */
    if (hg_core_handle->core_handle.info.addr != HG_CORE_ADDR_NULL) {
        ret = hg_core_addr_free_na((struct hg_core_private_addr *)
                                       hg_core_handle->core_handle.info.addr);
        HG_CHECK_HG_ERROR(done, ret, "Could not free NA addresses");
    }
    hg_core_handle->core_handle.info.id = 0;

    /* Reset the handle */
    hg_core_reset(hg_core_handle);

    /* Also reset additional handle parameters */
    hg_atomic_set32(&hg_core_handle->ref_count, 1);
    hg_core_handle->core_handle.rpc_info = NULL;

    /* Reset status */
    hg_atomic_set32(&hg_core_handle->status, 0);

    /* Safe to repost */
    ret = hg_core_post(hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Cannot post handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_set_rpc(struct hg_core_private_handle *hg_core_handle,
    struct hg_core_private_addr *hg_core_addr, na_addr_t na_addr, hg_id_t id)
{
    hg_return_t ret = HG_SUCCESS;

    /* We allow for NULL addr to be passed at creation time, this allows
     * for pool of handles to be created and later re-used after a call to
     * HG_Core_reset() */
    if (hg_core_addr && (hg_core_handle->core_handle.info.addr !=
                            (hg_core_addr_t) hg_core_addr)) {
        if (hg_core_handle->core_handle.info.addr != HG_CORE_ADDR_NULL) {
            ret = hg_core_addr_free((struct hg_core_private_addr *)
                                        hg_core_handle->core_handle.info.addr);
            HG_CHECK_HG_ERROR(done, ret, "Could not free address");
        }
        hg_core_handle->core_handle.info.addr = (hg_core_addr_t) hg_core_addr;
        hg_atomic_incr32(&hg_core_addr->ref_count);

        /* Set NA addr to use */
        hg_core_handle->na_addr = na_addr;

        /* Set forward call depending on address self */
        hg_core_handle->is_self =
            HG_CORE_HANDLE_CLASS(hg_core_handle)->loopback &&
            hg_core_addr->core_addr.is_self;

        hg_core_handle->forward =
            hg_core_handle->is_self ? hg_core_forward_self : hg_core_forward_na;
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
static hg_return_t
hg_core_post(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

#ifdef NA_HAS_SM
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
#ifdef NA_HAS_SM
    }
#endif

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_recv_input_cb, hg_core_handle,
        hg_core_handle->core_handle.in_buf,
        hg_core_handle->core_handle.in_buf_size,
        hg_core_handle->in_buf_plugin_data, hg_core_handle->na_recv_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post unexpected recv for input buffer (%s)",
        NA_Error_to_string(na_ret));

    HG_LOG_DEBUG("Posted handle (%p)", (void *) hg_core_handle);

    return ret;

error:
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    HG_LIST_REMOVE(hg_core_handle, pending);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward(struct hg_core_private_handle *hg_core_handle,
    hg_core_cb_t callback, void *arg, hg_uint8_t flags, hg_size_t payload_size)
{
    int32_t status;
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    status = hg_atomic_get32(&hg_core_handle->status);
    HG_CHECK_ERROR(
        !(status & HG_CORE_OP_COMPLETED) || (status & HG_CORE_OP_QUEUED), done,
        ret, HG_BUSY, "Attempting to use handle that was not completed");

    /* Increment ref_count on handle to allow for destroy to be pre-emptively
     * called */
    hg_atomic_incr32(&hg_core_handle->ref_count);

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    hg_core_stat_incr(&hg_core_rpc_count_g);
#endif

    /* Reset op counts */
    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_set32(&hg_core_handle->na_op_completed_count, 0);

    /* Reset status */
    hg_atomic_set32(&hg_core_handle->status, 0);

    /* Reset handle ret */
    hg_core_handle->ret = HG_SUCCESS;

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
    HG_CHECK_HG_ERROR(error, ret, "Could not forward buffer");

done:
    return ret;

error:
    /* Handle is no longer in use */
    hg_atomic_set32(&hg_core_handle->status, HG_CORE_OP_COMPLETED);

    /* Rollback ref_count taken above */
    hg_atomic_decr32(&hg_core_handle->ref_count);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_self(struct hg_core_private_handle *hg_core_handle)
{
    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Post operation to self processing pool */
    return hg_core_process_self(hg_core_handle);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_na(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

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
            hg_core_handle->out_buf_plugin_data, hg_core_handle->na_addr,
            hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
            hg_core_handle->na_recv_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not post recv for output buffer (%s)",
            NA_Error_to_string(na_ret));

        /* Increment number of expected NA operations */
        hg_core_handle->na_op_count++;
    }

    /* Mark handle as posted */
    hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_POSTED);

    /* Post send (input) */
    na_ret = NA_Msg_send_unexpected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_input_cb, hg_core_handle,
        hg_core_handle->core_handle.in_buf, hg_core_handle->in_buf_used,
        hg_core_handle->in_buf_plugin_data, hg_core_handle->na_addr,
        hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
        hg_core_handle->na_send_op_id);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post send for input buffer (%s)",
        NA_Error_to_string(na_ret));

done:
    return ret;

error:
    hg_atomic_and32(&hg_core_handle->status, ~HG_CORE_OP_POSTED);
    hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);

    if (hg_core_handle->no_response) {
        /* No recv was posted */
        return ret;
    } else {
        hg_core_handle->na_op_count--;

        /* Mark op as canceled and let it complete */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_CANCELED);

        /* Cancel the above posted recv op */
        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_recv_op_id);
        HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
            "Could not cancel recv op id (%s)", NA_Error_to_string(na_ret));

        /* Return success here but callback will return canceled */
        return HG_SUCCESS;
    }
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_respond(struct hg_core_private_handle *hg_core_handle,
    hg_core_cb_t callback, void *arg, hg_uint8_t flags, hg_size_t payload_size,
    hg_return_t ret_code)
{
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    /* Cannot respond if no_response flag set */
    HG_CHECK_ERROR(hg_core_handle->no_response, done, ret, HG_OPNOTSUPPORTED,
        "Sending response was disabled on that RPC");

    /* Reset status */
    hg_atomic_set32(&hg_core_handle->status, 0);

    /* Reset handle ret */
    hg_core_handle->ret = HG_SUCCESS;

    /* Set header size */
    header_size = hg_core_header_response_get_size() +
                  hg_core_handle->core_handle.na_out_header_offset;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_core_handle->out_buf_used = header_size + payload_size;
    HG_CHECK_ERROR(
        hg_core_handle->out_buf_used > hg_core_handle->core_handle.out_buf_size,
        error, ret, HG_MSGSIZE, "Exceeding output buffer size");

    /* Set callback, keep request and response callbacks separate so that
     * they do not get overwritten when forwarding to ourself */
    hg_core_handle->response_callback = callback;
    hg_core_handle->response_arg = arg;

    /* Set header */
    hg_core_handle->out_header.msg.response.ret_code = (hg_int8_t) ret_code;
    hg_core_handle->out_header.msg.response.flags = flags;
    hg_core_handle->out_header.msg.response.cookie = hg_core_handle->cookie;

    /* Encode response header */
    ret = hg_core_proc_header_response(
        &hg_core_handle->core_handle, &hg_core_handle->out_header, HG_ENCODE);
    HG_CHECK_HG_ERROR(error, ret, "Could not encode header");

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    ret = hg_core_handle->respond(hg_core_handle);
    HG_CHECK_HG_ERROR(error, ret, "Could not respond");

done:
    return ret;

error:
    /* Handle is no longer in use */
    hg_atomic_set32(&hg_core_handle->status, HG_CORE_OP_COMPLETED);

    /* Decrement refcount on handle */
    hg_atomic_decr32(&hg_core_handle->ref_count);

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_respond_self(struct hg_core_private_handle *hg_core_handle)
{
    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_RESPOND_SELF;

    /* Complete and add to completion queue */
    hg_core_complete((hg_core_handle_t) hg_core_handle);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_no_respond_self(struct hg_core_private_handle *hg_core_handle)
{
    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Complete and add to completion queue */
    hg_core_complete((hg_core_handle_t) hg_core_handle);

    return HG_SUCCESS;
}

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
        na_size_t buf_size = hg_core_handle->core_handle.na_out_header_offset +
                             sizeof(hg_uint8_t);
        hg_core_handle->ack_buf = NA_Msg_buf_alloc(hg_core_handle->na_class,
            buf_size, &hg_core_handle->ack_buf_plugin_data);
        HG_CHECK_ERROR(hg_core_handle->ack_buf == NULL, error, ret, HG_NA_ERROR,
            "Could not allocate buffer for ack");

        na_ret = NA_Msg_init_expected(
            hg_core_handle->na_class, hg_core_handle->ack_buf, buf_size);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not initialize ack buffer (%s)", NA_Error_to_string(na_ret));

        /* Increment number of expected NA operations */
        hg_core_handle->na_op_count++;

        /* Pre-post recv (ack) if more data is expected */
        na_ret = NA_Msg_recv_expected(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_recv_ack_cb, hg_core_handle,
            hg_core_handle->ack_buf, buf_size,
            hg_core_handle->ack_buf_plugin_data, hg_core_handle->na_addr,
            hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
            hg_core_handle->na_ack_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
            "Could not post recv for ack buffer (%s)",
            NA_Error_to_string(na_ret));
        ack_recv_posted = HG_TRUE;
    }

    /* Mark handle as posted */
    hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_POSTED);

    /* Post expected send (output) */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_output_cb, hg_core_handle,
        hg_core_handle->core_handle.out_buf, hg_core_handle->out_buf_used,
        hg_core_handle->out_buf_plugin_data, hg_core_handle->na_addr,
        hg_core_handle->core_handle.info.context_id, hg_core_handle->tag,
        hg_core_handle->na_send_op_id);
    /* Expected sends should always succeed after retry */
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not post send for output buffer (%s)",
        NA_Error_to_string(na_ret));

    return ret;

error:
    hg_atomic_and32(&hg_core_handle->status, ~HG_CORE_OP_POSTED);
    hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);

    if (ack_recv_posted) {
        hg_core_handle->na_op_count--;

        /* Mark op as canceled and let it complete */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_CANCELED);

        /* Cancel the above posted recv ack op */
        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_ack_op_id);
        HG_CHECK_ERROR_DONE(na_ret != NA_SUCCESS,
            "Could not cancel ack op id (%s)", NA_Error_to_string(na_ret));

        /* Return success here but callback will return canceled */
        return HG_SUCCESS;
    } else if (hg_core_handle->ack_buf) {
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
    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_NO_RESPOND;

    hg_core_complete((hg_core_handle_t) hg_core_handle);

    return HG_SUCCESS;
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
    if (callback_info->ret == NA_SUCCESS) {
        /* Nothing */
    } else if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");
    } else { /* All other errors */
        int32_t status;

        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));
        /* TODO return callback ret to user callback */

        /* Mark handle as errored */
        status = hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);

        if (!(status & HG_CORE_OP_CANCELED) && !hg_core_handle->no_response) {
            na_return_t na_ret;

            hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_CANCELED);

            /* Cancel posted recv for response */
            na_ret = NA_Cancel(hg_core_handle->na_class,
                hg_core_handle->na_context, hg_core_handle->na_recv_op_id);
            HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret,
                (hg_return_t) na_ret, "Could not cancel recv op id (%s)",
                NA_Error_to_string(na_ret));
        }
    }

done:
    hg_core_complete_na(hg_core_handle, &completed);
    (void) ret; /* TODO use ret in complete op */

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
    hg_bool_t completed = HG_TRUE;
    hg_return_t ret;

    /* Remove handle from pending list */
    hg_thread_spin_lock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);
    HG_LIST_REMOVE(hg_core_handle, pending);
    hg_thread_spin_unlock(
        &HG_CORE_HANDLE_CONTEXT(hg_core_handle)->pending_list_lock);

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_SUCCESS) {
        if (HG_CORE_HANDLE_CLASS(hg_core_handle)->request_post_incr > 0) {
            /* Check pending list and repost more handles if needed */
            ret = hg_core_context_check_pending(
                HG_CORE_HANDLE_CONTEXT(hg_core_handle),
                hg_core_handle->na_class, hg_core_handle->na_context,
                HG_CORE_HANDLE_CLASS(hg_core_handle)->request_post_incr);
            HG_CHECK_HG_ERROR(
                done, ret, "Could not check and repost pending requests");
        }

        /* Fill unexpected info */
        hg_core_handle->na_addr = na_cb_info_recv_unexpected->source;
#ifdef NA_HAS_SM
        if (hg_core_handle->na_class ==
            hg_core_handle->core_handle.info.core_class->na_sm_class) {
            HG_LOG_DEBUG("Using NA SM class for this handle");
            hg_core_handle->core_handle.info.addr->na_sm_addr =
                hg_core_handle->na_addr;
        } else
#endif
            hg_core_handle->core_handle.info.addr->na_addr =
                hg_core_handle->na_addr;
        hg_core_handle->tag = na_cb_info_recv_unexpected->tag;
        HG_CHECK_ERROR_NORET(na_cb_info_recv_unexpected->actual_buf_size >
                                 hg_core_handle->core_handle.in_buf_size,
            done, "Actual transfer size is too large for unexpected recv");
        hg_core_handle->in_buf_used =
            na_cb_info_recv_unexpected->actual_buf_size;

        HG_LOG_DEBUG(
            "Processing input for handle %p, tag=%u, buf_size=%" PRIu64,
            (void *) hg_core_handle, hg_core_handle->tag,
            hg_core_handle->in_buf_used);

        /* Process input information */
        ret = hg_core_process_input(hg_core_handle, &completed);
        HG_CHECK_HG_ERROR(done, ret, "Could not process input");

    } else if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");

        /* Do not add handle to completion queue if it was not posted */
        if (!(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_POSTED)) {
            /* Mark handle as completed */
            hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_COMPLETED);

            /* Clean up handle */
            ret = hg_core_destroy(hg_core_handle);
            HG_CHECK_ERROR_DONE(ret != HG_SUCCESS, "Could not destroy handle");

            return (int) completed;
        }

    } else {
        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));

        /* Mark handle as errored */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);
    }

done:
    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_PROCESS;

    /* Complete operation */
    hg_core_complete_na(hg_core_handle, &completed);

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
    hg_core_handle->respond =
        hg_core_handle->in_header.msg.request.flags & HG_CORE_SELF_FORWARD
            ? hg_core_respond_self
            : hg_core_respond_na;
    hg_core_handle->no_respond =
        hg_core_handle->in_header.msg.request.flags & HG_CORE_SELF_FORWARD
            ? hg_core_no_respond_self
            : hg_core_no_respond_na;

    HG_LOG_DEBUG("Processed input for handle %p, ID=%" PRIu64 ", cookie=%" PRIu8
                 ", no_response=%d",
        (void *) hg_core_handle, hg_core_handle->core_handle.info.id,
        hg_core_handle->cookie, hg_core_handle->no_response);

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->in_header.msg.request.flags & HG_CORE_MORE_DATA) {
        HG_CHECK_ERROR(!HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_acquire,
            done, ret, HG_OPNOTSUPPORTED,
            "No callback defined for acquiring more data");
        HG_LOG_DEBUG("Must acquire more input data for handle %p",
            (void *) hg_core_handle);
#ifdef HG_HAS_COLLECT_STATS
        /* Increment counter */
        hg_core_stat_incr(&hg_core_rpc_extra_count_g);
#endif
        ret = HG_CORE_HANDLE_CLASS(hg_core_handle)
                  ->more_data_acquire((hg_core_handle_t) hg_core_handle,
                      HG_INPUT, hg_core_more_data_complete);
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

    if (callback_info->ret == NA_SUCCESS) {
        /* Nothing */
    } else if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");
    } else {
        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));

        /* Mark handle as errored */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);
    }

    /* done: */
    /* Complete operation */
    hg_core_complete_na(hg_core_handle, &completed);

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

    if (callback_info->ret == NA_SUCCESS) {
        HG_LOG_DEBUG("Processing output for handle %p, tag=%u",
            (void *) hg_core_handle, hg_core_handle->tag);

        /* Process output information */
        ret = hg_core_process_output(
            hg_core_handle, &completed, hg_core_send_ack);
        HG_CHECK_HG_ERROR(done, ret, "Could not process output");

    } else if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");

    } else {
        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));

        /* Mark handle as errored */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);
    }

done:
    /* Complete operation */
    hg_core_complete_na(hg_core_handle, &completed);

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

    HG_LOG_DEBUG("Processed output for handle %p, ID=%" PRIu64 ", ret=%d",
        (void *) hg_core_handle, hg_core_handle->core_handle.info.id,
        hg_core_handle->ret);

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->out_header.msg.response.flags & HG_CORE_MORE_DATA) {
        HG_CHECK_ERROR(!HG_CORE_HANDLE_CLASS(hg_core_handle)->more_data_acquire,
            done, ret, HG_OPNOTSUPPORTED,
            "No callback defined for acquiring more data");
        HG_LOG_DEBUG("Must acquire more input data for handle %p",
            (void *) hg_core_handle);

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
static HG_INLINE hg_return_t
hg_core_more_data_complete(hg_core_handle_t handle)
{
    /* Complete and add to completion queue */
    hg_core_complete(handle);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_send_ack(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    na_size_t buf_size = handle->na_out_header_offset + sizeof(hg_uint8_t);

    /* Increment number of expected NA operations */
    hg_core_handle->na_op_count++;

    /* Allocate buffer for ack */
    hg_core_handle->ack_buf = NA_Msg_buf_alloc(hg_core_handle->na_class,
        buf_size, &hg_core_handle->ack_buf_plugin_data);
    HG_CHECK_ERROR(hg_core_handle->ack_buf == NULL, error, ret, HG_NA_ERROR,
        "Could not allocate buffer for ack");

    na_ret = NA_Msg_init_expected(
        hg_core_handle->na_class, hg_core_handle->ack_buf, buf_size);
    HG_CHECK_ERROR(na_ret != NA_SUCCESS, error, ret, (hg_return_t) na_ret,
        "Could not initialize ack buffer (%s)", NA_Error_to_string(na_ret));

    /* Post expected send (ack) */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_ack_cb, hg_core_handle,
        hg_core_handle->ack_buf, buf_size, hg_core_handle->ack_buf_plugin_data,
        hg_core_handle->na_addr, hg_core_handle->core_handle.info.context_id,
        hg_core_handle->tag, hg_core_handle->na_ack_op_id);
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

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));

        /* Mark handle as errored */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);
    }

    /* done: */
    /* Complete operation */
    hg_core_complete_na(hg_core_handle, &completed);

    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_recv_ack_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) callback_info->arg;
    hg_bool_t completed = HG_TRUE;

    /* If canceled, mark handle as canceled */
    if (callback_info->ret == NA_CANCELED) {
        HG_CHECK_WARNING(
            hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_COMPLETED,
            "Operation was completed");
        HG_LOG_DEBUG("NA_CANCELED event on handle %p", (void *) hg_core_handle);
        HG_CHECK_WARNING(
            !(hg_atomic_get32(&hg_core_handle->status) & HG_CORE_OP_CANCELED),
            "Received NA_CANCELED event on handle that was not canceled");
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("NA callback returned error (%s)",
            NA_Error_to_string(callback_info->ret));

        /* Mark handle as errored */
        hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_ERRORED);
    }

    /* done: */
    /* Complete operation */
    hg_core_complete_na(hg_core_handle, &completed);

    return (int) completed;
}

/*---------------------------------------------------------------------------*/
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
    ret = hg_core_process_output(
        hg_core_handle, &completed, hg_core_more_data_complete);
    HG_CHECK_HG_ERROR(done, ret, "Could not process output");

    /* Mark as completed */
    if (completed) {
        hg_core_complete((hg_core_handle_t) hg_core_handle);
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
        hg_core_complete((hg_core_handle_t) hg_core_handle);
    }

done:
    return ret;
}

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
static HG_INLINE void
hg_core_complete_na(
    struct hg_core_private_handle *hg_core_handle, hg_bool_t *completed)
{
    /* Add handle to completion queue when expected operations have completed */
    if (hg_atomic_incr32(&hg_core_handle->na_op_completed_count) ==
            (int32_t) hg_core_handle->na_op_count &&
        *completed) {
        /* Mark as completed */
        hg_core_complete((hg_core_handle_t) hg_core_handle);

        /* Increment number of entries added to completion queue */
        *completed = HG_TRUE;
    } else
        *completed = HG_FALSE;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_core_complete(hg_core_handle_t handle)
{
    struct hg_core_private_handle *hg_core_handle =
        (struct hg_core_private_handle *) handle;
    struct hg_completion_entry *hg_completion_entry =
        &hg_core_handle->hg_completion_entry;
    int32_t status;

    /* Mark op id as completed before checking for cancelation, also mark the
     * operation as queued to track when it will be released from the completion
     * queue. */
    status = hg_atomic_or32(
        &hg_core_handle->status, HG_CORE_OP_COMPLETED | HG_CORE_OP_QUEUED);

    /* Check for current status before completing (TODO keep until error is
     * properly forwarded) */
    if (status & HG_CORE_OP_ERRORED) {
        /* If it was errored, set callback ret accordingly */
        HG_LOG_DEBUG("Handle %p is errored", (void *) hg_core_handle);
        hg_core_handle->ret = HG_NA_ERROR;
    } else if (status & HG_CORE_OP_CANCELED) {
        /* If it was canceled while being processed, set callback ret
         * accordingly */
        HG_LOG_DEBUG("Handle %p was canceled", (void *) hg_core_handle);
        hg_core_handle->ret = HG_CANCELED;
    }

    hg_completion_entry->op_type = HG_RPC;
    hg_completion_entry->op_id.hg_core_handle = handle;

    (void) hg_core_completion_add(hg_core_handle->core_handle.info.context,
        hg_completion_entry, hg_core_handle->is_self);
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_completion_add(struct hg_core_context *context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify)
{
    struct hg_core_private_context *private_context =
        (struct hg_core_private_context *) context;
    hg_return_t ret = HG_SUCCESS;
    int rc;

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    if (hg_completion_entry->op_type == HG_BULK)
        hg_core_stat_incr(&hg_core_bulk_count_g);
#endif

    rc = hg_atomic_queue_push(
        private_context->completion_queue, hg_completion_entry);
    if (rc != HG_UTIL_SUCCESS) {
        /* Queue is full */
        hg_thread_mutex_lock(&private_context->completion_queue_mutex);
        HG_QUEUE_PUSH_TAIL(
            &private_context->backfill_queue, hg_completion_entry, entry);
        hg_atomic_incr32(&private_context->backfill_queue_count);
        hg_thread_mutex_unlock(&private_context->completion_queue_mutex);
    }

    /* Callback is pushed to the completion queue when something completes
     * so wake up anyone waiting in trigger */
    hg_thread_mutex_lock(&private_context->completion_queue_mutex);
    hg_thread_cond_signal(&private_context->completion_queue_cond);
    hg_thread_mutex_unlock(&private_context->completion_queue_mutex);

    if (self_notify && private_context->completion_queue_notify > 0) {
        hg_thread_mutex_lock(&private_context->completion_queue_notify_mutex);
        /* Do not bother notifying if it's not needed as any event call will
         * increase latency */
        if (hg_atomic_get32(&private_context->completion_queue_must_notify)) {
            rc = hg_event_set(private_context->completion_queue_notify);
            HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, unlock, ret, HG_FAULT,
                "Could not signal completion queue");
        }
unlock:
        hg_thread_mutex_unlock(&private_context->completion_queue_notify_mutex);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress(
    struct hg_core_private_context *context, unsigned int timeout_ms)
{
    hg_time_t deadline, now = hg_time_from_ms(0);
    hg_return_t ret;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    do {
        hg_bool_t safe_wait = HG_FALSE, progressed = HG_FALSE;
        unsigned int poll_timeout = 0;

        /* Bypass notifications if timeout_ms is 0 to prevent system calls */
        if (timeout_ms == 0) {
            ; // nothing to do
        } else if (context->poll_set) {
            hg_thread_mutex_lock(&context->completion_queue_notify_mutex);

            if (hg_core_poll_try_wait(context)) {
                safe_wait = HG_TRUE;
                poll_timeout = hg_time_to_ms(hg_time_subtract(deadline, now));

                /* We need to be notified when doing blocking progress */
                hg_atomic_set32(&context->completion_queue_must_notify, 1);
            }
            hg_thread_mutex_unlock(&context->completion_queue_notify_mutex);
        } else if (!HG_CORE_CONTEXT_CLASS(context)->loopback &&
                   hg_core_poll_try_wait(context)) {
            /* This is the case for NA plugins that don't expose a fd */
            poll_timeout = hg_time_to_ms(hg_time_subtract(deadline, now));
        }

        /* Only enter blocking wait if it is safe to */
        if (safe_wait) {
            ret = hg_core_poll_wait(context, poll_timeout, &progressed);
            HG_CHECK_HG_ERROR(
                error, ret, "Could not make blocking progress on context");
        } else {
            ret = hg_core_poll(context, poll_timeout, &progressed);
            HG_CHECK_HG_ERROR(
                error, ret, "Could not make non-blocking progress on context");
        }

        /* We progressed or we have something to trigger */
        if (progressed ||
            !hg_atomic_queue_is_empty(context->completion_queue) ||
            (hg_atomic_get32(&context->backfill_queue_count) > 0))
            return HG_SUCCESS;

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
    } while (hg_time_less(now, deadline));

    return HG_TIMEOUT;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_bool_t
hg_core_poll_try_wait(struct hg_core_private_context *context)
{
    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(context->completion_queue) ||
        (hg_atomic_get32(&context->backfill_queue_count) > 0))
        return HG_FALSE;

#ifdef NA_HAS_SM
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
hg_core_poll_wait(struct hg_core_private_context *context,
    unsigned int timeout_ms, hg_bool_t *progressed_ptr)
{
    unsigned int i, nevents;
    hg_return_t ret = HG_SUCCESS;
    hg_bool_t progressed = HG_FALSE;
    int rc;

    rc = hg_poll_wait(context->poll_set, timeout_ms, HG_CORE_MAX_EVENTS,
        context->poll_events, &nevents);

    /* No longer need to notify when we're not waiting */
    hg_atomic_set32(&context->completion_queue_must_notify, 0);

    HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_PROTOCOL_ERROR,
        "hg_poll_wait() failed");

    if (nevents == 1 && (context->poll_events[0].events & HG_POLLINTR)) {
        HG_LOG_DEBUG("Interrupted");
        *progressed_ptr = progressed;
        return ret;
    }

    /* Process events */
    for (i = 0; i < nevents; i++) {
        hg_bool_t progressed_event = HG_FALSE;

        switch (context->poll_events[i].data.u32) {
            case HG_CORE_POLL_LOOPBACK:
                HG_LOG_DEBUG("HG_CORE_POLL_LOOPBACK event");
                ret = hg_core_progress_loopback_notify(
                    context, &progressed_event);
                HG_CHECK_HG_ERROR(
                    done, ret, "hg_core_progress_loopback_notify() failed");
                break;
#ifdef NA_HAS_SM
            case HG_CORE_POLL_SM:
                HG_LOG_DEBUG("HG_CORE_POLL_SM event");

                /* TODO force epoll_wait */
                ret = hg_core_progress_na(
                    HG_CORE_CONTEXT_CLASS(context)->core_class.na_sm_class,
                    context->core_context.na_sm_context, 0, &progressed_event);
                HG_CHECK_HG_ERROR(done, ret, "hg_core_progress_na() failed");
                break;
#endif
            case HG_CORE_POLL_NA:
                HG_LOG_DEBUG("HG_CORE_POLL_NA event");

                /* TODO force epoll_wait */
                ret = hg_core_progress_na(
                    HG_CORE_CONTEXT_CLASS(context)->core_class.na_class,
                    context->core_context.na_context, 0, &progressed_event);
                HG_CHECK_HG_ERROR(done, ret, "hg_core_progress_na() failed");
                break;
            default:
                HG_GOTO_ERROR(done, ret, HG_INVALID_ARG,
                    "Invalid type of poll event (%d)",
                    (int) context->poll_events[i].data.u32);
        }
        progressed |= progressed_event;
    }

    *progressed_ptr = progressed;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_poll(struct hg_core_private_context *context, unsigned int timeout_ms,
    hg_bool_t *progressed_ptr)
{
    hg_bool_t progressed = HG_FALSE, progressed_na = HG_FALSE;
    unsigned int progress_timeout;
    hg_return_t ret;

#ifdef NA_HAS_SM
    /* Poll over SM first if set */
    if (context->core_context.na_sm_context) {
        ret = hg_core_progress_na(
            HG_CORE_CONTEXT_CLASS(context)->core_class.na_sm_class,
            context->core_context.na_sm_context, 0, &progressed_na);
        HG_CHECK_HG_ERROR(done, ret, "hg_core_progress_na() failed");

        progressed |= progressed_na;

        progress_timeout = 0;
    } else {
#endif
        progress_timeout = timeout_ms;
#ifdef NA_HAS_SM
    }
#endif

    /* Poll over defaut NA */
    ret =
        hg_core_progress_na(HG_CORE_CONTEXT_CLASS(context)->core_class.na_class,
            context->core_context.na_context, progress_timeout, &progressed_na);
    HG_CHECK_HG_ERROR(done, ret, "hg_core_progress_na() failed");

    *progressed_ptr = progressed | progressed_na;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_na(na_class_t *na_class, na_context_t *na_context,
    unsigned int timeout_ms, hg_bool_t *progressed_ptr)
{
    hg_time_t deadline, now = hg_time_from_ms(0);
    unsigned int completed_count = 0;
    hg_bool_t progressed = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    for (;;) {
        unsigned int actual_count = 0;
        na_return_t na_ret;

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
            progressed = HG_TRUE;
            break;
        }

        /* Make sure that timeout of 0 enters progress */
        if (timeout_ms != 0 && !hg_time_less(now, deadline))
            break;

        /* Otherwise try to make progress on NA */
        na_ret = NA_Progress(na_class, na_context,
            hg_time_to_ms(hg_time_subtract(deadline, now)));

        if (na_ret == NA_TIMEOUT)
            break;

        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not make progress on NA (%s)", NA_Error_to_string(na_ret));

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
    }

    *progressed_ptr = progressed;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_progress_loopback_notify(
    struct hg_core_private_context *context, hg_bool_t *progressed_ptr)
{
    hg_return_t ret = HG_SUCCESS;
    int rc;

    /* TODO we should be able to safely remove EFD_SEMAPHORE behavior */
    rc =
        hg_event_get(context->completion_queue_notify, (bool *) progressed_ptr);
    HG_CHECK_ERROR(rc != HG_UTIL_SUCCESS, done, ret, HG_PROTOCOL_ERROR,
        "Could not get completion notification");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger(struct hg_core_private_context *context,
    unsigned int timeout_ms, unsigned int max_count, unsigned int *actual_count)
{
    hg_time_t deadline, now = hg_time_from_ms(0);
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

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
                /* If something was already processed leave */
                if (count)
                    break;

                /* Timeout is 0 so leave */
                if (!hg_time_less(now, deadline)) {
                    ret = HG_TIMEOUT;
                    break;
                }

                hg_thread_mutex_lock(&context->completion_queue_mutex);
                /* Otherwise wait remaining ms */
                if (hg_atomic_queue_is_empty(context->completion_queue) &&
                    !hg_atomic_get32(&context->backfill_queue_count)) {
                    if (hg_thread_cond_timedwait(
                            &context->completion_queue_cond,
                            &context->completion_queue_mutex,
                            hg_time_to_ms(hg_time_subtract(deadline, now))) !=
                        HG_UTIL_SUCCESS)
                        ret = HG_TIMEOUT; /* Timeout occurred so leave */
                }
                hg_thread_mutex_unlock(&context->completion_queue_mutex);
                if (ret == HG_TIMEOUT)
                    break;

                if (timeout_ms != 0)
                    hg_time_get_current_ms(&now);
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

    /* NB. OK to free after callback execution, op ID is not re-used */
    free(hg_core_op_id);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_entry(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_atomic_and32(&hg_core_handle->status, ~HG_CORE_OP_QUEUED);

    if (hg_core_handle->op_type == HG_CORE_PROCESS) {

        /* Simply exit if error occurred */
        if (hg_core_handle->ret != HG_SUCCESS)
            HG_GOTO_DONE(done, ret, HG_SUCCESS);

        /* Take another reference to make sure the handle only gets freed
         * after the response is sent */
        hg_atomic_incr32(&hg_core_handle->ref_count);

        /* Run RPC callback */
        ret = hg_core_process(hg_core_handle);
        if (ret != HG_SUCCESS && !hg_core_handle->no_response) {
            hg_size_t header_size =
                hg_core_header_response_get_size() +
                hg_core_handle->core_handle.na_out_header_offset;

            /* Respond in case of error */
            ret = hg_core_respond(
                hg_core_handle, NULL, NULL, 0, header_size, ret);
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

        hg_core_cb_info.ret = hg_core_handle->ret;
        switch (hg_core_handle->op_type) {
            case HG_CORE_FORWARD_SELF:
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
            case HG_CORE_RESPOND_SELF:
                hg_cb = hg_core_self_cb;
                hg_core_cb_info.arg = hg_core_handle->response_arg;
                hg_core_cb_info.type = HG_CB_RESPOND;
                hg_core_cb_info.info.respond.handle =
                    (hg_core_handle_t) hg_core_handle;
                break;
            case HG_CORE_NO_RESPOND:
                /* Nothing */
                break;
            case HG_CORE_PROCESS:
            default:
                HG_GOTO_ERROR(done, ret, HG_OPNOTSUPPORTED,
                    "Invalid core operation type");
        }

        /* Execute user callback.
         * NB. The handle cannot be destroyed before the callback execution as
         * the user may carry the handle in the callback. */
        if (hg_cb)
            hg_cb(&hg_core_cb_info);
    }

done:
    /* Repost handle if we were listening, otherwise destroy it */
    ret = hg_core_destroy(hg_core_handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not destroy handle");

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_cancel(struct hg_core_private_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    int32_t status;

    HG_CHECK_ERROR(hg_core_handle->is_self, done, ret, HG_OPNOTSUPPORTED,
        "Local cancellation is not supported");

    /* Exit if op has already completed */
    status = hg_atomic_get32(&hg_core_handle->status);
    if ((status & HG_CORE_OP_COMPLETED) || (status & HG_CORE_OP_ERRORED) ||
        (status & HG_CORE_OP_CANCELED))
        return HG_SUCCESS;

    /* Let only one thread call NA_Cancel() */
    if (hg_atomic_or32(&hg_core_handle->status, HG_CORE_OP_CANCELED) &
        HG_CORE_OP_CANCELED)
        return HG_SUCCESS;

    /* Cancel all NA operations issued */
    if (hg_core_handle->na_recv_op_id != NULL) {
        na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_handle->na_recv_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not cancel recv op id (%s)", NA_Error_to_string(na_ret));
    }

    if (hg_core_handle->na_send_op_id != NULL) {
        na_return_t na_ret = NA_Cancel(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_handle->na_send_op_id);
        HG_CHECK_ERROR(na_ret != NA_SUCCESS, done, ret, (hg_return_t) na_ret,
            "Could not cancel send op id (%s)", NA_Error_to_string(na_ret));
    }

    if (hg_core_handle->na_ack_op_id != NULL) {
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
    struct hg_core_private_class *hg_core_class = NULL;

    HG_LOG_DEBUG("Initializing with %s, listen=%d", na_info_string, na_listen);

    hg_core_class = hg_core_init(na_info_string, na_listen, NULL);
    HG_CHECK_ERROR_NORET(
        hg_core_class == NULL, done, "Cannot initialize HG core layer");

    HG_LOG_DEBUG("Initialized core class (%p)", (void *) hg_core_class);

done:
    return (hg_core_class_t *) hg_core_class;
}

/*---------------------------------------------------------------------------*/
hg_core_class_t *
HG_Core_init_opt(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_core_private_class *hg_core_class = NULL;

    HG_LOG_DEBUG("Initializing with %s, listen=%d", na_info_string, na_listen);

    hg_core_class = hg_core_init(na_info_string, na_listen, hg_init_info);
    HG_CHECK_ERROR_NORET(
        hg_core_class == NULL, done, "Cannot initialize HG core layer");

    HG_LOG_DEBUG("Initialized core class (%p)", (void *) hg_core_class);

done:
    return (hg_core_class_t *) hg_core_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_finalize(hg_core_class_t *hg_core_class)
{
    hg_return_t ret;

    HG_LOG_DEBUG("Finalizing core class (%p)", (void *) hg_core_class);

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
    struct hg_core_private_context *context = NULL;
    hg_return_t ret;

    HG_CHECK_ERROR_NORET(hg_core_class == NULL, done, "NULL HG core class");

    HG_LOG_DEBUG("Creating new context with id=%u", 0);

    ret = hg_core_context_create(hg_core_class, 0, &context);
    HG_CHECK_HG_ERROR(done, ret, "Could not create context");

    HG_LOG_DEBUG("Created new context (%p)", (void *) context);

done:
    return (hg_core_context_t *) context;
}

/*---------------------------------------------------------------------------*/
hg_core_context_t *
HG_Core_context_create_id(hg_core_class_t *hg_core_class, hg_uint8_t id)
{
    struct hg_core_private_context *context = NULL;
    hg_return_t ret;

    HG_CHECK_ERROR_NORET(hg_core_class == NULL, done, "NULL HG core class");

    HG_LOG_DEBUG("Creating new context with id=%u", id);

    ret = hg_core_context_create(hg_core_class, id, &context);
    HG_CHECK_HG_ERROR(done, ret, "Could not create context");

    HG_LOG_DEBUG("Created new context (%p)", (void *) context);

done:
    return (hg_core_context_t *) context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_destroy(hg_core_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    HG_LOG_DEBUG("Destroying context (%p)", (void *) context);

    ret = hg_core_context_destroy((struct hg_core_private_context *) context);
    HG_CHECK_HG_ERROR(done, ret, "Could not destroy context");

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
HG_Core_context_post(hg_core_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;
    hg_bool_t posted = HG_FALSE;
    unsigned int request_count;

    HG_CHECK_ERROR(
        context == NULL, error, ret, HG_INVALID_ARG, "NULL HG core context");

    /* Get request count from init info */
    request_count = ((struct hg_core_private_class *) context->core_class)
                        ->request_post_init;
    HG_CHECK_ERROR(request_count == 0, error, ret, HG_INVALID_ARG,
        "Request count must be greater than 0");
    HG_LOG_DEBUG(
        "Posting %u requests on context (%p)", request_count, (void *) context);

    ret = hg_core_context_post((struct hg_core_private_context *) context,
        context->core_class->na_class, context->na_context, request_count);
    HG_CHECK_HG_ERROR(error, ret, "Could not post requests on context");
    posted = HG_TRUE;

#ifdef NA_HAS_SM
    if (context->na_sm_context) {
        ret = hg_core_context_post((struct hg_core_private_context *) context,
            context->core_class->na_sm_class, context->na_sm_context,
            request_count);
        HG_CHECK_HG_ERROR(error, ret, "Could not post SM requests on context");
    }
#endif

    HG_LOG_DEBUG(
        "Posted %u handles on context (%p)", request_count, (void *) context);

    return ret;

error:
    if (posted)
        hg_core_context_unpost((struct hg_core_private_context *) context);

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

    // TODO use RW lock

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
    *flag = (hg_bool_t) (hg_hash_table_lookup(private_class->func_map,
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
    HG_CHECK_ERROR(name == NULL, done, ret, HG_INVALID_ARG, "NULL lookup name");
    (void) op_id;

    HG_LOG_DEBUG("Looking up \"%s\"", name);

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

    HG_LOG_DEBUG("Created new address (%p)",
        (void *) hg_core_op_id->info.lookup.hg_core_addr);

    /* Add callback to completion queue */
    hg_completion_entry = &hg_core_op_id->hg_completion_entry;
    hg_completion_entry->op_type = HG_ADDR;
    hg_completion_entry->op_id.hg_core_op_id = hg_core_op_id;

    (void) hg_core_completion_add(context, hg_completion_entry, HG_TRUE);

done:
    return ret;

error:
    if (hg_core_op_id) {
        hg_core_addr_free(hg_core_op_id->info.lookup.hg_core_addr);
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
    HG_CHECK_ERROR(name == NULL, done, ret, HG_INVALID_ARG, "NULL lookup name");
    HG_CHECK_ERROR(
        addr == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to address");

    HG_LOG_DEBUG("Looking up \"%s\"", name);

    ret = hg_core_addr_lookup((struct hg_core_private_class *) hg_core_class,
        name, (struct hg_core_private_addr **) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not lookup address");

    HG_LOG_DEBUG("Created new address (%p)", (void *) *addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_free(hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_LOG_DEBUG("Freeing address (%p)", (void *) addr);

    ret = hg_core_addr_free((struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not free address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_set_remove(hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(addr == HG_CORE_ADDR_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core address");

    ret = hg_core_addr_set_remove((struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not set address to be removed");

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
    HG_CHECK_ERROR(addr == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to core address");

    ret = hg_core_addr_self((struct hg_core_private_class *) hg_core_class,
        (struct hg_core_private_addr **) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not get self address");

    HG_LOG_DEBUG("Created new self address (%p)", (void *) *addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_dup(hg_core_addr_t addr, hg_core_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(addr == HG_CORE_ADDR_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core address");
    HG_CHECK_ERROR(new_addr == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to dup addr");

    ret = hg_core_addr_dup((struct hg_core_private_addr *) addr,
        (struct hg_core_private_addr **) new_addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not duplicate address");

    HG_LOG_DEBUG("Duped address (%p) to address (%p)", (void *) addr,
        (void *) *new_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_bool_t
HG_Core_addr_cmp(hg_core_addr_t addr1, hg_core_addr_t addr2)
{
    hg_bool_t ret = HG_FALSE;

    if (addr1 == HG_CORE_ADDR_NULL && addr2 == HG_CORE_ADDR_NULL)
        HG_GOTO_DONE(done, ret, HG_TRUE);

    if (addr1 == HG_CORE_ADDR_NULL || addr2 == HG_CORE_ADDR_NULL)
        HG_GOTO_DONE(done, ret, HG_FALSE);

    ret = hg_core_addr_cmp((struct hg_core_private_addr *) addr1,
        (struct hg_core_private_addr *) addr2);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_to_string(char *buf, hg_size_t *buf_size, hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(buf_size == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to buffer size");
    HG_CHECK_ERROR(addr == HG_CORE_ADDR_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core address");

    ret = hg_core_addr_to_string(
        buf, buf_size, (struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not convert address to string");

    if (buf) {
        HG_LOG_DEBUG(
            "Generated string \"%s\" from address (%p)", buf, (void *) addr);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Core_addr_get_serialize_size(hg_core_addr_t addr, unsigned long flags)
{
    hg_size_t ret = 0;

    HG_CHECK_ERROR_NORET(
        addr == HG_CORE_ADDR_NULL, done, "NULL HG core address");

    ret = hg_core_addr_get_serialize_size(
        (struct hg_core_private_addr *) addr, flags & 0xff);

    HG_LOG_DEBUG("Serialize size is %" PRIu64 " bytes for address (%p)", ret,
        (void *) addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_serialize(
    void *buf, hg_size_t buf_size, unsigned long flags, hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        buf == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to buffer");
    HG_CHECK_ERROR(
        buf_size == 0, done, ret, HG_INVALID_ARG, "NULL buffer size");
    HG_CHECK_ERROR(addr == HG_CORE_ADDR_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core address");

    HG_LOG_DEBUG("Serializing address (%p)", (void *) addr);

    ret = hg_core_addr_serialize(
        buf, buf_size, flags & 0xff, (struct hg_core_private_addr *) addr);
    HG_CHECK_HG_ERROR(done, ret, "Could not serialize address");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_deserialize(hg_core_class_t *hg_core_class, hg_core_addr_t *addr,
    const void *buf, hg_size_t buf_size)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_core_class == NULL, done, ret, HG_INVALID_ARG, "NULL HG core class");
    HG_CHECK_ERROR(addr == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to HG core address");
    HG_CHECK_ERROR(
        buf == NULL, done, ret, HG_INVALID_ARG, "NULL pointer to buffer");
    HG_CHECK_ERROR(
        buf_size == 0, done, ret, HG_INVALID_ARG, "NULL buffer size");

    ret =
        hg_core_addr_deserialize((struct hg_core_private_class *) hg_core_class,
            (struct hg_core_private_addr **) addr, buf, buf_size);
    HG_CHECK_HG_ERROR(done, ret, "Could not deserialize address");

    HG_LOG_DEBUG("Deserialized into new address (%p)", (void *) *addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_create(hg_core_context_t *context, hg_core_addr_t addr, hg_id_t id,
    hg_core_handle_t *handle)
{
    struct hg_core_private_handle *hg_core_handle = NULL;
    struct hg_core_private_addr *hg_core_addr =
        (struct hg_core_private_addr *) addr;
    na_class_t *na_class;
    na_context_t *na_context;
    na_addr_t na_addr = NA_ADDR_NULL;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        context == NULL, done, ret, HG_INVALID_ARG, "NULL HG core context");
    HG_CHECK_ERROR(handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL pointer to HG core handle");

    HG_LOG_DEBUG("Creating new handle with ID=%" PRIu64 ", address=%p", id,
        (void *) addr);

    /* Determine which NA class/context to use */
#ifdef NA_HAS_SM
    if (hg_core_addr && !hg_core_addr->core_addr.is_self &&
        (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL)) {
        HG_LOG_DEBUG("Using NA SM class for this handle");
        na_class = context->core_class->na_sm_class;
        na_context = context->na_sm_context;
        na_addr = hg_core_addr->core_addr.na_sm_addr;
    } else {
#endif
        HG_LOG_DEBUG("Using default NA class for this handle");

        /* Default */
        na_class = context->core_class->na_class;
        na_context = context->na_context;
        if (hg_core_addr)
            na_addr = hg_core_addr->core_addr.na_addr;
#ifdef NA_HAS_SM
    }
#endif

    /* Create new handle */
    ret = hg_core_create((struct hg_core_private_context *) context, na_class,
        na_context, &hg_core_handle);
    HG_CHECK_HG_ERROR(error, ret, "Could not create HG core handle");

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, hg_core_addr, na_addr, id);
    if (ret == HG_NOENTRY)
        goto error;
    HG_CHECK_HG_ERROR(error, ret, "Could not set new RPC info to handle");

    HG_LOG_DEBUG("Created new handle (%p)", (void *) hg_core_handle);

    *handle = (hg_core_handle_t) hg_core_handle;

done:
    return ret;

error:
    hg_core_destroy(hg_core_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_destroy(hg_core_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (handle == HG_CORE_HANDLE_NULL)
        goto done;

    HG_LOG_DEBUG("Destroying handle (%p)", (void *) handle);

    ret = hg_core_destroy((struct hg_core_private_handle *) handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not destroy handle");

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
    na_class_t *na_class;
    na_context_t *na_context;
    na_addr_t na_addr = NA_ADDR_NULL;
    hg_return_t ret = HG_SUCCESS;
    int32_t status;

    HG_CHECK_ERROR(hg_core_handle == NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");

    /* Not safe to reset unless in completed state */
    status = hg_atomic_get32(&hg_core_handle->status);
    HG_CHECK_ERROR(
        !(status & HG_CORE_OP_COMPLETED) || (status & HG_CORE_OP_QUEUED), done,
        ret, HG_BUSY, "Cannot reset HG core handle, still in use");

    HG_LOG_DEBUG("Resetting handle (%p) with ID=%" PRIu64 ", address (%p)",
        (void *) handle, id, (void *) addr);

    /* Determine which NA class/context to use */
#ifdef NA_HAS_SM
    if (hg_core_addr && !hg_core_addr->core_addr.is_self &&
        (hg_core_addr->core_addr.na_sm_addr != NA_ADDR_NULL)) {
        HG_LOG_DEBUG("Using NA SM class for this handle");

        na_class = hg_core_handle->core_handle.info.core_class->na_sm_class;
        na_context = hg_core_handle->core_handle.info.context->na_sm_context;
        na_addr = hg_core_addr->core_addr.na_sm_addr;
    } else {
#endif
        HG_LOG_DEBUG("Using default NA class for this handle");

        /* Default */
        na_class = hg_core_handle->core_handle.info.core_class->na_class;
        na_context = hg_core_handle->core_handle.info.context->na_context;
        if (hg_core_addr)
            na_addr = hg_core_addr->core_addr.na_addr;
#ifdef NA_HAS_SM
    }
#endif

    /* In that case, we must free and re-allocate NA resources */
    if (na_class != hg_core_handle->na_class) {
        ret = hg_core_free_na(hg_core_handle);
        HG_CHECK_HG_ERROR(done, ret, "Could not release NA resources");

        ret = hg_core_alloc_na(hg_core_handle, na_class, na_context);
        HG_CHECK_HG_ERROR(done, ret, "Could not re-allocate NA resources");
    }

    /* Reset handle */
    hg_core_reset(hg_core_handle);

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, hg_core_addr, na_addr, id);
    if (ret == HG_NOENTRY)
        goto done;
    HG_CHECK_HG_ERROR(done, ret, "Could not set new RPC info to handle");

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
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(handle == HG_CORE_HANDLE_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");
    HG_CHECK_ERROR(handle->info.addr == HG_CORE_ADDR_NULL, done, ret,
        HG_INVALID_ARG, "NULL target addr");
    HG_CHECK_ERROR(
        handle->info.id == 0, done, ret, HG_INVALID_ARG, "NULL RPC ID");

    HG_LOG_DEBUG("Forwarding handle (%p), payload size is %" PRIu64,
        (void *) handle, payload_size);

    ret = hg_core_forward((struct hg_core_private_handle *) handle, callback,
        arg, flags, payload_size);
    HG_CHECK_HG_ERROR(done, ret, "Could not forward handle");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_respond(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    hg_uint8_t flags, hg_size_t payload_size)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(handle == HG_CORE_HANDLE_NULL, done, ret, HG_INVALID_ARG,
        "NULL HG core handle");

    HG_LOG_DEBUG("Responding on handle (%p), payload size is %" PRIu64,
        (void *) handle, payload_size);

    /* Explicit response return code is always success here */
    ret = hg_core_respond((struct hg_core_private_handle *) handle, callback,
        arg, flags, payload_size, HG_SUCCESS);
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

    HG_LOG_DEBUG("Canceling handle (%p)", (void *) handle);

    ret = hg_core_cancel((struct hg_core_private_handle *) handle);
    HG_CHECK_HG_ERROR(done, ret, "Could not cancel handle");

done:
    return ret;
}
