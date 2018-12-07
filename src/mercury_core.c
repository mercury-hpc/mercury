/*
 * Copyright (C) 2013-2018 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_core.h"
#include "mercury_core_header.h"
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
#include "mercury_mem.h"

#ifdef HG_HAS_SM_ROUTING
#include <uuid/uuid.h>
#endif

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_CORE_MAX_SELF_THREADS    4
#define HG_CORE_MASK_NBITS          8
#define HG_CORE_ATOMIC_QUEUE_SIZE   1024
#define HG_CORE_PENDING_INCR        256
#define HG_CORE_PROCESSING_TIMEOUT  1000
#ifdef HG_HAS_SM_ROUTING
# define HG_CORE_UUID_MAX_LEN       36
# define HG_CORE_ADDR_MAX_SIZE      256
# define HG_CORE_PROTO_DELIMITER    ":"
# define HG_CORE_ADDR_DELIMITER     ";"
# define HG_CORE_MIN(a, b)          (a < b) ? a : b /* Min macro */
#endif

/* Remove warnings when routine does not use arguments */
#if defined(__cplusplus)
# define HG_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
# define HG_UNUSED __attribute__((unused))
#else
# define HG_UNUSED
#endif

/* Map stat type to either 32-bit atomic or 64-bit */
#ifdef HG_HAS_COLLECT_STATS
#ifndef HG_UTIL_HAS_OPA_PRIMITIVES_H
typedef hg_atomic_int64_t hg_core_stat_t;
#define hg_core_stat_incr hg_atomic_incr64
#define hg_core_stat_get hg_atomic_get64
#else
typedef hg_atomic_int32_t hg_core_stat_t;
#define hg_core_stat_incr hg_atomic_incr32
#define hg_core_stat_get hg_atomic_get32
#endif
#define HG_CORE_STAT_INIT HG_ATOMIC_VAR_INIT
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG class */
struct hg_core_class {
    na_class_t *na_class;               /* NA class */
#ifdef HG_HAS_SM_ROUTING
    na_class_t *na_sm_class;            /* NA SM class */
    uuid_t na_sm_uuid;                  /* UUID for local identification */
#endif
    hg_hash_table_t *func_map;          /* Function map */
    hg_thread_spin_t func_map_lock;     /* Function map mutex */
    hg_atomic_int32_t request_tag;      /* Atomic used for tag generation */
    na_tag_t request_max_tag;           /* Max value for tag */
    hg_bool_t na_ext_init;              /* NA externally initialized */
    na_progress_mode_t progress_mode;   /* NA progress mode */
#ifdef HG_HAS_COLLECT_STATS
    hg_bool_t stats;                    /* (Debug) Print stats at exit */
#endif
    void *data;                         /* User data */
    void (*data_free_callback)(void *); /* User data free callback */
    hg_atomic_int32_t n_contexts;       /* Atomic used for number of contexts */
    hg_atomic_int32_t n_addrs;          /* Atomic used for number of addrs */

    /* Callbacks */
    hg_return_t (*more_data_acquire)(hg_core_handle_t, hg_op_t,
        hg_return_t (*done_callback)(hg_core_handle_t)); /* more_data_acquire */
    void (*more_data_release)(hg_core_handle_t); /* more_data_release */
};

/* HG context */
struct hg_core_context {
    struct hg_core_class *hg_core_class;          /* HG core class */
    na_context_t *na_context;                     /* NA context */
#ifdef HG_HAS_SM_ROUTING
    na_context_t *na_sm_context;                  /* NA SM context */
#endif
    hg_uint8_t id;                                /* Context ID */
    struct hg_poll_set *poll_set;                 /* Context poll set */
    /* Pointer to function used for making progress */
    hg_return_t (*progress)(struct hg_core_context *context, unsigned int timeout);
    struct hg_atomic_queue *completion_queue;     /* Default completion queue */
    HG_QUEUE_HEAD(hg_completion_entry) backfill_queue; /* Backfill completion queue */
    hg_atomic_int32_t backfill_queue_count;       /* Backfill queue count */
    hg_thread_mutex_t completion_queue_mutex;     /* Completion queue mutex */
    hg_thread_cond_t  completion_queue_cond;      /* Completion queue cond */
    hg_atomic_int32_t trigger_waiting;            /* Waiting in trigger */
    HG_LIST_HEAD(hg_core_handle) pending_list;    /* List of pending handles */
    hg_thread_spin_t pending_list_lock;           /* Pending list lock */
#ifdef HG_HAS_SM_ROUTING
    HG_LIST_HEAD(hg_core_handle) sm_pending_list; /* List of SM pending handles */
    hg_thread_spin_t sm_pending_list_lock;        /* SM pending list lock */
#endif
    HG_LIST_HEAD(hg_core_handle) created_list;    /* List of handles for that context */
    hg_thread_spin_t created_list_lock;           /* Handle list lock */
#ifdef HG_HAS_SELF_FORWARD
    int completion_queue_notify;                  /* Self notification */
    hg_thread_pool_t *self_processing_pool;       /* Thread pool for self processing */
#endif
    hg_return_t (*handle_create)(hg_core_handle_t, void *); /* handle_create */
    void *handle_create_arg;                      /* handle_create arg */
    void *data;                                   /* User data */
    void (*data_free_callback)(void *);           /* User data free callback */
    hg_bool_t finalizing;                         /* Prevent reposts */
    hg_atomic_int32_t n_handles;                  /* Atomic used for number of handles */
};

/* Info for function map */
struct hg_core_rpc_info {
    hg_core_rpc_cb_t rpc_cb;        /* RPC callback */
    void *data;                     /* User data */
    void (*free_callback)(void *);  /* User data free callback */
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
struct hg_core_addr {
    na_class_t *na_class;               /* NA class from NA address */
    na_addr_t na_addr;                  /* NA address */
#ifdef HG_HAS_SM_ROUTING
    na_addr_t na_sm_addr;               /* NA SM address */
    uuid_t na_sm_uuid;                  /* NA SM UUID */
#endif
    hg_bool_t is_mine;                  /* Created internally or not */
    hg_atomic_int32_t ref_count;        /* Reference count */
};

/* HG core op type */
typedef enum {
    HG_CORE_FORWARD,             /*!< Forward completion */
    HG_CORE_RESPOND,             /*!< Respond completion */
    HG_CORE_NO_RESPOND,          /*!< No response completion */
#ifdef HG_HAS_SELF_FORWARD
    HG_CORE_FORWARD_SELF,        /*!< Self forward completion */
    HG_CORE_RESPOND_SELF,        /*!< Self respond completion */
#endif
    HG_CORE_PROCESS              /*!< Process completion */
} hg_core_op_type_t;

/* HG core handle */
struct hg_core_handle {
    struct hg_core_info hg_info;        /* HG info */
    na_class_t *na_class;               /* NA class */
    na_context_t *na_context;           /* NA context */
    hg_core_cb_t request_callback;      /* Request callback */
    void *request_arg;                  /* Request callback arguments */
    hg_core_cb_t response_callback;     /* Response callback */
    void *response_arg;                 /* Response callback arguments */
    hg_core_op_type_t op_type;          /* Core operation type */
    na_tag_t tag;                       /* Tag used for request and response */
    hg_uint8_t cookie;                  /* Cookie */
    hg_return_t ret;                    /* Return code associated to handle */
    HG_LIST_ENTRY(hg_core_handle) created;  /* Created list entry */
    HG_LIST_ENTRY(hg_core_handle) pending;  /* Pending list entry */
    struct hg_completion_entry hg_completion_entry; /* Entry in completion queue */
    hg_bool_t repost;                   /* Repost handle on completion (listen) */
    hg_bool_t is_self;                  /* Self processed */
    hg_atomic_int32_t in_use;           /* Is in use */
    hg_bool_t no_response;              /* Require response or not */

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
    void *ack_buf;                      /* Ack buf for more data */
    void *ack_buf_plugin_data;          /* Ack plugin data */

    na_op_id_t na_send_op_id;           /* Operation ID for send */
    na_op_id_t na_recv_op_id;           /* Operation ID for recv */
    na_op_id_t na_ack_op_id;            /* Operation ID for ack */
    unsigned int na_op_count;           /* Number of ongoing operations */
    hg_atomic_int32_t na_op_completed_count;    /* Number of NA operations completed */
    hg_bool_t na_op_id_mine;            /* Operation ID created by HG */

    hg_atomic_int32_t ref_count;        /* Reference count */

    struct hg_core_header in_header;    /* Input header */
    struct hg_core_header out_header;   /* Output header */

    struct hg_core_rpc_info *hg_core_rpc_info;  /* Associated RPC info */
    void *data;                         /* User data */
    void (*data_free_callback)(void *); /* User data free callback */

    struct hg_thread_work thread_work;  /* Used for self processing and testing */

    /* Callbacks */
    hg_return_t (*forward)(
        struct hg_core_handle *hg_core_handle
        ); /* forward */
    hg_return_t (*respond)(
        struct hg_core_handle *hg_core_handle
        ); /* respond */
    hg_return_t (*no_respond)(
        struct hg_core_handle *hg_core_handle
        ); /* no_respond */
};

/* HG op id */
struct hg_core_op_info_lookup {
    struct hg_core_addr *hg_core_addr;  /* Address */
    na_op_id_t na_lookup_op_id;         /* Operation ID for lookup */
};

struct hg_core_op_id {
    struct hg_core_context *context;    /* Context */
    hg_cb_type_t type;                  /* Callback type */
    hg_core_cb_t callback;              /* Callback */
    void *arg;                          /* Callback arguments */
    hg_atomic_int32_t completed;        /* Operation completed TODO needed ? */
    union {
        struct hg_core_op_info_lookup lookup;
    } info;
    struct hg_completion_entry hg_completion_entry; /* Entry in completion queue */
};

/********************/
/* Local Prototypes */
/********************/

#ifdef HG_HAS_SM_ROUTING
/**
 * Get local ID used for detecting local nodes.
 */
static hg_return_t
hg_core_get_sm_uuid(
        uuid_t *sm_uuid
        );
#endif

/**
 * Equal function for function map.
 */
static HG_INLINE int
hg_core_int_equal(
        void *vlocation1,
        void *vlocation2
        );

/**
 * Hash function for function map.
 */
static HG_INLINE unsigned int
hg_core_int_hash(
        void *vlocation
        );

/**
 * Free function for value in function map.
 */
static void
hg_core_func_map_value_free(
        hg_hash_table_value_t value
        );

/**
 * Generate a new tag.
 */
static HG_INLINE na_tag_t
hg_core_gen_request_tag(
        struct hg_core_class *hg_core_class
        );

/**
 * Retrieve usable buffer to store input payload.
 */
static HG_INLINE void
hg_core_get_input(struct hg_core_handle *hg_core_handle, void **in_buf,
    hg_size_t *in_buf_size);

/**
 * Retrieve usable buffer to store output payload.
 */
static HG_INLINE void
hg_core_get_output(struct hg_core_handle *hg_core_handle, void **out_buf,
    hg_size_t *out_buf_size);

/**
 * Proc request header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_request(
        struct hg_core_handle *hg_core_handle,
        struct hg_core_header *hg_core_header,
        hg_proc_op_t op
        );

/**
 * Proc response header and verify it if decoded.
 */
static HG_INLINE hg_return_t
hg_core_proc_header_response(
        struct hg_core_handle *hg_core_handle,
        struct hg_core_header *hg_core_header,
        hg_proc_op_t op
        );

/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_core_pending_list_cancel(
        struct hg_core_context *context
        );

#ifdef HG_HAS_SM_ROUTING
/**
 * Cancel entries from pending list.
 */
static hg_return_t
hg_core_sm_pending_list_cancel(
        struct hg_core_context *context
        );
#endif

/**
 * Wail until handle list is empty.
 */
static hg_return_t
hg_core_created_list_wait(
        struct hg_core_context *context
        );

/**
 * Initialize class.
 */
static struct hg_core_class *
hg_core_init(
        const char *na_info_string,
        hg_bool_t na_listen,
        const struct hg_init_info *hg_init_info
        );

/**
 * Finalize class.
 */
static hg_return_t
hg_core_finalize(
        struct hg_core_class *hg_core_class
        );

/**
 * Create addr.
 */
static struct hg_core_addr *
hg_core_addr_create(
        struct hg_core_class *hg_core_class,
        na_class_t *na_class
        );

/**
 * Lookup addr.
 */
static hg_return_t
hg_core_addr_lookup(
        struct hg_core_context *context,
        hg_core_cb_t callback,
        void *arg,
        const char *name,
        hg_core_op_id_t *op_id
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
        struct hg_core_op_id *hg_core_op_id
        );

/**
 * Free addr.
 */
static hg_return_t
hg_core_addr_free(
        struct hg_core_class *hg_core_class,
        struct hg_core_addr *hg_core_addr
        );

/**
 * Self addr.
 */
static hg_return_t
hg_core_addr_self(
        struct hg_core_class *hg_core_class,
        struct hg_core_addr **self_addr
        );

/**
 * Dup addr.
 */
static hg_return_t
hg_core_addr_dup(
        struct hg_core_class *hg_core_class,
        struct hg_core_addr *hg_core_addr,
        struct hg_core_addr **hg_new_addr
        );

/**
 * Convert addr to string.
 */
static hg_return_t
hg_core_addr_to_string(
        struct hg_core_class *hg_core_class,
        char *buf,
        hg_size_t *buf_size,
        struct hg_core_addr *hg_core_addr
        );

/**
 * Create handle.
 */
static struct hg_core_handle *
hg_core_create(
        struct hg_core_context *context,
        hg_bool_t use_sm
        );

/**
 * Free handle.
 */
static void
hg_core_destroy(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Reset handle.
 */
static void
hg_core_reset(
        struct hg_core_handle *hg_core_handle,
        hg_bool_t reset_info
        );

/**
 * Set target addr / RPC ID
 */
static hg_return_t
hg_core_set_rpc(
        struct hg_core_handle *hg_core_handle,
        hg_core_addr_t addr,
        hg_id_t id
        );

/**
 * Get RPC registered data.
 */
void *
hg_core_get_rpc_data(
        struct hg_core_handle *hg_core_handle
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Forward handle locally.
 */
static hg_return_t
hg_core_forward_self(
        struct hg_core_handle *hg_core_handle
        );
#endif

/**
 * Forward handle through NA.
 */
static hg_return_t
hg_core_forward_na(
        struct hg_core_handle *hg_core_handle
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Send response locally.
 */
static HG_INLINE hg_return_t
hg_core_respond_self(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Do not send response locally.
 */
static HG_INLINE hg_return_t
hg_core_no_respond_self(
        struct hg_core_handle *hg_core_handle
        );
#endif

/**
 * Send response through NA.
 */
static hg_return_t
hg_core_respond_na(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Do not send response through NA.
 */
static HG_INLINE hg_return_t
hg_core_no_respond_na(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Send input callback.
 */
static HG_INLINE int
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
 * Process input.
 */
static hg_return_t
hg_core_process_input(
        struct hg_core_handle *hg_core_handle,
        hg_bool_t *completed
        );

/**
 * Send output callback.
 */
static HG_INLINE int
hg_core_send_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv output callback.
 */
static HG_INLINE int
hg_core_recv_output_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Process output.
 */
static hg_return_t
hg_core_process_output(
        struct hg_core_handle *hg_core_handle,
        hg_bool_t *completed,
        hg_return_t (*done_callback)(hg_core_handle_t)
        );

/**
 * Send ack for HG_CORE_MORE_DATA flag on output.
 */
static hg_return_t
hg_core_send_ack(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Send ack callback. (HG_CORE_MORE_DATA flag on output)
 */
static HG_INLINE int
hg_core_send_ack_cb(
        const struct na_cb_info *callback_info
        );

/**
 * Recv ack callback. (HG_CORE_MORE_DATA flag on output)
 */
static HG_INLINE int
hg_core_recv_ack_cb(
        const struct na_cb_info *callback_info
        );

#ifdef HG_HAS_SELF_FORWARD
/**
 * Wrapper for local callback execution.
 */
static hg_return_t
hg_core_self_cb(
        const struct hg_core_cb_info *callback_info
        );

/**
 * Process handle thread (used for self execution).
 */
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_core_process_thread(
        void *arg
        );
#endif

/**
 * Process handle.
 */
static hg_return_t
hg_core_process(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Complete handle and NA operation.
 */
static HG_INLINE hg_return_t
hg_core_complete_na(
        struct hg_core_handle *hg_core_handle,
        na_op_id_t *op_id,
        hg_bool_t *completed
        );

/**
 * Complete handle and add to completion queue.
 */
static HG_INLINE hg_return_t
hg_core_complete(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Add entry to completion queue.
 */
hg_return_t
hg_core_completion_add(
        struct hg_core_context *context,
        struct hg_completion_entry *hg_completion_entry,
        hg_bool_t self_notify
        );

/**
 * Start listening for incoming RPC requests.
 */
static hg_return_t
hg_core_context_post(
        struct hg_core_context *context,
        unsigned int request_count,
        hg_bool_t repost,
        hg_bool_t use_sm
        );

/**
 * Post handle and add it to pending list.
 */
static hg_return_t
hg_core_post(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Reset handle and re-post it.
 */
static hg_return_t
hg_core_reset_post(
        struct hg_core_handle *hg_core_handle
        );

/**
 * Make progress on NA layer.
 */
static hg_return_t
hg_core_progress_na(
        struct hg_core_context *context,
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
        int error,
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
        int error,
        hg_util_bool_t *progressed
        );

#ifdef HG_HAS_SM_ROUTING
/**
 * Progress callback on NA SM layer when hg_core_progress_poll() is used.
 */
static int
hg_core_progress_na_sm_cb(
        void *arg,
        unsigned int timeout,
        int error,
        hg_util_bool_t *progressed
        );
#endif

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
        struct hg_core_context *context,
        unsigned int timeout
        );

/**
 * Trigger callbacks.
 */
static hg_return_t
hg_core_trigger(
        struct hg_core_context *context,
        unsigned int timeout,
        unsigned int max_count,
        unsigned int *actual_count
        );

/**
 * Trigger callback from HG lookup op ID.
 */
static hg_return_t
hg_core_trigger_lookup_entry(
        struct hg_core_op_id *hg_core_op_id
        );

/**
 * Trigger callback from HG core handle.
 */
static hg_return_t
hg_core_trigger_entry(
        struct hg_core_handle *hg_core_handle
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
        struct hg_core_handle *hg_core_handle
        );

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
    printf("\n=================================================================\n");
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
#ifdef HG_HAS_SM_ROUTING
static hg_return_t
hg_core_get_sm_uuid(uuid_t *sm_uuid)
{
    const char *sm_path = NA_SM_TMP_DIRECTORY "/" NA_SM_SHM_PREFIX "/uuid.cfg";
    char uuid_str[HG_CORE_UUID_MAX_LEN + 1];
    FILE *uuid_config;
    uuid_t new_uuid;
    na_return_t ret = NA_SUCCESS;

    uuid_config = fopen(sm_path, "r");
    if (!uuid_config) {
        /* Generate a new one */
        uuid_generate(new_uuid);

        uuid_config = fopen(sm_path, "w");
        if (!uuid_config) {
            HG_LOG_ERROR("Could not open %s for write", sm_path);
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        uuid_unparse(new_uuid, uuid_str);
        fprintf(uuid_config, "%s\n", uuid_str);
    } else {
        /* Get the existing one */
        fgets(uuid_str, HG_CORE_UUID_MAX_LEN + 1, uuid_config);
        uuid_parse(uuid_str, new_uuid);
    }
    fclose(uuid_config);
    uuid_copy(*sm_uuid, new_uuid);

done:
    return ret;
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
    struct hg_core_rpc_info *hg_core_rpc_info = (struct hg_core_rpc_info *) value;

    if (hg_core_rpc_info->free_callback)
        hg_core_rpc_info->free_callback(hg_core_rpc_info->data);
    free(hg_core_rpc_info);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE na_tag_t
hg_core_gen_request_tag(struct hg_core_class *hg_core_class)
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
static HG_INLINE void
hg_core_get_input(struct hg_core_handle *hg_core_handle, void **in_buf,
    hg_size_t *in_buf_size)
{
    hg_size_t header_offset = hg_core_header_request_get_size() +
        hg_core_handle->na_in_header_offset;

    /* Space must be left for request header */
    *in_buf = (char *) hg_core_handle->in_buf + header_offset;
    *in_buf_size = hg_core_handle->in_buf_size - header_offset;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE void
hg_core_get_output(struct hg_core_handle *hg_core_handle, void **out_buf,
    hg_size_t *out_buf_size)
{
    hg_size_t header_offset = hg_core_header_response_get_size() +
        hg_core_handle->na_out_header_offset;

    /* Space must be left for response header */
    *out_buf = (char *) hg_core_handle->out_buf + header_offset;
    *out_buf_size = hg_core_handle->out_buf_size - header_offset;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_proc_header_request(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op)
{
    char *header_buf = (char *) hg_core_handle->in_buf +
        hg_core_handle->na_in_header_offset;
    size_t header_buf_size = hg_core_handle->in_buf_size -
        hg_core_handle->na_in_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc request header */
    ret = hg_core_header_request_proc(op, header_buf, header_buf_size,
        hg_core_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process request header");
        goto done;
    }

    if (op == HG_DECODE) {
        ret = hg_core_header_request_verify(hg_core_header);
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
hg_core_proc_header_response(struct hg_core_handle *hg_core_handle,
    struct hg_core_header *hg_core_header, hg_proc_op_t op)
{
    char *header_buf = (char *) hg_core_handle->out_buf +
        hg_core_handle->na_out_header_offset;
    size_t header_buf_size = hg_core_handle->out_buf_size -
        hg_core_handle->na_out_header_offset;
    hg_return_t ret = HG_SUCCESS;

    /* Proc response header */
    ret = hg_core_header_response_proc(op, header_buf, header_buf_size,
        hg_core_header);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process response header");
        goto done;
    }

    if (op == HG_DECODE) {
        ret = hg_core_header_response_verify(hg_core_header);
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
hg_core_pending_list_cancel(struct hg_core_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_spin_lock(&context->pending_list_lock);

    while (!HG_LIST_IS_EMPTY(&context->pending_list)) {
        struct hg_core_handle *hg_core_handle = HG_LIST_FIRST(&context->pending_list);
        HG_LIST_REMOVE(hg_core_handle, pending);

        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not cancel handle");
            break;
        }
    }

    hg_thread_spin_unlock(&context->pending_list_lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SM_ROUTING
static hg_return_t
hg_core_sm_pending_list_cancel(struct hg_core_context *context)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_spin_lock(&context->sm_pending_list_lock);

    while (!HG_LIST_IS_EMPTY(&context->sm_pending_list)) {
        struct hg_core_handle *hg_core_handle = HG_LIST_FIRST(&context->sm_pending_list);
        HG_LIST_REMOVE(hg_core_handle, pending);

        /* Prevent reposts */
        hg_core_handle->repost = HG_FALSE;

        /* Cancel handle */
        ret = hg_core_cancel(hg_core_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not cancel SM handle");
            break;
        }
    }

    hg_thread_spin_unlock(&context->sm_pending_list_lock);

    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_created_list_wait(struct hg_core_context *context)
{
    hg_util_bool_t created_list_empty = HG_UTIL_FALSE;
    /* Convert timeout in ms into seconds */
    double remaining = HG_CORE_PROCESSING_TIMEOUT / 1000.0;
    hg_return_t ret = HG_SUCCESS;

    while (remaining > 0) {
        unsigned int actual_count = 0;
        hg_time_t t1, t2;
        hg_return_t trigger_ret;

        hg_time_get_current(&t1);

        /* Trigger everything we can from HG */
        do {
            trigger_ret = hg_core_trigger(context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        hg_thread_spin_lock(&context->created_list_lock);
        created_list_empty = HG_LIST_IS_EMPTY(&context->created_list);
        hg_thread_spin_unlock(&context->created_list_lock);

        if (created_list_empty)
            break;

        ret = context->progress(context, (unsigned int) (remaining * 1000.0));
        if (ret != HG_SUCCESS && ret != HG_TIMEOUT) {
            HG_LOG_ERROR("Could not make progress");
            goto done;
        }
        hg_time_get_current(&t2);
        remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_class *
hg_core_init(const char *na_info_string, hg_bool_t na_listen,
    const struct hg_init_info *hg_init_info)
{
    struct hg_core_class *hg_core_class = NULL;
    na_tag_t na_max_tag;
#ifdef HG_HAS_SM_ROUTING
    na_tag_t na_sm_max_tag;
    hg_bool_t auto_sm = HG_FALSE;
#endif
    hg_return_t ret = HG_SUCCESS;

    /* Create new HG class */
    hg_core_class = (struct hg_core_class *) malloc(sizeof(struct hg_core_class));
    if (!hg_core_class) {
        HG_LOG_ERROR("Could not allocate HG class");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    memset(hg_core_class, 0, sizeof(struct hg_core_class));

    /* Parse options */
    if (hg_init_info) {
        /* External NA class */
        if (hg_init_info->na_class) {
            hg_core_class->na_class = hg_init_info->na_class;
            hg_core_class->na_ext_init = HG_TRUE;
        }
        hg_core_class->progress_mode = hg_init_info->na_init_info.progress_mode;
#ifdef HG_HAS_SM_ROUTING
        auto_sm = hg_init_info->auto_sm;
#else
        if (hg_init_info->auto_sm) {
            HG_LOG_WARNING("Auto SM requested but not enabled, "
                "please turn ON MERCURY_USE_SM_ROUTING in CMake options");
        }
#endif
#ifdef HG_HAS_COLLECT_STATS
        hg_core_class->stats = hg_init_info->stats;
        if (hg_core_class->stats && !hg_core_print_stats_registered_g) {
            if (atexit(hg_core_print_stats) != 0) {
                HG_LOG_ERROR("Could not register hg_core_print_stats");
                ret = HG_PROTOCOL_ERROR;
                goto done;
            }
            hg_core_print_stats_registered_g = HG_TRUE;
        }
#endif
    }

    /* Initialize NA if not provided externally */
    if (!hg_core_class->na_ext_init) {
        hg_core_class->na_class = NA_Initialize_opt(na_info_string, na_listen,
            &hg_init_info->na_init_info);
        if (!hg_core_class->na_class) {
            HG_LOG_ERROR("Could not initialize NA class");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

#ifdef HG_HAS_SM_ROUTING
    /* Initialize SM plugin */
    if (auto_sm) {
        if (strcmp(NA_Get_class_name(hg_core_class->na_class), "na") == 0) {
            HG_LOG_ERROR("Cannot use auto SM mode if initialized NA class is "
                "already using SM");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }

        /* Initialize NA SM first so that tmp directories are created */
        hg_core_class->na_sm_class = NA_Initialize_opt("na+sm", na_listen,
            &hg_init_info->na_init_info);
        if (!hg_core_class->na_sm_class) {
            HG_LOG_ERROR("Could not initialize NA SM class");
            ret = HG_NA_ERROR;
            goto done;
        }

        /* Get SM UUID */
        ret = hg_core_get_sm_uuid(&hg_core_class->na_sm_uuid);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not get SM UUID");
            goto done;
        }
    }
#endif

    /* Compute max request tag */
    na_max_tag = NA_Msg_get_max_tag(hg_core_class->na_class);
    if (!na_max_tag) {
        HG_LOG_ERROR("NA Max tag is not defined");
        ret = HG_NA_ERROR;
        goto done;
    }
    hg_core_class->request_max_tag = na_max_tag;

#ifdef HG_HAS_SM_ROUTING
    if (auto_sm) {
        na_sm_max_tag = NA_Msg_get_max_tag(hg_core_class->na_sm_class);
        if (!na_max_tag) {
            HG_LOG_ERROR("NA Max tag is not defined");
            ret = HG_NA_ERROR;
            goto done;
        }
        hg_core_class->request_max_tag = HG_CORE_MIN(hg_core_class->request_max_tag,
            na_sm_max_tag);
    }
#endif

    /* Initialize atomic for tags */
    hg_atomic_init32(&hg_core_class->request_tag, 0);

    /* No context created yet */
    hg_atomic_init32(&hg_core_class->n_contexts, 0);

    /* No addr created yet */
    hg_atomic_init32(&hg_core_class->n_addrs, 0);

    /* Create new function map */
    hg_core_class->func_map = hg_hash_table_new(hg_core_int_hash, hg_core_int_equal);
    if (!hg_core_class->func_map) {
        HG_LOG_ERROR("Could not create function map");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    /* Automatically free all the values with the hash map */
    hg_hash_table_register_free_functions(hg_core_class->func_map, free,
            hg_core_func_map_value_free);

    /* Initialize mutex */
    hg_thread_spin_init(&hg_core_class->func_map_lock);

done:
    if (ret != HG_SUCCESS) {
        hg_core_finalize(hg_core_class);
        hg_core_class = NULL;
    }
    return hg_core_class;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_finalize(struct hg_core_class *hg_core_class)
{
    hg_util_int32_t n_addrs, n_contexts;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) goto done;

    n_contexts = hg_atomic_get32(&hg_core_class->n_contexts);
    if (n_contexts != 0) {
        HG_LOG_ERROR("HG contexts must be destroyed before finalizing HG"
            " (%d remaining)", n_contexts);
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    n_addrs = hg_atomic_get32(&hg_core_class->n_addrs);
    if (n_addrs != 0) {
        HG_LOG_ERROR("HG addrs must be freed before finalizing HG"
            " (%d remaining)", n_addrs);
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Delete function map */
    if(hg_core_class->func_map)
        hg_hash_table_free(hg_core_class->func_map);
    hg_core_class->func_map = NULL;

    /* Free user data */
    if (hg_core_class->data_free_callback)
        hg_core_class->data_free_callback(hg_core_class->data);

    /* Destroy mutex */
    hg_thread_spin_destroy(&hg_core_class->func_map_lock);

    if (!hg_core_class->na_ext_init) {
        /* Finalize interface */
        if (NA_Finalize(hg_core_class->na_class) != NA_SUCCESS) {
            HG_LOG_ERROR("Could not finalize NA interface");
            ret = HG_NA_ERROR;
            goto done;
        }
        hg_core_class->na_class = NULL;
    }

#ifdef HG_HAS_SM_ROUTING
    /* Finalize SM interface */
    if (NA_Finalize(hg_core_class->na_sm_class) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not finalize NA SM interface");
        ret = HG_NA_ERROR;
        goto done;
    }
#endif

done:
    /* Free HG class */
    free(hg_core_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_addr *
hg_core_addr_create(struct hg_core_class *hg_core_class, na_class_t *na_class)
{
    struct hg_core_addr *hg_core_addr = NULL;

    hg_core_addr = (struct hg_core_addr *) malloc(sizeof(struct hg_core_addr));
    if (!hg_core_addr) {
        HG_LOG_ERROR("Could not allocate HG addr");
        goto done;
    }
    memset(hg_core_addr, 0, sizeof(struct hg_core_addr));
    hg_core_addr->na_class = na_class;
    hg_core_addr->na_addr = NA_ADDR_NULL;
#ifdef HG_HAS_SM_ROUTING
    hg_core_addr->na_sm_addr = NA_ADDR_NULL;
#endif
    hg_atomic_init32(&hg_core_addr->ref_count, 1);

    /* Increment N addrs from HG class */
    hg_atomic_incr32(&hg_core_class->n_addrs);

done:
    return hg_core_addr;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_lookup(struct hg_core_context *context, hg_core_cb_t callback, void *arg,
    const char *name, hg_core_op_id_t *op_id)
{
    na_class_t *na_class = context->hg_core_class->na_class;
    na_context_t *na_context = context->na_context;
    struct hg_core_op_id *hg_core_op_id = NULL;
    struct hg_core_addr *hg_core_addr = NULL;
    na_return_t na_ret;
#ifdef HG_HAS_SM_ROUTING
    char lookup_name[HG_CORE_ADDR_MAX_SIZE] = {'\0'};
#endif
    const char *name_str = name;
    hg_return_t ret = HG_SUCCESS, progress_ret;

    /* Allocate op_id */
    hg_core_op_id = (struct hg_core_op_id *) malloc(sizeof(struct hg_core_op_id));
    if (!hg_core_op_id) {
        HG_LOG_ERROR("Could not allocate HG operation ID");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_core_op_id->context = context;
    hg_core_op_id->type = HG_CB_LOOKUP;
    hg_core_op_id->callback = callback;
    hg_core_op_id->arg = arg;
    hg_atomic_init32(&hg_core_op_id->completed, 0);
    hg_core_op_id->info.lookup.hg_core_addr = NULL;
    hg_core_op_id->info.lookup.na_lookup_op_id = NA_OP_ID_NULL;

    /* Allocate addr */
    hg_core_addr = hg_core_addr_create(context->hg_core_class, NULL);
    if (!hg_core_addr) {
        HG_LOG_ERROR("Could not create HG addr");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    hg_core_op_id->info.lookup.hg_core_addr = hg_core_addr;

#ifdef HG_HAS_SM_ROUTING
    /* Parse name string */
    if (strstr(name, HG_CORE_ADDR_DELIMITER)) {
        char *lookup_names, *local_id_str;
        char *remote_name, *local_name;

        strcpy(lookup_name, name);

        /* Get first part of address string with UUID */
        strtok_r(lookup_name, HG_CORE_ADDR_DELIMITER, &lookup_names);

        if (!strstr(name, HG_CORE_PROTO_DELIMITER)) {
            HG_LOG_ERROR("Malformed address format");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        /* Get address SM UUID */
        strtok_r(lookup_name, HG_CORE_PROTO_DELIMITER, &local_id_str);
        uuid_parse(local_id_str + 2, hg_core_addr->na_sm_uuid);

        /* Separate remaining two parts */
        strtok_r(lookup_names, HG_CORE_ADDR_DELIMITER, &remote_name);
        local_name = lookup_names;

        /* Compare UUIDs, if they match it's local address */
        if (context->na_sm_context && uuid_compare(hg_core_addr->na_sm_uuid,
            context->hg_core_class->na_sm_uuid) == 0) {
            name_str = local_name;
            na_class = context->hg_core_class->na_sm_class;
            na_context = context->na_sm_context;
        } else {
            /* Remote lookup */
            name_str = remote_name;
        }
    }
#endif
    /* Assign corresponding NA class */
    hg_core_addr->na_class = na_class;

    /* Assign op_id */
    if (op_id && op_id != HG_CORE_OP_ID_IGNORE)
        *op_id = (hg_core_op_id_t) hg_core_op_id;

    na_ret = NA_Addr_lookup(na_class, na_context, hg_core_addr_lookup_cb,
        hg_core_op_id, name_str, &hg_core_op_id->info.lookup.na_lookup_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not start lookup for address %s", name_str);
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
        free(hg_core_op_id);
        if (hg_core_addr != NULL)
            hg_core_addr_free(context->hg_core_class, hg_core_addr);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_addr_lookup_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_op_id *hg_core_op_id = (struct hg_core_op_id *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    int ret = 0;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Assign addr */
    hg_core_op_id->info.lookup.hg_core_addr->na_addr = callback_info->info.lookup.addr;

    /* Mark as completed */
    if (hg_core_addr_lookup_complete(hg_core_op_id) != HG_SUCCESS) {
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
hg_core_addr_lookup_complete(struct hg_core_op_id *hg_core_op_id)
{
    hg_core_context_t *context = hg_core_op_id->context;
    struct hg_completion_entry *hg_completion_entry =
        &hg_core_op_id->hg_completion_entry;
    hg_return_t ret = HG_SUCCESS;

    /* Mark operation as completed */
    hg_atomic_incr32(&hg_core_op_id->completed);

    hg_completion_entry->op_type = HG_ADDR;
    hg_completion_entry->op_id.hg_core_op_id = hg_core_op_id;

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
hg_core_addr_free(struct hg_core_class *hg_core_class, struct hg_core_addr *hg_core_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!hg_core_addr) goto done;

    if (hg_atomic_decr32(&hg_core_addr->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Decrement N addrs from HG class */
    hg_atomic_decr32(&hg_core_class->n_addrs);

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr->na_sm_addr != NA_ADDR_NULL) { /* Self address case with SM */
        na_ret = NA_Addr_free(hg_core_class->na_sm_class, hg_core_addr->na_sm_addr);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not free NA SM address");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
#endif

    /* Free NA address */
    na_ret = NA_Addr_free(hg_core_addr->na_class, hg_core_addr->na_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not free address");
        ret = HG_NA_ERROR;
        goto done;
    }
    free(hg_core_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_self(struct hg_core_class *hg_core_class,
    struct hg_core_addr **self_addr)
{
    struct hg_core_addr *hg_core_addr = NULL;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    hg_core_addr = hg_core_addr_create(hg_core_class, hg_core_class->na_class);
    if (!hg_core_addr) {
        HG_LOG_ERROR("Could not create HG addr");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    na_ret = NA_Addr_self(hg_core_class->na_class, &hg_core_addr->na_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not get self address");
        ret = HG_NA_ERROR;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_class->na_sm_class) {
        /* Get SM address */
        na_ret = NA_Addr_self(hg_core_class->na_sm_class, &hg_core_addr->na_sm_addr);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not get self SM address");
            ret = HG_NA_ERROR;
            goto done;
        }

        /* Copy local UUID */
        uuid_copy(hg_core_addr->na_sm_uuid, hg_core_class->na_sm_uuid);
    }
#endif

    *self_addr = hg_core_addr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_addr_dup(struct hg_core_class *hg_core_class,
    struct hg_core_addr *hg_core_addr, struct hg_core_addr **hg_new_addr)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /**
     * If address is internal, create a new copy to prevent repost
     * operations to modify underlying NA address, otherwise simply increment
     * refcount of original address.
     */
    if (hg_core_addr->is_mine) {
        struct hg_core_addr *dup = NULL;

        dup = hg_core_addr_create(hg_core_class, hg_core_addr->na_class);
        if (!dup) {
            HG_LOG_ERROR("Could not create HG addr");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        na_ret = NA_Addr_dup(hg_core_addr->na_class, hg_core_addr->na_addr,
            &dup->na_addr);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not duplicate address");
            ret = HG_NA_ERROR;
            goto done;
        }
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
hg_core_addr_to_string(struct hg_core_class *hg_core_class, char *buf, hg_size_t *buf_size,
    struct hg_core_addr *hg_core_addr)
{
    char *buf_ptr = buf;
    hg_size_t new_buf_size = 0, buf_size_used = 0;
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (!buf_size) {
        HG_LOG_ERROR("NULL buffer size");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    new_buf_size = *buf_size;

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr->na_sm_addr) {
        char addr_str[HG_CORE_ADDR_MAX_SIZE];
        char uuid_str[HG_CORE_UUID_MAX_LEN + 1];
        int desc_len;

        /* Convert UUID to string and generate addr string */
        uuid_unparse(hg_core_addr->na_sm_uuid, uuid_str);
        desc_len = snprintf(addr_str, HG_CORE_ADDR_MAX_SIZE,
            "uid://%s" HG_CORE_ADDR_DELIMITER, uuid_str);
        if (desc_len > HG_CORE_ADDR_MAX_SIZE) {
            HG_LOG_ERROR("Exceeding max addr name");
            ret = HG_SIZE_ERROR;
            goto done;
        }
        if (buf_ptr) {
            strcpy(buf_ptr, addr_str);
            buf_ptr += desc_len;
        }
        buf_size_used += (hg_size_t) desc_len;
        if (*buf_size > (unsigned int) desc_len)
            new_buf_size = *buf_size - (hg_size_t) desc_len;

        /* Get NA SM address string */
        na_ret = NA_Addr_to_string(hg_core_class->na_sm_class, buf_ptr,
            &new_buf_size, hg_core_addr->na_sm_addr);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not convert SM address to string");
            ret = HG_NA_ERROR;
            goto done;
        }
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
    na_ret = NA_Addr_to_string(hg_core_class->na_class, buf_ptr, &new_buf_size,
        hg_core_addr->na_addr);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not convert address to string");
        ret = HG_NA_ERROR;
        goto done;
    }
    *buf_size = new_buf_size + buf_size_used;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct hg_core_handle *
hg_core_create(struct hg_core_context *context, hg_bool_t HG_UNUSED use_sm)
{
    na_class_t *na_class = context->hg_core_class->na_class;
    na_context_t *na_context = context->na_context;
    struct hg_core_handle *hg_core_handle = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_core_handle = (struct hg_core_handle *) malloc(sizeof(struct hg_core_handle));
    if (!hg_core_handle) {
        HG_LOG_ERROR("Could not allocate handle");
        goto done;
    }
    memset(hg_core_handle, 0, sizeof(struct hg_core_handle));

    hg_core_handle->op_type = HG_CORE_PROCESS; /* Default */
    hg_core_handle->hg_info.hg_core_class = context->hg_core_class;
    hg_core_handle->hg_info.context = context;
    hg_core_handle->hg_info.addr = HG_CORE_ADDR_NULL;
    hg_core_handle->hg_info.id = 0;
    hg_core_handle->hg_info.context_id = 0;
#ifdef HG_HAS_SM_ROUTING
    if (use_sm) {
        na_class = context->hg_core_class->na_sm_class;
        na_context = context->na_sm_context;
    }
#endif
    hg_core_handle->na_class = na_class;
    hg_core_handle->na_context = na_context;
    hg_core_handle->ret = HG_SUCCESS;

    /* Add handle to handle list so that we can track it */
    hg_thread_spin_lock(&hg_core_handle->hg_info.context->created_list_lock);
    HG_LIST_INSERT_HEAD(&hg_core_handle->hg_info.context->created_list,
        hg_core_handle, created);
    hg_thread_spin_unlock(&hg_core_handle->hg_info.context->created_list_lock);

    /* Handle is not in use */
    hg_atomic_init32(&hg_core_handle->in_use, HG_FALSE);

    /* Initialize processing buffers and use unexpected message size */
    hg_core_handle->in_buf_size = NA_Msg_get_max_unexpected_size(na_class);
    hg_core_handle->out_buf_size = NA_Msg_get_max_expected_size(na_class);
    hg_core_handle->na_in_header_offset = NA_Msg_get_unexpected_header_size(na_class);
    hg_core_handle->na_out_header_offset = NA_Msg_get_expected_header_size(na_class);

    hg_core_handle->in_buf = NA_Msg_buf_alloc(na_class, hg_core_handle->in_buf_size,
        &hg_core_handle->in_buf_plugin_data);
    if (!hg_core_handle->in_buf) {
        HG_LOG_ERROR("Could not allocate buffer for input");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    NA_Msg_init_unexpected(na_class, hg_core_handle->in_buf, hg_core_handle->in_buf_size);

    hg_core_handle->out_buf = NA_Msg_buf_alloc(na_class, hg_core_handle->out_buf_size,
        &hg_core_handle->out_buf_plugin_data);
    if (!hg_core_handle->out_buf) {
        HG_LOG_ERROR("Could not allocate buffer for output");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    NA_Msg_init_expected(na_class, hg_core_handle->out_buf, hg_core_handle->out_buf_size);

    /* Init in/out header */
    hg_core_header_request_init(&hg_core_handle->in_header);
    hg_core_header_response_init(&hg_core_handle->out_header);

    /* Create NA operation IDs */
    hg_core_handle->na_send_op_id = NA_Op_create(na_class);
    hg_core_handle->na_recv_op_id = NA_Op_create(na_class);
    if (hg_core_handle->na_recv_op_id || hg_core_handle->na_send_op_id) {
        if ((hg_core_handle->na_recv_op_id == NA_OP_ID_NULL)
            || (hg_core_handle->na_send_op_id == NA_OP_ID_NULL)) {
            HG_LOG_ERROR("NULL operation ID");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        hg_core_handle->na_op_id_mine = HG_TRUE;
    }
    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_init32(&hg_core_handle->na_op_completed_count, 0);

    /* Set refcount to 1 */
    hg_atomic_init32(&hg_core_handle->ref_count, 1);

    /* Increment N handles from HG context */
    hg_atomic_incr32(&context->n_handles);

done:
    if (ret != HG_SUCCESS) {
        hg_core_destroy(hg_core_handle);
        hg_core_handle = NULL;
    }
    return hg_core_handle;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_destroy(struct hg_core_handle *hg_core_handle)
{
    na_return_t na_ret;

    if (!hg_core_handle) goto done;

    if (hg_atomic_decr32(&hg_core_handle->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Remove handle from list */
    hg_thread_spin_lock(&hg_core_handle->hg_info.context->created_list_lock);
    HG_LIST_REMOVE(hg_core_handle, created);
    hg_thread_spin_unlock(&hg_core_handle->hg_info.context->created_list_lock);

    /* Decrement N handles from HG context */
    hg_atomic_decr32(&hg_core_handle->hg_info.context->n_handles);

    /* Remove reference to HG addr */
    hg_core_addr_free(hg_core_handle->hg_info.hg_core_class, hg_core_handle->hg_info.addr);

    na_ret = NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA op ID");
    NA_Op_destroy(hg_core_handle->na_class, hg_core_handle->na_recv_op_id);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA op ID");

    hg_core_header_request_finalize(&hg_core_handle->in_header);
    hg_core_header_response_finalize(&hg_core_handle->out_header);

    na_ret = NA_Msg_buf_free(hg_core_handle->na_class, hg_core_handle->in_buf,
        hg_core_handle->in_buf_plugin_data);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA input msg buffer");
    na_ret = NA_Msg_buf_free(hg_core_handle->na_class, hg_core_handle->out_buf,
        hg_core_handle->out_buf_plugin_data);
    if (na_ret != NA_SUCCESS)
        HG_LOG_ERROR("Could not destroy NA output msg buffer");

    /* Free extra data here if needed */
    if (hg_core_handle->hg_info.hg_core_class->more_data_release)
        hg_core_handle->hg_info.hg_core_class->more_data_release(
            (hg_core_handle_t) hg_core_handle);
    if (hg_core_handle->ack_buf)
        NA_Msg_buf_free(hg_core_handle->na_class, hg_core_handle->ack_buf,
            hg_core_handle->ack_buf_plugin_data);

    /* Free user data */
    if (hg_core_handle->data_free_callback)
        hg_core_handle->data_free_callback(hg_core_handle->data);

    free(hg_core_handle);

done:
    return;
}

/*---------------------------------------------------------------------------*/
static void
hg_core_reset(struct hg_core_handle *hg_core_handle, hg_bool_t reset_info)
{
    /* Reset source address */
    if (reset_info) {
        if (hg_core_handle->hg_info.addr != HG_CORE_ADDR_NULL
            && hg_core_handle->hg_info.addr->na_addr != NA_ADDR_NULL) {
            NA_Addr_free(hg_core_handle->na_class, hg_core_handle->hg_info.addr->na_addr);
            hg_core_handle->hg_info.addr->na_addr = NA_ADDR_NULL;
        }
        hg_core_handle->hg_info.id = 0;
    }
    hg_core_handle->hg_info.context_id = 0;
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
    if (hg_core_handle->hg_info.hg_core_class->more_data_release)
        hg_core_handle->hg_info.hg_core_class->more_data_release(
            (hg_core_handle_t) hg_core_handle);
    if (hg_core_handle->ack_buf) {
        NA_Msg_buf_free(hg_core_handle->na_class, hg_core_handle->ack_buf,
            hg_core_handle->ack_buf_plugin_data);
        hg_core_handle->ack_buf = NULL;
        hg_core_handle->ack_buf_plugin_data = NULL;
    }

    hg_core_header_request_reset(&hg_core_handle->in_header);
    hg_core_header_response_reset(&hg_core_handle->out_header);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_set_rpc(struct hg_core_handle *hg_core_handle, hg_core_addr_t addr, hg_id_t id)
{
    struct hg_core_info *hg_info = &hg_core_handle->hg_info;
    hg_return_t ret = HG_SUCCESS;

    /* We allow for NULL addr to be passed at creation time, this allows
     * for pool of handles to be created and later re-used after a call to
     * HG_Core_reset() */
    if (addr != HG_CORE_ADDR_NULL && hg_info->addr != addr) {
        if (hg_info->addr != HG_CORE_ADDR_NULL)
             hg_core_addr_free(hg_info->hg_core_class, hg_info->addr);
        hg_info->addr = addr;
        hg_atomic_incr32(&addr->ref_count); /* Increase ref to addr */

        /* Set forward call depending on address self */
        hg_core_handle->is_self = NA_Addr_is_self(hg_info->addr->na_class,
            hg_info->addr->na_addr);
#ifdef HG_HAS_SELF_FORWARD
        hg_core_handle->forward =
            hg_core_handle->is_self ? hg_core_forward_self : hg_core_forward_na;
#else
        hg_core_handle->forward = hg_core_forward_na;
#endif
    }

    /* We also allow for NULL RPC id to be passed (same reason as above) */
    if (id && hg_core_handle->hg_info.id != id) {
        struct hg_core_rpc_info *hg_core_rpc_info;
        hg_core_context_t *context = hg_core_handle->hg_info.context;

        /* Retrieve ID function from function map */
        hg_thread_spin_lock(&context->hg_core_class->func_map_lock);
        hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
            context->hg_core_class->func_map, (hg_hash_table_key_t) &id);
        hg_thread_spin_unlock(&context->hg_core_class->func_map_lock);
        if (!hg_core_rpc_info) {
            /* HG_LOG_ERROR("Could not find RPC ID in function map"); */
            ret = HG_NO_MATCH;
            goto done;
        }
        hg_core_handle->hg_info.id = id;

        /* Cache RPC info */
        hg_core_handle->hg_core_rpc_info = hg_core_rpc_info;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
hg_core_get_rpc_data(struct hg_core_handle *hg_core_handle)
{
    void *data = NULL;

    if (hg_core_handle->hg_core_rpc_info)
        data = hg_core_handle->hg_core_rpc_info->data;

    return data;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_forward_self(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Initialize thread pool if not initialized yet */
    if (!hg_core_handle->hg_info.context->self_processing_pool) {
        hg_thread_pool_init(HG_CORE_MAX_SELF_THREADS,
            &hg_core_handle->hg_info.context->self_processing_pool);
    }

    /* Post operation to self processing pool */
    hg_core_handle->thread_work.func = hg_core_process_thread;
    hg_core_handle->thread_work.args = hg_core_handle;
    hg_thread_pool_post(hg_core_handle->hg_info.context->self_processing_pool,
        &hg_core_handle->thread_work);

    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_forward_na(struct hg_core_handle *hg_core_handle)
{
    struct hg_core_class *hg_core_class = hg_core_handle->hg_info.hg_core_class;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD;

    /* Generate tag */
    hg_core_handle->tag = hg_core_gen_request_tag(hg_core_class);

    if (!hg_core_handle->no_response) {
        /* Increment number of expected NA operations */
        hg_core_handle->na_op_count++;

        /* Pre-post the recv message (output) if response is expected */
        na_ret = NA_Msg_recv_expected(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_recv_output_cb, hg_core_handle,
            hg_core_handle->out_buf, hg_core_handle->out_buf_size,
            hg_core_handle->out_buf_plugin_data, hg_core_handle->hg_info.addr->na_addr,
            hg_core_handle->hg_info.context_id, hg_core_handle->tag,
            &hg_core_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post recv for output buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* And post the send message (input) */
    na_ret = NA_Msg_send_unexpected(hg_core_handle->na_class, hg_core_handle->na_context,
        hg_core_send_input_cb, hg_core_handle, hg_core_handle->in_buf,
        hg_core_handle->in_buf_used, hg_core_handle->in_buf_plugin_data,
        hg_core_handle->hg_info.addr->na_addr, hg_core_handle->hg_info.context_id,
        hg_core_handle->tag, &hg_core_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for input buffer");
        /* Cancel the above posted recv op */
        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_recv_op_id);
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
static HG_INLINE hg_return_t
hg_core_respond_self(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_RESPOND_SELF;

    /* Complete and add to completion queue */
    ret = hg_core_complete(hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete handle");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_no_respond_self(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_FORWARD_SELF;

    /* Complete and add to completion queue */
    ret = hg_core_complete(hg_core_handle);
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
hg_core_respond_na(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

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
        if (!hg_core_handle->ack_buf) {
            HG_LOG_ERROR("Could not allocate buffer for ack");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        NA_Msg_init_expected(hg_core_handle->na_class, hg_core_handle->ack_buf,
            sizeof(hg_uint8_t));

        /* Pre-post the recv message (output) if response is expected */
        na_ret = NA_Msg_recv_expected(hg_core_handle->na_class,
            hg_core_handle->na_context, hg_core_recv_ack_cb, hg_core_handle,
            hg_core_handle->ack_buf, sizeof(hg_uint8_t),
            hg_core_handle->ack_buf_plugin_data,
            hg_core_handle->hg_info.addr->na_addr,
            hg_core_handle->hg_info.context_id, hg_core_handle->tag,
            &hg_core_handle->na_ack_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not post recv for ack buffer");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* Respond back */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_output_cb, hg_core_handle,
        hg_core_handle->out_buf, hg_core_handle->out_buf_used,
        hg_core_handle->out_buf_plugin_data,
        hg_core_handle->hg_info.addr->na_addr,
        hg_core_handle->hg_info.context_id, hg_core_handle->tag,
        &hg_core_handle->na_send_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for output buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_no_respond_na(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_NO_RESPOND;

    ret = hg_core_complete(hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_send_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_send_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static int
hg_core_recv_input_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    struct hg_core_context *hg_core_context = hg_core_handle->hg_info.context;
    const struct na_cb_info_recv_unexpected *na_cb_info_recv_unexpected =
        &callback_info->info.recv_unexpected;
#ifndef HG_HAS_POST_LIMIT
    hg_bool_t pending_empty = NA_FALSE;
# ifdef HG_HAS_SM_ROUTING
    hg_bool_t sm_pending_empty = NA_FALSE;
# endif
#endif
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
        /* Only decrement refcount and exit */
        hg_core_destroy(hg_core_handle);
        goto done;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Fill unexpected info */
    hg_core_handle->hg_info.addr->na_addr = na_cb_info_recv_unexpected->source;
    hg_core_handle->tag = na_cb_info_recv_unexpected->tag;
    if (na_cb_info_recv_unexpected->actual_buf_size > hg_core_handle->in_buf_size) {
        HG_LOG_ERROR("Actual transfer size is too large for unexpected recv");
        goto done;
    }
    hg_core_handle->in_buf_used = na_cb_info_recv_unexpected->actual_buf_size;

    /* Remove handle from pending list */
#ifdef HG_HAS_SM_ROUTING
    if (hg_core_handle->na_class == hg_core_handle->hg_info.hg_core_class->na_sm_class) {
        hg_thread_spin_lock(&hg_core_context->sm_pending_list_lock);
        HG_LIST_REMOVE(hg_core_handle, pending);
# ifndef HG_HAS_POST_LIMIT
        sm_pending_empty = HG_LIST_IS_EMPTY(&hg_core_context->sm_pending_list);
# endif
        hg_thread_spin_unlock(&hg_core_context->sm_pending_list_lock);
    } else {
#endif
        hg_thread_spin_lock(&hg_core_context->pending_list_lock);
        HG_LIST_REMOVE(hg_core_handle, pending);
#ifndef HG_HAS_POST_LIMIT
        pending_empty = HG_LIST_IS_EMPTY(&hg_core_context->pending_list);
#endif
        hg_thread_spin_unlock(&hg_core_context->pending_list_lock);
#ifdef HG_HAS_SM_ROUTING
    }
#endif

#ifndef HG_HAS_POST_LIMIT
    /* If pending list is empty, post more handles */
    if (pending_empty && hg_core_context_post(hg_core_context,
        HG_CORE_PENDING_INCR, hg_core_handle->repost, HG_FALSE) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not post additional handles");
        goto done;
    }
# ifdef HG_HAS_SM_ROUTING
    /* If pending list is empty, post more handles */
    if (sm_pending_empty && hg_core_context_post(hg_core_context,
        HG_CORE_PENDING_INCR, hg_core_handle->repost, HG_TRUE) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not post additional SM handles");
        goto done;
    }
# endif
#endif

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_PROCESS;

    /* Process input information */
    if (hg_core_process_input(hg_core_handle, &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process input");
        goto done;
    }

    /* Complete operation */
    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_recv_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process_input(struct hg_core_handle *hg_core_handle,
    hg_bool_t *completed)
{
    struct hg_core_context *hg_core_context = hg_core_handle->hg_info.context;
    hg_return_t ret = HG_SUCCESS;

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    hg_core_stat_incr(&hg_core_rpc_count_g);
#endif

    /* Get and verify input header */
    ret = hg_core_proc_header_request(hg_core_handle,
        &hg_core_handle->in_header, HG_DECODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get request header");
        goto done;
    }

    /* Get operation ID from header */
    hg_core_handle->hg_info.id = hg_core_handle->in_header.msg.request.id;
    hg_core_handle->cookie = hg_core_handle->in_header.msg.request.cookie;
    /* TODO assign target ID from cookie directly for now */
    hg_core_handle->hg_info.context_id = hg_core_handle->cookie;

    /* Parse flags */
    hg_core_handle->no_response = hg_core_handle->in_header.msg.request.flags
        & HG_CORE_NO_RESPONSE;
#ifdef HG_HAS_SELF_FORWARD
    hg_core_handle->respond = hg_core_handle->in_header.msg.request.flags
        & HG_CORE_SELF_FORWARD ? hg_core_respond_self : hg_core_respond_na;
    hg_core_handle->no_respond = hg_core_handle->in_header.msg.request.flags
        & HG_CORE_SELF_FORWARD ? hg_core_no_respond_self : hg_core_no_respond_na;
#else
    hg_core_handle->respond = hg_core_respond_na;
    hg_core_handle->no_respond = hg_core_no_respond_na;
#endif

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->in_header.msg.request.flags & HG_CORE_MORE_DATA) {
        if (!hg_core_context->hg_core_class->more_data_acquire) {
            HG_LOG_ERROR("No callback defined for acquiring more data");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
#ifdef HG_HAS_COLLECT_STATS
        /* Increment counter */
        hg_core_stat_incr(&hg_core_rpc_extra_count_g);
#endif
        ret = hg_core_context->hg_core_class->more_data_acquire(
            (hg_core_handle_t) hg_core_handle, HG_INPUT, hg_core_complete);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in HG core handle more data acquire callback");
            goto done;
        }
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
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Complete operation */
    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_send_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_recv_output_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Process output information */
    if (hg_core_handle->ret != HG_CANCELED
        && hg_core_process_output(hg_core_handle, &completed, hg_core_send_ack)
            != HG_SUCCESS) {
        HG_LOG_ERROR("Could not process output");
        goto done;
    }

    /* Complete operation */
    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_recv_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process_output(struct hg_core_handle *hg_core_handle,
    hg_bool_t *completed, hg_return_t (*done_callback)(hg_core_handle_t))
{
    struct hg_core_context *hg_core_context = hg_core_handle->hg_info.context;
    hg_return_t ret = HG_SUCCESS;

    /* Get and verify output header */
    if (hg_core_proc_header_response(hg_core_handle, &hg_core_handle->out_header,
        HG_DECODE) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not decode header");
        goto done;
    }

    /* Get return code from header */
    hg_core_handle->ret =
        (hg_return_t) hg_core_handle->out_header.msg.response.ret_code;

    /* Parse flags */

    /* Must let upper layer get extra payload if HG_CORE_MORE_DATA is set */
    if (hg_core_handle->out_header.msg.response.flags & HG_CORE_MORE_DATA) {
        if (!hg_core_context->hg_core_class->more_data_acquire) {
            HG_LOG_ERROR("No callback defined for acquiring more data");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        ret = hg_core_context->hg_core_class->more_data_acquire(
            (hg_core_handle_t) hg_core_handle, HG_OUTPUT, done_callback);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in HG core handle more data acquire callback");
            goto done;
        }
        *completed = HG_FALSE;
    } else
        *completed = HG_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_send_ack(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    /* Increment number of expected NA operations */
    hg_core_handle->na_op_count++;

    /* Allocate buffer for ack */
    hg_core_handle->ack_buf = NA_Msg_buf_alloc(hg_core_handle->na_class,
        sizeof(hg_uint8_t), &hg_core_handle->ack_buf_plugin_data);
    if (!hg_core_handle->ack_buf) {
        HG_LOG_ERROR("Could not allocate buffer for ack");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    NA_Msg_init_expected(hg_core_handle->na_class, hg_core_handle->ack_buf,
        sizeof(hg_uint8_t));

    /* Pre-post the recv message (output) if response is expected */
    na_ret = NA_Msg_send_expected(hg_core_handle->na_class,
        hg_core_handle->na_context, hg_core_send_ack_cb, hg_core_handle,
        hg_core_handle->ack_buf, sizeof(hg_uint8_t),
        hg_core_handle->ack_buf_plugin_data,
        hg_core_handle->hg_info.addr->na_addr,
        hg_core_handle->hg_info.context_id, hg_core_handle->tag,
        &hg_core_handle->na_ack_op_id);
    if (na_ret != NA_SUCCESS) {
        HG_LOG_ERROR("Could not post send for ack buffer");
        ret = HG_NA_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_send_ack_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Complete operation */
    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_ack_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE int
hg_core_recv_ack_cb(const struct na_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->arg;
    na_return_t na_ret = NA_SUCCESS;
    hg_bool_t completed = HG_TRUE;

    if (callback_info->ret == NA_CANCELED) {
        /* If canceled, mark handle as canceled */
        hg_core_handle->ret = HG_CANCELED;
    } else if (callback_info->ret != NA_SUCCESS) {
        HG_LOG_ERROR("Error in NA callback");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Complete operation */
    if (hg_core_complete_na(hg_core_handle, &hg_core_handle->na_ack_op_id,
        &completed) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    (void) na_ret; /* unused */
    return (int) completed;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SELF_FORWARD
static hg_return_t
hg_core_self_cb(const struct hg_core_cb_info *callback_info)
{
    struct hg_core_handle *hg_core_handle =
        (struct hg_core_handle *) callback_info->info.respond.handle;
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
    if (ret != HG_SUCCESS) {
       HG_LOG_ERROR("Could not process output");
       goto done;
   }

    /* Mark as completed */
    if (completed && hg_core_complete(hg_core_handle) != HG_SUCCESS) {
        HG_LOG_ERROR("Could not complete operation");
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_core_process_thread(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) arg;
    hg_bool_t completed = HG_FALSE;

    /* Set operation type for trigger */
    hg_core_handle->op_type = HG_CORE_PROCESS;

    /* Process input */
   if (hg_core_process_input(hg_core_handle, &completed) != HG_SUCCESS) {
       HG_LOG_ERROR("Could not process input");
   }

   /* Mark as completed */
   if (completed && hg_core_complete(hg_core_handle) != HG_SUCCESS) {
       HG_LOG_ERROR("Could not complete operation");
   }

   return thread_ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_process(struct hg_core_handle *hg_core_handle)
{
    struct hg_core_class *hg_core_class = hg_core_handle->hg_info.hg_core_class;
    struct hg_core_rpc_info *hg_core_rpc_info;
    hg_return_t ret = HG_SUCCESS;

    /* Retrieve exe function from function map */
    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
        hg_core_class->func_map, (hg_hash_table_key_t) &hg_core_handle->hg_info.id);
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);
    if (!hg_core_rpc_info) {
        HG_LOG_WARNING("Could not find RPC ID in function map");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (!hg_core_rpc_info->rpc_cb) {
        HG_LOG_ERROR("No RPC callback registered");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Cache RPC info */
    hg_core_handle->hg_core_rpc_info = hg_core_rpc_info;

    /* Increment ref count here so that a call to HG_Destroy in user's RPC
     * callback does not free the handle but only schedules its completion */
    hg_atomic_incr32(&hg_core_handle->ref_count);

    /* Execute RPC callback */
    ret = hg_core_rpc_info->rpc_cb((hg_core_handle_t) hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error while executing RPC callback");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_complete_na(struct hg_core_handle *hg_core_handle, na_op_id_t *op_id,
    hg_bool_t *completed)
{
    hg_return_t ret = HG_SUCCESS;

    /* Reset op ID value */
    if (!hg_core_handle->na_op_id_mine)
        *op_id = NA_OP_ID_NULL;

    /* Add handle to completion queue when expected operations have completed */
    if (hg_atomic_incr32(&hg_core_handle->na_op_completed_count)
        == (hg_util_int32_t) hg_core_handle->na_op_count && *completed) {
        /* Mark as completed */
        if (hg_core_complete(hg_core_handle) != HG_SUCCESS) {
            HG_LOG_ERROR("Could not complete operation");
            goto done;
        }
        /* Increment number of entries added to completion queue */
        *completed = HG_TRUE;
    } else
        *completed = HG_FALSE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_core_complete(struct hg_core_handle *hg_core_handle)
{
    struct hg_core_context *context = hg_core_handle->hg_info.context;
    struct hg_completion_entry *hg_completion_entry =
        &hg_core_handle->hg_completion_entry;
    hg_return_t ret = HG_SUCCESS;

    hg_completion_entry->op_type = HG_RPC;
    hg_completion_entry->op_id.hg_core_handle = hg_core_handle;

    ret = hg_core_completion_add(context, hg_completion_entry,
        hg_core_handle->is_self);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not add HG completion entry to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_completion_add(struct hg_core_context *context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify)
{
    hg_return_t ret = HG_SUCCESS;

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    if (hg_completion_entry->op_type == HG_BULK)
        hg_core_stat_incr(&hg_core_bulk_count_g);
#endif

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
hg_core_context_post(struct hg_core_context *context, unsigned int request_count,
    hg_bool_t repost, hg_bool_t use_sm)
{
    unsigned int nentry = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Create a bunch of handles and post unexpected receives */
    for (nentry = 0; nentry < request_count; nentry++) {
        struct hg_core_handle *hg_core_handle = NULL;
        struct hg_core_addr *hg_core_addr = NULL;

        /* Create a new handle */
        hg_core_handle = hg_core_create(context, use_sm);
        if (!hg_core_handle) {
            HG_LOG_ERROR("Could not create HG core handle");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        /* Execute class callback on handle, this allows upper layers to
         * allocate private data on handle creation */
        if (context->handle_create) {
            ret = context->handle_create(hg_core_handle,
                context->handle_create_arg);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Error in HG core handle create callback");
                goto done;
            }
        }

        /* Create internal addresses */
        hg_core_addr = hg_core_addr_create(context->hg_core_class,
            hg_core_handle->na_class);
        if (!hg_core_addr) {
            HG_LOG_ERROR("Could not create HG addr");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        /* To safely repost handle and prevent externally referenced address */
        hg_core_addr->is_mine = HG_TRUE;
        hg_core_handle->hg_info.addr = hg_core_addr;

        /* Repost handle on completion if told so */
        hg_core_handle->repost = repost;

        ret = hg_core_post(hg_core_handle);
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
hg_core_post(struct hg_core_handle *hg_core_handle)
{
    struct hg_core_context *context = hg_core_handle->hg_info.context;
    na_return_t na_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Handle is now in use */
    hg_atomic_set32(&hg_core_handle->in_use, HG_TRUE);

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_handle->na_class == hg_core_handle->hg_info.hg_core_class->na_sm_class) {
        hg_thread_spin_lock(&context->sm_pending_list_lock);
        HG_LIST_INSERT_HEAD(&context->sm_pending_list, hg_core_handle, pending);
        hg_thread_spin_unlock(&context->sm_pending_list_lock);
    } else {
#endif
        hg_thread_spin_lock(&context->pending_list_lock);
        HG_LIST_INSERT_HEAD(&context->pending_list, hg_core_handle, pending);
        hg_thread_spin_unlock(&context->pending_list_lock);
#ifdef HG_HAS_SM_ROUTING
    }
#endif

    /* Post a new unexpected receive */
    na_ret = NA_Msg_recv_unexpected(hg_core_handle->na_class, hg_core_handle->na_context,
        hg_core_recv_input_cb, hg_core_handle, hg_core_handle->in_buf,
        hg_core_handle->in_buf_size, hg_core_handle->in_buf_plugin_data,
        &hg_core_handle->na_recv_op_id);
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
hg_core_reset_post(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_atomic_decr32(&hg_core_handle->ref_count))
        goto done;

    /* Reset the handle */
    hg_core_reset(hg_core_handle, HG_TRUE);

    /* Also reset additional handle parameters */
    hg_atomic_set32(&hg_core_handle->ref_count, 1);
    hg_core_handle->hg_core_rpc_info = NULL;

    /* Safe to repost */
    ret = hg_core_post(hg_core_handle);
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
    int HG_UNUSED error, hg_util_bool_t *progressed)
{
    struct hg_core_context *context = (struct hg_core_context *) arg;
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
hg_core_progress_na_cb(void *arg, unsigned int timeout, int HG_UNUSED error,
    hg_util_bool_t *progressed)
{
    struct hg_core_context *context = (struct hg_core_context *) arg;
    struct hg_core_class *hg_core_class = context->hg_core_class;
    unsigned int actual_count = 0;
    na_return_t na_ret;
    unsigned int completed_count = 0;
    int cb_ret[1] = {0};
    int ret = HG_UTIL_SUCCESS;

    /* Check progress on NA (no need to call try_wait here) */
    na_ret = NA_Progress(hg_core_class->na_class, context->na_context, timeout);
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
#ifdef HG_HAS_SM_ROUTING
static int
hg_core_progress_na_sm_cb(void *arg, unsigned int timeout, int HG_UNUSED error,
    hg_util_bool_t *progressed)
{
    struct hg_core_context *context = (struct hg_core_context *) arg;
    struct hg_core_class *hg_core_class = context->hg_core_class;
    unsigned int actual_count = 0;
    na_return_t na_ret;
    unsigned int completed_count = 0;
    int cb_ret[1] = {0};
    int ret = HG_UTIL_SUCCESS;

    /* Check progress on NA SM (no need to call try_wait here) */
    na_ret = NA_Progress(hg_core_class->na_sm_class, context->na_sm_context, timeout);
    if (na_ret != NA_SUCCESS && na_ret != NA_TIMEOUT) {
        HG_LOG_ERROR("Could not make progress on NA SM");
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
        na_ret = NA_Trigger(context->na_sm_context, 0, 1, cb_ret, &actual_count);

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
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_na(struct hg_core_context *context, unsigned int timeout)
{
    double remaining;
    hg_return_t ret = HG_TIMEOUT;

    /* Do not block if NA_NO_BLOCK option is passed */
    if (context->hg_core_class->progress_mode == NA_NO_BLOCK) {
        timeout = 0;
        remaining = 0;
    } else {
        remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    }

    for (;;) {
        struct hg_core_class *hg_core_class = context->hg_core_class;
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
            NA_Poll_try_wait(hg_core_class->na_class, context->na_context))
            progress_timeout = (unsigned int) (remaining * 1000.0);
        else
            progress_timeout = 0;

        /* Otherwise try to make progress on NA */
        na_ret = NA_Progress(hg_core_class->na_class, context->na_context,
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
    struct hg_core_context *hg_core_context = (struct hg_core_context *) arg;

    /* Do not try to wait if NA_NO_BLOCK is set */
    if (hg_core_context->hg_core_class->progress_mode == NA_NO_BLOCK)
        return NA_FALSE;

    /* Something is in one of the completion queues */
    if (!hg_atomic_queue_is_empty(hg_core_context->completion_queue) ||
        hg_atomic_get32(&hg_core_context->backfill_queue_count)) {
        return NA_FALSE;
    }

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_context->hg_core_class->na_sm_class) {
        na_bool_t ret = NA_Poll_try_wait(hg_core_context->hg_core_class->na_sm_class,
            hg_core_context->na_sm_context);
        if (ret)
            return ret;
    }
#endif

    return NA_Poll_try_wait(hg_core_context->hg_core_class->na_class,
        hg_core_context->na_context);
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_progress_poll(struct hg_core_context *context, unsigned int timeout)
{
    double remaining;
    hg_return_t ret = HG_TIMEOUT;

    /* Do not block if NA_NO_BLOCK option is passed */
    if (context->hg_core_class->progress_mode == NA_NO_BLOCK) {
        timeout = 0;
        remaining = 0;
    } else {
        remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    }

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
hg_core_trigger(struct hg_core_context *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    double remaining;
    unsigned int count = 0;
    hg_return_t ret = HG_SUCCESS;

    /* Do not block if NA_NO_BLOCK option is passed */
    if (context->hg_core_class->progress_mode == NA_NO_BLOCK) {
        timeout = 0;
        remaining = 0;
    } else {
        remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    }

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
                ret = hg_core_trigger_lookup_entry(hg_completion_entry->op_id.hg_core_op_id);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not trigger completion entry");
                    goto done;
                }
                break;
            case HG_RPC:
                ret = hg_core_trigger_entry(hg_completion_entry->op_id.hg_core_handle);
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
hg_core_trigger_lookup_entry(struct hg_core_op_id *hg_core_op_id)
{
    hg_return_t ret = HG_SUCCESS;

    /* Execute callback */
    if (hg_core_op_id->callback) {
        struct hg_core_cb_info hg_core_cb_info;

        hg_core_cb_info.arg = hg_core_op_id->arg;
        hg_core_cb_info.ret =  HG_SUCCESS; /* TODO report failure */
        hg_core_cb_info.type = HG_CB_LOOKUP;
        hg_core_cb_info.info.lookup.addr = hg_core_op_id->info.lookup.hg_core_addr;

        hg_core_op_id->callback(&hg_core_cb_info);
    }

    /* Free op */
    free(hg_core_op_id);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_trigger_entry(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_core_handle->op_type == HG_CORE_PROCESS) {
        /* Run RPC callback */
        ret = hg_core_process(hg_core_handle);
        if (ret != HG_SUCCESS && !hg_core_handle->no_response) {
            hg_size_t header_size = hg_core_header_response_get_size() +
                hg_core_handle->na_out_header_offset;

            /* Respond in case of error */
            hg_core_handle->ret = ret;
            ret = HG_Core_respond(hg_core_handle, NULL, NULL, 0, header_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not respond");
                goto done;
            }
        }

        /* No response callback */
        if (hg_core_handle->no_response) {
            ret = hg_core_handle->no_respond(hg_core_handle);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Could not complete handle");
                goto done;
            }
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
                hg_core_cb_info.info.forward.handle = (hg_core_handle_t) hg_core_handle;
                break;
            case HG_CORE_RESPOND:
                hg_cb = hg_core_handle->response_callback;
                hg_core_cb_info.arg = hg_core_handle->response_arg;
                hg_core_cb_info.type = HG_CB_RESPOND;
                hg_core_cb_info.info.respond.handle = (hg_core_handle_t) hg_core_handle;
                break;
#ifdef HG_HAS_SELF_FORWARD
            case HG_CORE_RESPOND_SELF:
                hg_cb = hg_core_self_cb;
                hg_core_cb_info.arg = hg_core_handle->response_arg;
                hg_core_cb_info.type = HG_CB_RESPOND;
                hg_core_cb_info.info.respond.handle = (hg_core_handle_t) hg_core_handle;
                break;
#endif
            case HG_CORE_NO_RESPOND:
                /* Nothing */
                break;
            case HG_CORE_PROCESS:
            default:
                HG_LOG_ERROR("Invalid core operation type");
                ret = HG_PROTOCOL_ERROR;
                goto done;
        }

        /* Execute user callback */
        if (hg_cb)
            hg_cb(&hg_core_cb_info);

        /* Repost handle if we were listening, otherwise destroy it */
        if (hg_core_handle->repost && !hg_core_handle->hg_info.context->finalizing) {
            /* Repost handle */
            ret = hg_core_reset_post(hg_core_handle);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Cannot repost handle");
                goto done;
            }
        } else
            hg_core_destroy(hg_core_handle);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_core_cancel(struct hg_core_handle *hg_core_handle)
{
    hg_return_t ret = HG_SUCCESS;

    if (hg_core_handle->is_self) {
        HG_LOG_ERROR("Local cancelation is not supported");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Cancel all NA operations issued */
    if (hg_core_handle->na_recv_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_recv_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel recv op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    if (hg_core_handle->na_send_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_send_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel send op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }

    /* TODO
    if (hg_core_handle->na_ack_op_id != NA_OP_ID_NULL) {
        na_return_t na_ret;

        na_ret = NA_Cancel(hg_core_handle->na_class, hg_core_handle->na_context,
            hg_core_handle->na_ack_op_id);
        if (na_ret != NA_SUCCESS) {
            HG_LOG_ERROR("Could not cancel ack op id");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
    */

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
    struct hg_core_class *hg_core_class = NULL;
    hg_return_t ret = HG_SUCCESS;

    hg_core_class = hg_core_init(na_info_string, na_listen, hg_init_info);
    if (!hg_core_class) {
        HG_LOG_ERROR("Cannot initialize HG core layer");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != HG_SUCCESS) {
        /* Nothing */
    }
    return hg_core_class;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_finalize(hg_core_class_t *hg_core_class)
{
    hg_return_t ret = HG_SUCCESS;

    ret = hg_core_finalize(hg_core_class);
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
hg_return_t
HG_Core_set_more_data_callback(struct hg_core_class *hg_core_class,
    hg_return_t (*more_data_acquire_callback)(hg_core_handle_t, hg_op_t,
        hg_return_t (*done_callback)(hg_core_handle_t)),
    void (*more_data_release_callback)(hg_core_handle_t))
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_class->more_data_acquire = more_data_acquire_callback;
    hg_core_class->more_data_release = more_data_release_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_name(const hg_core_class_t *hg_core_class)
{
    const char *ret = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = NA_Get_class_name(hg_core_class->na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const char *
HG_Core_class_get_protocol(const hg_core_class_t *hg_core_class)
{
    const char *ret = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = NA_Get_class_protocol(hg_core_class->na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_bool_t
HG_Core_class_is_listening(const hg_core_class_t *hg_core_class)
{
    hg_bool_t ret = HG_FALSE;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = NA_Is_listening(hg_core_class->na_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_class_t *
HG_Core_class_get_na(const hg_core_class_t *hg_core_class)
{
    na_class_t *ret = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = hg_core_class->na_class;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SM_ROUTING
na_class_t *
HG_Core_class_get_na_sm(const hg_core_class_t *hg_core_class)
{
    na_class_t *ret = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = hg_core_class->na_sm_class;

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Core_class_get_input_eager_size(const hg_core_class_t *hg_core_class)
{
    hg_size_t ret = 0, unexp, header;

    if (hg_core_class == NULL) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    unexp  = NA_Msg_get_max_unexpected_size(hg_core_class->na_class);
    header = hg_core_header_request_get_size() +
        NA_Msg_get_unexpected_header_size(hg_core_class->na_class);
    if (unexp > header)
        ret = unexp - header;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
HG_Core_class_get_output_eager_size(const hg_core_class_t *hg_core_class)
{
    hg_size_t ret = 0, exp, header;

    if (hg_core_class == NULL) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    exp    = NA_Msg_get_max_expected_size(hg_core_class->na_class);
    header = hg_core_header_response_get_size() +
        NA_Msg_get_expected_header_size(hg_core_class->na_class);
    if (exp > header)
        ret = exp - header;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_class_set_data(hg_core_class_t *hg_core_class, void *data,
    void (*free_callback)(void *))
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_class->data = data;
    hg_core_class->data_free_callback = free_callback;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_class_get_data(const hg_core_class_t *hg_core_class)
{
    void *ret = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    ret = hg_core_class->data;

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
    hg_return_t ret = HG_SUCCESS;
    struct hg_core_context *context = NULL;
    int na_poll_fd;
#ifdef HG_HAS_SELF_FORWARD
    int fd;
#endif

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context = (struct hg_core_context *) malloc(sizeof(struct hg_core_context));
    if (!context) {
        HG_LOG_ERROR("Could not allocate HG context");
        ret = HG_NOMEM_ERROR;
        goto done;
    }
    memset(context, 0, sizeof(struct hg_core_context));
    context->hg_core_class = hg_core_class;
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
#ifdef HG_HAS_SM_ROUTING
    HG_LIST_INIT(&context->sm_pending_list);
#endif
    HG_LIST_INIT(&context->created_list);

    /* No handle created yet */
    hg_atomic_init32(&context->n_handles, 0);

    /* Initialize completion queue mutex/cond */
    hg_thread_mutex_init(&context->completion_queue_mutex);
    hg_thread_cond_init(&context->completion_queue_cond);
    hg_atomic_init32(&context->trigger_waiting, 0);

    hg_thread_spin_init(&context->pending_list_lock);
#ifdef HG_HAS_SM_ROUTING
    hg_thread_spin_init(&context->sm_pending_list_lock);
#endif
    hg_thread_spin_init(&context->created_list_lock);

    context->na_context = NA_Context_create_id(hg_core_class->na_class, id);
    if (!context->na_context) {
        HG_LOG_ERROR("Could not create NA context");
        ret = HG_NA_ERROR;
        goto done;
    }
#ifdef HG_HAS_SM_ROUTING
    if (hg_core_class->na_sm_class) {
        context->na_sm_context = NA_Context_create(hg_core_class->na_sm_class);
        if (!context->na_sm_context) {
            HG_LOG_ERROR("Could not create NA SM context");
            ret = HG_NA_ERROR;
            goto done;
        }
    }
#endif

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

    if (context->hg_core_class->progress_mode == NA_NO_BLOCK)
        /* Force to use progress poll */
        na_poll_fd = 0;
    else
        /* If NA plugin exposes fd, add it to poll set and use appropriate
         * progress function */
        na_poll_fd = NA_Poll_get_fd(hg_core_class->na_class, context->na_context);
    if (na_poll_fd >= 0) {
        hg_poll_add(context->poll_set, na_poll_fd, HG_POLLIN,
            hg_core_progress_na_cb, context);
        hg_poll_set_try_wait(context->poll_set, hg_core_poll_try_wait_cb,
            context);
        context->progress = hg_core_progress_poll;
    } else
        context->progress = hg_core_progress_na;

#ifdef HG_HAS_SM_ROUTING
    /* Auto SM requires hg_core_progress_poll */
    if (context->na_sm_context) {
        if (context->progress != hg_core_progress_poll) {
            HG_LOG_ERROR("Auto SM mode not supported with selected plugin");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        if (context->hg_core_class->progress_mode == NA_NO_BLOCK)
            /* Force to use progress poll */
            na_poll_fd = 0;
        else {
            na_poll_fd = NA_Poll_get_fd(hg_core_class->na_sm_class,
                context->na_sm_context);
            if (na_poll_fd < 0) {
                HG_LOG_ERROR("Could not get NA SM poll fd");
                ret = HG_NA_ERROR;
                goto done;
            }
        }
        hg_poll_add(context->poll_set, na_poll_fd, HG_POLLIN,
            hg_core_progress_na_sm_cb, context);
    }
#endif

    /* Assign context ID */
    context->id = id;

    /* Increment context count of parent class */
    hg_atomic_incr32(&hg_core_class->n_contexts);

done:
    if (ret != HG_SUCCESS && context) {
        HG_Core_context_destroy(context);
        context = NULL;
    }
    return context;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_destroy(hg_core_context_t *context)
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
#ifdef HG_HAS_SM_ROUTING
    /* Check pending list and cancel posted handles */
    if (!HG_LIST_IS_EMPTY(&context->sm_pending_list)) {
        ret = hg_core_sm_pending_list_cancel(context);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot cancel list of SM pending entries");
            goto done;
        }
    }
#endif

    /* Trigger everything we can from NA, if something completed it will
     * be moved to the HG context completion queue */
    do {
        na_ret = NA_Trigger(context->na_context, 0, 1, NULL, &actual_count);
    } while ((na_ret == NA_SUCCESS) && actual_count);

#ifdef HG_HAS_SM_ROUTING
    if (context->na_sm_context) {
        do {
            na_ret = NA_Trigger(context->na_sm_context, 0, 1, NULL, &actual_count);
        } while ((na_ret == NA_SUCCESS) && actual_count);
    }
#endif

    /* Check that operations have completed */
    ret = hg_core_created_list_wait(context);
    if (ret != HG_SUCCESS && ret != HG_TIMEOUT) {
        HG_LOG_ERROR("Could not wait on HG core handle list");
        goto done;
    }

#ifdef HG_HAS_SELF_FORWARD
    /* Destroy self processing pool if created */
    hg_thread_pool_destroy(context->self_processing_pool);
#endif

    /* Number of handles for that context should be 0 */
    n_handles = hg_atomic_get32(&context->n_handles);
    if (n_handles != 0) {
        struct hg_core_handle *hg_core_handle = NULL;
        HG_LOG_ERROR("HG core handles must be freed before destroying context "
            "(%d remaining)", n_handles);
        hg_thread_spin_lock(&context->created_list_lock);
        HG_LIST_FOREACH(hg_core_handle, &context->created_list, created) {
            HG_LOG_ERROR("HG core handle at address %p was not destroyed",
                hg_core_handle);
        }
        hg_thread_spin_unlock(&context->created_list_lock);
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

    if (context->hg_core_class->progress_mode == NA_NO_BLOCK)
        /* Was forced to use progress poll */
        na_poll_fd = 0;
    else
        /* If NA plugin exposes fd, remove it from poll set */
        na_poll_fd = NA_Poll_get_fd(context->hg_core_class->na_class,
            context->na_context);
    if ((na_poll_fd >= 0)
        && hg_poll_remove(context->poll_set, na_poll_fd) != HG_UTIL_SUCCESS) {
        HG_LOG_ERROR("Could not remove NA poll descriptor from poll set");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    if (context->na_sm_context) {
        if (context->hg_core_class->progress_mode == NA_NO_BLOCK)
            /* Was forced to use progress poll */
            na_poll_fd = 0;
        else
            /* If NA plugin exposes fd, remove it from poll set */
            na_poll_fd = NA_Poll_get_fd(context->hg_core_class->na_sm_class,
                context->na_sm_context);
        if ((na_poll_fd >= 0)
            && hg_poll_remove(context->poll_set, na_poll_fd) != HG_UTIL_SUCCESS) {
            HG_LOG_ERROR("Could not remove NA poll descriptor from poll set");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }
#endif

    /* Destroy poll set */
    if (hg_poll_destroy(context->poll_set) != HG_UTIL_SUCCESS) {
        HG_LOG_ERROR("Could not destroy poll set");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Destroy NA context */
    if (context->na_context && NA_Context_destroy(context->hg_core_class->na_class,
            context->na_context) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not destroy NA context");
        ret = HG_NA_ERROR;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    /* Destroy NA SM context */
    if (context->na_sm_context && NA_Context_destroy(
        context->hg_core_class->na_sm_class, context->na_sm_context) != NA_SUCCESS) {
        HG_LOG_ERROR("Could not destroy NA SM context");
        ret = HG_NA_ERROR;
        goto done;
    }
#endif

    /* Free user data */
    if (context->data_free_callback)
        context->data_free_callback(context->data);

    /* Destroy completion queue mutex/cond */
    hg_thread_mutex_destroy(&context->completion_queue_mutex);
    hg_thread_cond_destroy(&context->completion_queue_cond);
    hg_thread_spin_destroy(&context->pending_list_lock);
#ifdef HG_HAS_SM_ROUTING
    hg_thread_spin_destroy(&context->sm_pending_list_lock);
#endif
    hg_thread_spin_destroy(&context->created_list_lock);

    /* Decrement context count of parent class */
    hg_atomic_decr32(&context->hg_core_class->n_contexts);

    free(context);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_core_class_t *
HG_Core_context_get_class(const hg_core_context_t *context)
{
    hg_core_class_t *ret = NULL;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        goto done;
    }

    ret = context->hg_core_class;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_context_t *
HG_Core_context_get_na(const hg_core_context_t *context)
{
    na_context_t *ret = NULL;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        goto done;
    }

    ret = context->na_context;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_SM_ROUTING
na_context_t *
HG_Core_context_get_na_sm(const hg_core_context_t *context)
{
    na_context_t *ret = NULL;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        goto done;
    }

    ret = context->na_sm_context;

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
hg_uint8_t
HG_Core_context_get_id(const hg_core_context_t *context)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = context->id;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_set_data(hg_core_context_t *context, void *data,
    void (*free_callback)(void *))
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context->data = data;
    context->data_free_callback = free_callback;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_context_get_data(const hg_core_context_t *context)
{
    void *ret = NULL;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        goto done;
    }

    ret = context->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_set_handle_create_callback(hg_core_context_t *context,
    hg_return_t (*callback)(hg_core_handle_t, void *), void *arg)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    context->handle_create = callback;
    context->handle_create_arg = arg;

 done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_context_post(hg_core_context_t *context, unsigned int request_count,
    hg_bool_t repost)
{
    hg_bool_t use_sm = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!request_count) {
        HG_LOG_ERROR("Request count must be greater than 0");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    do {
#endif
        ret = hg_core_context_post(context, request_count, repost, use_sm);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not post requests on context");
            goto done;
        }
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
HG_Core_register(hg_core_class_t *hg_core_class, hg_id_t id,
    hg_core_rpc_cb_t rpc_cb)
{
    hg_id_t *func_key = NULL;
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;
    int hash_ret;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Check if registered and set RPC CB */
    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(
            hg_core_class->func_map, (hg_hash_table_key_t) &id);
    if (hg_core_rpc_info && rpc_cb)
        hg_core_rpc_info->rpc_cb = rpc_cb;
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);

    if (!hg_core_rpc_info) {
        /* Allocate the key */
        func_key = (hg_id_t *) malloc(sizeof(hg_id_t));
        if (!func_key) {
            HG_LOG_ERROR("Could not allocate ID");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        *func_key = id;

        /* Fill info and store it into the function map */
        hg_core_rpc_info = (struct hg_core_rpc_info *) malloc(sizeof(struct hg_core_rpc_info));
        if (!hg_core_rpc_info) {
            HG_LOG_ERROR("Could not allocate HG info");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        hg_core_rpc_info->rpc_cb = rpc_cb;
        hg_core_rpc_info->data = NULL;
        hg_core_rpc_info->free_callback = NULL;

        hg_thread_spin_lock(&hg_core_class->func_map_lock);
        hash_ret = hg_hash_table_insert(hg_core_class->func_map,
            (hg_hash_table_key_t) func_key, hg_core_rpc_info);
        hg_thread_spin_unlock(&hg_core_class->func_map_lock);
        if (!hash_ret) {
            HG_LOG_ERROR("Could not insert RPC ID into function map (already registered?)");
            ret = HG_INVALID_PARAM;
            goto done;
        }
    }

done:
    if (ret != HG_SUCCESS) {
        free(func_key);
        free(hg_core_rpc_info);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_deregister(hg_core_class_t *hg_core_class, hg_id_t id)
{
    hg_return_t ret = HG_SUCCESS;
    int hash_ret;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    hash_ret = hg_hash_table_remove(hg_core_class->func_map,
        (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);
    if (!hash_ret) {
        HG_LOG_ERROR("Could not deregister RPC ID from function map");
        ret = HG_INVALID_PARAM;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_registered(hg_core_class_t *hg_core_class, hg_id_t id, hg_bool_t *flag)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!flag) {
        HG_LOG_ERROR("NULL flag");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    *flag = (hg_bool_t) (hg_hash_table_lookup(hg_core_class->func_map,
            (hg_hash_table_key_t) &id) != HG_HASH_TABLE_NULL);
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_register_data(hg_core_class_t *hg_core_class, hg_id_t id, void *data,
    void (*free_callback)(void *))
{
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(hg_core_class->func_map,
            (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);
    if (!hg_core_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (hg_core_rpc_info->data)
        HG_LOG_WARNING("Overriding data previously registered");
    hg_core_rpc_info->data = data;
    hg_core_rpc_info->free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_registered_data(hg_core_class_t *hg_core_class, hg_id_t id)
{
    struct hg_core_rpc_info *hg_core_rpc_info = NULL;
    void *data = NULL;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        goto done;
    }

    hg_thread_spin_lock(&hg_core_class->func_map_lock);
    hg_core_rpc_info = (struct hg_core_rpc_info *) hg_hash_table_lookup(hg_core_class->func_map,
            (hg_hash_table_key_t) &id);
    hg_thread_spin_unlock(&hg_core_class->func_map_lock);
    if (!hg_core_rpc_info) {
        HG_LOG_ERROR("Could not find RPC ID in function map");
        goto done;
    }

    data = hg_core_rpc_info->data;

done:
   return data;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_lookup(hg_core_context_t *context, hg_core_cb_t callback, void *arg,
    const char *name, hg_core_op_id_t *op_id)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
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
hg_core_addr_t
HG_Core_addr_create(hg_core_class_t *core_class)
{
    if (core_class == NULL) {
        HG_LOG_ERROR("NULL HG core class");
        return HG_CORE_ADDR_NULL;
    }

    return hg_core_addr_create(core_class, core_class->na_class);

}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_free(hg_core_class_t *hg_core_class, hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_free(hg_core_class, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not free address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
HG_Core_addr_set_na(hg_core_addr_t core_addr, na_addr_t na_addr)
{
    if (core_addr == HG_CORE_ADDR_NULL)
        return;

    core_addr->na_addr = na_addr;
}

/*---------------------------------------------------------------------------*/
na_addr_t
HG_Core_addr_get_na(hg_core_addr_t addr)
{
    na_addr_t ret = NA_ADDR_NULL;

    if (addr == HG_CORE_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
        goto done;
    }

    ret = addr->na_addr;

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
na_class_t *
HG_Core_addr_get_na_class(hg_core_addr_t addr)
{
    na_class_t *ret = NULL;

    if (addr == HG_CORE_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
        goto done;
    }

    ret = addr->na_class;

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_self(hg_core_class_t *hg_core_class, hg_core_addr_t *addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!addr) {
        HG_LOG_ERROR("NULL pointer to address");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_self(hg_core_class, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not get self address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_dup(hg_core_class_t *hg_core_class, hg_core_addr_t addr, hg_core_addr_t *new_addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (addr == HG_CORE_ADDR_NULL) {
        HG_LOG_ERROR("NULL addr");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!new_addr) {
        HG_LOG_ERROR("NULL pointer to destination address");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_dup(hg_core_class, addr, new_addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not duplicate address");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_addr_to_string(hg_core_class_t *hg_core_class, char *buf, hg_size_t *buf_size,
    hg_core_addr_t addr)
{
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_class) {
        HG_LOG_ERROR("NULL HG core class");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_addr_to_string(hg_core_class, buf, buf_size, addr);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not convert address to string");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_create(hg_core_context_t *context, hg_core_addr_t addr, hg_id_t id,
    hg_core_handle_t *handle)
{
    struct hg_core_handle *hg_core_handle = NULL;
#ifdef HG_HAS_SM_ROUTING
    struct hg_core_addr *hg_core_addr = addr;
#endif
    hg_bool_t use_sm = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr && (hg_core_addr->na_class == context->hg_core_class->na_sm_class))
        use_sm = HG_TRUE;
#endif

    /* Create new handle */
    hg_core_handle = hg_core_create(context, use_sm);
    if (!hg_core_handle) {
        HG_LOG_ERROR("Could not create HG core handle");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, addr, id);
    if (ret != HG_SUCCESS) {
        if (ret != HG_NO_MATCH) /* silence error if invalid ID is used */
            HG_LOG_ERROR("Could not set rpc to handle");
        goto done;
    }

    /* Execute class callback on handle, this allows upper layers to
     * allocate private data on handle creation */
    if (context->handle_create) {
        ret = context->handle_create(hg_core_handle,
            context->handle_create_arg);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in HG core handle create callback");
            goto done;
        }
    }

    *handle = (hg_core_handle_t) hg_core_handle;

done:
    if (ret != HG_SUCCESS) {
        hg_core_destroy(hg_core_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_destroy(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Repost handle if we were listening, otherwise destroy it */
    if (hg_core_handle->repost && !hg_core_handle->hg_info.context->finalizing) {
        /* Repost handle */
        ret = hg_core_reset_post(hg_core_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Cannot repost handle");
            goto done;
        }
    } else
        hg_core_destroy(hg_core_handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_reset(hg_core_handle_t handle, hg_core_addr_t addr, hg_id_t id)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
#ifdef HG_HAS_SM_ROUTING
    struct hg_core_addr *hg_core_addr = addr;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_SM_ROUTING
    if (hg_core_addr && (hg_core_addr->na_class != hg_core_handle->na_class)) {
        HG_LOG_ERROR("Cannot reset handle to a different address NA class");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#endif

    /* Not safe to reset
     * TODO could add the ability to defer the reset operation */
    if (hg_atomic_get32(&hg_core_handle->in_use)) {
        HG_LOG_ERROR("Cannot reset HG core handle, handle is still in use, "
            "refcount: %d", hg_atomic_get32(&hg_core_handle->ref_count));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
    hg_core_reset(hg_core_handle, HG_FALSE);

    /* Set addr / RPC ID */
    ret = hg_core_set_rpc(hg_core_handle, addr, id);
    if (ret != HG_SUCCESS) {
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_ref_incr(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_atomic_incr32(&hg_core_handle->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_int32_t
HG_Core_ref_get(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_int32_t ret = -1;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        goto done;
    }

    ret = (hg_int32_t) hg_atomic_get32(&hg_core_handle->ref_count);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_set_data(hg_core_handle_t handle, void *data,
    void (*free_callback)(void *))
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_handle->data = data;
    hg_core_handle->data_free_callback = free_callback;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
HG_Core_get_data(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    void *ret = NULL;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL pointer to HG core handle");
        goto done;
    }

    ret = hg_core_handle->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
const struct hg_core_info *
HG_Core_get_info(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    struct hg_core_info *ret = NULL;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        goto done;
    }

    ret = &hg_core_handle->hg_info;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_set_target_id(hg_core_handle_t handle, hg_uint8_t id)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!handle) {
        HG_LOG_ERROR("NULL HG core handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_handle->hg_info.context_id = id;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_get_input(hg_core_handle_t handle, void **in_buf, hg_size_t *in_buf_size)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!in_buf || !in_buf_size) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_get_input(hg_core_handle, in_buf, in_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_get_output(hg_core_handle_t handle, void **out_buf, hg_size_t *out_buf_size)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (!out_buf || !out_buf_size) {
        HG_LOG_ERROR("NULL pointer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_core_get_output(hg_core_handle, out_buf, out_buf_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_forward(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    hg_uint8_t flags, hg_size_t payload_size)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (hg_core_handle->hg_info.addr == HG_CORE_ADDR_NULL) {
        HG_LOG_ERROR("NULL target addr");
        ret = HG_INVALID_PARAM;
        goto done;
    }
    if (!hg_core_handle->hg_info.id) {
        HG_LOG_ERROR("NULL RPC ID");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#ifndef HG_HAS_SELF_FORWARD
    if (hg_core_handle->is_self) {
        HG_LOG_ERROR("Not enabled, please enable HG_USE_SELF_FORWARD");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#endif
    if (hg_atomic_cas32(&hg_core_handle->in_use, HG_FALSE, HG_TRUE)
        != HG_UTIL_TRUE) {
        /* Not safe to reset
         * TODO could add the ability to defer the reset operation */
        HG_LOG_ERROR("Not safe to use HG core handle, handle is still in use, "
            "refcount: %d", hg_atomic_get32(&hg_core_handle->ref_count));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

#ifdef HG_HAS_COLLECT_STATS
    /* Increment counter */
    hg_core_stat_incr(&hg_core_rpc_count_g);
#endif

    /* Reset op counts */
    hg_core_handle->na_op_count = 1; /* Default (no response) */
    hg_atomic_set32(&hg_core_handle->na_op_completed_count, 0);

    /* Set header size */
    header_size = hg_core_header_request_get_size() +
        hg_core_handle->na_in_header_offset;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_core_handle->in_buf_used = header_size + payload_size;
    if (hg_core_handle->in_buf_used > hg_core_handle->in_buf_size) {
        HG_LOG_ERROR("Exceeding input buffer size");
        ret = HG_SIZE_ERROR;
        /* Handle is no longer in use */
        hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);
        goto done;
    }

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
    hg_core_handle->in_header.msg.request.id = hg_core_handle->hg_info.id;
    hg_core_handle->in_header.msg.request.flags = flags;
    /* Set the cookie as origin context ID, so that when the cookie is unpacked
     * by the target and assigned to HG info context_id, the NA layer knows
     * which context ID it needs to send the response to. */
    hg_core_handle->in_header.msg.request.cookie =
        hg_core_handle->hg_info.context->id;

    /* Encode request header */
    ret = hg_core_proc_header_request(hg_core_handle,
        &hg_core_handle->in_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        /* Handle is no longer in use */
        hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);
        goto done;
    }

    /* Increase ref count here so that a call to HG_Destroy does not free the
     * handle but only schedules its completion
     */
    hg_atomic_incr32(&hg_core_handle->ref_count);

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    ret = hg_core_handle->forward(hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward buffer");
        /* Handle is no longer in use */
        hg_atomic_set32(&hg_core_handle->in_use, HG_FALSE);
        /* Rollback ref_count taken above */
        hg_atomic_decr32(&hg_core_handle->ref_count);
        goto done;
    }

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_respond(hg_core_handle_t handle, hg_core_cb_t callback, void *arg,
    hg_uint8_t flags, hg_size_t payload_size)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_size_t header_size;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#ifndef HG_HAS_SELF_FORWARD
    if (NA_Addr_is_self(hg_core_handle->hg_info.addr->na_class,
        hg_core_handle->hg_info.addr->na_addr)) {
        HG_LOG_ERROR("Not enabled, please enable HG_USE_SELF_FORWARD");
        ret = HG_INVALID_PARAM;
        goto done;
    }
#endif
    /* Cannot respond if no_response flag set */
    if (hg_core_handle->no_response) {
        HG_LOG_ERROR("Sending response was disabled on that RPC");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    /* Set header size */
    header_size = hg_core_header_response_get_size() +
        hg_core_handle->na_out_header_offset;

    /* Set the actual size of the msg that needs to be transmitted */
    hg_core_handle->out_buf_used = header_size + payload_size;
    if (hg_core_handle->out_buf_used > hg_core_handle->out_buf_size) {
        HG_LOG_ERROR("Exceeding output buffer size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Set callback, keep request and response callbacks separate so that
     * they do not get overwritten when forwarding to ourself */
    hg_core_handle->response_callback = callback;
    hg_core_handle->response_arg = arg;

    /* Set header */
    hg_core_handle->out_header.msg.response.ret_code = hg_core_handle->ret;
    hg_core_handle->out_header.msg.response.flags = flags;
    hg_core_handle->out_header.msg.response.cookie = hg_core_handle->cookie;

    /* Encode response header */
    ret = hg_core_proc_header_response(hg_core_handle,
        &hg_core_handle->out_header, HG_ENCODE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not encode header");
        goto done;
    }

    /* If addr is self, forward locally, otherwise send the encoded buffer
     * through NA and pre-post response */
    ret = hg_core_handle->respond(hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not respond");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Core_progress(hg_core_context_t *context, unsigned int timeout)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
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
HG_Core_trigger(hg_core_context_t *context, unsigned int timeout,
    unsigned int max_count, unsigned int *actual_count)
{
    hg_return_t ret = HG_SUCCESS;

    if (!context) {
        HG_LOG_ERROR("NULL HG core context");
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
HG_Core_cancel(hg_core_handle_t handle)
{
    struct hg_core_handle *hg_core_handle = (struct hg_core_handle *) handle;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_core_handle) {
        HG_LOG_ERROR("NULL handle");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    ret = hg_core_cancel(hg_core_handle);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not cancel handle");
        goto done;
    }

done:
    return ret;
}
