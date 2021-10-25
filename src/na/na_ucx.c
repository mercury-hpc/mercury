/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_plugin.h"

#include "na_ip.h"

#include "mercury_hash_table.h"
#include "mercury_mem.h"
#include "mercury_mem_pool.h"
#include "mercury_queue.h"
#include "mercury_thread_rwlock.h"
#include "mercury_thread_spin.h"

#include <ucp/api/ucp.h>

#include <stdalign.h>
#include <string.h>

#include <netdb.h>
#include <sys/socket.h>

/****************/
/* Local Macros */
/****************/

/* Default protocol */
#define NA_UCX_PROTOCOL_DEFAULT "all"

/* Default max msg size */
#define NA_UCX_MSG_SIZE_MAX (4096)

/* Address pool (enabled by default, comment out to disable) */
#define NA_UCX_HAS_ADDR_POOL
#define NA_UCX_ADDR_POOL_SIZE (64)

#define NA_UCX_CONN_RETRY_MAX (1024)

/* Memory pool (enabled by default, comment out to disable) */
// #define NA_UCX_HAS_MEM_POOL
#define NA_UCX_MEM_CHUNK_COUNT (256)
#define NA_UCX_MEM_BLOCK_COUNT (2)

/* Max tag */
#define NA_UCX_MAX_TAG UINT32_MAX

/* Reserved tags */
#define NA_UCX_TAG_MASK        ((uint64_t) 0x00000000FFFFFFFF)
#define NA_UCX_TAG_UNEXPECTED  ((uint64_t) 0x0000000100000000)
#define NA_UCX_TAG_SENDER_MASK ((uint64_t) 0xFFFFFFFE00000000)

/* Maximum number of pre-allocated IOV entries */
#define NA_UCX_IOV_STATIC_MAX (8)

/* Op ID status bits */
#define NA_UCX_OP_COMPLETED (1 << 0)
#define NA_UCX_OP_CANCELING (1 << 1)
#define NA_UCX_OP_CANCELED  (1 << 2)
#define NA_UCX_OP_QUEUED    (1 << 3)
#define NA_UCX_OP_ERRORED   (1 << 4)

/* Private data access */
#define NA_UCX_CLASS(na_class)                                                 \
    ((struct na_ucx_class *) ((na_class)->plugin_class))
#define NA_UCX_CONTEXT(na_context)                                             \
    ((struct na_ucx_context *) ((na_context)->plugin_context))

/* Reset op ID */
#define NA_UCX_OP_RESET(__op, __context, __cb_type, __cb, __arg, __addr)       \
    do {                                                                       \
        __op->context = __context;                                             \
        __op->completion_data.callback_info.type = __cb_type;                  \
        __op->completion_data.callback = __cb;                                 \
        __op->completion_data.callback_info.arg = __arg;                       \
        __op->addr = __addr;                                                   \
        na_ucx_addr_ref_incr(__addr);                                          \
        hg_atomic_set32(&__op->status, 0);                                     \
    } while (0)

#define NA_UCX_OP_RESET_UNEXPECTED_RECV(__op, __context, __cb, __arg)          \
    do {                                                                       \
        __op->context = __context;                                             \
        __op->completion_data.callback_info.type = NA_CB_RECV_UNEXPECTED;      \
        __op->completion_data.callback = __cb;                                 \
        __op->completion_data.callback_info.arg = __arg;                       \
        __op->completion_data.callback_info.info.recv_unexpected =             \
            (struct na_cb_info_recv_unexpected){                               \
                .actual_buf_size = 0, .source = NA_ADDR_NULL, .tag = 0};       \
        __op->addr = NULL;                                                     \
        hg_atomic_set32(&__op->status, 0);                                     \
    } while (0)

#define NA_UCX_OP_RELEASE(__op)                                                \
    do {                                                                       \
        if (__op->addr)                                                        \
            na_ucx_addr_ref_decr(__op->addr);                                  \
        hg_atomic_set32(&__op->status, NA_UCX_OP_COMPLETED);                   \
    } while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Address status */
enum na_ucx_addr_status {
    NA_UCX_ADDR_INIT,
    NA_UCX_ADDR_RESOLVING,
    NA_UCX_ADDR_RESOLVED
};

/* Address */
struct na_ucx_addr {
    HG_QUEUE_ENTRY(na_ucx_addr) entry; /* Entry in addr pool */
    struct sockaddr_storage ss_addr;   /* Sock addr */
    ucs_sock_addr_t addr_key;          /* Address key */
    struct na_ucx_class *na_ucx_class; /* NA UCX class */
    ucp_address_t *worker_addr;        /* Worker addr */
    size_t worker_addr_len;            /* Worker addr len */
    na_bool_t worker_addr_alloc;       /* Worker addr was allocated by us */
    ucp_ep_h ucp_ep;                   /* Currently only one EP per address */
    uint32_t conn_id;                  /* Connection ID (local) */
    uint32_t remote_conn_id;           /* Connection ID (remote) */
    hg_atomic_int32_t refcount;        /* Reference counter */
    hg_atomic_int32_t status;          /* Resolution status */
};

/* Map (used to cache addresses) */
struct na_ucx_map {
    hg_thread_rwlock_t lock;
    hg_hash_table_t *map;
};

/* Memory descriptor */
struct na_ucx_mem_desc {
    void *base;           /* Base address */
    size_t len;           /* Size of region */
    size_t rkey_buf_size; /* Cached rkey buf size */
    na_uint8_t flags;     /* Flag of operation access */
};

/* Handle type */
enum na_ucx_mem_handle_type {
    NA_UCX_MEM_HANDLE_LOCAL,
    NA_UCX_MEM_HANDLE_REMOTE_PACKED,
    NA_UCX_MEM_HANDLE_REMOTE_UNPACKED
};

/* Memory handle */
struct na_ucx_mem_handle {
    struct na_ucx_mem_desc desc;        /* Memory descriptor */
    hg_thread_mutex_t rkey_unpack_lock; /* Unpack lock */
    union {
        ucp_mem_h mem;   /* UCP mem handle */
        ucp_rkey_h rkey; /* UCP rkey handle */
    } ucp_mr;
    void *rkey_buf;         /* Cached rkey buf */
    hg_atomic_int32_t type; /* Handle type (local / remote) */
};

/* Msg info */
struct na_ucx_msg_info {
    union {
        const void *const_ptr;
        void *ptr;
    } buf;
    size_t buf_size;
    na_tag_t tag;
};

/* UCP RMA op (put/get) */
typedef na_return_t (*na_ucp_rma_op_t)(ucp_ep_h ep, void *buf, size_t buf_size,
    uint64_t remote_addr, ucp_rkey_h rkey, void *request);

/* RMA info */
struct na_ucx_rma_info {
    na_ucp_rma_op_t ucp_rma_op;
    void *buf;
    size_t buf_size;
    uint64_t remote_addr;
    ucp_rkey_h remote_key;
};

/* Operation ID */
struct na_ucx_op_id {
    struct na_cb_completion_data completion_data; /* Completion data    */
    union {
        struct na_ucx_msg_info msg;
        struct na_ucx_rma_info rma;
    } info;                             /* Op info                  */
    HG_QUEUE_ENTRY(na_ucx_op_id) entry; /* Entry in queue           */
    na_context_t *context;              /* NA context associated    */
    struct na_ucx_addr *addr;           /* Address associated       */
    hg_atomic_int32_t status;           /* Operation status         */
};

/* Addr ppol */
struct na_ucx_addr_pool {
    HG_QUEUE_HEAD(na_ucx_addr) queue;
    hg_thread_spin_t lock;
};

/* Op ID queue */
struct na_ucx_op_queue {
    HG_QUEUE_HEAD(na_ucx_op_id) queue;
    hg_thread_spin_t lock;
};

/* UCX class */
struct na_ucx_class {
    struct na_ucx_map addr_map;            /* Address map */
    struct na_ucx_map addr_conn;           /* Connection ID map */
    struct na_ucx_op_queue retry_op_queue; /* Retry op queue */
    struct na_ucx_addr_pool addr_pool;     /* Addr pool */
    ucp_context_h ucp_context;             /* UCP context */
    ucp_worker_h ucp_worker;               /* Shared UCP worker */
    ucp_listener_h ucp_listener;           /* Listener handle if listening */
    struct na_ucx_addr *self_addr;         /* Self address */
    struct hg_mem_pool *mem_pool;          /* Msg buf pool */
    size_t ucp_request_size;               /* Size of UCP requests */
    char *protocol_name;                   /* Protocol used */
    na_size_t unexpected_size_max;         /* Max unexpected size */
    na_size_t expected_size_max;           /* Max expected size */
    hg_atomic_int32_t conn_id;             /* Connection ID */
    hg_atomic_int32_t ncontexts;           /* Number of contexts */
    na_bool_t no_wait;                     /* Wait disabled */
};

/********************/
/* Local Prototypes */
/********************/

/*---------------------------------------------------------------------------*/
/* NA UCP helpers                                                            */
/*---------------------------------------------------------------------------*/

/**
 * Init config.
 */
static na_return_t
na_ucp_config_init(
    const char *tls, const char *net_devices, ucp_config_t **config_p);

/**
 * Release config.
 */
static void
na_ucp_config_release(ucp_config_t *config);

/**
 * Create context.
 */
static na_return_t
na_ucp_context_create(const ucp_config_t *config, na_bool_t no_wait,
    ucs_thread_mode_t thread_mode, ucp_context_h *context_p,
    size_t *request_size_p);

/**
 * Destroy context.
 */
static void
na_ucp_context_destroy(ucp_context_h context);

/**
 * Create worker.
 */
static na_return_t
na_ucp_worker_create(ucp_context_h context, ucs_thread_mode_t thread_mode,
    ucp_worker_h *worker_p);

/**
 * Destroy worker.
 */
static void
na_ucp_worker_destroy(ucp_worker_h worker);

/**
 * Retrieve worker address.
 */
static na_return_t
na_ucp_worker_get_address(
    ucp_worker_h worker, ucp_address_t **addr_p, size_t *addr_len_p);

/**
 * Create listener.
 */
static na_return_t
na_ucp_listener_create(ucp_worker_h context, const struct sockaddr *addr,
    socklen_t addrlen, void *listener_arg, ucp_listener_h *listener_p,
    struct sockaddr_storage *listener_addr);

/**
 * Destroy listener.
 */
static void
na_ucp_listener_destroy(ucp_listener_h listener);

/**
 * Listener callback.
 */
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void *arg);

/**
 * Accept connection.
 */
static na_return_t
na_ucp_accept(ucp_worker_h worker, ucp_conn_request_h conn_request,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Establish connection.
 */
static na_return_t
na_ucp_connect(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, ucp_err_handler_cb_t err_handler_cb,
    void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Create endpoint to worker using worker address (unconnected).
 */
static na_return_t
na_ucp_connect_worker(ucp_worker_h worker, ucp_address_t *address,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Create endpoint.
 */
static na_return_t
na_ucp_ep_create(ucp_worker_h worker, ucp_ep_params_t *ep_params,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Error handler.
 */
static void
na_ucp_ep_error_cb(void *arg, ucp_ep_h ep, ucs_status_t status);

/**
 * Get next connection ID.
 */
static uint32_t
na_ucp_conn_id_gen(struct na_ucx_class *na_ucx_class);

/**
 * Exchange (send/recv) connection IDs.
 */
static na_return_t
na_ucp_conn_id_exchange(ucp_ep_h ep, const uint32_t *local_conn_id,
    uint32_t *remote_conn_id, void *arg);

/**
 * Connection ID send callback.
 */
static void
na_ucp_conn_id_send_cb(void *request, ucs_status_t status, void *user_data);

/**
 * Connection ID recv callback.
 */
static void
na_ucp_conn_id_recv_cb(
    void *request, ucs_status_t status, size_t length, void *user_data);

/**
 * Create a msg tag.
 */
static NA_INLINE ucp_tag_t
na_ucp_tag_gen(uint32_t tag, uint8_t unexpected, uint32_t conn_id);

/**
 * Convert a msg tag to a connection ID.
 */
static NA_INLINE uint32_t
na_ucp_tag_to_conn_id(ucp_tag_t tag);

/**
 * Allocate and register memory.
 */
static void *
na_ucp_mem_alloc(ucp_context_h context, size_t len, ucp_mem_h *mem_p);

/**
 * Free memory.
 */
static na_return_t
na_ucp_mem_free(ucp_context_h context, ucp_mem_h mem);

#ifdef NA_UCX_HAS_MEM_POOL
/**
 * Register memory buffer.
 */
static int
na_ucp_mem_buf_register(const void *buf, size_t len, void **handle, void *arg);

/**
 * Deregister memory buffer.
 */
static int
na_ucp_mem_buf_deregister(void *handle, void *arg);

#endif /* NA_UCX_HAS_MEM_POOL */

/**
 * Send a msg.
 */
static na_return_t
na_ucp_msg_send(ucp_ep_h ep, const void *buf, size_t buf_size, ucp_tag_t tag,
    void *request);

/**
 * Send msg callback.
 */
static void
na_ucp_msg_send_cb(void *request, ucs_status_t status, void *user_data);

/**
 * Recv a msg.
 */
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request, ucp_tag_recv_nbx_callback_t recv_cb,
    void *user_data);

/**
 * Recv unexpected msg callback.
 */
static void
na_ucp_msg_recv_unexpected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void *user_data);

/**
 * Recv expected msg callback.
 */
static void
na_ucp_msg_recv_expected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void *user_data);

/**
 * RMA put.
 */
static na_return_t
na_ucp_put(ucp_ep_h ep, void *buf, size_t buf_size, uint64_t remote_addr,
    ucp_rkey_h rkey, void *request);

/**
 * RMA get.
 */
static na_return_t
na_ucp_get(ucp_ep_h ep, void *buf, size_t buf_size, uint64_t remote_addr,
    ucp_rkey_h rkey, void *request);

/**
 * RMA callback.
 */
static void
na_ucp_rma_cb(void *request, ucs_status_t status, void *user_data);

/*---------------------------------------------------------------------------*/
/* NA UCX helpers                                                            */
/*---------------------------------------------------------------------------*/

/**
 * Allocate new UCX class.
 */
static struct na_ucx_class *
na_ucx_class_alloc(void);

/**
 * Free UCX class.
 */
static void
na_ucx_class_free(struct na_ucx_class *na_ucx_class);

/**
 * Parse hostname info.
 */
static na_return_t
na_ucx_parse_hostname_info(const char *hostname_info, const char *subnet_info,
    char **net_device_p, struct sockaddr_storage **sockaddr_p);

/**
 * Hash address key.
 */
static NA_INLINE unsigned int
na_ucx_addr_key_hash(hg_hash_table_key_t key);

/**
 * Compare address keys.
 */
static NA_INLINE int
na_ucx_addr_key_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Lookup addr from addr_key.
 */
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_map_lookup(
    struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key);

/**
 * Insert new addr using addr_key (if it does not already exist).
 */
static na_return_t
na_ucx_addr_map_insert(struct na_ucx_class *na_ucx_class,
    struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key,
    struct na_ucx_addr **na_ucx_addr_p);

/**
 * Remove addr from map using addr_key.
 */
static na_return_t
na_ucx_addr_map_remove(
    struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key);

/**
 * Hash connection ID.
 */
static NA_INLINE unsigned int
na_ucx_addr_conn_hash(hg_hash_table_key_t key);

/**
 * Compare connection IDs.
 */
static NA_INLINE int
na_ucx_addr_conn_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Lookup addr from connection ID.
 */
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_conn_lookup(struct na_ucx_map *na_ucx_map, uint32_t *conn_id);

/**
 * Insert new addr using connection ID (if it does not already exist).
 */
static na_return_t
na_ucx_addr_conn_insert(
    struct na_ucx_map *na_ucx_map, struct na_ucx_addr *na_ucx_addr);

/**
 * Remove addr from map using connection ID.
 */
static na_return_t
na_ucx_addr_conn_remove(struct na_ucx_map *na_ucx_map, uint32_t *conn_id);

/**
 * Allocate empty address.
 */
static struct na_ucx_addr *
na_ucx_addr_alloc(struct na_ucx_class *na_ucx_class);

/**
 * Destroy address.
 */
static void
na_ucx_addr_destroy(struct na_ucx_addr *na_ucx_addr);

#ifdef NA_UCX_HAS_ADDR_POOL
/**
 * Retrieve address from pool.
 */
static struct na_ucx_addr *
na_ucx_addr_pool_get(struct na_ucx_class *na_ucx_class);
#endif

/**
 * Release address without destroying it.
 */
static void
na_ucx_addr_release(struct na_ucx_addr *na_ucx_addr);

/**
 * Reset address.
 */
static void
na_ucx_addr_reset(struct na_ucx_addr *na_ucx_addr, ucs_sock_addr_t *addr_key);

/**
 * Create address.
 */
static na_return_t
na_ucx_addr_create(struct na_ucx_class *na_ucx_class, ucs_sock_addr_t *addr_key,
    struct na_ucx_addr **na_ucx_addr_p);

/**
 * Increment ref count.
 */
static NA_INLINE void
na_ucx_addr_ref_incr(struct na_ucx_addr *na_ucx_addr);

/**
 * Decrement ref count and free address if 0.
 */
static NA_INLINE void
na_ucx_addr_ref_decr(struct na_ucx_addr *na_ucx_addr);

/**
 * Resolve address.
 */
static na_return_t
na_ucx_addr_resolve(
    struct na_ucx_class *na_ucx_class, struct na_ucx_addr *na_ucx_addr);

/**
 * Send msg.
 */
static na_return_t
na_ucx_msg_send(struct na_ucx_class *na_ucx_class, na_context_t *context,
    na_cb_type_t cb_type, na_cb_t callback, void *arg, const void *buf,
    na_size_t buf_size, struct na_ucx_addr *na_ucx_addr, na_tag_t tag,
    struct na_ucx_op_id *na_ucx_op_id);

/**
 * Post RMA operation.
 */
static na_return_t
na_ucx_rma(struct na_ucx_class *na_ucx_class, na_context_t *context,
    na_cb_type_t cb_type, na_cb_t callback, void *arg,
    struct na_ucx_mem_handle *local_mem_handle, na_offset_t local_offset,
    struct na_ucx_mem_handle *remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, struct na_ucx_addr *na_ucx_addr,
    struct na_ucx_op_id *na_ucx_op_id);

/**
 * Resolve RMA remote key.
 */
static na_return_t
na_ucx_rma_key_resolve(ucp_ep_h ep, struct na_ucx_mem_handle *na_ucx_mem_handle,
    ucp_rkey_h *rkey_p);

/**
 * Push operation to retry queue.
 */
static NA_INLINE void
na_ucx_op_retry(
    struct na_ucx_class *na_ucx_class, struct na_ucx_op_id *na_ucx_op_id);

/**
 * Retry operations from retry queue.
 */
static na_return_t
na_ucx_process_retries(struct na_ucx_class *na_ucx_class);

/**
 * Complete UCX operation.
 */
static NA_INLINE void
na_ucx_complete(struct na_ucx_op_id *na_ucx_op_id, na_return_t cb_ret);

/**
 * Release resources after NA callback execution.
 */
static NA_INLINE void
na_ucx_release(void *arg);

/********************/
/* Plugin callbacks */
/********************/

/* check_protocol */
static na_bool_t
na_ucx_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_ucx_initialize(
    na_class_t *na_class, const struct na_info *na_info, na_bool_t listen);

/* finalize */
static na_return_t
na_ucx_finalize(na_class_t *na_class);

/* op_create */
static na_op_id_t *
na_ucx_op_create(na_class_t *na_class);

/* op_destroy */
static na_return_t
na_ucx_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_ucx_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p);

/* addr_free */
static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_self */
static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *na_class, na_addr_t *addr);

/* addr_dup */
static NA_INLINE na_return_t
na_ucx_addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr);

/* addr_dup */
static na_bool_t
na_ucx_addr_cmp(na_class_t *na_class, na_addr_t addr1, na_addr_t addr2);

/* addr_is_self */
static NA_INLINE na_bool_t
na_ucx_addr_is_self(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t
na_ucx_addr_to_string(
    na_class_t *na_class, char *buf, na_size_t *buf_size, na_addr_t addr);

/* addr_get_serialize_size */
static NA_INLINE na_size_t
na_ucx_addr_get_serialize_size(na_class_t *na_class, na_addr_t addr);

/* addr_serialize */
static na_return_t
na_ucx_addr_serialize(
    na_class_t *na_class, void *buf, na_size_t buf_size, na_addr_t addr);

/* addr_deserialize */
static na_return_t
na_ucx_addr_deserialize(na_class_t *na_class, na_addr_t *addr_p,
    const void *buf, na_size_t buf_size);

/* msg_get_max_unexpected_size */
static NA_INLINE na_size_t
na_ucx_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static NA_INLINE na_size_t
na_ucx_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_max_tag */
static NA_INLINE na_tag_t
na_ucx_msg_get_max_tag(const na_class_t *na_class);

/* msg_buf_alloc */
static void *
na_ucx_msg_buf_alloc(na_class_t *na_class, na_size_t size, void **plugin_data);

/* msg_buf_free */
static na_return_t
na_ucx_msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data);

/* msg_send_unexpected */
static na_return_t
na_ucx_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ucx_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ucx_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ucx_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source_addr, na_uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id);

/* mem_handle */
static na_return_t
na_ucx_mem_handle_create(na_class_t *na_class, void *buf, na_size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle_p);

static na_return_t
na_ucx_mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle);

static NA_INLINE na_size_t
na_ucx_mem_handle_get_max_segments(const na_class_t *na_class);

static na_return_t
na_ucx_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle);

/* mem_handle serialization */
static NA_INLINE na_size_t
na_ucx_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_handle_serialize(na_class_t *na_class, void *buf, na_size_t buf_size,
    na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_handle_deserialize(na_class_t *na_class,
    na_mem_handle_t *mem_handle_p, const void *buf, na_size_t buf_size);

/* put */
static na_return_t
na_ucx_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_ucx_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static int
na_ucx_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* progress */
static na_return_t
na_ucx_progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout);

/* cancel */
static na_return_t
na_ucx_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/*******************/
/* Local Variables */
/*******************/

const struct na_class_ops NA_PLUGIN_OPS(ucx) = {
    "ucx",                                /* name */
    na_ucx_check_protocol,                /* check_protocol */
    na_ucx_initialize,                    /* initialize */
    na_ucx_finalize,                      /* finalize */
    NULL,                                 /* cleanup */
    NULL,                                 /* context_create */
    NULL,                                 /* context_destroy */
    na_ucx_op_create,                     /* op_create */
    na_ucx_op_destroy,                    /* op_destroy */
    na_ucx_addr_lookup,                   /* addr_lookup */
    na_ucx_addr_free,                     /* addr_free */
    NULL,                                 /* addr_set_remove */
    na_ucx_addr_self,                     /* addr_self */
    na_ucx_addr_dup,                      /* addr_dup */
    na_ucx_addr_cmp,                      /* addr_cmp */
    na_ucx_addr_is_self,                  /* addr_is_self */
    na_ucx_addr_to_string,                /* addr_to_string */
    na_ucx_addr_get_serialize_size,       /* addr_get_serialize_size */
    na_ucx_addr_serialize,                /* addr_serialize */
    na_ucx_addr_deserialize,              /* addr_deserialize */
    na_ucx_msg_get_max_unexpected_size,   /* msg_get_max_unexpected_size */
    na_ucx_msg_get_max_expected_size,     /* msg_get_max_expected_size */
    NULL,                                 /* msg_get_unexpected_header_size */
    NULL,                                 /* msg_get_expected_header_size */
    na_ucx_msg_get_max_tag,               /* msg_get_max_tag */
    na_ucx_msg_buf_alloc,                 /* msg_buf_alloc */
    na_ucx_msg_buf_free,                  /* msg_buf_free */
    NULL,                                 /* msg_init_unexpected */
    na_ucx_msg_send_unexpected,           /* msg_send_unexpected */
    na_ucx_msg_recv_unexpected,           /* msg_recv_unexpected */
    NULL,                                 /* msg_init_expected */
    na_ucx_msg_send_expected,             /* msg_send_expected */
    na_ucx_msg_recv_expected,             /* msg_recv_expected */
    na_ucx_mem_handle_create,             /* mem_handle_create */
    NULL,                                 /* mem_handle_create_segment */
    na_ucx_mem_handle_free,               /* mem_handle_free */
    na_ucx_mem_handle_get_max_segments,   /* mem_handle_get_max_segments */
    na_ucx_mem_register,                  /* mem_register */
    na_ucx_mem_deregister,                /* mem_deregister */
    na_ucx_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
    na_ucx_mem_handle_serialize,          /* mem_handle_serialize */
    na_ucx_mem_handle_deserialize,        /* mem_handle_deserialize */
    na_ucx_put,                           /* put */
    na_ucx_get,                           /* get */
    na_ucx_poll_get_fd,                   /* poll_get_fd */
    na_ucx_poll_try_wait,                 /* poll_try_wait */
    na_ucx_progress,                      /* progress */
    na_ucx_cancel                         /* cancel */
};

/* Thread mode names */
#ifndef NA_UCX_HAS_THREAD_MODE_NAMES
#    define NA_UCX_THREAD_MODES                                                \
        X(UCS_THREAD_MODE_SINGLE, "single")                                    \
        X(UCS_THREAD_MODE_SERIALIZED, "serialized")                            \
        X(UCS_THREAD_MODE_MULTI, "multi")
#    define X(a, b) b,
static const char *ucs_thread_mode_names[UCS_THREAD_MODE_LAST] = {
    NA_UCX_THREAD_MODES};
#    undef X
#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_config_init(
    const char *tls, const char *net_devices, ucp_config_t **config_p)
{
    ucp_config_t *config = NULL;
    ucs_status_t status;
    na_return_t ret;

    /* Read UCP configuration */
    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Set user-requested transport */
    status = ucp_config_modify(config, "TLS", tls);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Use mutex instead of spinlock */
    // status = ucp_config_modify(config, "USE_MT_MUTEX", "y");
    // NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret,
    // NA_PROTOCOL_ERROR,
    //     "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* TODO Currently assume that systems are homogeneous */
    status = ucp_config_modify(config, "UNIFIED_MODE", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Add address debug info if running in debug */
    // status = ucp_config_modify(config, "ADDRESS_DEBUG_INFO", "y");
    // NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret,
    // NA_PROTOCOL_ERROR,
    //     "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Set network devices to use */
    if (net_devices) {
        status = ucp_config_modify(config, "NET_DEVICES", net_devices);
        NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret,
            NA_PROTOCOL_ERROR, "ucp_config_modify() failed (%s)",
            ucs_status_string(status));
    } else
        NA_LOG_SUBSYS_DEBUG(
            cls, "Could not find NET_DEVICE to use, using default");

    /* Print UCX config */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls,
        ucp_config_print(config, hg_log_get_stream_debug(),
            "NA UCX class configuration used",
            UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER),
        "Now using the following UCX global configuration");

    *config_p = config;

    return NA_SUCCESS;

error:
    if (config)
        ucp_config_release(config);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_config_release(ucp_config_t *config)
{
    ucp_config_release(config);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_context_create(const ucp_config_t *config, na_bool_t no_wait,
    ucs_thread_mode_t thread_mode, ucp_context_h *context_p,
    size_t *request_size_p)
{
    ucp_context_h context = NULL;
    ucp_params_t context_params = {
        .field_mask =
            UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_TAG_SENDER_MASK,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA | UCP_FEATURE_STREAM,
        .tag_sender_mask = NA_UCX_TAG_SENDER_MASK};
    ucp_context_attr_t context_attrs = {
        .field_mask = UCP_ATTR_FIELD_REQUEST_SIZE | UCP_ATTR_FIELD_THREAD_MODE};
    ucs_status_t status;
    na_return_t ret;

    /* Skip wakeup feature if not waiting */
    if (no_wait != NA_TRUE)
        context_params.features |= UCP_FEATURE_WAKEUP;

    if (thread_mode == UCS_THREAD_MODE_MULTI) {
        /* If the UCP context can potentially be used by more than one
         * worker / thread, then this context needs thread safety. */
        context_params.field_mask |= UCP_PARAM_FIELD_MT_WORKERS_SHARED;
        context_params.mt_workers_shared = 1;
    }

    /* Create UCP context */
    status = ucp_init(&context_params, config, &context);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_init() failed (%s)", ucs_status_string(status));

    /* Print context info */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls,
        ucp_context_print_info(context, hg_log_get_stream_debug()),
        "Context info");

    /* Query context to ensure we got what we asked for */
    status = ucp_context_query(context, &context_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_context_query() failed (%s)", ucs_status_string(status));

    /* Check that expected fields are present */
    NA_CHECK_SUBSYS_ERROR(cls,
        (context_attrs.field_mask & UCP_ATTR_FIELD_REQUEST_SIZE) == 0, error,
        ret, NA_PROTOCOL_ERROR, "context attributes contain no request size");
    NA_CHECK_SUBSYS_ERROR(cls,
        (context_attrs.field_mask & UCP_ATTR_FIELD_THREAD_MODE) == 0, error,
        ret, NA_PROTOCOL_ERROR, "context attributes contain no thread mode");

    /* Do not continue if thread mode is less than expected */
    NA_CHECK_SUBSYS_ERROR(cls,
        thread_mode != UCS_THREAD_MODE_SINGLE &&
            context_attrs.thread_mode < thread_mode,
        error, ret, NA_PROTOCOL_ERROR, "Context thread mode is: %s",
        ucs_thread_mode_names[context_attrs.thread_mode]);

    NA_LOG_SUBSYS_DEBUG(
        cls, "UCP request size is %zu", context_attrs.request_size);

    *context_p = context;
    *request_size_p = context_attrs.request_size;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_context_destroy(ucp_context_h context)
{
    ucp_cleanup(context);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_worker_create(ucp_context_h context, ucs_thread_mode_t thread_mode,
    ucp_worker_h *worker_p)
{
    ucp_worker_h worker = NULL;
    ucp_worker_params_t worker_params = {
        .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
        .thread_mode = thread_mode};
    ucp_worker_attr_t worker_attrs = {
        .field_mask = UCP_WORKER_ATTR_FIELD_THREAD_MODE};
    ucs_status_t status;
    na_return_t ret;

    /* Create UCP worker */
    status = ucp_worker_create(context, &worker_params, &worker);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_worker_create() failed (%s)", ucs_status_string(status));

    /* Print worker info */
    NA_LOG_SUBSYS_DEBUG_FUNC(ctx,
        ucp_worker_print_info(worker, hg_log_get_stream_debug()),
        "Worker info");

    /* Check thread mode */
    status = ucp_worker_query(worker, &worker_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_worker_query() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(cls,
        (worker_attrs.field_mask & UCP_WORKER_ATTR_FIELD_THREAD_MODE) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "worker attributes contain no thread mode");
    NA_CHECK_SUBSYS_ERROR(cls,
        thread_mode != UCS_THREAD_MODE_SINGLE &&
            worker_attrs.thread_mode < thread_mode,
        error, ret, NA_PROTONOSUPPORT,
        "UCP worker thread mode (%s) is not supported",
        ucs_thread_mode_names[worker_attrs.thread_mode]);

    *worker_p = worker;

    return NA_SUCCESS;

error:
    if (worker)
        ucp_worker_destroy(worker);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_worker_destroy(ucp_worker_h worker)
{
    ucp_worker_destroy(worker);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_worker_get_address(
    ucp_worker_h worker, ucp_address_t **addr_p, size_t *addr_len_p)
{
    ucs_status_t status;
    na_return_t ret = NA_SUCCESS;

    status = ucp_worker_get_address(worker, addr_p, addr_len_p);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, done, ret, NA_PROTOCOL_ERROR,
        "ucp_worker_get_address() failed (%s)", ucs_status_string(status));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_listener_create(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, void *listener_arg, ucp_listener_h *listener_p,
    struct sockaddr_storage *listener_addr)
{
    ucp_listener_h listener = NULL;
    ucp_listener_params_t listener_params = {
        .field_mask = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
                      UCP_LISTENER_PARAM_FIELD_CONN_HANDLER,
        .sockaddr = (ucs_sock_addr_t){.addr = addr, .addrlen = addrlen},
        .conn_handler = (ucp_listener_conn_handler_t){
            .cb = na_ucp_listener_conn_cb, .arg = listener_arg}};
    ucp_listener_attr_t listener_attrs = {
        .field_mask = UCP_LISTENER_ATTR_FIELD_SOCKADDR};
    ucs_status_t status;
    na_return_t ret;

    /* Create listener on worker */
    status = ucp_listener_create(worker, &listener_params, &listener);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_listener_create() failed (%s)", ucs_status_string(status));

    /* Check sockaddr */
    status = ucp_listener_query(listener, &listener_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_listener_query() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(cls,
        (listener_attrs.field_mask & UCP_LISTENER_ATTR_FIELD_SOCKADDR) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "listener attributes contain no sockaddr");

    *listener_p = listener;
    memcpy(listener_addr, &listener_attrs.sockaddr, sizeof(*listener_addr));

    return NA_SUCCESS;

error:
    if (listener)
        ucp_listener_destroy(listener);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_listener_destroy(ucp_listener_h listener)
{
    ucp_listener_destroy(listener);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void *arg)
{
    struct na_ucx_class *na_ucx_class = (struct na_ucx_class *) arg;
    ucp_conn_request_attr_t conn_request_attrs = {
        .field_mask = UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR};
    struct na_ucx_addr *na_ucx_addr = NULL;
    ucs_sock_addr_t addr_key;
    ucs_status_t status;
    unsigned int retry = 0;
    na_return_t na_ret;

    status = ucp_conn_request_query(conn_request, &conn_request_attrs);
    NA_CHECK_SUBSYS_ERROR_NORET(addr, status != UCS_OK, error,
        "ucp_conn_request_query() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR_NORET(addr,
        (conn_request_attrs.field_mask &
            UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR) == 0,
        error, "conn attributes contain no client addr");

    /* Lookup address from table */
    addr_key = (ucs_sock_addr_t){
        .addr = (const struct sockaddr *) &conn_request_attrs.client_address,
        .addrlen = sizeof(conn_request_attrs.client_address)};
    na_ucx_addr = na_ucx_addr_map_lookup(&na_ucx_class->addr_map, &addr_key);
    NA_CHECK_SUBSYS_ERROR_NORET(addr, na_ucx_addr != NULL, error,
        "An entry is already present for this address");

    /* Insert new entry and create new address */
    na_ret = na_ucx_addr_map_insert(
        na_ucx_class, &na_ucx_class->addr_map, &addr_key, &na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, na_ret, "Could not insert new address");

    /* Accept connection */
    na_ret = na_ucp_accept(na_ucx_class->ucp_worker, conn_request,
        na_ucp_ep_error_cb, (void *) na_ucx_addr, &na_ucx_addr->ucp_ep);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, na_ret, "Could not accept connection request");

    while (retry < NA_UCX_CONN_RETRY_MAX) {
        /* Generate connection ID */
        na_ucx_addr->conn_id = na_ucp_conn_id_gen(na_ucx_class);

        /* Insert connection entry to lookup address by connection ID */
        na_ret = na_ucx_addr_conn_insert(&na_ucx_class->addr_conn, na_ucx_addr);
        if (na_ret == NA_SUCCESS)
            break;
        else if (na_ret == NA_EXIST) {
            /* Attempt to use another connection ID */
            retry++;
            continue;
        } else
            NA_CHECK_SUBSYS_NA_ERROR(
                addr, error, na_ret, "Could not insert new address");
    }

    /* Exchange IDs so that we can later use that ID to identify msg senders */
    na_ret = na_ucp_conn_id_exchange(na_ucx_addr->ucp_ep, &na_ucx_addr->conn_id,
        &na_ucx_addr->remote_conn_id, na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, na_ret, "Could not exchange connection IDs");

    return;

error:
    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_accept(ucp_worker_h worker, ucp_conn_request_h conn_request,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_params_t ep_params = {.field_mask = UCP_EP_PARAM_FIELD_CONN_REQUEST,
        .conn_request = conn_request};

    return na_ucp_ep_create(
        worker, &ep_params, err_handler_cb, err_handler_arg, ep_p);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_connect(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, ucp_err_handler_cb_t err_handler_cb,
    void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_params_t ep_params = {
        .field_mask = UCP_EP_PARAM_FIELD_FLAGS | UCP_EP_PARAM_FIELD_SOCK_ADDR,
        .flags = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER,
        .sockaddr = (ucs_sock_addr_t){.addr = addr, .addrlen = addrlen},
        .conn_request = NULL};

    return na_ucp_ep_create(
        worker, &ep_params, err_handler_cb, err_handler_arg, ep_p);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_connect_worker(ucp_worker_h worker, ucp_address_t *address,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_params_t ep_params = {
        .field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS,
        .address = address,
        .conn_request = NULL};

    NA_LOG_SUBSYS_DEBUG(addr, "Connecting to worker ");

    return na_ucp_ep_create(
        worker, &ep_params, err_handler_cb, err_handler_arg, ep_p);
}

/*---------------------------------------------------------------------------*/
static uint32_t
na_ucp_conn_id_gen(struct na_ucx_class *na_ucx_class)
{
    return (hg_atomic_cas32(&na_ucx_class->conn_id, INT32_MAX, 0))
               ? 1 /* Incremented value */
               : (uint32_t) hg_atomic_incr32(&na_ucx_class->conn_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_conn_id_exchange(ucp_ep_h ep, const uint32_t *local_conn_id,
    uint32_t *remote_conn_id, void *arg)
{
    const ucp_request_param_t recv_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA |
                        UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
        .cb = {.recv_stream = na_ucp_conn_id_recv_cb},
        .user_data = arg,
        .datatype = ucp_dt_make_contig(sizeof(uint32_t)),
        .flags = UCP_STREAM_RECV_FLAG_WAITALL};
    const ucp_request_param_t send_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA |
                        UCP_OP_ATTR_FIELD_DATATYPE,
        .cb = {.send = na_ucp_conn_id_send_cb},
        .user_data = arg,
        .datatype = ucp_dt_make_contig(sizeof(uint32_t))};
    ucs_status_ptr_t send_ptr, recv_ptr;
    na_return_t ret;
    size_t recv_len;

    /* Recv remote conn ID */
    recv_ptr =
        ucp_stream_recv_nbx(ep, remote_conn_id, 1, &recv_len, &recv_params);
    if (recv_ptr == NULL) {
        /* Completed immediately */
        NA_LOG_SUBSYS_DEBUG(
            addr, "ucp_stream_recv_nbx() completed immediately");

        /* Directly execute callback */
        na_ucp_conn_id_recv_cb(NULL, UCS_OK, recv_len, arg);
    } else
        NA_CHECK_SUBSYS_ERROR(addr, UCS_PTR_IS_ERR(recv_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_stream_recv_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(recv_ptr)));

    /* Send local conn ID */
    send_ptr = ucp_stream_send_nbx(ep, local_conn_id, 1, &send_params);
    if (send_ptr == NULL) {
        /* Completed immediately */
        NA_LOG_SUBSYS_DEBUG(
            addr, "ucp_stream_send_nbx() completed immediately");

        /* Directly execute callback */
        na_ucp_conn_id_send_cb(NULL, UCS_OK, arg);
    } else
        NA_CHECK_SUBSYS_ERROR(addr, UCS_PTR_IS_ERR(send_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_stream_send_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(send_ptr)));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_conn_id_send_cb(
    void *request, ucs_status_t status, void NA_UNUSED *user_data)
{
    na_return_t cb_ret;

    NA_LOG_SUBSYS_DEBUG(addr, "ucp_stream_send_nbx() completed (%s)",
        ucs_status_string(status));

    if (status == UCS_OK)
        NA_GOTO_DONE(done, cb_ret, NA_SUCCESS);
    else if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(addr, done, cb_ret, NA_PROTOCOL_ERROR,
            "ucp_stream_send_nbx() failed (%s)", ucs_status_string(status));

done:
    if (request)
        ucp_request_free(request);

    /* TODO link request to op id */
    (void) cb_ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_conn_id_recv_cb(void *request, ucs_status_t status,
    size_t NA_UNUSED length, void NA_UNUSED *user_data)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) user_data;
    na_return_t cb_ret;

    NA_LOG_SUBSYS_DEBUG(addr, "ucp_stream_recv_nbx() completed (%s)",
        ucs_status_string(status));

    if (status == UCS_OK) {
        NA_LOG_SUBSYS_DEBUG(
            addr, "Marking addr (%p) as resolved", (void *) na_ucx_addr);
        hg_atomic_set32(&na_ucx_addr->status, NA_UCX_ADDR_RESOLVED);
        NA_GOTO_DONE(done, cb_ret, NA_SUCCESS);
    } else if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(addr, done, cb_ret, NA_PROTOCOL_ERROR,
            "ucp_stream_recv_nbx() failed (%s)", ucs_status_string(status));

done:
    if (request)
        ucp_request_free(request);

    /* TODO link request to op id */
    (void) cb_ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE ucp_tag_t
na_ucp_tag_gen(uint32_t tag, uint8_t unexpected, uint32_t conn_id)
{
    return (((ucp_tag_t) conn_id << 33) |
            (((ucp_tag_t) unexpected & 0x1) << 32) | (ucp_tag_t) tag);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint32_t
na_ucp_tag_to_conn_id(ucp_tag_t tag)
{
    return (uint32_t) ((tag & NA_UCX_TAG_SENDER_MASK) >> 33);
}

/*---------------------------------------------------------------------------*/
static void *
na_ucp_mem_alloc(ucp_context_h context, size_t len, ucp_mem_h *mem_p)
{
    const ucp_mem_map_params_t mem_map_params = {
        .field_mask =
            UCP_MEM_MAP_PARAM_FIELD_LENGTH | UCP_MEM_MAP_PARAM_FIELD_FLAGS,
        .length = len,
        .flags = UCP_MEM_MAP_ALLOCATE // TODO use UCP_MEM_MAP_NONBLOCK ?
    };
    ucp_mem_attr_t mem_attrs = {.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS};
    ucp_mem_h mem = NULL;
    ucs_status_t status;

    /* Register memory */
    status = ucp_mem_map(context, &mem_map_params, &mem);
    NA_CHECK_SUBSYS_ERROR_NORET(mem, status != UCS_OK, error,
        "ucp_mem_map() failed (%s)", ucs_status_string(status));

    /* Query memory address */
    status = ucp_mem_query(mem, &mem_attrs);
    NA_CHECK_SUBSYS_ERROR_NORET(mem, status != UCS_OK, error,
        "ucp_mem_map() failed (%s)", ucs_status_string(status));
    NA_CHECK_SUBSYS_ERROR_NORET(mem,
        (mem_attrs.field_mask & UCP_MEM_ATTR_FIELD_ADDRESS) == 0, error,
        "mem attributes contain no address");

    *mem_p = mem;

    return mem_attrs.address;

error:
    if (mem)
        (void) ucp_mem_unmap(context, mem);
    return NULL;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_mem_free(ucp_context_h context, ucp_mem_h mem)
{
    ucs_status_t status;
    na_return_t ret;

    status = ucp_mem_unmap(context, mem);
    NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_mem_unmap() failed (%s)", ucs_status_string(status));

    return NA_SUCCESS;

error:
    return ret;
}

#ifdef NA_UCX_HAS_MEM_POOL
/*---------------------------------------------------------------------------*/
static int
na_ucp_mem_buf_register(const void *buf, size_t len, void **handle, void *arg)
{
    struct na_ucx_class *na_ucx_class = (struct na_ucx_class *) arg;
    union {
        void *ptr;
        const void *const_ptr;
    } safe_buf = {.const_ptr = buf};
    const ucp_mem_map_params_t mem_map_params = {
        .field_mask =
            UCP_MEM_MAP_PARAM_FIELD_ADDRESS | UCP_MEM_MAP_PARAM_FIELD_LENGTH,
        .address = safe_buf.ptr,
        .length = len};
    ucs_status_t status;
    int ret;

    /* Register memory */
    status = ucp_mem_map(
        na_ucx_class->ucp_context, &mem_map_params, (ucp_mem_h *) handle);
    NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, HG_UTIL_FAIL,
        "ucp_mem_map() failed (%s)", ucs_status_string(status));

    return HG_UTIL_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_ucp_mem_buf_deregister(void *handle, void *arg)
{
    int ret;

    if (handle) {
        struct na_ucx_class *na_ucx_class = (struct na_ucx_class *) arg;
        ucp_mem_h mem = (ucp_mem_h) handle;
        ucs_status_t status;

        status = ucp_mem_unmap(na_ucx_class->ucp_context, mem);
        NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, HG_UTIL_FAIL,
            "ucp_mem_unmap() failed (%s)", ucs_status_string(status));
    }

    return HG_UTIL_SUCCESS;

error:
    return ret;
}

#endif /* NA_UCX_HAS_MEM_POOL */

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_ep_create(ucp_worker_h worker, ucp_ep_params_t *ep_params,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_h ep = NULL;
    ucs_status_t status;
    na_return_t ret;

    ep_params->field_mask |=
        UCP_EP_PARAM_FIELD_ERR_HANDLER | UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    if (!(ep_params->field_mask & UCP_EP_PARAM_FIELD_REMOTE_ADDRESS))
        ep_params->err_mode = UCP_ERR_HANDLING_MODE_PEER;
    ep_params->err_handler.cb = err_handler_cb;
    ep_params->err_handler.arg = err_handler_arg;

    status = ucp_ep_create(worker, ep_params, &ep);
    NA_CHECK_SUBSYS_ERROR(addr, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_ep_create() failed (%s)", ucs_status_string(status));

    *ep_p = ep;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_ep_error_cb(
    void *arg, ucp_ep_h NA_UNUSED ep, ucs_status_t NA_DEBUG_LOG_USED status)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) arg;

    NA_LOG_SUBSYS_DEBUG(addr,
        "ep_err_handler() returned (%s) for address (conn_id=%d)",
        ucs_status_string(status), na_ucx_addr->conn_id);

    /* Will schedule removal of address */
    na_ucx_addr_ref_decr(na_ucx_addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_msg_send(
    ucp_ep_h ep, const void *buf, size_t buf_size, ucp_tag_t tag, void *request)
{
    const ucp_request_param_t send_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_REQUEST | UCP_OP_ATTR_FIELD_CALLBACK,
        .cb = {.send = na_ucp_msg_send_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    NA_LOG_SUBSYS_DEBUG(msg,
        "Posting msg send with buf_size=%zu, tag=0x%" PRIx64, buf_size, tag);

    status_ptr = ucp_tag_send_nbx(ep, buf, buf_size, tag, &send_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(msg, "ucp_tag_send_nbx() completed immediately");

        /* Directly execute callback */
        na_ucp_msg_send_cb(request, UCS_OK, NULL);
    } else
        NA_CHECK_SUBSYS_ERROR(msg, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_tag_send_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    NA_LOG_SUBSYS_DEBUG(msg, "ucp_tag_send_nbx() was posted");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_send_cb(
    void *request, ucs_status_t status, void NA_UNUSED *user_data)
{
    na_return_t cb_ret;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_send_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_OK)
        NA_GOTO_DONE(done, cb_ret, NA_SUCCESS);
    if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(msg, done, cb_ret, NA_PROTOCOL_ERROR,
            "ucp_tag_send_nbx() failed (%s)", ucs_status_string(status));

done:
    na_ucx_complete((struct na_ucx_op_id *) request, cb_ret);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request, ucp_tag_recv_nbx_callback_t recv_cb,
    void *user_data)
{
    ucp_tag_recv_info_t tag_recv_info;
    const ucp_request_param_t recv_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_REQUEST | UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA |
                        UCP_OP_ATTR_FIELD_RECV_INFO,
        .cb = {.recv = recv_cb},
        .request = request,
        .user_data = user_data,
        .recv_info.tag_info = &tag_recv_info};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    NA_LOG_SUBSYS_DEBUG(msg,
        "Posting msg recv with buf_size=%zu, tag=0x%" PRIx64
        ", tag_mask=0x%" PRIx64,
        buf_size, tag, tag_mask);

    status_ptr =
        ucp_tag_recv_nbx(worker, buf, buf_size, tag, tag_mask, &recv_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(msg, "ucp_tag_recv_nbx() completed immediately");

        /* Directly execute callback */
        recv_cb(request, UCS_OK, &tag_recv_info, user_data);
    } else
        NA_CHECK_SUBSYS_ERROR(msg, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    NA_LOG_SUBSYS_DEBUG(msg, "ucp_tag_recv_nbx() was posted");

    return NA_SUCCESS;

error:

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_recv_unexpected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void *user_data)
{
    struct na_ucx_class *na_ucx_class = (struct na_ucx_class *) user_data;
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_cb_type_t cb_type = na_ucx_op_id->completion_data.callback_info.type;
    struct na_cb_info_recv_unexpected *recv_unexpected_info =
        &na_ucx_op_id->completion_data.callback_info.info.recv_unexpected;
    struct na_ucx_addr *source_addr = NULL;
    uint32_t conn_id;
    na_return_t cb_ret;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_recv_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_OK)
        cb_ret = NA_SUCCESS;
    else if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(msg, done, cb_ret, NA_PROTOCOL_ERROR,
            "ucp_tag_recv_nbx() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(msg,
        (info->sender_tag & NA_UCX_TAG_MASK) > NA_UCX_MAX_TAG, done, cb_ret,
        NA_OVERFLOW, "Invalid tag value 0x%" PRIx64, info->sender_tag);
    NA_CHECK_SUBSYS_ERROR(msg, cb_type != NA_CB_RECV_UNEXPECTED, done, cb_ret,
        NA_INVALID_ARG, "Invalid cb_type %s, expected NA_CB_RECV_UNEXPECTED",
        na_cb_type_to_string(cb_type));

    NA_LOG_SUBSYS_DEBUG(msg, "Received msg length=%zu, sender_tag=0x%" PRIx64,
        info->length, info->sender_tag);

    /* Fill unexpected info */
    recv_unexpected_info->tag = (na_tag_t) (info->sender_tag & NA_UCX_TAG_MASK);
    recv_unexpected_info->actual_buf_size = (na_size_t) info->length;

    /* Lookup source address */
    conn_id = na_ucp_tag_to_conn_id(info->sender_tag);
    source_addr = na_ucx_addr_conn_lookup(&na_ucx_class->addr_conn, &conn_id);
    NA_CHECK_SUBSYS_ERROR(msg, source_addr == NULL, done, cb_ret,
        NA_PROTOCOL_ERROR, "Could not find address for connection ID %" PRId32,
        conn_id);
    recv_unexpected_info->source = (na_addr_t) source_addr;
    na_ucx_addr_ref_incr(source_addr);

done:
    na_ucx_complete(na_ucx_op_id, cb_ret);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_recv_expected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_cb_type_t cb_type = na_ucx_op_id->completion_data.callback_info.type;
    struct na_cb_info_recv_expected *recv_expected_info =
        &na_ucx_op_id->completion_data.callback_info.info.recv_expected;
    na_return_t cb_ret = NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_recv_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_OK)
        cb_ret = NA_SUCCESS;
    else if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(msg, done, cb_ret, NA_PROTOCOL_ERROR,
            "ucp_tag_recv_nbx() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(msg,
        (info->sender_tag & NA_UCX_TAG_MASK) > NA_UCX_MAX_TAG, done, cb_ret,
        NA_OVERFLOW, "Invalid tag value 0x%" PRIx64, info->sender_tag);
    NA_CHECK_SUBSYS_ERROR(msg, cb_type != NA_CB_RECV_EXPECTED, done, cb_ret,
        NA_INVALID_ARG, "Invalid cb_type %s, expected NA_CB_RECV_EXPECTED",
        na_cb_type_to_string(cb_type));

    NA_LOG_SUBSYS_DEBUG(msg, "Received msg length=%zu, sender_tag=0x%" PRIx64,
        info->length, info->sender_tag);

    /* Check that this is the expected sender */
    NA_CHECK_SUBSYS_ERROR(msg,
        na_ucp_tag_to_conn_id(info->sender_tag) != na_ucx_op_id->addr->conn_id,
        done, cb_ret, NA_PROTOCOL_ERROR,
        "Invalid sender connection ID, expected %" PRId32 ", got %" PRId32,
        na_ucx_op_id->addr->conn_id, na_ucp_tag_to_conn_id(info->sender_tag));

    /* Keep actual msg size */
    NA_CHECK_SUBSYS_ERROR(msg, info->length > na_ucx_op_id->info.msg.buf_size,
        done, cb_ret, NA_MSGSIZE,
        "Expected recv msg size too large for buffer");
    recv_expected_info->actual_buf_size = (na_size_t) info->length;

done:
    na_ucx_complete(na_ucx_op_id, cb_ret);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_put(ucp_ep_h ep, void *buf, size_t buf_size, uint64_t remote_addr,
    ucp_rkey_h rkey, void *request)
{
    const ucp_request_param_t rma_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST,
        .cb = {.send = na_ucp_rma_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    status_ptr = ucp_put_nbx(ep, buf, buf_size, remote_addr, rkey, &rma_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(rma, "ucp_put_nbx() completed immediately");

        /* Directly execute callback */
        na_ucp_rma_cb(request, UCS_OK, NULL);
    } else
        NA_CHECK_SUBSYS_ERROR(rma, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_put_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    NA_LOG_SUBSYS_DEBUG(rma, "ucp_put_nbx() was posted");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_get(ucp_ep_h ep, void *buf, size_t buf_size, uint64_t remote_addr,
    ucp_rkey_h rkey, void *request)
{
    const ucp_request_param_t rma_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST,
        .cb = {.send = na_ucp_rma_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    status_ptr = ucp_get_nbx(ep, buf, buf_size, remote_addr, rkey, &rma_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(rma, "ucp_get_nbx() completed immediately");

        /* Directly execute callback */
        na_ucp_rma_cb(request, UCS_OK, NULL);
    } else
        NA_CHECK_SUBSYS_ERROR(rma, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_get_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    NA_LOG_SUBSYS_DEBUG(rma, "ucp_get_nbx() was posted");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_rma_cb(void *request, ucs_status_t status, void NA_UNUSED *user_data)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_return_t cb_ret;

    NA_LOG_SUBSYS_DEBUG(
        rma, "ucp_put/get_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_OK)
        NA_GOTO_DONE(done, cb_ret, NA_SUCCESS);
    if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_GOTO_SUBSYS_ERROR(rma, done, cb_ret, NA_PROTOCOL_ERROR,
            "na_ucp_rma_cb() failed (%s)", ucs_status_string(status));

done:
    na_ucx_complete(na_ucx_op_id, cb_ret);
}

/*---------------------------------------------------------------------------*/
static struct na_ucx_class *
na_ucx_class_alloc(void)
{
    struct na_ucx_class *na_ucx_class = NULL;
    int rc;

    na_ucx_class = calloc(1, sizeof(*na_ucx_class));
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ucx_class == NULL, error,
        "Could not allocate NA private data class");
    hg_atomic_init32(&na_ucx_class->conn_id, 0);

    /* Init table lock */
    rc = hg_thread_rwlock_init(&na_ucx_class->addr_map.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_rwlock_init() failed");

    /* Init table lock */
    rc = hg_thread_rwlock_init(&na_ucx_class->addr_conn.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_rwlock_init() failed");

    /* Initialize retry op queue */
    rc = hg_thread_spin_init(&na_ucx_class->retry_op_queue.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_spin_init() failed");
    HG_QUEUE_INIT(&na_ucx_class->retry_op_queue.queue);

    /* Initialize addr pool */
    rc = hg_thread_spin_init(&na_ucx_class->addr_pool.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_spin_init() failed");
    HG_QUEUE_INIT(&na_ucx_class->addr_pool.queue);

    /* Create address map */
    na_ucx_class->addr_map.map =
        hg_hash_table_new(na_ucx_addr_key_hash, na_ucx_addr_key_equal);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ucx_class->addr_map.map == NULL, error,
        "Could not allocate address table");

    /* Create connection map */
    na_ucx_class->addr_conn.map =
        hg_hash_table_new(na_ucx_addr_conn_hash, na_ucx_addr_conn_equal);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ucx_class->addr_conn.map == NULL, error,
        "Could not allocate address table");

    return na_ucx_class;

error:
    if (na_ucx_class)
        na_ucx_class_free(na_ucx_class);

    return NULL;
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_class_free(struct na_ucx_class *na_ucx_class)
{
    if (na_ucx_class->self_addr)
        na_ucx_addr_destroy(na_ucx_class->self_addr);
    if (na_ucx_class->ucp_listener)
        na_ucp_listener_destroy(na_ucx_class->ucp_listener);
    if (na_ucx_class->ucp_worker)
        na_ucp_worker_destroy(na_ucx_class->ucp_worker);
    if (na_ucx_class->ucp_context)
        na_ucp_context_destroy(na_ucx_class->ucp_context);

    if (na_ucx_class->addr_map.map)
        hg_hash_table_free(na_ucx_class->addr_map.map);
    if (na_ucx_class->addr_conn.map)
        hg_hash_table_free(na_ucx_class->addr_conn.map);
    (void) hg_thread_rwlock_destroy(&na_ucx_class->addr_map.lock);
    (void) hg_thread_rwlock_destroy(&na_ucx_class->addr_conn.lock);
    (void) hg_thread_spin_destroy(&na_ucx_class->retry_op_queue.lock);
    (void) hg_thread_spin_destroy(&na_ucx_class->addr_pool.lock);

#ifdef NA_UCX_HAS_MEM_POOL
    hg_mem_pool_destroy(na_ucx_class->mem_pool);
#endif

    free(na_ucx_class->protocol_name);
    free(na_ucx_class);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_parse_hostname_info(const char *hostname_info, const char *subnet_info,
    char **net_device_p, struct sockaddr_storage **sockaddr_p)
{
    char **ifa_name_p = NULL;
    char *hostname = NULL;
    unsigned int port = 0;
    na_return_t ret = NA_SUCCESS;

    /* Set hostname (use default interface name if no hostname was passed) */
    if (hostname_info) {
        hostname = strdup(hostname_info);
        NA_CHECK_SUBSYS_ERROR(cls, hostname == NULL, done, ret, NA_NOMEM,
            "strdup() of hostname failed");

        /* TODO add support for IPv6 address parsing */

        /* Extract hostname : port */
        if (strstr(hostname, ":")) {
            char *port_str = NULL;
            strtok_r(hostname, ":", &port_str);
            port = (unsigned int) strtoul(port_str, NULL, 10);
        }

        /* Extract net_device if explicitly listed with '/' before IP */
        if (strstr(hostname, "/")) {
            char *host_str = NULL;
            strtok_r(hostname, "/", &host_str);

            *net_device_p = hostname;
            hostname = strdup(host_str);
            NA_CHECK_SUBSYS_ERROR(cls, hostname == NULL, done, ret, NA_NOMEM,
                "strdup() of hostname failed");
        } else
            ifa_name_p = net_device_p;
    }

    /* TODO add support for IPv6 wildcards */

    if (hostname && strcmp(hostname, "0.0.0.0") != 0) {
        /* Try to get matching IP/device */
        ret = na_ip_check_interface(hostname, port, ifa_name_p, sockaddr_p);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "Could not check interfaces");
    } else {
        char pref_anyip[NI_MAXHOST];
        uint32_t subnet = 0, netmask = 0;

        /* Try to use IP subnet */
        if (subnet_info) {
            ret = na_ip_parse_subnet(subnet_info, &subnet, &netmask);
            NA_CHECK_SUBSYS_NA_ERROR(
                cls, done, ret, "na_ip_parse_subnet() failed");
        }
        ret = na_ip_pref_addr(subnet, netmask, pref_anyip);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "na_ip_pref_addr() failed");

        /* Generate IP address (ignore net_device) */
        ret = na_ip_check_interface(pref_anyip, port, NULL, sockaddr_p);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "Could not check interfaces");
    }

done:
    free(hostname);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
na_ucx_addr_key_hash(hg_hash_table_key_t key)
{
    ucs_sock_addr_t *addr_key = (ucs_sock_addr_t *) key;

    if (addr_key->addr->sa_family == AF_INET)
        return (unsigned int) ((const struct sockaddr_in *) addr_key->addr)
            ->sin_addr.s_addr;
    else
        return (unsigned int) ((const struct sockaddr_in6 *) addr_key->addr)
            ->sin6_addr.__in6_u.__u6_addr32[0];
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ucx_addr_key_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    ucs_sock_addr_t *addr_key1 = (ucs_sock_addr_t *) key1,
                    *addr_key2 = (ucs_sock_addr_t *) key2;

    return (addr_key1->addrlen == addr_key2->addrlen) &&
           (memcmp(addr_key1->addr, addr_key2->addr, addr_key1->addrlen) == 0);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_map_lookup(struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key)
{
    hg_hash_table_value_t value = NULL;

    /* Lookup key */
    hg_thread_rwlock_rdlock(&na_ucx_map->lock);
    value =
        hg_hash_table_lookup(na_ucx_map->map, (hg_hash_table_key_t) addr_key);
    hg_thread_rwlock_release_rdlock(&na_ucx_map->lock);

    return (value == HG_HASH_TABLE_NULL) ? NULL : (struct na_ucx_addr *) value;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_map_insert(struct na_ucx_class *na_ucx_class,
    struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key,
    struct na_ucx_addr **na_ucx_addr_p)
{
    struct na_ucx_addr *na_ucx_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);

    /* Look up again to prevent race between lock release/acquire */
    na_ucx_addr = (struct na_ucx_addr *) hg_hash_table_lookup(
        na_ucx_map->map, (hg_hash_table_key_t) addr_key);
    if (na_ucx_addr) {
        ret = NA_EXIST; /* Entry already exists */
        goto done;
    }

    /* Allocate address */
    ret = na_ucx_addr_create(na_ucx_class, addr_key, &na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not allocate NA UCX addr");

    /* Insert new value */
    rc = hg_hash_table_insert(na_ucx_map->map,
        (hg_hash_table_key_t) &na_ucx_addr->addr_key,
        (hg_hash_table_value_t) na_ucx_addr);
    NA_CHECK_SUBSYS_ERROR(
        addr, rc == 0, error, ret, NA_NOMEM, "hg_hash_table_insert() failed");

done:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    *na_ucx_addr_p = na_ucx_addr;

    return ret;

error:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);
    if (na_ucx_addr)
        na_ucx_addr_destroy(na_ucx_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_map_remove(struct na_ucx_map *na_ucx_map, ucs_sock_addr_t *addr_key)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);
    if (hg_hash_table_lookup(na_ucx_map->map, (hg_hash_table_key_t) addr_key) ==
        HG_HASH_TABLE_NULL)
        goto unlock;

    rc = hg_hash_table_remove(na_ucx_map->map, (hg_hash_table_key_t) addr_key);
    NA_CHECK_SUBSYS_ERROR_DONE(addr, rc == 0, "Could not remove key");

unlock:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
na_ucx_addr_conn_hash(hg_hash_table_key_t key)
{
    return (unsigned int) *((uint32_t *) key);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ucx_addr_conn_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    return *((uint32_t *) key1) == *((uint32_t *) key2);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_conn_lookup(struct na_ucx_map *na_ucx_map, uint32_t *conn_id)
{
    hg_hash_table_value_t value = NULL;

    /* Lookup key */
    hg_thread_rwlock_rdlock(&na_ucx_map->lock);
    value =
        hg_hash_table_lookup(na_ucx_map->map, (hg_hash_table_key_t) conn_id);
    hg_thread_rwlock_release_rdlock(&na_ucx_map->lock);

    return (value == HG_HASH_TABLE_NULL) ? NULL : (struct na_ucx_addr *) value;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_conn_insert(
    struct na_ucx_map *na_ucx_map, struct na_ucx_addr *na_ucx_addr)
{
    hg_hash_table_value_t lookup_value = NULL;
    na_return_t ret;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);

    /* Look up again to prevent race between lock release/acquire */
    lookup_value = hg_hash_table_lookup(
        na_ucx_map->map, (hg_hash_table_key_t) &na_ucx_addr->conn_id);
    if (lookup_value != HG_HASH_TABLE_NULL) {
        ret = NA_EXIST; /* Entry already exists */
        goto done;
    }

    /* Insert new value */
    rc = hg_hash_table_insert(na_ucx_map->map,
        (hg_hash_table_key_t) &na_ucx_addr->conn_id,
        (hg_hash_table_value_t) na_ucx_addr);
    NA_CHECK_SUBSYS_ERROR(
        addr, rc == 0, error, ret, NA_NOMEM, "hg_hash_table_insert() failed");

done:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    return NA_SUCCESS;

error:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_conn_remove(struct na_ucx_map *na_ucx_map, uint32_t *conn_id)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);
    if (hg_hash_table_lookup(na_ucx_map->map, (hg_hash_table_key_t) conn_id) ==
        HG_HASH_TABLE_NULL)
        goto unlock;

    rc = hg_hash_table_remove(na_ucx_map->map, (hg_hash_table_key_t) conn_id);
    NA_CHECK_SUBSYS_ERROR_DONE(addr, rc == 0, "Could not remove key");

unlock:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ucx_addr *
na_ucx_addr_alloc(struct na_ucx_class *na_ucx_class)
{
    struct na_ucx_addr *na_ucx_addr;

    na_ucx_addr = calloc(1, sizeof(*na_ucx_addr));
    if (na_ucx_addr)
        na_ucx_addr->na_ucx_class = na_ucx_class;

    return na_ucx_addr;
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_addr_destroy(struct na_ucx_addr *na_ucx_addr)
{
    NA_LOG_SUBSYS_DEBUG(addr, "Destroying address %p", (void *) na_ucx_addr);

    na_ucx_addr_release(na_ucx_addr);
    free(na_ucx_addr);
}

/*---------------------------------------------------------------------------*/
#ifdef NA_UCX_HAS_ADDR_POOL
static struct na_ucx_addr *
na_ucx_addr_pool_get(struct na_ucx_class *na_ucx_class)
{
    struct na_ucx_addr *na_ucx_addr = NULL;

    hg_thread_spin_lock(&na_ucx_class->addr_pool.lock);
    na_ucx_addr = HG_QUEUE_FIRST(&na_ucx_class->addr_pool.queue);
    if (na_ucx_addr) {
        HG_QUEUE_POP_HEAD(&na_ucx_class->addr_pool.queue, entry);
        hg_thread_spin_unlock(&na_ucx_class->addr_pool.lock);
    } else {
        hg_thread_spin_unlock(&na_ucx_class->addr_pool.lock);
        /* Fallback to allocation if pool is empty */
        na_ucx_addr = na_ucx_addr_alloc(na_ucx_class);
    }

    return na_ucx_addr;
}
#endif

/*---------------------------------------------------------------------------*/
static void
na_ucx_addr_release(struct na_ucx_addr *na_ucx_addr)
{
    if (na_ucx_addr->ucp_ep != NULL) {
        ucp_ep_close_nb(na_ucx_addr->ucp_ep, UCP_EP_CLOSE_MODE_FORCE);
        na_ucx_addr->ucp_ep = NULL;
    }
    if (na_ucx_addr->addr_key.addr)
        na_ucx_addr_map_remove(
            &na_ucx_addr->na_ucx_class->addr_map, &na_ucx_addr->addr_key);
    if (na_ucx_addr->conn_id)
        na_ucx_addr_conn_remove(
            &na_ucx_addr->na_ucx_class->addr_conn, &na_ucx_addr->conn_id);
    if (na_ucx_addr->worker_addr != NULL) {
        if (na_ucx_addr->worker_addr_alloc)
            free(na_ucx_addr->worker_addr);
        else
            ucp_worker_release_address(na_ucx_addr->na_ucx_class->ucp_worker,
                na_ucx_addr->worker_addr);
        na_ucx_addr->worker_addr = NULL;
    }
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_addr_reset(struct na_ucx_addr *na_ucx_addr, ucs_sock_addr_t *addr_key)
{
    na_ucx_addr->ucp_ep = NULL;
    hg_atomic_init32(&na_ucx_addr->refcount, 1);
    hg_atomic_init32(&na_ucx_addr->status, NA_UCX_ADDR_INIT);

    if (addr_key && addr_key->addr) {
        memcpy(&na_ucx_addr->ss_addr, addr_key->addr, addr_key->addrlen);

        /* Point key back to ss_addr */
        na_ucx_addr->addr_key.addr =
            (const struct sockaddr *) &na_ucx_addr->ss_addr;
        na_ucx_addr->addr_key.addrlen = addr_key->addrlen;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_create(struct na_ucx_class *na_ucx_class, ucs_sock_addr_t *addr_key,
    struct na_ucx_addr **na_ucx_addr_p)
{
    struct na_ucx_addr *na_ucx_addr;
    na_return_t ret;

#ifdef NA_UCX_HAS_ADDR_POOL
    na_ucx_addr = na_ucx_addr_pool_get(na_ucx_class);
#else
    na_ucx_addr = na_ucx_addr_alloc(na_ucx_class);
#endif
    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX addr");

    na_ucx_addr_reset(na_ucx_addr, addr_key);

#ifdef NA_HAS_DEBUG
    if (addr_key && addr_key->addr) {
        char host_string[NI_MAXHOST];
        char serv_string[NI_MAXSERV];
        int rc;

        rc = getnameinfo(addr_key->addr, addr_key->addrlen, host_string,
            sizeof(host_string), serv_string, sizeof(serv_string),
            NI_NUMERICHOST | NI_NUMERICSERV);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "getnameinfo() failed (%s)", gai_strerror(rc));

        NA_LOG_SUBSYS_DEBUG(
            addr, "Created new address for %s:%s", host_string, serv_string);
    }
#endif

    NA_LOG_SUBSYS_DEBUG(addr, "Created address %p", (void *) na_ucx_addr);

    *na_ucx_addr_p = na_ucx_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_addr_ref_incr(struct na_ucx_addr *na_ucx_addr)
{
    hg_atomic_incr32(&na_ucx_addr->refcount);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_addr_ref_decr(struct na_ucx_addr *na_ucx_addr)
{
    if (hg_atomic_decr32(&na_ucx_addr->refcount) == 0) {
#ifdef NA_UCX_HAS_ADDR_POOL
        struct na_ucx_addr_pool *addr_pool =
            &na_ucx_addr->na_ucx_class->addr_pool;

        na_ucx_addr_release(na_ucx_addr);

        /* Push address back to addr pool */
        hg_thread_spin_lock(&addr_pool->lock);
        HG_QUEUE_PUSH_TAIL(&addr_pool->queue, na_ucx_addr, entry);
        hg_thread_spin_unlock(&addr_pool->lock);
#else
        na_ucx_addr_destroy(na_ucx_addr);
#endif
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_resolve(
    struct na_ucx_class *na_ucx_class, struct na_ucx_addr *na_ucx_addr)
{
    unsigned int retry = 0;
    na_return_t ret;

    /* Let only one thread at a time resolving the address */
    if (!hg_atomic_cas32(
            &na_ucx_addr->status, NA_UCX_ADDR_INIT, NA_UCX_ADDR_RESOLVING))
        return NA_SUCCESS;

    /* Create new endpoint */
    ret = na_ucp_connect(na_ucx_class->ucp_worker, na_ucx_addr->addr_key.addr,
        na_ucx_addr->addr_key.addrlen, na_ucp_ep_error_cb, (void *) na_ucx_addr,
        &na_ucx_addr->ucp_ep);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not connect UCP endpoint");

    while (retry < NA_UCX_CONN_RETRY_MAX) {
        /* Generate connection ID */
        na_ucx_addr->conn_id = na_ucp_conn_id_gen(na_ucx_class);
        NA_LOG_SUBSYS_DEBUG(
            addr, "Generated connection ID %" PRId32, na_ucx_addr->conn_id);

        /* Insert connection entry to lookup address by connection ID */
        ret = na_ucx_addr_conn_insert(&na_ucx_class->addr_conn, na_ucx_addr);
        if (ret == NA_SUCCESS)
            break;
        else if (ret == NA_EXIST) {
            /* Attempt to use another connection ID */
            retry++;
            continue;
        } else
            NA_CHECK_SUBSYS_NA_ERROR(
                addr, error, ret, "Could not insert new address");
    }
    /* Exchange IDs so that we can later use that ID to identify msg senders */
    ret = na_ucp_conn_id_exchange(na_ucx_addr->ucp_ep, &na_ucx_addr->conn_id,
        &na_ucx_addr->remote_conn_id, na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not exchange connection IDs");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send(struct na_ucx_class *na_ucx_class, na_context_t *context,
    na_cb_type_t cb_type, na_cb_t callback, void *arg, const void *buf,
    na_size_t buf_size, struct na_ucx_addr *na_ucx_addr, na_tag_t tag,
    struct na_ucx_op_id *na_ucx_op_id)
{
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed (%s)",
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    NA_UCX_OP_RESET(na_ucx_op_id, context, cb_type, callback, arg, na_ucx_addr);

    /* TODO we assume that buf remains valid (safe because we pre-allocate
     * buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){
        .buf.const_ptr = buf, .buf_size = buf_size, .tag = tag};

    if (hg_atomic_get32(&na_ucx_addr->status) != NA_UCX_ADDR_RESOLVED) {
        ret = na_ucx_addr_resolve(na_ucx_class, na_ucx_addr);
        NA_CHECK_SUBSYS_NA_ERROR(
            msg, release, ret, "Could not resolve address");

        na_ucx_op_retry(na_ucx_class, na_ucx_op_id);
    } else {
        ucp_tag_t ucp_tag = na_ucp_tag_gen(
            tag, cb_type == NA_CB_SEND_UNEXPECTED, na_ucx_addr->remote_conn_id);

        ret = na_ucp_msg_send(
            na_ucx_addr->ucp_ep, buf, buf_size, ucp_tag, na_ucx_op_id);
        NA_CHECK_SUBSYS_NA_ERROR(msg, release, ret, "Could not post msg send");
    }

    return NA_SUCCESS;

release:
    NA_UCX_OP_RELEASE(na_ucx_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_rma(struct na_ucx_class NA_UNUSED *na_ucx_class, na_context_t *context,
    na_cb_type_t cb_type, na_cb_t callback, void *arg,
    struct na_ucx_mem_handle *local_mem_handle, na_offset_t local_offset,
    struct na_ucx_mem_handle *remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, struct na_ucx_addr *na_ucx_addr,
    struct na_ucx_op_id *na_ucx_op_id)
{
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed (%s)",
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    NA_UCX_OP_RESET(na_ucx_op_id, context, cb_type, callback, arg, na_ucx_addr);

    na_ucx_op_id->info.rma.ucp_rma_op =
        (cb_type == NA_CB_PUT) ? na_ucp_put : na_ucp_get;
    na_ucx_op_id->info.rma.buf =
        (char *) local_mem_handle->desc.base + local_offset;
    na_ucx_op_id->info.rma.remote_addr =
        (uint64_t) remote_mem_handle->desc.base + remote_offset;
    na_ucx_op_id->info.rma.buf_size = length;
    na_ucx_op_id->info.rma.remote_key = NULL;

    /* There is no need to have a fully resolved address to start an RMA.
     * This is only necessary for two-sided communication. */

    /* TODO UCX requires the remote key to be bound to the origin, do we need a
     * new API? */
    ret = na_ucx_rma_key_resolve(na_ucx_addr->ucp_ep, remote_mem_handle,
        &na_ucx_op_id->info.rma.remote_key);
    NA_CHECK_SUBSYS_NA_ERROR(rma, release, ret, "Could not resolve remote key");

    /* Post RMA op */
    ret = na_ucx_op_id->info.rma.ucp_rma_op(na_ucx_addr->ucp_ep,
        na_ucx_op_id->info.rma.buf, na_ucx_op_id->info.rma.buf_size,
        na_ucx_op_id->info.rma.remote_addr, na_ucx_op_id->info.rma.remote_key,
        na_ucx_op_id);
    NA_CHECK_SUBSYS_NA_ERROR(rma, release, ret, "Could not post rma operation");

    return NA_SUCCESS;

release:
    NA_UCX_OP_RELEASE(na_ucx_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_rma_key_resolve(ucp_ep_h ep, struct na_ucx_mem_handle *na_ucx_mem_handle,
    ucp_rkey_h *rkey_p)
{
    na_return_t ret;

    if (hg_atomic_get32(&na_ucx_mem_handle->type) ==
        NA_UCX_MEM_HANDLE_REMOTE_UNPACKED) {
        *rkey_p = na_ucx_mem_handle->ucp_mr.rkey;
        return NA_SUCCESS;
    }

    hg_thread_mutex_lock(&na_ucx_mem_handle->rkey_unpack_lock);

    switch (hg_atomic_get32(&na_ucx_mem_handle->type)) {
        case NA_UCX_MEM_HANDLE_REMOTE_PACKED: {
            ucs_status_t status = ucp_ep_rkey_unpack(ep,
                na_ucx_mem_handle->rkey_buf, &na_ucx_mem_handle->ucp_mr.rkey);
            NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret,
                NA_PROTOCOL_ERROR, "ucp_ep_rkey_unpack() failed (%s)",
                ucs_status_string(status));
            /* Handle is now unpacked */
            hg_atomic_set32(
                &na_ucx_mem_handle->type, NA_UCX_MEM_HANDLE_REMOTE_UNPACKED);
            break;
        }
        case NA_UCX_MEM_HANDLE_REMOTE_UNPACKED:
            break;
        case NA_UCX_MEM_HANDLE_LOCAL:
        default:
            NA_GOTO_SUBSYS_ERROR(
                mem, error, ret, NA_INVALID_ARG, "Invalid memory handle type");
    }

    *rkey_p = na_ucx_mem_handle->ucp_mr.rkey;
    hg_thread_mutex_unlock(&na_ucx_mem_handle->rkey_unpack_lock);

    return NA_SUCCESS;

error:
    hg_thread_mutex_unlock(&na_ucx_mem_handle->rkey_unpack_lock);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_op_retry(
    struct na_ucx_class *na_ucx_class, struct na_ucx_op_id *na_ucx_op_id)
{
    struct na_ucx_op_queue *retry_op_queue = &na_ucx_class->retry_op_queue;

    NA_LOG_SUBSYS_DEBUG(op, "Pushing %p for retry (%s)", (void *) na_ucx_op_id,
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    /* Push op ID to retry queue */
    hg_thread_spin_lock(&retry_op_queue->lock);
    HG_QUEUE_PUSH_TAIL(&retry_op_queue->queue, na_ucx_op_id, entry);
    hg_atomic_set32(&na_ucx_op_id->status, NA_UCX_OP_QUEUED);
    hg_thread_spin_unlock(&retry_op_queue->lock);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_process_retries(struct na_ucx_class *na_ucx_class)
{
    struct na_ucx_op_queue *op_queue = &na_ucx_class->retry_op_queue;
    struct na_ucx_op_id *na_ucx_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    do {
        na_bool_t canceled = NA_FALSE;
        na_cb_type_t cb_type;

        hg_thread_spin_lock(&op_queue->lock);
        na_ucx_op_id = HG_QUEUE_FIRST(&op_queue->queue);
        if (!na_ucx_op_id) {
            hg_thread_spin_unlock(&op_queue->lock);
            /* Queue is empty */
            break;
        }

        /* Check if OP ID was canceled */
        if (hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_CANCELING) {
            hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_CANCELED);
            canceled = NA_TRUE;
        } else if (hg_atomic_get32(&na_ucx_op_id->addr->status) !=
                   NA_UCX_ADDR_RESOLVED) {
            hg_thread_spin_unlock(&op_queue->lock);
            break;
        }

        /* Dequeue OP ID */
        HG_QUEUE_POP_HEAD(&op_queue->queue, entry);
        hg_atomic_and32(&na_ucx_op_id->status, ~NA_UCX_OP_QUEUED);

        hg_thread_spin_unlock(&op_queue->lock);

        if (canceled) {
            na_ucx_complete(na_ucx_op_id, NA_CANCELED);
            /* Try again */
            continue;
        }

        NA_LOG_SUBSYS_DEBUG(
            op, "Attempting to retry %p", (void *) na_ucx_op_id);

        cb_type = na_ucx_op_id->completion_data.callback_info.type;

        /* Retry operation */
        switch (cb_type) {
            case NA_CB_SEND_UNEXPECTED:
            case NA_CB_SEND_EXPECTED: {
                ucp_tag_t ucp_tag = na_ucp_tag_gen(na_ucx_op_id->info.msg.tag,
                    (cb_type == NA_CB_SEND_UNEXPECTED),
                    na_ucx_op_id->addr->remote_conn_id);

                ret = na_ucp_msg_send(na_ucx_op_id->addr->ucp_ep,
                    na_ucx_op_id->info.msg.buf.const_ptr,
                    na_ucx_op_id->info.msg.buf_size, ucp_tag, na_ucx_op_id);
                NA_CHECK_SUBSYS_NA_ERROR(
                    msg, error_retry, ret, "Could not post msg send operation");
                break;
            }
            case NA_CB_RECV_EXPECTED: {
                ucp_tag_t ucp_tag = na_ucp_tag_gen(na_ucx_op_id->info.msg.tag,
                    NA_FALSE, na_ucx_op_id->addr->conn_id);

                ret = na_ucp_msg_recv(na_ucx_class->ucp_worker,
                    na_ucx_op_id->info.msg.buf.ptr,
                    na_ucx_op_id->info.msg.buf_size, ucp_tag,
                    NA_UCX_TAG_MASK | NA_UCX_TAG_SENDER_MASK, na_ucx_op_id,
                    na_ucp_msg_recv_expected_cb, na_ucx_class);
                NA_CHECK_SUBSYS_NA_ERROR(
                    msg, error_retry, ret, "Could not post expected msg recv");
                break;
            }
            case NA_CB_PUT:
            case NA_CB_GET:
                ret = na_ucx_op_id->info.rma.ucp_rma_op(
                    na_ucx_op_id->addr->ucp_ep, na_ucx_op_id->info.rma.buf,
                    na_ucx_op_id->info.rma.buf_size,
                    na_ucx_op_id->info.rma.remote_addr,
                    na_ucx_op_id->info.rma.remote_key, na_ucx_op_id);
                NA_CHECK_SUBSYS_NA_ERROR(
                    rma, error_retry, ret, "Could not post rma op");
                break;
            case NA_CB_RECV_UNEXPECTED:
            default:
                NA_GOTO_SUBSYS_ERROR(op, error, ret, NA_INVALID_ARG,
                    "Operation type %s not supported",
                    na_cb_type_to_string(cb_type));
        }

        /* If the operation got canceled while we retried it, attempt to
         * cancel it */
        if (hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_CANCELING) {
            /* Do best effort to cancel the operation */
            hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_CANCELED);
            ucp_request_cancel(na_ucx_class->ucp_worker, (void *) na_ucx_op_id);
        }
    } while (1);

    return NA_SUCCESS;

error_retry:
    /* Force internal completion in error mode */
    hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_ERRORED);
    na_ucx_complete(na_ucx_op_id, ret);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_complete(struct na_ucx_op_id *na_ucx_op_id, na_return_t cb_ret)
{
    /* Mark op id as completed (independent of cb_ret) */
    hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_COMPLETED);

    /* Set callback ret */
    na_ucx_op_id->completion_data.callback_info.ret = cb_ret;

    /* Add OP to NA completion queue */
    na_cb_completion_add(na_ucx_op_id->context, &na_ucx_op_id->completion_data);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_release(void *arg)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) arg;

    NA_CHECK_SUBSYS_WARNING(op,
        na_ucx_op_id &&
            (!(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED)),
        "Releasing resources from an uncompleted operation");

    if (na_ucx_op_id && na_ucx_op_id->addr != NULL) {
        na_ucx_addr_ref_decr(na_ucx_op_id->addr);
        na_ucx_op_id->addr = NULL;
    }
}

/********************/
/* Plugin callbacks */
/********************/

static na_bool_t
na_ucx_check_protocol(const char *protocol_name)
{
    ucp_config_t *config = NULL;
    ucp_params_t params = {.field_mask = UCP_PARAM_FIELD_FEATURES,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA | UCP_FEATURE_STREAM};
    ucp_context_h context = NULL;
    ucs_status_t status;
    na_bool_t accept = NA_FALSE;

    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Try to use requested protocol */
    status = ucp_config_modify(config, "TLS", protocol_name);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    status = ucp_init(&params, config, &context);
    if (status == UCS_OK) {
        accept = NA_TRUE;
        ucp_cleanup(context);
    }

done:
    if (config)
        ucp_config_release(config);

    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_initialize(
    na_class_t *na_class, const struct na_info *na_info, na_bool_t listen)
{
    struct na_ucx_class *na_ucx_class = NULL;
#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attr_t ucp_lib_attrs;
#endif
    char *net_device = NULL;
    struct sockaddr_storage *listen_ss_addr = NULL;
    struct sockaddr_storage ucp_listener_ss_addr;
    ucs_sock_addr_t addr_key = {.addr = NULL, .addrlen = 0};
    ucp_config_t *config;
    na_bool_t no_wait = NA_FALSE;
    na_size_t unexpected_size_max = 0, expected_size_max = 0;
    ucs_thread_mode_t context_thread_mode = UCS_THREAD_MODE_SINGLE,
                      worker_thread_mode = UCS_THREAD_MODE_MULTI;
    na_return_t ret;
#ifdef NA_UCX_HAS_ADDR_POOL
    unsigned int i;
#endif
#ifdef NA_UCX_HAS_LIB_QUERY
    ucs_status_t status;
#endif

    if (na_info->na_init_info != NULL) {
        /* Progress mode */
        if (na_info->na_init_info->progress_mode & NA_NO_BLOCK)
            no_wait = NA_TRUE;
        /* Max contexts */
        // if (na_info->na_init_info->max_contexts)
        //     context_max = na_info->na_init_info->max_contexts;
        /* Sizes */
        if (na_info->na_init_info->max_unexpected_size)
            unexpected_size_max = na_info->na_init_info->max_unexpected_size;
        if (na_info->na_init_info->max_expected_size)
            expected_size_max = na_info->na_init_info->max_expected_size;
        /* Thread mode */
        if ((na_info->na_init_info->max_contexts > 1) &&
            !(na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE))
            context_thread_mode = UCS_THREAD_MODE_MULTI;

        if (na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE_CTX)
            worker_thread_mode = UCS_THREAD_MODE_SINGLE;
    }

#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attrs.field_mask = UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL;
    status = ucp_lib_query(&ucp_lib_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_context_query: %s", ucs_status_string(status));
    NA_CHECK_SUBSYS_ERROR(cls,
        (ucp_lib_attrs.field_mask & UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "lib attributes contain no max thread level");

    /* Best effort to ensure thread safety
     * (no error to allow for UCS_THREAD_MODE_SERIALIZED) */
    if (worker_thread_mode != UCS_THREAD_MODE_SINGLE &&
        ucp_lib_attrs.max_thread_level == UCS_THREAD_MODE_SERIALIZED) {
        worker_thread_mode = UCS_THREAD_MODE_SERIALIZED;
        NA_LOG_SUBSYS_WARNING(cls, "Max worker thread level is: %s",
            ucs_thread_mode_names[worker_thread_mode]);
    }
#endif

    /* Parse hostname info and get device / listener IP */
    ret = na_ucx_parse_hostname_info(na_info->host_name,
        (na_info->na_init_info && na_info->na_init_info->ip_subnet)
            ? na_info->na_init_info->ip_subnet
            : NULL,
        &net_device, (listen) ? &listen_ss_addr : NULL);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "na_ucx_parse_hostname_info() failed");

    /* Create new UCX class */
    na_ucx_class = na_ucx_class_alloc();
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX class");

    /* Keep a copy of the protocol name */
    na_ucx_class->protocol_name = (na_info->protocol_name)
                                      ? strdup(na_info->protocol_name)
                                      : strdup(NA_UCX_PROTOCOL_DEFAULT);
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class->protocol_name == NULL, error, ret,
        NA_NOMEM, "Could not dup NA protocol name");

    /* Set wait mode */
    na_ucx_class->no_wait = no_wait;

    /* TODO may need to query UCX */
    na_ucx_class->unexpected_size_max =
        unexpected_size_max ? unexpected_size_max : NA_UCX_MSG_SIZE_MAX;
    na_ucx_class->expected_size_max =
        expected_size_max ? expected_size_max : NA_UCX_MSG_SIZE_MAX;

    /* Init config options */
    ret = na_ucp_config_init(na_info->protocol_name, net_device, &config);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "Could not initialize UCX config");

    /* No longer needed */
    free(net_device);
    net_device = NULL;

    /* Create UCP context and release config */
    ret = na_ucp_context_create(config, no_wait, context_thread_mode,
        &na_ucx_class->ucp_context, &na_ucx_class->ucp_request_size);
    na_ucp_config_release(config);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create UCX context");

    /* Create single worker */
    ret = na_ucp_worker_create(na_ucx_class->ucp_context, worker_thread_mode,
        &na_ucx_class->ucp_worker);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create UCX worker");

    /* Create listener if we're listening */
    if (listen) {
        ret = na_ucp_listener_create(na_ucx_class->ucp_worker,
            (const struct sockaddr *) listen_ss_addr, sizeof(*listen_ss_addr),
            (void *) na_ucx_class, &na_ucx_class->ucp_listener,
            &ucp_listener_ss_addr);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "Could not create UCX listener");

        addr_key = (ucs_sock_addr_t){
            .addr = (const struct sockaddr *) &ucp_listener_ss_addr,
            .addrlen = sizeof(ucp_listener_ss_addr)};

        /* No longer needed */
        free(listen_ss_addr);
        listen_ss_addr = NULL;
    }

#ifdef NA_UCX_HAS_ADDR_POOL
    /* Create pool of addresses */
    for (i = 0; i < NA_UCX_ADDR_POOL_SIZE; i++) {
        struct na_ucx_addr *na_ucx_addr = na_ucx_addr_alloc(na_ucx_class);
        HG_QUEUE_PUSH_TAIL(&na_ucx_class->addr_pool.queue, na_ucx_addr, entry);
    }
#endif

    /* Create self address */
    ret = na_ucx_addr_create(na_ucx_class, &addr_key, &na_ucx_class->self_addr);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create self address");

    /* Attach worker address */
    ret = na_ucp_worker_get_address(na_ucx_class->ucp_worker,
        &na_ucx_class->self_addr->worker_addr,
        &na_ucx_class->self_addr->worker_addr_len);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not get worker address");

    /* Register initial mempool */
#ifdef NA_UCX_HAS_MEM_POOL
    na_ucx_class->mem_pool = hg_mem_pool_create(
        MAX(na_ucx_class->unexpected_size_max, na_ucx_class->expected_size_max),
        NA_UCX_MEM_CHUNK_COUNT, NA_UCX_MEM_BLOCK_COUNT, na_ucp_mem_buf_register,
        na_ucp_mem_buf_deregister, (void *) na_ucx_class);
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class->mem_pool == NULL, error, ret,
        NA_NOMEM,
        "Could not create memory pool with %d blocks of size %d x %zu bytes",
        NA_UCX_MEM_BLOCK_COUNT, NA_UCX_MEM_CHUNK_COUNT,
        MAX(na_ucx_class->unexpected_size_max,
            na_ucx_class->expected_size_max));
#endif

    na_class->plugin_class = (void *) na_ucx_class;

    return NA_SUCCESS;

error:
    free(net_device);
    free(listen_ss_addr);
    if (na_ucx_class)
        na_ucx_class_free(na_ucx_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_finalize(na_class_t *na_class)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    hg_hash_table_iter_t addr_table_iter;
    na_return_t ret = NA_SUCCESS;

    if (na_ucx_class == NULL)
        return ret;

    NA_CHECK_SUBSYS_ERROR(cls, hg_atomic_get32(&na_ucx_class->ncontexts) != 0,
        done, ret, NA_BUSY, "Contexts were not destroyed (%d remaining)",
        hg_atomic_get32(&na_ucx_class->ncontexts));

    /* Iterate over remaining addresses and free them */
    hg_hash_table_iterate(na_ucx_class->addr_map.map, &addr_table_iter);
    while (hg_hash_table_iter_has_more(&addr_table_iter)) {
        struct na_ucx_addr *na_ucx_addr =
            (struct na_ucx_addr *) hg_hash_table_iter_next(&addr_table_iter);
        na_ucx_addr_destroy(na_ucx_addr);
    }

#ifdef NA_UCX_HAS_ADDR_POOL
    /* Free addresse pool */
    while (!HG_QUEUE_IS_EMPTY(&na_ucx_class->addr_pool.queue)) {
        struct na_ucx_addr *na_ucx_addr =
            HG_QUEUE_FIRST(&na_ucx_class->addr_pool.queue);
        HG_QUEUE_POP_HEAD(&na_ucx_class->addr_pool.queue, entry);
        na_ucx_addr_destroy(na_ucx_addr);
    }
#endif

    na_ucx_class_free(na_ucx_class);
    na_class->plugin_class = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_ucx_op_create(na_class_t *na_class)
{
    struct na_ucx_op_id *na_ucx_op_id = NULL;

    /* When using UCP requests, OP IDs must have enough space to fit the
     * UCP request data as a header */
    na_ucx_op_id = hg_mem_header_alloc(NA_UCX_CLASS(na_class)->ucp_request_size,
        alignof(struct na_ucx_op_id), sizeof(*na_ucx_op_id));
    NA_CHECK_SUBSYS_ERROR_NORET(op, na_ucx_op_id == NULL, out,
        "Could not allocate NA OFI operation ID");

    memset(na_ucx_op_id, 0, sizeof(struct na_ucx_op_id));

    /* Completed by default */
    hg_atomic_init32(&na_ucx_op_id->status, NA_UCX_OP_COMPLETED);

    /* Set op ID release callbacks */
    na_ucx_op_id->completion_data.plugin_callback = na_ucx_release;
    na_ucx_op_id->completion_data.plugin_callback_args = na_ucx_op_id;

out:
    return (na_op_id_t *) na_ucx_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), done,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed (%s)",
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    hg_mem_header_free(NA_UCX_CLASS(na_class)->ucp_request_size,
        alignof(struct na_ucx_op_id), na_ucx_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p)
{
    char host_string[NI_MAXHOST];
    char serv_string[NI_MAXSERV];
    struct addrinfo hints, *hostname_res = NULL;
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    struct na_ucx_addr *na_ucx_addr = NULL;
    ucs_sock_addr_t addr_key = {.addr = NULL, .addrlen = 0};
    na_return_t ret;
    int rc;

    /* Only support 'all' or same protocol */
    NA_CHECK_SUBSYS_ERROR(fatal,
        strncmp(name, "all", strlen("all")) &&
            strncmp(name, na_ucx_class->protocol_name,
                strlen(na_ucx_class->protocol_name)),
        error, ret, NA_PROTOCOL_ERROR,
        "Protocol not supported by this class (%s)",
        na_ucx_class->protocol_name);

    /* Retrieve address */
    rc = sscanf(name, "%*[^:]://%[^:]:%s", host_string, serv_string);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 2, error, ret, NA_PROTONOSUPPORT,
        "Malformed address string");

    NA_LOG_SUBSYS_DEBUG(addr, "Host %s, Serv %s", host_string, serv_string);

    /* Resolve address */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_protocol = 0;
    rc = getaddrinfo(host_string, serv_string, &hints, &hostname_res);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "getaddrinfo() failed (%s)", gai_strerror(rc));

    /* Lookup address from table */
    addr_key = (ucs_sock_addr_t){
        .addr = hostname_res->ai_addr, .addrlen = hostname_res->ai_addrlen};
    na_ucx_addr = na_ucx_addr_map_lookup(&na_ucx_class->addr_map, &addr_key);

    if (!na_ucx_addr) {
        na_return_t na_ret;

        NA_LOG_SUBSYS_DEBUG(addr,
            "Address for %s was not found, attempting to insert it",
            host_string);

        /* Insert new entry and create new address if needed */
        na_ret = na_ucx_addr_map_insert(
            na_ucx_class, &na_ucx_class->addr_map, &addr_key, &na_ucx_addr);
        freeaddrinfo(hostname_res);
        NA_CHECK_SUBSYS_ERROR(addr, na_ret != NA_SUCCESS && na_ret != NA_EXIST,
            error, ret, na_ret, "Could not insert new address");
    } else {
        freeaddrinfo(hostname_res);
        NA_LOG_SUBSYS_DEBUG(addr, "Address for %s was found", host_string);
    }

    na_ucx_addr_ref_incr(na_ucx_addr);

    *addr_p = (na_addr_t) na_ucx_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ucx_addr_ref_decr((struct na_ucx_addr *) addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *na_class, na_addr_t *addr_p)
{
    na_ucx_addr_ref_incr(NA_UCX_CLASS(na_class)->self_addr);
    *addr_p = (na_addr_t) NA_UCX_CLASS(na_class)->self_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_dup(
    na_class_t NA_UNUSED *na_class, na_addr_t addr, na_addr_t *new_addr)
{
    na_ucx_addr_ref_incr((struct na_ucx_addr *) addr);
    *new_addr = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ucx_addr_cmp(
    na_class_t NA_UNUSED *na_class, na_addr_t addr1, na_addr_t addr2)
{
    return addr1 == addr2;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ucx_addr_is_self(na_class_t *na_class, na_addr_t addr)
{
    return NA_UCX_CLASS(na_class)->self_addr == (struct na_ucx_addr *) addr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_to_string(
    na_class_t *na_class, char *buf, na_size_t *buf_size_p, na_addr_t addr)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) addr;
    char host_string[NI_MAXHOST];
    char serv_string[NI_MAXSERV];
    na_size_t buf_size;
    na_return_t ret;
    int rc;

    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr->addr_key.addrlen == 0, error, ret,
        NA_OPNOTSUPPORTED, "Cannot convert address to string");

    rc = getnameinfo(na_ucx_addr->addr_key.addr, na_ucx_addr->addr_key.addrlen,
        host_string, sizeof(host_string), serv_string, sizeof(serv_string),
        NI_NUMERICHOST | NI_NUMERICSERV);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "getnameinfo() failed (%s)", gai_strerror(rc));

    buf_size = strlen(host_string) + strlen(serv_string) +
               strlen(na_ucx_class->protocol_name) + 5;
    if (buf) {
        rc = snprintf(buf, buf_size, "%s://%s:%s", na_ucx_class->protocol_name,
            host_string, serv_string);
        NA_CHECK_SUBSYS_ERROR(addr, rc < 0 || rc > (int) buf_size, error, ret,
            NA_OVERFLOW, "snprintf() failed or name truncated, rc: %d", rc);

        NA_LOG_SUBSYS_DEBUG(addr, "Converted UCX address (%p) to string (%s)",
            (void *) na_ucx_addr, buf);
    }
    *buf_size_p = buf_size;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_addr_get_serialize_size(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    return ((struct na_ucx_addr *) addr)->worker_addr_len + sizeof(size_t);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, na_addr_t addr)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) addr;
    char *buf_ptr = (char *) buf;
    na_size_t buf_size_left = buf_size;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr->worker_addr == NULL, done, ret,
        NA_PROTONOSUPPORT,
        "Serialization of addresses can only be done if worker address is "
        "available");
    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr->worker_addr_len > buf_size, done,
        ret, NA_OVERFLOW,
        "Space left to encode worker address is not sufficient");

    /* Encode worker_addr_len and worker_addr */
    NA_ENCODE(done, ret, buf_ptr, buf_size_left, &na_ucx_addr->worker_addr_len,
        size_t);
    memcpy(buf_ptr, na_ucx_addr->worker_addr, na_ucx_addr->worker_addr_len);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_deserialize(na_class_t *na_class, na_addr_t *addr_p,
    const void *buf, na_size_t buf_size)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    struct na_ucx_addr *na_ucx_addr = NULL;
    const char *buf_ptr = (const char *) buf;
    na_size_t buf_size_left = buf_size;
    ucp_address_t *worker_addr = NULL;
    size_t worker_addr_len = 0;
    na_return_t ret;

    /* Encode worker_addr_len and worker_addr */
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &worker_addr_len, size_t);

    NA_CHECK_SUBSYS_ERROR(addr, buf_size_left < worker_addr_len, error, ret,
        NA_OVERFLOW, "Space left to decode worker address is not sufficient");

    worker_addr = (ucp_address_t *) malloc(worker_addr_len);
    NA_CHECK_SUBSYS_ERROR(addr, worker_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate worker_addr");
    memcpy(worker_addr, buf_ptr, worker_addr_len);

    /* Create new address */
    ret = na_ucx_addr_create(na_ucx_class, NULL, &na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not create address");

    /* Attach worker address */
    na_ucx_addr->worker_addr = worker_addr;
    na_ucx_addr->worker_addr_len = worker_addr_len;
    na_ucx_addr->worker_addr_alloc = NA_TRUE;

    /* Create EP */
    ret = na_ucp_connect_worker(na_ucx_class->ucp_worker, worker_addr,
        na_ucp_ep_error_cb, na_ucx_addr, &na_ucx_addr->ucp_ep);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not connect to remote worker");

    *addr_p = (na_addr_t) na_ucx_addr;

    return NA_SUCCESS;

error:
    if (na_ucx_addr)
        na_ucx_addr_destroy(na_ucx_addr);
    if (worker_addr)
        free(worker_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_UCX_CLASS(na_class)->unexpected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_UCX_CLASS(na_class)->expected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_tag_t
na_ucx_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_UCX_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static void *
na_ucx_msg_buf_alloc(na_class_t *na_class, na_size_t size, void **plugin_data)
{
    void *mem_ptr;

#ifdef NA_UCX_HAS_MEM_POOL
    mem_ptr =
        hg_mem_pool_alloc(NA_UCX_CLASS(na_class)->mem_pool, size, plugin_data);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, mem_ptr == NULL, done, "Could not allocate buffer from pool");
#else
    mem_ptr = na_ucp_mem_alloc(
        NA_UCX_CLASS(na_class)->ucp_context, size, (ucp_mem_h *) plugin_data);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, mem_ptr == NULL, done, "Could not allocate memory");
#endif

done:
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data)
{
    na_return_t ret = NA_SUCCESS;

#ifdef NA_UCX_HAS_MEM_POOL
    hg_mem_pool_free(NA_UCX_CLASS(na_class)->mem_pool, buf, plugin_data);
#else
    ret = na_ucp_mem_free(
        NA_UCX_CLASS(na_class)->ucp_context, (ucp_mem_h) plugin_data);
    NA_CHECK_SUBSYS_NA_ERROR(mem, done, ret, "Could not free memory");
    (void) buf;

done:
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_ucx_msg_send(NA_UCX_CLASS(na_class), context,
        NA_CB_SEND_UNEXPECTED, callback, arg, buf, buf_size,
        (struct na_ucx_addr *) dest_addr, tag, (struct na_ucx_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_op_id_t *op_id)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed (%s)",
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    NA_UCX_OP_RESET_UNEXPECTED_RECV(na_ucx_op_id, context, callback, arg);

    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){
        .buf.ptr = buf, .buf_size = buf_size, .tag = 0};

    ret = na_ucp_msg_recv(NA_UCX_CLASS(na_class)->ucp_worker, buf, buf_size,
        NA_UCX_TAG_UNEXPECTED, NA_UCX_TAG_UNEXPECTED, na_ucx_op_id,
        na_ucp_msg_recv_unexpected_cb, NA_UCX_CLASS(na_class));
    NA_CHECK_SUBSYS_NA_ERROR(
        msg, release, ret, "Could not post unexpected msg recv");

    return NA_SUCCESS;

release:
    NA_UCX_OP_RELEASE(na_ucx_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    return na_ucx_msg_send(NA_UCX_CLASS(na_class), context, NA_CB_SEND_EXPECTED,
        callback, arg, buf, buf_size, (struct na_ucx_addr *) dest_addr, tag,
        (struct na_ucx_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t source_addr,
    na_uint8_t NA_UNUSED source_id, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) source_addr;
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed (%s)",
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    NA_UCX_OP_RESET(
        na_ucx_op_id, context, NA_CB_RECV_EXPECTED, callback, arg, na_ucx_addr);
    na_ucx_op_id->completion_data.callback_info.info.recv_expected =
        (struct na_cb_info_recv_expected){.actual_buf_size = 0};

    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){
        .buf.ptr = buf, .buf_size = buf_size, .tag = tag};

    if (hg_atomic_get32(&na_ucx_addr->status) != NA_UCX_ADDR_RESOLVED) {
        ret = na_ucx_addr_resolve(NA_UCX_CLASS(na_class), na_ucx_addr);
        NA_CHECK_SUBSYS_NA_ERROR(
            msg, release, ret, "Could not resolve address");

        na_ucx_op_retry(NA_UCX_CLASS(na_class), na_ucx_op_id);
    } else {
        ucp_tag_t ucp_tag = na_ucp_tag_gen(tag, NA_FALSE, na_ucx_addr->conn_id);

        ret = na_ucp_msg_recv(NA_UCX_CLASS(na_class)->ucp_worker, buf, buf_size,
            ucp_tag, NA_UCX_TAG_MASK | NA_UCX_TAG_SENDER_MASK, na_ucx_op_id,
            na_ucp_msg_recv_expected_cb, NA_UCX_CLASS(na_class));
        NA_CHECK_SUBSYS_NA_ERROR(
            msg, release, ret, "Could not post expected msg recv");
    }

    NA_LOG_SUBSYS_DEBUG(msg, "Posted recv");

    return NA_SUCCESS;

release:
    NA_UCX_OP_RELEASE(na_ucx_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle_p)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle = NULL;
    na_return_t ret;

    /* Allocate memory handle */
    na_ucx_mem_handle = (struct na_ucx_mem_handle *) calloc(
        1, sizeof(struct na_ucx_mem_handle));
    NA_CHECK_SUBSYS_ERROR(mem, na_ucx_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX memory handle");

    na_ucx_mem_handle->desc.base = buf;
    na_ucx_mem_handle->desc.flags = flags & 0xff;
    na_ucx_mem_handle->desc.len = buf_size;
    hg_atomic_init32(&na_ucx_mem_handle->type, NA_UCX_MEM_HANDLE_LOCAL);
    hg_thread_mutex_init(&na_ucx_mem_handle->rkey_unpack_lock);

    *mem_handle_p = (na_mem_handle_t) na_ucx_mem_handle;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_free(
    na_class_t NA_UNUSED *na_class, na_mem_handle_t mem_handle)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) mem_handle;
    na_return_t ret;

    switch (hg_atomic_get32(&na_ucx_mem_handle->type)) {
        case NA_UCX_MEM_HANDLE_LOCAL:
            /* nothing to do here */
            break;
        case NA_UCX_MEM_HANDLE_REMOTE_UNPACKED:
            ucp_rkey_destroy(na_ucx_mem_handle->ucp_mr.rkey);
            NA_FALLTHROUGH;
        case NA_UCX_MEM_HANDLE_REMOTE_PACKED:
            free(na_ucx_mem_handle->rkey_buf);
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(
                mem, error, ret, NA_INVALID_ARG, "Invalid memory handle type");
    }

    hg_thread_mutex_destroy(&na_ucx_mem_handle->rkey_unpack_lock);
    free(na_ucx_mem_handle);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_mem_handle_get_max_segments(const na_class_t NA_UNUSED *na_class)
{
    return 1;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) mem_handle;
    ucp_mem_map_params_t mem_map_params = {
        .field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                      UCP_MEM_MAP_PARAM_FIELD_LENGTH |
                      UCP_MEM_MAP_PARAM_FIELD_PROT,
        .address = na_ucx_mem_handle->desc.base,
        .length = na_ucx_mem_handle->desc.len};
    ucs_status_t status;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(mem,
        hg_atomic_get32(&na_ucx_mem_handle->type) != NA_UCX_MEM_HANDLE_LOCAL,
        error, ret, NA_OPNOTSUPPORTED,
        "cannot register memory on remote handle");

    /* Set access mode */
    switch (na_ucx_mem_handle->desc.flags) {
        case NA_MEM_READ_ONLY:
            mem_map_params.prot =
                UCP_MEM_MAP_PROT_REMOTE_READ | UCP_MEM_MAP_PROT_LOCAL_WRITE;
            break;
        case NA_MEM_WRITE_ONLY:
            mem_map_params.prot =
                UCP_MEM_MAP_PROT_REMOTE_WRITE | UCP_MEM_MAP_PROT_LOCAL_READ;
            break;
        case NA_MEM_READWRITE:
            mem_map_params.prot =
                UCP_MEM_MAP_PROT_LOCAL_READ | UCP_MEM_MAP_PROT_LOCAL_WRITE |
                UCP_MEM_MAP_PROT_REMOTE_READ | UCP_MEM_MAP_PROT_REMOTE_WRITE;
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(
                mem, error, ret, NA_INVALID_ARG, "Invalid memory access flag");
            break;
    }

    /* Register memory */
    status = ucp_mem_map(NA_UCX_CLASS(na_class)->ucp_context, &mem_map_params,
        &na_ucx_mem_handle->ucp_mr.mem);
    NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_mem_map() failed (%s)", ucs_status_string(status));

    /* Keep a copy of the rkey to share with the remote */
    /* TODO that could have been a good candidate for publish */
    status = ucp_rkey_pack(NA_UCX_CLASS(na_class)->ucp_context,
        na_ucx_mem_handle->ucp_mr.mem, &na_ucx_mem_handle->rkey_buf,
        &na_ucx_mem_handle->desc.rkey_buf_size);
    NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_rkey_pack() failed (%s)", ucs_status_string(status));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) mem_handle;
    ucs_status_t status;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(mem,
        hg_atomic_get32(&na_ucx_mem_handle->type) != NA_UCX_MEM_HANDLE_LOCAL,
        error, ret, NA_OPNOTSUPPORTED,
        "cannot unregister memory on remote handle");

    /* Deregister memory */
    status = ucp_mem_unmap(
        NA_UCX_CLASS(na_class)->ucp_context, na_ucx_mem_handle->ucp_mr.mem);
    NA_CHECK_SUBSYS_ERROR(mem, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_mem_unmap() failed (%s)", ucs_status_string(status));
    na_ucx_mem_handle->ucp_mr.mem = NULL;

    /* TODO that could have been a good candidate for unpublish */
    ucp_rkey_buffer_release(na_ucx_mem_handle->rkey_buf);
    na_ucx_mem_handle->rkey_buf = NULL;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_mem_handle_get_serialize_size(
    na_class_t NA_UNUSED *na_class, na_mem_handle_t mem_handle)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) mem_handle;

    return sizeof(na_ucx_mem_handle->desc) +
           na_ucx_mem_handle->desc.rkey_buf_size;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) mem_handle;
    char *buf_ptr = (char *) buf;
    na_size_t buf_size_left = buf_size;
    na_return_t ret;

    /* Descriptor info */
    NA_ENCODE(error, ret, buf_ptr, buf_size_left, &na_ucx_mem_handle->desc,
        struct na_ucx_mem_desc);

    /* Encode rkey */
    memcpy(buf_ptr, na_ucx_mem_handle->rkey_buf,
        na_ucx_mem_handle->desc.rkey_buf_size);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t *mem_handle_p, const void *buf, na_size_t buf_size)
{
    struct na_ucx_mem_handle *na_ucx_mem_handle = NULL;
    const char *buf_ptr = (const char *) buf;
    na_size_t buf_size_left = buf_size;
    na_return_t ret;

    na_ucx_mem_handle =
        (struct na_ucx_mem_handle *) malloc(sizeof(struct na_ucx_mem_handle));
    NA_CHECK_SUBSYS_ERROR(mem, na_ucx_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX memory handle");
    na_ucx_mem_handle->rkey_buf = NULL;
    na_ucx_mem_handle->ucp_mr.rkey = NULL;
    hg_atomic_init32(&na_ucx_mem_handle->type, NA_UCX_MEM_HANDLE_REMOTE_PACKED);
    hg_thread_mutex_init(&na_ucx_mem_handle->rkey_unpack_lock);

    /* Descriptor info */
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &na_ucx_mem_handle->desc,
        struct na_ucx_mem_desc);

    /* Packed rkey */
    na_ucx_mem_handle->rkey_buf = malloc(na_ucx_mem_handle->desc.rkey_buf_size);
    NA_CHECK_SUBSYS_ERROR(mem, na_ucx_mem_handle->rkey_buf == NULL, error, ret,
        NA_NOMEM, "Could not allocate rkey buffer");

    NA_CHECK_SUBSYS_ERROR(mem,
        buf_size_left < na_ucx_mem_handle->desc.rkey_buf_size, error, ret,
        NA_OVERFLOW, "Insufficient size left to copy rkey buffer");
    memcpy(na_ucx_mem_handle->rkey_buf, buf_ptr,
        na_ucx_mem_handle->desc.rkey_buf_size);

    *mem_handle_p = (na_mem_handle_t) na_ucx_mem_handle;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t NA_UNUSED remote_id,
    na_op_id_t *op_id)
{
    return na_ucx_rma(NA_UCX_CLASS(na_class), context, NA_CB_PUT, callback, arg,
        (struct na_ucx_mem_handle *) local_mem_handle, local_offset,
        (struct na_ucx_mem_handle *) remote_mem_handle, remote_offset, length,
        (struct na_ucx_addr *) remote_addr, (struct na_ucx_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t NA_UNUSED remote_id,
    na_op_id_t *op_id)
{
    return na_ucx_rma(NA_UCX_CLASS(na_class), context, NA_CB_GET, callback, arg,
        (struct na_ucx_mem_handle *) local_mem_handle, local_offset,
        (struct na_ucx_mem_handle *) remote_mem_handle, remote_offset, length,
        (struct na_ucx_addr *) remote_addr, (struct na_ucx_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static int
na_ucx_poll_get_fd(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    ucs_status_t status;
    int fd;

    if (na_ucx_class->no_wait)
        return -1;

    status = ucp_worker_get_efd(na_ucx_class->ucp_worker, &fd);
    NA_CHECK_SUBSYS_ERROR(poll, status != UCS_OK, error, fd, -1,
        "ucp_worker_get_efd() failed (%s)", ucs_status_string(status));

    return fd;

error:
    return -1;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    ucs_status_t status;
    na_bool_t retry_queue_empty;

    if (na_ucx_class->no_wait)
        return NA_FALSE;

    /* Keep making progress if retry queue is not empty */
    hg_thread_spin_lock(&na_ucx_class->retry_op_queue.lock);
    retry_queue_empty = HG_QUEUE_IS_EMPTY(&na_ucx_class->retry_op_queue.queue);
    hg_thread_spin_unlock(&na_ucx_class->retry_op_queue.lock);
    if (!retry_queue_empty)
        return NA_FALSE;

    status = ucp_worker_arm(na_ucx_class->ucp_worker);
    if (status == UCS_ERR_BUSY) {
        /* Events have already arrived */
        return NA_FALSE;
    } else if (status != UCS_OK) {
        NA_LOG_SUBSYS_ERROR(
            poll, "ucp_worker_arm() failed (%s)", ucs_status_string(status));
        return NA_FALSE;
    }

    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_progress(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms)
{
    hg_time_t deadline, now = hg_time_from_ms(0);
    na_return_t ret;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    do {
        unsigned int progressed =
            ucp_worker_progress(NA_UCX_CLASS(na_class)->ucp_worker);

        /* Attempt to process retries */
        ret = na_ucx_process_retries(NA_UCX_CLASS(na_class));
        NA_CHECK_SUBSYS_NA_ERROR(poll, error, ret, "Could not process retries");

        if (progressed != 0)
            return NA_SUCCESS;

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
    } while (hg_time_less(now, deadline));

    return NA_TIMEOUT;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_cancel(
    na_class_t *na_class, na_context_t NA_UNUSED *context, na_op_id_t *op_id)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    int32_t status;

    /* Exit if op has already completed */
    status = hg_atomic_get32(&na_ucx_op_id->status);
    if ((status & NA_UCX_OP_COMPLETED) || (status & NA_UCX_OP_ERRORED) ||
        (status & NA_UCX_OP_CANCELED) || (status & NA_UCX_OP_CANCELING))
        return NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(op, "Canceling operation ID %p (%s)",
        (void *) na_ucx_op_id,
        na_cb_type_to_string(na_ucx_op_id->completion_data.callback_info.type));

    /* Must set canceling before we check for the retry queue */
    hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_CANCELING);

    /* Check if op_id is in retry queue */
    if (hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_QUEUED) {
        struct na_ucx_op_queue *op_queue =
            &NA_UCX_CLASS(na_class)->retry_op_queue;
        na_bool_t canceled = NA_FALSE;

        /* If dequeued by process_retries() in the meantime, we'll just let it
         * cancel there */

        hg_thread_spin_lock(&op_queue->lock);
        if (hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_QUEUED) {
            HG_QUEUE_REMOVE(
                &op_queue->queue, na_ucx_op_id, na_ucx_op_id, entry);
            hg_atomic_and32(&na_ucx_op_id->status, ~NA_UCX_OP_QUEUED);
            hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_CANCELED);
            canceled = NA_TRUE;
        }
        hg_thread_spin_unlock(&op_queue->lock);

        if (canceled)
            na_ucx_complete(na_ucx_op_id, NA_CANCELED);
    } else {
        /* Do best effort to cancel the operation */
        hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_CANCELED);
        ucp_request_cancel(
            NA_UCX_CLASS(na_class)->ucp_worker, (void *) na_ucx_op_id);
    }

    return NA_SUCCESS;
}
