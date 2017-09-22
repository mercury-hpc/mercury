/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "na_private.h"
#include "na_error.h"

#include "mercury_queue.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_spin.h"
#include "mercury_time.h"
#include "mercury_atomic.h"
#include "mercury_atomic_queue.h"
#include "mercury_thread.h"
#include "mercury_poll.h"
#include "mercury_event.h"
#include "mercury_mem.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <process.h>
#else
#include <ftw.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#if defined(NA_SM_HAS_CMA)
#include <sys/uio.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#endif

/****************/
/* Local Macros */
/****************/

/* Plugin constants */
#define NA_SM_MAX_FILENAME      64
#define NA_SM_NUM_BUFS          64
#define NA_SM_CACHE_LINE_SIZE   HG_UTIL_CACHE_ALIGNMENT
#define NA_SM_RING_BUF_SIZE \
    (sizeof(struct na_sm_ring_buf) + NA_SM_NUM_BUFS * HG_ATOMIC_QUEUE_ELT_SIZE)
#define NA_SM_COPY_BUF_SIZE     4096
#define NA_SM_CLEANUP_NFDS      16

#define NA_SM_LISTEN_BACKLOG    64
#define NA_SM_ACCEPT_INTERVAL   100 /* 100 ms */

/* Msg sizes */
#define NA_SM_UNEXPECTED_SIZE   4096
#define NA_SM_EXPECTED_SIZE     NA_SM_UNEXPECTED_SIZE

/* Max tag */
#define NA_SM_MAX_TAG           NA_TAG_UB

/* Private data access */
#define NA_SM_PRIVATE_DATA(na_class) \
    ((struct na_sm_private_data *)(na_class->private_data))

/* Min macro */
#define NA_SM_MIN(a, b) \
    (a < b) ? a : b

/* Struct msghdr initializer */
#define NA_SM_MSGHDR_INITIALIZER {NULL, 0, NULL, 0, NULL, 0, 0}

/* Default filenames/paths */
#define NA_SM_SOCK_PATH NA_SM_TMP_DIRECTORY "/" NA_SM_SHM_PREFIX
#define NA_SM_SHM_PATH "/dev/shm"

#define NA_SM_GEN_SHM_NAME(filename, na_sm_addr)        \
    do {                                                \
        sprintf(filename, "%s-%d-%u", NA_SM_SHM_PREFIX, \
            na_sm_addr->pid, na_sm_addr->id);           \
    } while (0)

#define NA_SM_GEN_SOCK_PATH(pathname, na_sm_addr)               \
    do {                                                        \
        sprintf(pathname, "%s/%s/%d/%u", NA_SM_TMP_DIRECTORY,   \
            NA_SM_SHM_PREFIX, na_sm_addr->pid, na_sm_addr->id); \
    } while (0)

#define NA_SM_SEND_NAME "s" /* used for pair_name */
#define NA_SM_RECV_NAME "r" /* used for pair_name */
#define NA_SM_GEN_RING_NAME(filename, pair_name, na_sm_addr)            \
    do {                                                                \
        sprintf(filename, "%s-%d-%u-%u-" pair_name, NA_SM_SHM_PREFIX,   \
            na_sm_addr->pid, na_sm_addr->id, na_sm_addr->conn_id);      \
    } while (0)

#ifndef HG_UTIL_HAS_SYSEVENTFD_H
#define NA_SM_GEN_FIFO_NAME(filename, pair_name, na_sm_addr)            \
    do {                                                                \
        sprintf(filename, "%s/%s/%d/%u/fifo-%u-" pair_name,             \
            NA_SM_TMP_DIRECTORY, NA_SM_SHM_PREFIX, na_sm_addr->pid,     \
            na_sm_addr->id, na_sm_addr->conn_id);                       \
    } while (0)
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

typedef union {
    hg_atomic_int32_t val;
    char pad[NA_SM_CACHE_LINE_SIZE];
} na_sm_cacheline_atomic_int32_t;

typedef union {
    hg_atomic_int64_t val;
    char pad[NA_SM_CACHE_LINE_SIZE];
} na_sm_cacheline_atomic_int64_t;

typedef union {
    struct {
        unsigned int type       : 4;    /* Message type */
        unsigned int buf_idx    : 8;    /* Index reserved: 64 MAX */
        unsigned int buf_size   : 16;   /* Buffer length: 4KB MAX */
        unsigned int tag        : 32;   /* Message tag : UINT MAX */
        unsigned int pad        : 4;    /* 4 bits left */
    } hdr;
    na_uint64_t val;
} na_sm_cacheline_hdr_t;

/* Ring buffer */
struct na_sm_ring_buf {
    na_sm_cacheline_atomic_int32_t notify_count;
    na_sm_cacheline_atomic_int32_t polling;
    struct hg_atomic_queue queue;
    char pad[NA_SM_COPY_BUF_SIZE - sizeof(struct hg_atomic_queue)
             - 2 * NA_SM_CACHE_LINE_SIZE
             - NA_SM_NUM_BUFS * HG_ATOMIC_QUEUE_ELT_SIZE];
};

/* Shared copy buffer */
struct na_sm_copy_buf {
    na_sm_cacheline_atomic_int64_t available;       /* Atomic bitmask */
    char buf[NA_SM_NUM_BUFS][NA_SM_COPY_BUF_SIZE];  /* Buffer used for msgs */
    char pad[NA_SM_COPY_BUF_SIZE - NA_SM_CACHE_LINE_SIZE];
};

/* Poll type */
typedef enum na_sm_poll_type {
    NA_SM_ACCEPT = 1,
    NA_SM_SOCK,
    NA_SM_NOTIFY
} na_sm_poll_type_t;

/* Poll data */
struct na_sm_poll_data {
    na_class_t *na_class;
    na_sm_poll_type_t type;  /* Type of operation */
    struct na_sm_addr *addr; /* Address */
};

/* Sock progress type */
typedef enum {
    NA_SM_ADDR_INFO,
    NA_SM_CONN_ID,
    NA_SM_SOCK_DONE
} na_sm_sock_progress_t;

/* Address */
struct na_sm_addr {
    pid_t pid;                              /* PID */
    unsigned int id;                        /* SM ID */
    unsigned int conn_id;                   /* Connection ID */
    struct na_sm_ring_buf *na_sm_send_ring_buf; /* Shared send ring buffer */
    struct na_sm_ring_buf *na_sm_recv_ring_buf; /* Shared recv ring buffer */
    struct na_sm_copy_buf *na_sm_copy_buf;  /* Shared copy buffer */
    na_bool_t accepted;                     /* Created on accept */
    na_bool_t self;                         /* Self address */
    int sock;                               /* Sock fd */
    na_sm_sock_progress_t sock_progress;    /* Current sock progress state */
    struct na_sm_poll_data *sock_poll_data; /* Sock poll data */
    int local_notify;                       /* Local notify fd */
    struct na_sm_poll_data *local_notify_poll_data; /* Notify poll data */
    int remote_notify;                      /* Remote notify fd */
    hg_atomic_int32_t ref_count;            /* Ref count */
    HG_QUEUE_ENTRY(na_sm_addr) entry;       /* Next queue entry */
    HG_QUEUE_ENTRY(na_sm_addr) poll_entry;  /* Next poll queue entry */
};

/* Unexpected message info */
struct na_sm_unexpected_info {
    struct na_sm_addr *na_sm_addr;
    na_sm_cacheline_hdr_t na_sm_hdr;
    HG_QUEUE_ENTRY(na_sm_unexpected_info) entry;
};

/* Memory handle */
struct na_sm_mem_handle {
    struct iovec *iov;
    unsigned long iovcnt;
    unsigned long flags; /* Flag of operation access */
    size_t len;
};

/* Lookup info */
struct na_sm_info_lookup {
    struct na_sm_addr *na_sm_addr;
};

/* Send unexpected and expected */
struct na_sm_info_send {
    void *buf;
    size_t buf_size;
    struct na_sm_addr *na_sm_addr;
    na_tag_t tag;
};

/* Unexpected recv info */
struct na_sm_info_recv_unexpected {
    void *buf;
    size_t buf_size;
    struct na_sm_unexpected_info unexpected_info;
};

/* Expected recv info */
struct na_sm_info_recv_expected {
    void *buf;
    size_t buf_size;
    struct na_sm_addr *na_sm_addr;
    na_tag_t tag;
};

/* Operation ID */
struct na_sm_op_id {
    na_class_t *na_class;
    na_context_t *context;
    struct na_cb_completion_data completion_data;
    hg_atomic_int32_t completed;    /* Operation completed */
    hg_atomic_int32_t canceled;     /* Operation canceled */
    union {
        struct na_sm_info_lookup lookup;
        struct na_sm_info_send send;
        struct na_sm_info_recv_unexpected recv_unexpected;
        struct na_sm_info_recv_expected recv_expected;
    } info;
    hg_atomic_int32_t ref_count;    /* Ref count */
    HG_QUEUE_ENTRY(na_sm_op_id) entry;
};

/* Private data */
struct na_sm_private_data {
    struct na_sm_addr *self_addr;
    hg_poll_set_t *poll_set;
    HG_QUEUE_HEAD(na_sm_addr) accepted_addr_queue;
    HG_QUEUE_HEAD(na_sm_addr) poll_addr_queue;
    HG_QUEUE_HEAD(na_sm_unexpected_info) unexpected_msg_queue;
    HG_QUEUE_HEAD(na_sm_op_id) lookup_op_queue;
    HG_QUEUE_HEAD(na_sm_op_id) unexpected_op_queue;
    HG_QUEUE_HEAD(na_sm_op_id) expected_op_queue;
    hg_thread_spin_t accepted_addr_queue_lock;
    hg_thread_spin_t poll_addr_queue_lock;
    hg_thread_spin_t unexpected_msg_queue_lock;
    hg_thread_spin_t lookup_op_queue_lock;
    hg_thread_spin_t unexpected_op_queue_lock;
    hg_thread_spin_t expected_op_queue_lock;
    hg_thread_spin_t copy_buf_lock;
    hg_time_t last_accept_time;
    hg_atomic_int32_t polling;
    hg_atomic_int32_t notify_count;
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Open shared buf.
 */
static void *
na_sm_open_shared_buf(
    const char *name,
    size_t buf_size,
    na_bool_t create
    );

/**
 * Close shared buf.
 */
static na_return_t
na_sm_close_shared_buf(
    const char *filename,
    void *buf,
    size_t buf_size
    );

/**
 * Create UNIX domain socket.
 */
static na_return_t
na_sm_create_sock(
    const char *pathname,
    na_bool_t na_listen,
    int *sock);

/**
 * Close socket.
 */
static na_return_t
na_sm_close_sock(
    int sock,
    const char *pathname
    );

/**
 * Clean up file.
 */
static int
na_sm_cleanup_file(
    const char *fpath,
    const struct stat *sb,
    int typeflag,
    struct FTW *ftwbuf
    );

/**
 * Clean up shm segment.
 */
static int
na_sm_cleanup_shm(
    const char *fpath,
    const struct stat *sb,
    int typeflag,
    struct FTW *ftwbuf
    );

#ifndef HG_UTIL_HAS_SYSEVENTFD_H

/**
 * Create event using named pipe.
 */
static int
na_sm_event_create(
    const char *filename
    );

/**
 * Destroy event.
 */
static na_return_t
na_sm_event_destroy(
    const char *filename,
    int fd
    );

/**
 * Set event.
 */
static na_return_t
na_sm_event_set(
    int fd
    );

/**
 * Get event.
 */
static na_return_t
na_sm_event_get(
    int fd,
    na_bool_t *signaled
    );

#endif

/**
 * Register addr to poll set.
 */
static na_return_t
na_sm_poll_register(
    na_class_t *na_class,
    na_sm_poll_type_t poll_type,
    struct na_sm_addr *na_sm_addr
    );

/**
 * Deregister addr from poll set.
 */
static na_return_t
na_sm_poll_deregister(
    na_class_t *na_class,
    na_sm_poll_type_t poll_type,
    struct na_sm_addr *na_sm_addr
    );

/**
 * Create copy buf and sock and register self address.
 */
static na_return_t na_sm_setup_shm(
    na_class_t *na_class,
    struct na_sm_addr *na_sm_addr
    );

/**
 * Send addr info.
 */
static na_return_t
na_sm_send_addr_info(
    na_class_t *na_class,
    struct na_sm_addr *na_sm_addr
    );

/**
 * Recv addr info.
 */
static na_return_t
na_sm_recv_addr_info(
    struct na_sm_addr *na_sm_addr,
    na_bool_t *received
    );

/**
 * Send connection ID.
 */
static na_return_t
na_sm_send_conn_id(
    struct na_sm_addr *na_sm_addr
    );

/**
 * Recv connection ID.
 */
static na_return_t
na_sm_recv_conn_id(
    struct na_sm_addr *na_sm_addr,
    na_bool_t *received
    );

/**
 * Initialize ring buffer.
 */
static void
na_sm_ring_buf_init(
    struct na_sm_ring_buf *na_sm_ring_buf
    );

/**
 * Multi-producer safe lock-free ring buffer enqueue.
 */
static NA_INLINE na_bool_t
na_sm_ring_buf_push(
    struct na_sm_ring_buf *na_sm_ring_buf,
    na_sm_cacheline_hdr_t na_sm_hdr
    );

/**
 * Single-consumer dequeue.
 */
static NA_INLINE na_bool_t
na_sm_ring_buf_pop(
    struct na_sm_ring_buf *na_sm_ring_buf,
    na_sm_cacheline_hdr_t *na_sm_hdr_ptr
    );

/**
 * Reserve shared copy buf.
 */
static NA_INLINE na_return_t
na_sm_reserve_and_copy_buf(
    na_class_t *na_class,
    struct na_sm_copy_buf *na_sm_copy_buf,
    const void *buf,
    size_t buf_size,
    unsigned int *idx_reserved
    );

/**
 * Free shared copy buf.
 */
static NA_INLINE void
na_sm_copy_and_free_buf(
    na_class_t *na_class,
    struct na_sm_copy_buf *na_sm_copy_buf,
    void *buf,
    size_t buf_size,
    unsigned int idx_reserved
    );

/**
 * Translate offset from mem_handle into usable iovec.
 */
static void
na_sm_offset_translate(
    struct na_sm_mem_handle *mem_handle,
    na_offset_t offset,
    na_size_t length,
    struct iovec *iov,
    unsigned long *iovcnt
    );

/**
 * Progress callback
 */
static int
na_sm_progress_cb(
    void *arg,
    unsigned int timeout,
    hg_util_bool_t *progressed
    );

/**
 * Progress on accept.
 */
static na_return_t
na_sm_progress_accept(
    na_class_t *na_class,
    struct na_sm_addr *poll_addr,
    na_bool_t *progressed
    );

/**
 * Progress on socket.
 */
static na_return_t
na_sm_progress_sock(
    na_class_t *na_class,
    struct na_sm_addr *poll_addr,
    na_bool_t *progressed
    );

/**
 * Progress on notifications.
 */
static na_return_t
na_sm_progress_notify(
    na_class_t *na_class,
    struct na_sm_addr *poll_addr,
    na_bool_t *progressed
    );

/**
 * Progress on unexpected messages.
 */
static na_return_t
na_sm_progress_unexpected(
    na_class_t *na_class,
    struct na_sm_addr *poll_addr,
    na_sm_cacheline_hdr_t na_sm_hdr
    );

/**
 * Progress on expected messages.
 */
static na_return_t
na_sm_progress_expected(
    na_class_t *na_class,
    struct na_sm_addr *poll_addr,
    na_sm_cacheline_hdr_t na_sm_hdr
    );

/**
 * Complete operation.
 */
static na_return_t
na_sm_complete(
    struct na_sm_op_id *na_sm_op_id
    );

/**
 * Release memory.
 */
static void
na_sm_release(
    void *arg
    );

/* check_protocol */
static na_bool_t
na_sm_check_protocol(
    const char *protocol_name
    );

/* initialize */
static na_return_t
na_sm_initialize(
    na_class_t *na_class,
    const struct na_info *na_info,
    na_bool_t listen
    );

/* finalize */
static na_return_t
na_sm_finalize(
    na_class_t *na_class
    );

/* cleanup */
static void
na_sm_cleanup(
    void
    );

/* check_feature */
static na_bool_t
na_sm_check_feature(
    na_class_t *na_class,
    na_uint8_t feature
    );

/* op_create */
static na_op_id_t
na_sm_op_create(
    na_class_t *na_class
    );

/* op_destroy */
static na_return_t
na_sm_op_destroy(
    na_class_t *na_class,
    na_op_id_t op_id
    );

/* addr_lookup */
static na_return_t
na_sm_addr_lookup(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    const char *name,
    na_op_id_t *op_id
    );

/* addr_free */
static na_return_t
na_sm_addr_free(
    na_class_t *na_class,
    na_addr_t addr
    );

/* addr_self */
static na_return_t
na_sm_addr_self(
    na_class_t *na_class,
    na_addr_t *addr
    );

/* addr_dup */
static na_return_t
na_sm_addr_dup(
    na_class_t *na_class,
    na_addr_t   addr,
    na_addr_t  *new_addr
    );

/* addr_is_self */
static na_bool_t
na_sm_addr_is_self(
    na_class_t *na_class,
    na_addr_t addr
    );

/* addr_to_string */
static na_return_t
na_sm_addr_to_string(
    na_class_t *na_class,
    char *buf,
    na_size_t *buf_size,
    na_addr_t addr
    );

/* msg_get_max_unexpected_size */
static na_size_t
na_sm_msg_get_max_unexpected_size(
    const na_class_t *na_class
    );

/* msg_get_max_expected_size */
static na_size_t
na_sm_msg_get_max_expected_size(
    const na_class_t *na_class
    );

/* msg_get_max_tag */
static na_tag_t
na_sm_msg_get_max_tag(
    const na_class_t *na_class
    );

/* msg_send_unexpected */
static na_return_t
na_sm_msg_send_unexpected(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    const void *buf,
    na_size_t buf_size,
    void *plugin_data,
    na_addr_t dest,
    na_tag_t tag,
    na_op_id_t *op_id
    );

/* msg_recv_unexpected */
static na_return_t
na_sm_msg_recv_unexpected(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    void *buf,
    na_size_t buf_size,
    void *plugin_data,
    na_tag_t mask,
    na_op_id_t *op_id
    );

/* msg_send_expected */
static na_return_t
na_sm_msg_send_expected(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    const void *buf,
    na_size_t buf_size,
    void *plugin_data,
    na_addr_t dest,
    na_tag_t tag,
    na_op_id_t *op_id
    );

/* msg_recv_expected */
static na_return_t
na_sm_msg_recv_expected(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    void *buf,
    na_size_t buf_size,
    void *plugin_data,
    na_addr_t source,
    na_tag_t tag,
    na_op_id_t *op_id
    );

/* mem_handle_create */
static na_return_t
na_sm_mem_handle_create(
    na_class_t *na_class,
    void *buf,
    na_size_t buf_size,
    unsigned long flags,
    na_mem_handle_t *mem_handle
    );

#ifdef NA_SM_HAS_CMA
/* mem_handle_create_segments */
static na_return_t
na_sm_mem_handle_create_segments(
    na_class_t *na_class,
    struct na_segment *segments,
    na_size_t segment_count,
    unsigned long flags,
    na_mem_handle_t *mem_handle
    );
#endif

/* mem_handle_free */
static na_return_t
na_sm_mem_handle_free(
    na_class_t *na_class,
    na_mem_handle_t mem_handle
    );

/* mem_handle_get_serialize_size */
static na_size_t
na_sm_mem_handle_get_serialize_size(
    na_class_t *na_class,
    na_mem_handle_t mem_handle
    );

/* mem_handle_serialize */
static na_return_t
na_sm_mem_handle_serialize(
    na_class_t *na_class,
    void *buf,
    na_size_t buf_size,
    na_mem_handle_t mem_handle
    );

/* mem_handle_deserialize */
static na_return_t
na_sm_mem_handle_deserialize(
    na_class_t *na_class,
    na_mem_handle_t *mem_handle,
    const void *buf,
    na_size_t buf_size
    );

/* put */
static na_return_t
na_sm_put(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    na_mem_handle_t local_mem_handle,
    na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle,
    na_offset_t remote_offset,
    na_size_t length,
    na_addr_t remote_addr,
    na_op_id_t *op_id
    );

/* get */
static na_return_t
na_sm_get(
    na_class_t *na_class,
    na_context_t *context,
    na_cb_t callback,
    void *arg,
    na_mem_handle_t local_mem_handle,
    na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle,
    na_offset_t remote_offset,
    na_size_t length,
    na_addr_t remote_addr,
    na_op_id_t *op_id
    );

/* poll_get_fd */
static int
na_sm_poll_get_fd(
    na_class_t      *na_class,
    na_context_t    *context
    );

/* poll_try_wait */
static na_bool_t
na_sm_poll_try_wait(
    na_class_t      *na_class,
    na_context_t    *context
    );

/* progress */
static na_return_t
na_sm_progress(
    na_class_t *na_class,
    na_context_t *context,
    unsigned int timeout
    );

/* cancel */
static na_return_t
na_sm_cancel(
    na_class_t *na_class,
    na_context_t *context,
    na_op_id_t op_id
    );

/*******************/
/* Local Variables */
/*******************/

const na_class_t na_sm_class_g = {
    NULL,                                   /* private_data */
    "na",                                   /* name */
    na_sm_check_protocol,                   /* check_protocol */
    na_sm_initialize,                       /* initialize */
    na_sm_finalize,                         /* finalize */
    na_sm_cleanup,                          /* cleanup */
    na_sm_check_feature,                    /* check_feature */
    NULL,                                   /* context_create */
    NULL,                                   /* context_destroy */
    na_sm_op_create,                        /* op_create */
    na_sm_op_destroy,                       /* op_destroy */
    na_sm_addr_lookup,                      /* addr_lookup */
    na_sm_addr_free,                        /* addr_free */
    na_sm_addr_self,                        /* addr_self */
    na_sm_addr_dup,                         /* addr_dup */
    na_sm_addr_is_self,                     /* addr_is_self */
    na_sm_addr_to_string,                   /* addr_to_string */
    na_sm_msg_get_max_unexpected_size,      /* msg_get_max_unexpected_size */
    na_sm_msg_get_max_expected_size,        /* msg_get_max_expected_size */
    NULL,                                   /* msg_get_unexpected_header_size */
    NULL,                                   /* msg_get_expected_header_size */
    na_sm_msg_get_max_tag,                  /* msg_get_max_tag */
    NULL,                                   /* msg_buf_alloc */
    NULL,                                   /* msg_buf_free */
    NULL,                                   /* msg_init_unexpected */
    na_sm_msg_send_unexpected,              /* msg_send_unexpected */
    na_sm_msg_recv_unexpected,              /* msg_recv_unexpected */
    NULL,                                   /* msg_init_expected */
    na_sm_msg_send_expected,                /* msg_send_expected */
    na_sm_msg_recv_expected,                /* msg_recv_expected */
    na_sm_mem_handle_create,                /* mem_handle_create */
#ifdef NA_SM_HAS_CMA
    na_sm_mem_handle_create_segments,       /* mem_handle_create_segments */
#else
    NULL,                                   /* mem_handle_create_segments */
#endif
    na_sm_mem_handle_free,                  /* mem_handle_free */
    NULL,                                   /* mem_register */
    NULL,                                   /* mem_deregister */
    NULL,                                   /* mem_publish */
    NULL,                                   /* mem_unpublish */
    na_sm_mem_handle_get_serialize_size,    /* mem_handle_get_serialize_size */
    na_sm_mem_handle_serialize,             /* mem_handle_serialize */
    na_sm_mem_handle_deserialize,           /* mem_handle_deserialize */
    na_sm_put,                              /* put */
    na_sm_get,                              /* get */
    na_sm_poll_get_fd,                      /* poll_get_fd */
    na_sm_poll_try_wait,                    /* poll_try_wait */
    na_sm_progress,                         /* progress */
    na_sm_cancel                            /* cancel */
};

/********************/
/* Plugin callbacks */
/********************/

/*
static char*
itoa(uint64_t val, int base)
{
    static char buf[64] = {0};
    int i = 62;

    for (; val && i; --i, val /= base)
        buf[i] = "0123456789abcdef"[val % base];

    return &buf[i + 1];
}
*/

/*
static void
na_sm_print_addr(struct na_sm_addr *na_sm_addr)
{
    NA_LOG_DEBUG("pid=%d, id=%d, copy_buf=0x%lX, sock=%d, local_notify=%d, "
        "remote_notify=%d", na_sm_addr->pid, na_sm_addr->id,
        (uint64_t)na_sm_addr->na_sm_copy_buf, na_sm_addr->sock,
        na_sm_addr->local_notify, na_sm_addr->remote_notify);
}
*/

/*---------------------------------------------------------------------------*/
static void *
na_sm_open_shared_buf(const char *name, size_t buf_size, na_bool_t create)
{
    na_size_t page_size = (na_size_t) hg_mem_get_page_size();
    void *ret = NULL;

    /* Check alignment */
    if (buf_size / page_size * page_size != buf_size) {
        NA_LOG_ERROR(
            "Not aligned properly, page size=%zu bytes, buf size=%zu bytes",
            page_size, buf_size);
        goto done;
    }

    ret = hg_mem_shm_map(name, buf_size, create);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_close_shared_buf(const char *filename, void *buf, size_t buf_size)
{
    return hg_mem_shm_unmap(filename, buf, buf_size);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_create_sock(const char *pathname, na_bool_t na_listen, int *sock)
{
    struct sockaddr_un addr;
    na_return_t ret = NA_SUCCESS;
    int fd;

    /* Create a non-blocking socket so that we can poll for incoming connections */
#ifdef SOCK_NONBLOCK
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
#else
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if (fd == -1) {
        NA_LOG_ERROR("socket() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#ifndef SOCK_NONBLOCK
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        NA_LOG_ERROR("fcntl() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    };
#endif

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    if (strlen(pathname) + strlen("/sock") > sizeof(addr.sun_path) - 1) {
        NA_LOG_ERROR("Exceeds maximum AF UNIX socket path length");
        ret = NA_SIZE_ERROR;
        goto done;
    }
    strcpy(addr.sun_path, pathname);
    strcat(addr.sun_path, "/sock");

    if (na_listen) {
        char *dup_path = strdup(pathname);
        char stat_path[NA_SM_MAX_FILENAME];
        char *path_ptr = dup_path;

        memset(stat_path, '\0', NA_SM_MAX_FILENAME);
        if (dup_path[0] == '/') {
            path_ptr++;
            stat_path[0] = '/';
        }

        /* Create path */
        while (path_ptr) {
            struct stat sb;
            char *current = strtok_r(path_ptr, "/", &path_ptr);
            if (!current) break;

            strcat(stat_path, current);
            if (stat(stat_path, &sb) == -1) {
                if (mkdir(stat_path, 0775) == -1 && errno != EEXIST) {
                    NA_LOG_ERROR("Could not create directory: %s (%s)",
                        stat_path, strerror(errno));
                    ret = NA_PROTOCOL_ERROR;
                    free(dup_path);
                    goto done;
                }
            }
            strcat(stat_path, "/");
        }
        free(dup_path);

        /* Bind */
        if (bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
            NA_LOG_ERROR("bind() socket (%s)", strerror(errno));
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        /* Listen */
        if (listen(fd, NA_SM_LISTEN_BACKLOG) == -1) {
            NA_LOG_ERROR("listen() failed (%s)", strerror(errno));
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    } else {
        /* Connect */
        if (connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
            NA_LOG_ERROR("connect() failed (%s)", strerror(errno));
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
    }

    *sock = fd;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_close_sock(int sock, const char *pathname)
{
    na_return_t ret = NA_SUCCESS;

    if (close(sock) == -1) {
        NA_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (pathname) {
        char dup_path[NA_SM_MAX_FILENAME];
        char *path_ptr = NULL;

        strcpy(dup_path, pathname);
        strcat(dup_path, "/sock");

        if (unlink(dup_path) == -1) {
            NA_LOG_ERROR("unlink() failed (%s)", strerror(errno));
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        /* Delete path */
        path_ptr = strrchr(dup_path, '/');
        while (path_ptr) {
            *path_ptr = '\0';
            if (rmdir(dup_path) == -1) {
                /* Silently ignore */
            }
            path_ptr = strrchr(dup_path, '/');
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_sm_cleanup_file(const char *fpath, const struct stat NA_UNUSED *sb,
    int NA_UNUSED typeflag, struct FTW NA_UNUSED *ftwbuf)
{
    return remove(fpath);
}

/*---------------------------------------------------------------------------*/
static int
na_sm_cleanup_shm(const char *fpath, const struct stat NA_UNUSED *sb,
    int NA_UNUSED typeflag, struct FTW NA_UNUSED *ftwbuf)
{
    const char *prefix = NA_SM_SHM_PATH "/" NA_SM_SHM_PREFIX;
    int ret = 0;

    if (strncmp(fpath, prefix, strlen(prefix)) == 0) {
        const char *file = fpath + strlen(NA_SM_SHM_PATH "/");
        ret = hg_mem_shm_unmap(file, NULL, 0);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
#ifndef HG_UTIL_HAS_SYSEVENTFD_H

static int
na_sm_event_create(const char *filename)
{
    int fd = -1;

    /* Create FIFO */
    if (mkfifo(filename, S_IRUSR | S_IWUSR) == - 1) {
        NA_LOG_ERROR("mkfifo() failed (%s)", strerror(errno));
        goto done;
    }

    /* Open FIFO (RDWR for convenience) */
    fd = open(filename, O_RDWR);
    if (fd == -1) {
        NA_LOG_ERROR("open() failed (%s)", strerror(errno));
        goto done;
    }

    /* Set FIFO to be non-blocking */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        NA_LOG_ERROR("fcntl() failed (%s)", strerror(errno));
        close(fd);
        fd = -1;
        goto done;
    };

done:
    return fd;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_sm_event_destroy(const char *filename, int fd)
{
    na_return_t ret = NA_SUCCESS;

    if (close(fd) == -1) {
        NA_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (filename && unlink(filename) == -1) {
        NA_LOG_ERROR("unlink() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_sm_event_set(int fd)
{
    na_return_t ret = NA_SUCCESS;
    uint64_t count = 1;
    ssize_t s;

    s = write(fd, &count, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        NA_LOG_ERROR("write() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_sm_event_get(int fd, na_bool_t *signaled)
{
    na_return_t ret = NA_SUCCESS;
    na_bool_t event_signal = NA_FALSE;
    uint64_t count = 1;
    ssize_t s;

    s = read(fd, &count, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        if (errno == EAGAIN)
            goto done;
        NA_LOG_ERROR("read() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    event_signal = NA_TRUE;

    if (signaled) *signaled = event_signal;

done:
    return ret;
}

#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_poll_register(na_class_t *na_class, na_sm_poll_type_t poll_type,
    struct na_sm_addr *na_sm_addr)
{
    struct na_sm_poll_data *na_sm_poll_data = NULL;
    struct na_sm_poll_data **na_sm_poll_data_ptr = NULL;
    unsigned int flags = HG_POLLIN;
    int fd;
    na_return_t ret = NA_SUCCESS;

    switch (poll_type) {
        case NA_SM_ACCEPT:
            fd = na_sm_addr->sock;
            na_sm_poll_data_ptr = &na_sm_addr->sock_poll_data;
            break;
        case NA_SM_SOCK:
            fd = na_sm_addr->sock;
            na_sm_poll_data_ptr = &na_sm_addr->sock_poll_data;
            break;
        case NA_SM_NOTIFY:
            fd = na_sm_addr->local_notify;
            na_sm_poll_data_ptr = &na_sm_addr->local_notify_poll_data;
            break;
        default:
            NA_LOG_ERROR("Invalid poll type");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    na_sm_poll_data = (struct na_sm_poll_data *) malloc(sizeof(struct na_sm_poll_data));
    if (!na_sm_poll_data) {
        NA_LOG_ERROR("Could not allocate NA SM poll data");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_sm_poll_data->na_class = na_class;
    na_sm_poll_data->type = poll_type;
    na_sm_poll_data->addr = na_sm_addr;
    *na_sm_poll_data_ptr = na_sm_poll_data;

    if (hg_poll_add(NA_SM_PRIVATE_DATA(na_class)->poll_set, fd, flags,
        na_sm_progress_cb, na_sm_poll_data) != HG_UTIL_SUCCESS) {
        NA_LOG_ERROR("hg_poll_add failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_poll_deregister(na_class_t *na_class, na_sm_poll_type_t poll_type,
    struct na_sm_addr *na_sm_addr)
{
    int fd;
    struct na_sm_poll_data *na_sm_poll_data = NULL;
    na_return_t ret = NA_SUCCESS;

    switch (poll_type) {
        case NA_SM_ACCEPT:
            na_sm_poll_data = na_sm_addr->sock_poll_data;
            fd = na_sm_addr->sock;
            break;
        case NA_SM_SOCK:
            na_sm_poll_data = na_sm_addr->sock_poll_data;
            fd = na_sm_addr->sock;
            break;
        case NA_SM_NOTIFY:
            na_sm_poll_data = na_sm_addr->local_notify_poll_data;
            fd = na_sm_addr->local_notify;
            break;
        default:
            NA_LOG_ERROR("Invalid poll type");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    if (hg_poll_remove(NA_SM_PRIVATE_DATA(na_class)->poll_set,
        fd) != HG_UTIL_SUCCESS) {
        NA_LOG_ERROR("hg_poll_remove failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    free(na_sm_poll_data);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_setup_shm(na_class_t *na_class, struct na_sm_addr *na_sm_addr)
{
    char filename[NA_SM_MAX_FILENAME], pathname[NA_SM_MAX_FILENAME];
    struct na_sm_copy_buf *na_sm_copy_buf = NULL;
    int listen_sock;
    na_return_t ret = NA_SUCCESS;

    /* Create SHM buffer */
    NA_SM_GEN_SHM_NAME(filename, na_sm_addr);
    na_sm_copy_buf = (struct na_sm_copy_buf *) na_sm_open_shared_buf(
        filename, sizeof(struct na_sm_copy_buf), NA_TRUE);
    if (!na_sm_copy_buf) {
        NA_LOG_ERROR("Could not create copy buffer");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    /* Initialize copy buf, store 1111111111...1111 */
    hg_atomic_init64(&na_sm_copy_buf->available.val, ~((hg_util_int64_t)0));
    na_sm_addr->na_sm_copy_buf = na_sm_copy_buf;

    /* Create SHM sock */
    NA_SM_GEN_SOCK_PATH(pathname, na_sm_addr);
    ret = na_sm_create_sock(pathname, NA_TRUE, &listen_sock);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not create sock");
        goto done;
    }
    na_sm_addr->sock = listen_sock;

    /* Add listen_sock to poll set */
    ret = na_sm_poll_register(na_class, NA_SM_ACCEPT, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add listen_sock to poll set");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_send_addr_info(na_class_t *na_class, struct na_sm_addr *na_sm_addr)
{
    struct msghdr msg = NA_SM_MSGHDR_INITIALIZER;
    ssize_t nsend;
    struct iovec iovec[2];
    na_return_t ret = NA_SUCCESS;

    /* Send local PID / ID */
    iovec[0].iov_base = &NA_SM_PRIVATE_DATA(na_class)->self_addr->pid;
    iovec[0].iov_len = sizeof(pid_t);
    iovec[1].iov_base = &NA_SM_PRIVATE_DATA(na_class)->self_addr->id;
    iovec[1].iov_len = sizeof(unsigned int);
    msg.msg_iov = iovec;
    msg.msg_iovlen = 2;

    nsend = sendmsg(na_sm_addr->sock, &msg, 0);
    if (nsend == -1) {
        NA_LOG_ERROR("sendmsg() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_recv_addr_info(struct na_sm_addr *na_sm_addr, na_bool_t *received)
{
    struct msghdr msg = NA_SM_MSGHDR_INITIALIZER;
    ssize_t nrecv;
    struct iovec iovec[2];
    na_return_t ret = NA_SUCCESS;

    /* Receive remote PID / ID */
    iovec[0].iov_base = &na_sm_addr->pid;
    iovec[0].iov_len = sizeof(pid_t);
    iovec[1].iov_base = &na_sm_addr->id;
    iovec[1].iov_len = sizeof(unsigned int);
    msg.msg_iov = iovec;
    msg.msg_iovlen = 2;

    nrecv = recvmsg(na_sm_addr->sock, &msg, 0);
    if (nrecv == -1) {
        if (errno == EAGAIN) {
            *received = NA_FALSE;
            goto done;
        }
        NA_LOG_ERROR("recvmsg() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    *received = NA_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_send_conn_id(struct na_sm_addr *na_sm_addr)
{
    struct msghdr msg = NA_SM_MSGHDR_INITIALIZER;
    struct cmsghdr *cmsg;
    /* Contains the file descriptors to pass */
    int fds[2] = {na_sm_addr->local_notify, na_sm_addr->remote_notify};
    union {
        /* ancillary data buffer, wrapped in a union in order to ensure
           it is suitably aligned */
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    int *fdptr;
    struct iovec iovec[1];
    ssize_t nsend;
    na_return_t ret = NA_SUCCESS;

    /* Send local PID / ID */
    iovec[0].iov_base = &na_sm_addr->conn_id;
    iovec[0].iov_len = sizeof(unsigned int);
    msg.msg_iov = iovec;
    msg.msg_iovlen = 1;

    /* Send notify event descriptors as ancillary data */
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));

    /* Initialize the payload */
    fdptr = (int *) CMSG_DATA(cmsg);
    memcpy(fdptr, fds, sizeof(fds));

    nsend = sendmsg(na_sm_addr->sock, &msg, 0);
    if (nsend == -1) {
        NA_LOG_ERROR("sendmsg() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_recv_conn_id(struct na_sm_addr *na_sm_addr, na_bool_t *received)
{
    struct msghdr msg = NA_SM_MSGHDR_INITIALIZER;
    struct cmsghdr *cmsg;
    int *fdptr;
    int fds[2];
    union {
        /* ancillary data buffer, wrapped in a union in order to ensure
           it is suitably aligned */
        char buf[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } u;
    ssize_t nrecv;
    struct iovec iovec[1];
    na_return_t ret = NA_SUCCESS;

    /* Receive remote PID / ID */
    iovec[0].iov_base = &na_sm_addr->conn_id;
    iovec[0].iov_len = sizeof(unsigned int);
    msg.msg_iov = iovec;
    msg.msg_iovlen = 1;

    /* Recv notify event descriptor as ancillary data */
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;

    nrecv = recvmsg(na_sm_addr->sock, &msg, 0);
    if (nrecv == -1) {
        if (errno == EAGAIN) {
            *received = NA_FALSE;
            goto done;
        }
        NA_LOG_ERROR("recvmsg() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    *received = NA_TRUE;

    /* Retrieve ancillary data */
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL) {
        NA_LOG_ERROR("NULL cmsg");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    fdptr = (int *) CMSG_DATA(cmsg);
    memcpy(fds, fdptr ,sizeof(fds));
    /* Invert descriptors so that local is remote and remote is local */
    na_sm_addr->local_notify = fds[1];
    na_sm_addr->remote_notify = fds[0];

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_sm_ring_buf_init(struct na_sm_ring_buf *na_sm_ring_buf)
{
    struct hg_atomic_queue *hg_atomic_queue = &na_sm_ring_buf->queue;
    unsigned int count = NA_SM_NUM_BUFS;

    hg_atomic_queue->prod_size = hg_atomic_queue->cons_size = count;
    hg_atomic_queue->prod_mask = hg_atomic_queue->cons_mask = count - 1;
    hg_atomic_init32(&hg_atomic_queue->prod_head, 0);
    hg_atomic_init32(&hg_atomic_queue->cons_head, 0);
    hg_atomic_init32(&hg_atomic_queue->prod_tail, 0);
    hg_atomic_init32(&hg_atomic_queue->cons_tail, 0);
    hg_atomic_init32(&na_sm_ring_buf->polling.val, NA_FALSE);
    hg_atomic_init32(&na_sm_ring_buf->notify_count.val, 0);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_sm_ring_buf_push(struct na_sm_ring_buf *na_sm_ring_buf,
    na_sm_cacheline_hdr_t na_sm_hdr)
{
    na_bool_t ret = NA_TRUE;

    if (hg_atomic_queue_push(&na_sm_ring_buf->queue,
        (void *) na_sm_hdr.val) == HG_UTIL_FAIL)
        ret = NA_FALSE;

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_sm_ring_buf_pop(struct na_sm_ring_buf *na_sm_ring_buf,
    na_sm_cacheline_hdr_t *na_sm_hdr_ptr)
{
    na_sm_cacheline_hdr_t na_sm_hdr;
    na_bool_t ret = NA_TRUE;

    na_sm_hdr.val = (na_uint64_t) hg_atomic_queue_pop_sc(&na_sm_ring_buf->queue);
    if (!na_sm_hdr.val) {
        /* Empty */
        ret = NA_FALSE;
        goto done;
    }

    *na_sm_hdr_ptr = na_sm_hdr;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_sm_reserve_and_copy_buf(na_class_t *na_class,
    struct na_sm_copy_buf *na_sm_copy_buf, const void *buf, size_t buf_size,
    unsigned int *idx_reserved)
{
    hg_util_int64_t bits = 1LL;
    na_return_t ret = NA_SIZE_ERROR;
    unsigned int i = 0;

    hg_thread_spin_lock(&NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);

    do {
        hg_util_int64_t available = hg_atomic_get64(
            &na_sm_copy_buf->available.val);
        if (!available)
            /* Nothing available */
            break;
        if ((available & bits) != bits) {
            /* Already reserved */
            hg_atomic_fence();
            i++;
            bits <<= 1;
            continue;
        }

        if (hg_atomic_cas64(&na_sm_copy_buf->available.val, available,
            available & ~bits)) {
            /* Reservation succeeded, copy buffer */
            memcpy(na_sm_copy_buf->buf[i], buf, buf_size);
            *idx_reserved = i;
//            NA_LOG_DEBUG("Reserved %u is:\n%s", i,
//                itoa(hg_atomic_get64(&na_sm_copy_buf->available.val), 2));
            ret = NA_SUCCESS;
            break;
        }
        /* Can't use atomic XOR directly, if there is a race and the cas
         * fails, we should be able to pick the next one available */
    } while (i < (NA_SM_NUM_BUFS - 1));

    hg_thread_spin_unlock(&NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_sm_copy_and_free_buf(na_class_t *na_class,
    struct na_sm_copy_buf *na_sm_copy_buf, void *buf, size_t buf_size,
    unsigned int idx_reserved)
{
    hg_util_int64_t bits = 1LL << idx_reserved;
#if defined(HG_UTIL_HAS_OPA_PRIMITIVES_H)
    hg_util_int64_t available;
#endif

    hg_thread_spin_lock(&NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);

    memcpy(buf, na_sm_copy_buf->buf[idx_reserved], buf_size);

#if !defined(HG_UTIL_HAS_OPA_PRIMITIVES_H)
    hg_atomic_or64(&na_sm_copy_buf->available.val, bits);
#else
    do {
        available = hg_atomic_get64(&na_sm_copy_buf->available.val);
    } while (!hg_atomic_cas64(&na_sm_copy_buf->available.val, available,
        (available | bits)));
#endif

    hg_thread_spin_unlock(&NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_msg_insert(na_class_t *na_class, struct na_sm_op_id *na_sm_op_id,
    na_cb_type_t cb_type, struct na_sm_addr *na_sm_addr,
    unsigned int idx_reserved, na_size_t buf_size, na_tag_t tag)
{
    na_sm_cacheline_hdr_t na_sm_hdr;
    na_return_t ret = NA_SUCCESS;

    /* Post the SM send request */
    na_sm_hdr.hdr.type = cb_type;
    na_sm_hdr.hdr.buf_idx = idx_reserved & 0xff;
    na_sm_hdr.hdr.buf_size = buf_size & 0xffff;
    na_sm_hdr.hdr.tag = tag;
    if (!na_sm_ring_buf_push(na_sm_addr->na_sm_send_ring_buf, na_sm_hdr)) {
        NA_LOG_ERROR("Full ring buffer");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Immediate completion, add directly to completion queue. */
    ret = na_sm_complete(na_sm_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

    /* Notify remote */
    hg_atomic_incr32(&na_sm_addr->na_sm_send_ring_buf->notify_count.val);
    if (hg_atomic_get32(&na_sm_addr->na_sm_send_ring_buf->polling.val)) {
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
        if (hg_event_set(na_sm_addr->remote_notify) != HG_UTIL_SUCCESS) {
            NA_LOG_ERROR("Could not send completion notification");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#else
        if (na_sm_event_set(na_sm_addr->remote_notify) != NA_SUCCESS) {
            NA_LOG_ERROR("Could not send completion notification");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#endif
    }

    /* Notify local completion */
    hg_atomic_incr32(&NA_SM_PRIVATE_DATA(na_class)->notify_count);
    if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->polling)
        && (hg_event_set(NA_SM_PRIVATE_DATA(na_class)->self_addr->local_notify)
        != HG_UTIL_SUCCESS)) {
        NA_LOG_ERROR("Could not signal local completion");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_sm_offset_translate(struct na_sm_mem_handle *mem_handle, na_offset_t offset,
    na_size_t length, struct iovec *iov, unsigned long *iovcnt)
{
    unsigned long i, new_start_index = 0;
    na_offset_t new_offset = offset, next_offset = 0;
    na_size_t remaining_len = length;

    /* Get start index and handle offset */
    for (i = 0; i < mem_handle->iovcnt; i++) {
        next_offset += mem_handle->iov[i].iov_len;
        if (offset < next_offset) {
            new_start_index = i;
            break;
        }
        new_offset -= mem_handle->iov[i].iov_len;
    }

    iov[0].iov_base = (char *) mem_handle->iov[new_start_index].iov_base +
        new_offset;
    iov[0].iov_len = NA_SM_MIN(remaining_len,
        mem_handle->iov[new_start_index].iov_len - new_offset);
    remaining_len -= iov[0].iov_len;

    for (i = 1; remaining_len && (i < mem_handle->iovcnt - new_start_index); i++) {
        iov[i].iov_base = mem_handle->iov[i + new_start_index].iov_base;
        /* Can only transfer smallest size */
        iov[i].iov_len = NA_SM_MIN(remaining_len,
            mem_handle->iov[i + new_start_index].iov_len);

        /* Decrease remaining len from the len of data */
        remaining_len -= iov[i].iov_len;
    }

    *iovcnt = i;
}

/*---------------------------------------------------------------------------*/
static int
na_sm_progress_cb(void *arg, unsigned int NA_UNUSED timeout,
    hg_util_bool_t *progressed)
{
    na_class_t *na_class;
    struct na_sm_poll_data *na_sm_poll_data = (struct na_sm_poll_data *) arg;
    na_return_t na_ret;

    if (!na_sm_poll_data) {
        NA_LOG_ERROR("NULL SM poll data");
        na_ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    na_class = na_sm_poll_data->na_class;

    switch (na_sm_poll_data->type) {
        case NA_SM_ACCEPT:
            na_ret = na_sm_progress_accept(na_class, na_sm_poll_data->addr,
                (hg_util_bool_t *) progressed);
            if (na_ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make progress on accept");
                goto done;
            }
            break;
        case NA_SM_SOCK:
            na_ret = na_sm_progress_sock(na_class, na_sm_poll_data->addr,
                (hg_util_bool_t *) progressed);
            if (na_ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make progress on sock");
                goto done;
            }
            break;
        case NA_SM_NOTIFY:
            na_ret = na_sm_progress_notify(na_class, na_sm_poll_data->addr,
                (hg_util_bool_t *) progressed);
            if (na_ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make progress on notify");
                goto done;
            }
            break;
        default:
            NA_LOG_ERROR("Unknown poll data type");
            na_ret = NA_PROTOCOL_ERROR;
            goto done;
            break;
    }

done:
    return (na_ret == NA_SUCCESS) ? HG_UTIL_SUCCESS : HG_UTIL_FAIL;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress_accept(na_class_t *na_class, struct na_sm_addr *poll_addr,
    na_bool_t *progressed)
{
    struct na_sm_addr *na_sm_addr = NULL;
    struct na_sm_ring_buf *na_sm_ring_buf = NULL;
    char filename[NA_SM_MAX_FILENAME];
    int conn_sock, local_notify, remote_notify;
    hg_time_t now;
    double elapsed_ms;
    na_return_t ret = NA_SUCCESS;

    if (poll_addr != NA_SM_PRIVATE_DATA(na_class)->self_addr) {
        NA_LOG_ERROR("Unrecognized poll addr");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Prevent from entering accept too often */
    hg_time_get_current(&now);
    elapsed_ms = hg_time_to_double(hg_time_subtract(now,
        NA_SM_PRIVATE_DATA(na_class)->last_accept_time)) * 1000.0;
    if (elapsed_ms < NA_SM_ACCEPT_INTERVAL) {
        *progressed = NA_FALSE;
        goto done;
    }
    NA_SM_PRIVATE_DATA(na_class)->last_accept_time = now;

#ifdef SOCK_NONBLOCK
    conn_sock = accept4(poll_addr->sock, NULL, NULL, SOCK_NONBLOCK);
#else
    conn_sock = accept(poll_addr->sock, NULL, NULL);
#endif
    if (conn_sock == -1) {
        if (errno == EAGAIN) {
            *progressed = NA_FALSE;
            goto done;
        }
        NA_LOG_ERROR("accept() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#ifndef SOCK_NONBLOCK
    if (fcntl(conn_sock, F_SETFL, O_NONBLOCK) == -1) {
        NA_LOG_ERROR("fcntl() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    };
#endif

    /* Allocate new addr and pass it to poll set */
    na_sm_addr = (struct na_sm_addr *) malloc(sizeof(struct na_sm_addr));
    if (!na_sm_addr) {
        NA_LOG_ERROR("Could not allocate NA SM addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    memset(na_sm_addr, 0, sizeof(struct na_sm_addr));
    hg_atomic_init32(&na_sm_addr->ref_count, 1);
    na_sm_addr->accepted = NA_TRUE;
    na_sm_addr->na_sm_copy_buf = poll_addr->na_sm_copy_buf;
    na_sm_addr->sock = conn_sock;
    /* We need to receive addr info in sock progress */
    na_sm_addr->sock_progress = NA_SM_ADDR_INFO;

    /* Add conn_sock to poll set */
    ret = na_sm_poll_register(na_class, NA_SM_SOCK, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add conn_sock to poll set");
        goto done;
    }

    /* Set up ring buffer pair (send/recv) for connection IDs */
    na_sm_addr->conn_id = NA_SM_PRIVATE_DATA(na_class)->self_addr->conn_id;
    NA_SM_GEN_RING_NAME(filename, NA_SM_SEND_NAME,
        NA_SM_PRIVATE_DATA(na_class)->self_addr);
    na_sm_ring_buf = (struct na_sm_ring_buf *) na_sm_open_shared_buf(filename,
        NA_SM_RING_BUF_SIZE, NA_TRUE);
    if (!na_sm_ring_buf) {
        NA_LOG_ERROR("Could not open ring buf");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    /* Initialize ring buffer */
    na_sm_ring_buf_init(na_sm_ring_buf);
    na_sm_addr->na_sm_send_ring_buf = na_sm_ring_buf;

    NA_SM_GEN_RING_NAME(filename, NA_SM_RECV_NAME,
        NA_SM_PRIVATE_DATA(na_class)->self_addr);
    na_sm_ring_buf = (struct na_sm_ring_buf *) na_sm_open_shared_buf(filename,
        NA_SM_RING_BUF_SIZE, NA_TRUE);
    if (!na_sm_ring_buf) {
        NA_LOG_ERROR("Could not open ring buf");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    /* Initialize ring buffer */
    na_sm_ring_buf_init(na_sm_ring_buf);
    na_sm_addr->na_sm_recv_ring_buf = na_sm_ring_buf;

    /* Create local signal event */
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
    local_notify = hg_event_create();
    if (local_notify == HG_UTIL_FAIL) {
        NA_LOG_ERROR("hg_event_create() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#else
    /**
     * If eventfd is not supported, we need to explicitly use named pipes in
     * this case as kqueue file descriptors cannot be exchanged through
     * ancillary data
     */
    NA_SM_GEN_FIFO_NAME(filename, NA_SM_RECV_NAME,
        NA_SM_PRIVATE_DATA(na_class)->self_addr);
    local_notify = na_sm_event_create(filename);
    if (local_notify == -1) {
        NA_LOG_ERROR("na_sm_event_create() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#endif
    na_sm_addr->local_notify = local_notify;

    /* Create remote signal event */
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
    remote_notify = hg_event_create();
    if (remote_notify == HG_UTIL_FAIL) {
        NA_LOG_ERROR("hg_event_create() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#else
    /**
     * If eventfd is not supported, we need to explicitly use named pipes in
     * this case as kqueue file descriptors cannot be exchanged through
     * ancillary data
     */
    NA_SM_GEN_FIFO_NAME(filename, NA_SM_SEND_NAME,
        NA_SM_PRIVATE_DATA(na_class)->self_addr);
    remote_notify = na_sm_event_create(filename);
    if (remote_notify == -1) {
        NA_LOG_ERROR("na_sm_event_create() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#endif
    na_sm_addr->remote_notify = remote_notify;

    /* Add local notify to poll set */
    ret = na_sm_poll_register(na_class, NA_SM_NOTIFY, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add notify to poll set");
        goto done;
    }

    /* Addr addr to poll addr queue */
    hg_thread_spin_lock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue,
        na_sm_addr, poll_entry);
    hg_thread_spin_unlock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);

    /* Send connection ID / event IDs */
    ret = na_sm_send_conn_id(na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not send connection ID");
        goto done;
    }

    /* Increment connection ID */
    NA_SM_PRIVATE_DATA(na_class)->self_addr->conn_id++;

    /* Push the addr to accepted addr queue so that we can free it later */
    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue_lock);
    HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue,
        na_sm_addr, entry);
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue_lock);

    *progressed = NA_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress_sock(na_class_t *na_class, struct na_sm_addr *poll_addr,
    na_bool_t *progressed)
{
    na_return_t ret = NA_SUCCESS;

    if (poll_addr == NA_SM_PRIVATE_DATA(na_class)->self_addr) {
        *progressed = NA_FALSE;
        goto done;
    }

    switch (poll_addr->sock_progress) {
        case NA_SM_ADDR_INFO: {
            na_bool_t received = NA_FALSE;

            /* Receive addr info (PID / ID) */
            ret = na_sm_recv_addr_info(poll_addr, &received);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not recv addr info");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            if (!received) {
                *progressed = NA_FALSE;
                goto done;
            }

            poll_addr->sock_progress = NA_SM_SOCK_DONE;

            /* Progressed */
            *progressed = NA_TRUE;
        }
        break;
        case NA_SM_CONN_ID: {
            char filename[NA_SM_MAX_FILENAME];
            struct na_sm_ring_buf *na_sm_ring_buf;
            struct na_sm_op_id *na_sm_op_id = NULL;
            na_bool_t received = NA_FALSE;

            /* Receive connection ID / event IDs */
            ret = na_sm_recv_conn_id(poll_addr, &received);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not recv connection ID");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            if (!received) {
                *progressed = NA_FALSE;
                goto done;
            }
            poll_addr->sock_progress = NA_SM_SOCK_DONE;

            /* Find op ID that corresponds to addr */
            hg_thread_spin_lock(
                &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);
            HG_QUEUE_FOREACH(na_sm_op_id,
                &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue, entry) {
                if (na_sm_op_id->info.lookup.na_sm_addr == poll_addr) {
                    HG_QUEUE_REMOVE(
                        &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue,
                        na_sm_op_id, na_sm_op_id, entry);
                    break;
                }
            }
            hg_thread_spin_unlock(
                &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);

            if (!na_sm_op_id) {
                NA_LOG_ERROR("Could not find lookup op ID, conn ID=%u, PID=%u",
                    poll_addr->conn_id, (unsigned int) poll_addr->pid);
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }

            /* Open remote ring buf pair (send and recv names correspond to
             * remote ring buffer pair) */
            NA_SM_GEN_RING_NAME(filename, NA_SM_RECV_NAME, poll_addr);
            na_sm_ring_buf = (struct na_sm_ring_buf *) na_sm_open_shared_buf(
                filename, NA_SM_RING_BUF_SIZE, NA_FALSE);
            if (!na_sm_ring_buf) {
                NA_LOG_ERROR("Could not open ring buf");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            poll_addr->na_sm_send_ring_buf = na_sm_ring_buf;

            NA_SM_GEN_RING_NAME(filename, NA_SM_SEND_NAME, poll_addr);
            na_sm_ring_buf = (struct na_sm_ring_buf *) na_sm_open_shared_buf(
                filename, NA_SM_RING_BUF_SIZE, NA_FALSE);
            if (!na_sm_ring_buf) {
                NA_LOG_ERROR("Could not open ring buf");
                ret = NA_PROTOCOL_ERROR;
                goto done;
            }
            poll_addr->na_sm_recv_ring_buf = na_sm_ring_buf;

            /* Add received local notify to poll set */
            ret = na_sm_poll_register(na_class, NA_SM_NOTIFY, poll_addr);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not add notify to poll set");
                goto done;
            }

            /* Add addr to poll addr queue */
            hg_thread_spin_lock(
                &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
            HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue,
                poll_addr, poll_entry);
            hg_thread_spin_unlock(
                &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);

            /* Completion */
            ret = na_sm_complete(na_sm_op_id);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not complete operation");
                goto done;
            }

            /* Progressed */
            *progressed = NA_TRUE;
        }
        break;
        default:
            /* TODO Silently ignore, no progress */
            *progressed = NA_FALSE;
            break;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress_notify(na_class_t *na_class, struct na_sm_addr *poll_addr,
    na_bool_t *progressed)
{
    na_sm_cacheline_hdr_t na_sm_hdr;
    na_bool_t notified = NA_FALSE, notify_count = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    if (poll_addr == NA_SM_PRIVATE_DATA(na_class)->self_addr) {
        if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->notify_count)) {
            hg_atomic_decr32(&NA_SM_PRIVATE_DATA(na_class)->notify_count);
            notify_count = NA_TRUE;
        }

        /* Local notification */
        if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->polling)
            && (hg_event_get(poll_addr->local_notify, (hg_util_bool_t *) &notified)
            != HG_UTIL_SUCCESS)) {
            NA_LOG_ERROR("Could not get completion notification");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        if (!notified && !notify_count) {
            *progressed = NA_FALSE;
            goto done;
        }
        *progressed = NA_TRUE;
        goto done;
    }

    /* Remote notification */
    if (hg_atomic_get32(&poll_addr->na_sm_recv_ring_buf->notify_count.val)) {
        hg_atomic_decr32(&poll_addr->na_sm_recv_ring_buf->notify_count.val);
        notify_count = NA_TRUE;
    }

    if (hg_atomic_get32(&poll_addr->na_sm_recv_ring_buf->polling.val)) {
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
        if (hg_event_get(poll_addr->local_notify, (hg_util_bool_t *) &notified)
            != HG_UTIL_SUCCESS) {
            NA_LOG_ERROR("Could not get completion notification");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#else
        if (na_sm_event_get(poll_addr->local_notify, &notified) != NA_SUCCESS) {
            NA_LOG_ERROR("Could not get completion notification");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#endif
    }

    if (!notified && !notify_count) {
        *progressed = NA_FALSE;
        goto done;
    }

    if (!na_sm_ring_buf_pop(poll_addr->na_sm_recv_ring_buf, &na_sm_hdr)) {
        *progressed = NA_FALSE;
        goto done;
    }

    switch (na_sm_hdr.hdr.type) {
        case NA_CB_RECV_UNEXPECTED:
            ret = na_sm_progress_unexpected(na_class, poll_addr, na_sm_hdr);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make progress on unexpected msg");
            }
            break;
        case NA_CB_RECV_EXPECTED:
            ret = na_sm_progress_expected(na_class, poll_addr, na_sm_hdr);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not make progress on expected msg");
            }
            break;
        default:
            NA_LOG_ERROR("Unknown type of operation");
            ret = NA_PROTOCOL_ERROR;
            break;
    }
    *progressed = NA_TRUE;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress_unexpected(na_class_t *na_class, struct na_sm_addr *poll_addr,
    na_sm_cacheline_hdr_t na_sm_hdr)
{
    struct na_sm_unexpected_info *na_sm_unexpected_info = NULL;
    struct na_sm_op_id *na_sm_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Pop op ID from queue */
    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
    na_sm_op_id = HG_QUEUE_FIRST(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue);
    HG_QUEUE_POP_HEAD(&NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue,
        entry);
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);

    if (na_sm_op_id) {
        /* If an op id was pushed, associate unexpected info to this
         * operation ID and complete operation */
        na_sm_op_id->info.recv_unexpected.unexpected_info.na_sm_addr = poll_addr;
        na_sm_op_id->info.recv_unexpected.unexpected_info.na_sm_hdr = na_sm_hdr;

        ret = na_sm_complete(na_sm_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    } else {
        /* If no error and message arrived, keep a copy of the struct in
         * the unexpected message queue (should rarely happen) */
        na_sm_unexpected_info = (struct na_sm_unexpected_info *) malloc(
            sizeof(struct na_sm_unexpected_info));
        if (!na_sm_unexpected_info) {
            NA_LOG_ERROR("Could not allocate unexpected info");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
        na_sm_unexpected_info->na_sm_addr = poll_addr;
        na_sm_unexpected_info->na_sm_hdr = na_sm_hdr;

        /* Otherwise push the unexpected message into our unexpected queue so
         * that we can treat it later when a recv_unexpected is posted */
        hg_thread_spin_lock(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
        HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue,
            na_sm_unexpected_info, entry);
        hg_thread_spin_unlock(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress_expected(na_class_t *na_class, struct na_sm_addr *poll_addr,
    na_sm_cacheline_hdr_t na_sm_hdr)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);
    HG_QUEUE_FOREACH(na_sm_op_id,
        &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue, entry) {
        if (na_sm_op_id->info.recv_expected.na_sm_addr == poll_addr &&
            na_sm_op_id->info.recv_expected.tag == na_sm_hdr.hdr.tag) {
            HG_QUEUE_REMOVE(&NA_SM_PRIVATE_DATA(na_class)->expected_op_queue,
                na_sm_op_id, na_sm_op_id, entry);
            break;
        }
    }
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);

    if (!na_sm_op_id) {
        /* No match if either the message was not pre-posted or it was canceled */
        NA_LOG_WARNING("Ignored expected message received (canceled?)");
        goto done;
    }

    /* Copy and free buffer atomically */
    na_sm_copy_and_free_buf(na_class, poll_addr->na_sm_copy_buf,
        na_sm_op_id->info.recv_expected.buf, na_sm_hdr.hdr.buf_size,
        na_sm_hdr.hdr.buf_idx);

    ret = na_sm_complete(na_sm_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_complete(struct na_sm_op_id *na_sm_op_id)
{
    struct na_cb_info *callback_info = NULL;
    na_bool_t canceled = (na_bool_t) hg_atomic_get32(&na_sm_op_id->canceled);
    na_return_t ret = NA_SUCCESS;

    /* Init callback info */
    callback_info = &na_sm_op_id->completion_data.callback_info;
    callback_info->ret = (canceled) ? NA_CANCELED : ret;

    switch (callback_info->type) {
        case NA_CB_LOOKUP:
            callback_info->info.lookup.addr =
                (na_addr_t) na_sm_op_id->info.lookup.na_sm_addr;
            break;
        case NA_CB_SEND_UNEXPECTED:
            break;
        case NA_CB_RECV_UNEXPECTED: {
            struct na_sm_unexpected_info *na_sm_unexpected_info =
                &na_sm_op_id->info.recv_unexpected.unexpected_info;
            struct na_sm_copy_buf *na_sm_copy_buf;

            if (canceled) {
                /* In case of cancellation where no recv'd data */
                callback_info->info.recv_unexpected.actual_buf_size = 0;
                callback_info->info.recv_unexpected.source = NA_ADDR_NULL;
                callback_info->info.recv_unexpected.tag = 0;
                break;
            }

            /* Increment addr ref count */
            hg_atomic_incr32(&na_sm_unexpected_info->na_sm_addr->ref_count);

            /* Fill callback info */
            callback_info->info.recv_unexpected.actual_buf_size =
                (na_size_t) na_sm_unexpected_info->na_sm_hdr.hdr.buf_size;
            callback_info->info.recv_unexpected.source =
                (na_addr_t) na_sm_unexpected_info->na_sm_addr;
            callback_info->info.recv_unexpected.tag =
                (na_tag_t) na_sm_unexpected_info->na_sm_hdr.hdr.tag;

            /* Copy and free buffer atomically */
            na_sm_copy_buf = na_sm_unexpected_info->na_sm_addr->na_sm_copy_buf;
            na_sm_copy_and_free_buf(na_sm_op_id->na_class, na_sm_copy_buf,
                na_sm_op_id->info.recv_unexpected.buf,
                na_sm_unexpected_info->na_sm_hdr.hdr.buf_size,
                na_sm_unexpected_info->na_sm_hdr.hdr.buf_idx);
            break;
        }
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_RECV_EXPECTED:
            break;
        case NA_CB_PUT:
            break;
        case NA_CB_GET:
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

    /* Mark op id as completed */
    hg_atomic_set32(&na_sm_op_id->completed, NA_TRUE);

    ret = na_cb_completion_add(na_sm_op_id->context,
        &na_sm_op_id->completion_data);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add callback to completion queue");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_sm_release(void *arg)
{
    struct na_sm_op_id *na_sm_op_id = (struct na_sm_op_id *) arg;

    if (na_sm_op_id && !hg_atomic_get32(&na_sm_op_id->completed)) {
        NA_LOG_WARNING("Releasing resources from an uncompleted operation");
    }
    na_sm_op_destroy(NULL, na_sm_op_id);
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_sm_check_protocol(const char *protocol_name)
{
    na_bool_t accept = NA_FALSE;

    if (!strcmp("sm", protocol_name))
        accept = NA_TRUE;

    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_initialize(na_class_t *na_class, const struct na_info NA_UNUSED *na_info,
    na_bool_t listen)
{
    static hg_atomic_int32_t id = HG_ATOMIC_VAR_INIT(0);
    struct na_sm_addr *na_sm_addr = NULL;
    pid_t pid;
    hg_poll_set_t *poll_set;
    int local_notify;
    na_return_t ret = NA_SUCCESS;

    /* TODO parse host name */

    /* Get PID */
    pid = getpid();

    /* Initialize errno */
    errno = 0;

    /* Initialize private data */
    na_class->private_data = malloc(sizeof(struct na_sm_private_data));
    if (!na_class->private_data) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    memset(na_class->private_data, 0, sizeof(struct na_sm_private_data));
    hg_atomic_init32(&NA_SM_PRIVATE_DATA(na_class)->polling, NA_FALSE);
    hg_atomic_init32(&NA_SM_PRIVATE_DATA(na_class)->notify_count, 0);

    /* Create poll set to wait for events */
    poll_set = hg_poll_create();
    if (!poll_set) {
        NA_LOG_ERROR("cannot create poll set");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    NA_SM_PRIVATE_DATA(na_class)->poll_set = poll_set;

    /* Create self addr */
    na_sm_addr = (struct na_sm_addr *) malloc(sizeof(struct na_sm_addr));
    if (!na_sm_addr) {
        NA_LOG_ERROR("Could not allocate NA SM addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    memset(na_sm_addr, 0, sizeof(struct na_sm_addr));
    na_sm_addr->pid = pid;
    na_sm_addr->id = (unsigned int) hg_atomic_incr32(&id) - 1;
    na_sm_addr->self = NA_TRUE;
    hg_atomic_init32(&na_sm_addr->ref_count, 1);
    /* If we're listening, create a new shm region */
    if (listen) {
        ret = na_sm_setup_shm(na_class, na_sm_addr);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not setup shm");
            goto done;
        }
    }
    /* Create local signal event on self address */
    local_notify = hg_event_create();
    if (local_notify == HG_UTIL_FAIL) {
        NA_LOG_ERROR("hg_event_create() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    na_sm_addr->local_notify = local_notify;

    /* Add local notify to poll set */
    ret = na_sm_poll_register(na_class, NA_SM_NOTIFY, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add notify to poll set");
        goto done;
    }
    NA_SM_PRIVATE_DATA(na_class)->self_addr = na_sm_addr;

    /* Initialize queues */
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue);
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue);
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue);
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue);
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue);
    HG_QUEUE_INIT(&NA_SM_PRIVATE_DATA(na_class)->expected_op_queue);

    /* Initialize mutexes */
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue_lock);
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
    hg_thread_spin_init(
            &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);
    hg_thread_spin_init(
             &NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_finalize(na_class_t *na_class)
{
    na_return_t ret = NA_SUCCESS;

    if (!na_class->private_data) {
        goto done;
    }

    /* Check that lookup op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue)) {
        NA_LOG_ERROR("Lookup op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Check that unexpected op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Check that unexpected message queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue)) {
        NA_LOG_ERROR("Unexpected msg queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Check that expected op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&NA_SM_PRIVATE_DATA(na_class)->expected_op_queue)) {
        NA_LOG_ERROR("Expected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Check that accepted addr queue is empty */
    while (!HG_QUEUE_IS_EMPTY(&NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue)) {
        struct na_sm_addr *na_sm_addr = HG_QUEUE_FIRST(
            &NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue);
        HG_QUEUE_POP_HEAD(&NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue, entry);
        ret = na_sm_addr_free(na_class, na_sm_addr);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not free accepted addr");
            goto done;
        }
    }

    /* Free self addr */
    ret = na_sm_addr_free(na_class, NA_SM_PRIVATE_DATA(na_class)->self_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not free self addr");
        goto done;
    }

    /* Close poll set */
    if (hg_poll_destroy(NA_SM_PRIVATE_DATA(na_class)->poll_set) != HG_UTIL_SUCCESS) {
        NA_LOG_ERROR("hg_poll_destroy() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Destroy mutexes */
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->accepted_addr_queue_lock);
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
    hg_thread_spin_destroy(
            &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);
    hg_thread_spin_destroy(
             &NA_SM_PRIVATE_DATA(na_class)->copy_buf_lock);

    free(na_class->private_data);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_sm_cleanup(void)
{
    int ret;

    /* We need to remove all files first before being able to remove the
     * directories */
    ret = nftw(NA_SM_SOCK_PATH, na_sm_cleanup_file, NA_SM_CLEANUP_NFDS,
        FTW_PHYS | FTW_DEPTH);
    if (ret != 0 && errno != ENOENT) {
        NA_LOG_WARNING("nftw() failed (%s)", strerror(errno));
    }

    ret = nftw(NA_SM_SHM_PATH, na_sm_cleanup_shm, NA_SM_CLEANUP_NFDS,
        FTW_PHYS);
    if (ret != 0 && errno != ENOENT) {
        NA_LOG_WARNING("nftw() failed (%s)", strerror(errno));
    }
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_sm_check_feature(na_class_t NA_UNUSED *na_class, na_uint8_t feature)
{
    na_bool_t ret = NA_FALSE;

    switch (feature) {
        case NA_HAS_TAG_MASK:
            ret = NA_FALSE;
            break;
        default:
            break;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t
na_sm_op_create(na_class_t *na_class)
{
    struct na_sm_op_id *na_sm_op_id = NULL;

    na_sm_op_id = (struct na_sm_op_id *) malloc(sizeof(struct na_sm_op_id));
    if (!na_sm_op_id) {
        NA_LOG_ERROR("Could not allocate NA SM operation ID");
        goto done;
    }
    memset(na_sm_op_id, 0, sizeof(struct na_sm_op_id));
    na_sm_op_id->na_class = na_class;
    hg_atomic_init32(&na_sm_op_id->ref_count, 1);
    hg_atomic_init32(&na_sm_op_id->completed, NA_TRUE); /* Completed by default */

    /* Set op ID release callbacks */
    na_sm_op_id->completion_data.plugin_callback = na_sm_release;
    na_sm_op_id->completion_data.plugin_callback_args = na_sm_op_id;

done:
    return (na_op_id_t) na_sm_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t op_id)
{
    struct na_sm_op_id *na_sm_op_id = (struct na_sm_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    if (hg_atomic_decr32(&na_sm_op_id->ref_count)) {
        /* Cannot free yet */
        goto done;
    }
    free(na_sm_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_addr_lookup(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const char *name, na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    struct na_sm_addr *na_sm_addr = NULL;
    struct na_sm_copy_buf *na_sm_copy_buf = NULL;
    char filename[NA_SM_MAX_FILENAME];
    char pathname[NA_SM_MAX_FILENAME];
    int conn_sock;
    char *name_string = NULL, *short_name = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_LOOKUP;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);

    /* Allocate addr */
    na_sm_addr = (struct na_sm_addr *) malloc(sizeof(struct na_sm_addr));
    if (!na_sm_addr) {
        NA_LOG_ERROR("Could not allocate NA SM addr");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    memset(na_sm_addr, 0, sizeof(struct na_sm_addr));
    hg_atomic_init32(&na_sm_addr->ref_count, 1);
    na_sm_op_id->info.lookup.na_sm_addr = na_sm_addr;

    /**
     * Clean up name, strings can be of the format:
     *   <protocol>://<host string>
     */
    name_string = strdup(name);
    if (!name_string) {
        NA_LOG_ERROR("Could not duplicate string");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    if (strstr(name_string, ":") != NULL) {
         strtok_r(name_string, ":", &short_name);
         short_name += 2;
    } else
         short_name = name_string;

    /* Get PID / ID from name */
    sscanf(short_name, "%d/%u", &na_sm_addr->pid, &na_sm_addr->id);

    /* Open shared copy buf */
    NA_SM_GEN_SHM_NAME(filename, na_sm_addr);
    na_sm_copy_buf = (struct na_sm_copy_buf *) na_sm_open_shared_buf(
        filename, sizeof(struct na_sm_copy_buf), NA_FALSE);
    if (!na_sm_copy_buf) {
        NA_LOG_ERROR("Could not open copy buf");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    na_sm_addr->na_sm_copy_buf = na_sm_copy_buf;

    /* Open SHM sock */
    NA_SM_GEN_SOCK_PATH(pathname, na_sm_addr);
    ret = na_sm_create_sock(pathname, NA_FALSE, &conn_sock);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not create sock");
        goto done;
    }
    na_sm_addr->sock = conn_sock;
    /* We only need to receive conn ID in sock progress */
    na_sm_addr->sock_progress = NA_SM_CONN_ID;

    /* Push op ID to lookup op queue */
    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);
    HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue,
        na_sm_op_id, entry);
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->lookup_op_queue_lock);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Add conn_sock to poll set */
    ret = na_sm_poll_register(na_class, NA_SM_SOCK, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add conn_sock to poll set");
        goto done;
    }

    /* Send addr info (PID / ID) */
    ret = na_sm_send_addr_info(na_class, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not send addr info");
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        free(na_sm_addr);
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    free(name_string);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_addr_free(na_class_t *na_class, na_addr_t addr)
{
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) addr;
    const char *copy_buf_name = NULL, *send_ring_buf_name = NULL,
        *recv_ring_buf_name = NULL, *pathname = NULL;
    char na_sm_copy_buf_name[NA_SM_MAX_FILENAME],
        na_sm_send_ring_buf_name[NA_SM_MAX_FILENAME],
        na_sm_recv_ring_buf_name[NA_SM_MAX_FILENAME],
        na_sock_name[NA_SM_MAX_FILENAME];
    na_return_t ret = NA_SUCCESS;

    if (!na_sm_addr) {
        NA_LOG_ERROR("NULL SM addr");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    if (hg_atomic_decr32(&na_sm_addr->ref_count)) {
        /* Cannot free yet */
        goto done;
    }

    /* Deregister event file descriptors from poll set */
    ret = na_sm_poll_deregister(na_class, NA_SM_NOTIFY, na_sm_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not delete notify from poll set");
        goto done;
    }

    /* Destroy local event */
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
    if (hg_event_destroy(na_sm_addr->local_notify) == HG_UTIL_FAIL) {
        NA_LOG_ERROR("hg_event_destroy() failed");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#endif

    if (!na_sm_addr->self) { /* Created by lookup/connect or accept */
#ifndef HG_UTIL_HAS_SYSEVENTFD_H
        char na_sm_local_event_name[NA_SM_MAX_FILENAME],
            na_sm_remote_event_name[NA_SM_MAX_FILENAME];
        const char *local_event_name = NULL, *remote_event_name = NULL;
#endif

        /* Deregister sock file descriptor */
        ret = na_sm_poll_deregister(na_class, NA_SM_SOCK, na_sm_addr);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not delete sock from poll set");
            goto done;
        }

        /* Remove addr from poll addr queue */
        hg_thread_spin_lock(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
        HG_QUEUE_REMOVE(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue,
            na_sm_addr, na_sm_addr, poll_entry);
        hg_thread_spin_unlock(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);

        if (na_sm_addr->accepted) { /* Create by accept */
            /* Get file names from ring bufs / events to delete files */
            sprintf(na_sm_send_ring_buf_name, "%s-%d-%d-%d-%s",
                NA_SM_SHM_PREFIX, NA_SM_PRIVATE_DATA(na_class)->self_addr->pid,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->id,
                na_sm_addr->conn_id, NA_SM_SEND_NAME);
            sprintf(na_sm_recv_ring_buf_name, "%s-%d-%d-%d-%s",
                NA_SM_SHM_PREFIX, NA_SM_PRIVATE_DATA(na_class)->self_addr->pid,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->id,
                na_sm_addr->conn_id, NA_SM_RECV_NAME);
            send_ring_buf_name = na_sm_send_ring_buf_name;
            recv_ring_buf_name = na_sm_recv_ring_buf_name;

#ifndef HG_UTIL_HAS_SYSEVENTFD_H
            sprintf(na_sm_local_event_name, "%s/%s/%d/%u/fifo-%u-%s",
                NA_SM_TMP_DIRECTORY, NA_SM_SHM_PREFIX,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->pid,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->id,
                na_sm_addr->conn_id, NA_SM_RECV_NAME);
            sprintf(na_sm_remote_event_name, "%s/%s/%d/%u/fifo-%u-%s",
                NA_SM_TMP_DIRECTORY, NA_SM_SHM_PREFIX,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->pid,
                NA_SM_PRIVATE_DATA(na_class)->self_addr->id,
                na_sm_addr->conn_id, NA_SM_SEND_NAME);
            local_event_name = na_sm_local_event_name;
            remote_event_name = na_sm_remote_event_name;
#endif
        }

        /* Destroy events */
#ifdef HG_UTIL_HAS_SYSEVENTFD_H
        if (hg_event_destroy(na_sm_addr->remote_notify) == HG_UTIL_FAIL) {
            NA_LOG_ERROR("hg_event_destroy() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#else
        if (na_sm_event_destroy(local_event_name, na_sm_addr->local_notify)
            != NA_SUCCESS) {
            NA_LOG_ERROR("na_sm_event_destroy() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        if (na_sm_event_destroy(remote_event_name, na_sm_addr->remote_notify)
            != NA_SUCCESS) {
            NA_LOG_ERROR("na_sm_event_destroy() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#endif
    } else {
#ifndef HG_UTIL_HAS_SYSEVENTFD_H
        /* Destroy local event */
        if (hg_event_destroy(na_sm_addr->local_notify) == HG_UTIL_FAIL) {
            NA_LOG_ERROR("hg_event_destroy() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }
#endif
        if (na_sm_addr->na_sm_copy_buf) { /* Self addr and listen */
            ret = na_sm_poll_deregister(na_class, NA_SM_ACCEPT, na_sm_addr);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("Could not delete listen from poll set");
                goto done;
            }

            NA_SM_GEN_SHM_NAME(na_sm_copy_buf_name, na_sm_addr);
            copy_buf_name = na_sm_copy_buf_name;
            NA_SM_GEN_SOCK_PATH(na_sock_name, na_sm_addr);
            pathname = na_sock_name;
        }
    }

    /* Close sock (delete also tmp dir if pathname is set) */
    ret = na_sm_close_sock(na_sm_addr->sock, pathname);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close sock");
        goto done;
    }

    /* Close ring buf (send) */
    ret = na_sm_close_shared_buf(send_ring_buf_name,
        na_sm_addr->na_sm_send_ring_buf, sizeof(struct na_sm_ring_buf));
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close send ring buffer");
        goto done;
    }

    /* Close ring buf (recv) */
    ret = na_sm_close_shared_buf(recv_ring_buf_name,
        na_sm_addr->na_sm_recv_ring_buf, sizeof(struct na_sm_ring_buf));
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close recv ring buffer");
        goto done;
    }

    /* Close copy buf */
    ret = na_sm_close_shared_buf(copy_buf_name, na_sm_addr->na_sm_copy_buf,
        sizeof(struct na_sm_copy_buf));
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close copy buffer");
        goto done;
    }

    free(na_sm_addr);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_addr_self(na_class_t *na_class, na_addr_t *addr)
{
    struct na_sm_addr *na_sm_addr = NA_SM_PRIVATE_DATA(na_class)->self_addr;
    na_return_t ret = NA_SUCCESS;

    /* Increment refcount */
    hg_atomic_incr32(&na_sm_addr->ref_count);

    *addr = (na_addr_t) na_sm_addr;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t addr,
    na_addr_t *new_addr)
{
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) addr;
    na_return_t ret = NA_SUCCESS;

    /* Increment refcount */
    hg_atomic_incr32(&na_sm_addr->ref_count);

    *new_addr = (na_addr_t) na_sm_addr;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_sm_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) addr;

    return na_sm_addr->self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    na_size_t *buf_size, na_addr_t addr)
{
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) addr;
    na_size_t string_len;
    char addr_string[NA_SM_MAX_FILENAME];
    na_return_t ret = NA_SUCCESS;

    sprintf(addr_string, "sm://%d/%u", na_sm_addr->pid, na_sm_addr->id);
    string_len = strlen(addr_string);
    if (buf) {
        if (string_len >= *buf_size) {
            NA_LOG_ERROR("Buffer size too small to copy addr");
            ret = NA_SIZE_ERROR;
            goto done;
        } else {
            strcpy(buf, addr_string);
        }
    }

    *buf_size = string_len + 1;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_sm_msg_get_max_unexpected_size(const na_class_t NA_UNUSED *na_class)
{
    return NA_SM_UNEXPECTED_SIZE;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_sm_msg_get_max_expected_size(const na_class_t NA_UNUSED *na_class)
{
    return NA_SM_EXPECTED_SIZE;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_sm_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_SM_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) dest;
    unsigned int idx_reserved;
    na_return_t ret = NA_SUCCESS;

    if (buf_size > NA_SM_UNEXPECTED_SIZE) {
        NA_LOG_ERROR("Exceeds unexpected size");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_SEND_UNEXPECTED;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Try to reserve buffer atomically */
    do {
        ret = na_sm_reserve_and_copy_buf(na_class, na_sm_addr->na_sm_copy_buf,
            buf, buf_size, &idx_reserved);
        if (ret != NA_SUCCESS) {
            na_return_t progress_ret = na_sm_progress(na_class, context, 0);

            if (progress_ret != NA_SUCCESS && progress_ret != NA_TIMEOUT) {
                NA_LOG_ERROR("Could not make progress");
                ret = progress_ret;
                goto done;
            }
            continue;
        }
        break;
    } while (1);

    /* Insert message into ring buffer (complete OP ID) */
    ret = na_sm_msg_insert(na_class, na_sm_op_id, NA_CB_RECV_UNEXPECTED,
        na_sm_addr, idx_reserved, buf_size, tag);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not insert message");
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_tag_t NA_UNUSED mask, na_op_id_t *op_id)
{
    struct na_sm_unexpected_info *na_sm_unexpected_info;
    struct na_sm_op_id *na_sm_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    if (buf_size > NA_SM_UNEXPECTED_SIZE) {
        NA_LOG_ERROR("Exceeds unexpected size, %d", buf_size);
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_RECV_UNEXPECTED;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);
    na_sm_op_id->info.recv_unexpected.buf = buf;
    na_sm_op_id->info.recv_unexpected.buf_size = buf_size;
    na_sm_op_id->info.recv_unexpected.unexpected_info.na_sm_addr = NULL;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Look for an unexpected message already received */
    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
    na_sm_unexpected_info = HG_QUEUE_FIRST(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue);
    HG_QUEUE_POP_HEAD(&NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue,
        entry);
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->unexpected_msg_queue_lock);
    if (na_sm_unexpected_info) {
        na_sm_op_id->info.recv_unexpected.unexpected_info =
            *na_sm_unexpected_info;
        free(na_sm_unexpected_info);

        ret = na_sm_complete(na_sm_op_id);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not complete operation");
            goto done;
        }
    } else {
        /* Nothing has been received yet so add op_id to progress queue */
        hg_thread_spin_lock(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
        HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue,
            na_sm_op_id, entry);
        hg_thread_spin_unlock(
            &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
    }

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_msg_send_expected(na_class_t NA_UNUSED *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) dest;
    unsigned int idx_reserved;
    na_return_t ret = NA_SUCCESS;

    if (buf_size > NA_SM_EXPECTED_SIZE) {
        NA_LOG_ERROR("Exceeds expected size");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_SEND_EXPECTED;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Try to reserve buffer atomically */
    do {
        ret = na_sm_reserve_and_copy_buf(na_class, na_sm_addr->na_sm_copy_buf,
            buf, buf_size, &idx_reserved);
        if (ret != NA_SUCCESS) {
            na_return_t progress_ret = na_sm_progress(na_class, context, 0);

            if (progress_ret != NA_SUCCESS && progress_ret != NA_TIMEOUT) {
                NA_LOG_ERROR("Could not make progress");
                ret = progress_ret;
                goto done;
            }
            continue;
        }
        break;
    } while (1);

    /* Insert message into ring buffer (complete OP ID) */
    ret = na_sm_msg_insert(na_class, na_sm_op_id, NA_CB_RECV_EXPECTED,
        na_sm_addr, idx_reserved, buf_size, tag);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not insert message");
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t source, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    na_return_t ret = NA_SUCCESS;

    if (buf_size > NA_SM_EXPECTED_SIZE) {
        NA_LOG_ERROR("Exceeds expected size");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_RECV_EXPECTED;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);
    na_sm_op_id->info.recv_expected.buf = buf;
    na_sm_op_id->info.recv_expected.buf_size = buf_size;
    na_sm_op_id->info.recv_expected.na_sm_addr = (struct na_sm_addr *) source;
    na_sm_op_id->info.recv_expected.tag = tag;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Expected messages must always be pre-posted, therefore a message should
     * never arrive before that call returns (not completes), simply add
     * op_id to queue */
    hg_thread_spin_lock(
        &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);
    HG_QUEUE_PUSH_TAIL(&NA_SM_PRIVATE_DATA(na_class)->expected_op_queue,
        na_sm_op_id, entry);
    hg_thread_spin_unlock(
        &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    struct na_sm_mem_handle *na_sm_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    na_sm_mem_handle = (struct na_sm_mem_handle *) malloc(
        sizeof(struct na_sm_mem_handle));
    if (!na_sm_mem_handle) {
        NA_LOG_ERROR("Could not allocate NA SM memory handle");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_sm_mem_handle->iov = (struct iovec *) malloc(sizeof(struct iovec));
    if (!na_sm_mem_handle->iov) {
        NA_LOG_ERROR("Could not allocate iovec");
        ret = NA_NOMEM_ERROR;
        free(na_sm_mem_handle);
        goto done;
    }
    na_sm_mem_handle->iov->iov_base = buf;
    na_sm_mem_handle->iov->iov_len = buf_size;
    na_sm_mem_handle->iovcnt = 1;
    na_sm_mem_handle->flags = flags;
    na_sm_mem_handle->len = buf_size;

    *mem_handle = (na_mem_handle_t) na_sm_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_SM_HAS_CMA
static na_return_t
na_sm_mem_handle_create_segments(na_class_t NA_UNUSED *na_class,
    struct na_segment *segments, na_size_t segment_count, unsigned long flags,
    na_mem_handle_t *mem_handle)
{
    struct na_sm_mem_handle *na_sm_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;
    na_size_t i, iov_max;

    /* Check that we do not exceed IOV_MAX */
    iov_max = (na_size_t) sysconf(_SC_IOV_MAX);
    if (segment_count > iov_max) {
        NA_LOG_ERROR("Segment count exceeds IOV_MAX limit");
        ret = NA_INVALID_PARAM;
        goto done;
    }

    na_sm_mem_handle = (struct na_sm_mem_handle *) malloc(
        sizeof(struct na_sm_mem_handle));
    if (!na_sm_mem_handle) {
        NA_LOG_ERROR("Could not allocate NA SM memory handle");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_sm_mem_handle->iov = (struct iovec *) malloc(
        segment_count * sizeof(struct iovec));
    if (!na_sm_mem_handle->iov) {
        NA_LOG_ERROR("Could not allocate iovec");
        ret = NA_NOMEM_ERROR;
        goto done;
    }
    na_sm_mem_handle->len = 0;
    for (i = 0; i < segment_count; i++) {
        na_sm_mem_handle->iov[i].iov_base = (void *) segments[i].address;
        na_sm_mem_handle->iov[i].iov_len = segments[i].size;
        na_sm_mem_handle->len += na_sm_mem_handle->iov[i].iov_len;
    }
    na_sm_mem_handle->iovcnt = segment_count;
    na_sm_mem_handle->flags = flags;

    *mem_handle = (na_mem_handle_t) na_sm_mem_handle;

done:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_mem_handle_free(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t mem_handle)
{
    struct na_sm_mem_handle *na_sm_mem_handle =
        (struct na_sm_mem_handle *) mem_handle;
    na_return_t ret = NA_SUCCESS;

    free(na_sm_mem_handle->iov);
    free(na_sm_mem_handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_sm_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t mem_handle)
{
    struct na_sm_mem_handle *na_sm_mem_handle =
        (struct na_sm_mem_handle *) mem_handle;
    unsigned long i;
    na_size_t ret = 2 * sizeof(unsigned long) + sizeof(size_t);

    for (i = 0; i < na_sm_mem_handle->iovcnt; i++) {
        ret += sizeof(void *) + sizeof(size_t);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t NA_UNUSED buf_size, na_mem_handle_t mem_handle)
{
    struct na_sm_mem_handle *na_sm_mem_handle =
        (struct na_sm_mem_handle*) mem_handle;
    char *buf_ptr = (char *) buf;
    na_return_t ret = NA_SUCCESS;
    unsigned long i;

    /* Number of segments */
    memcpy(buf_ptr, &na_sm_mem_handle->iovcnt, sizeof(unsigned long));
    buf_ptr += sizeof(unsigned long);

    /* Flags */
    memcpy(buf_ptr, &na_sm_mem_handle->flags, sizeof(unsigned long));
    buf_ptr += sizeof(unsigned long);

    /* Length */
    memcpy(buf_ptr, &na_sm_mem_handle->len, sizeof(size_t));
    buf_ptr += sizeof(size_t);

    /* Segments */
    for (i = 0; i < na_sm_mem_handle->iovcnt; i++) {
        memcpy(buf_ptr, &na_sm_mem_handle->iov[i].iov_base, sizeof(void *));
        buf_ptr += sizeof(void *);
        memcpy(buf_ptr, &na_sm_mem_handle->iov[i].iov_len, sizeof(size_t));
        buf_ptr += sizeof(size_t);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t *mem_handle, const void *buf, NA_UNUSED na_size_t buf_size)
{
    struct na_sm_mem_handle *na_sm_mem_handle = NULL;
    const char *buf_ptr = (const char *) buf;
    na_return_t ret = NA_SUCCESS;
    unsigned long i;

    na_sm_mem_handle = (struct na_sm_mem_handle *) malloc(
        sizeof(struct na_sm_mem_handle));
    if (!na_sm_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA SM memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }

    /* Number of segments */
    memcpy(&na_sm_mem_handle->iovcnt, buf_ptr, sizeof(unsigned long));
    buf_ptr += sizeof(unsigned long);
    if (!na_sm_mem_handle->iovcnt) {
        NA_LOG_ERROR("NULL segment count");
        ret = NA_SIZE_ERROR;
        free(na_sm_mem_handle);
        goto done;
    }

    /* Flags */
    memcpy(&na_sm_mem_handle->flags, buf_ptr, sizeof(unsigned long));
    buf_ptr += sizeof(unsigned long);

    /* Length */
    memcpy(&na_sm_mem_handle->len, buf_ptr, sizeof(size_t));
    buf_ptr += sizeof(size_t);

    /* Segments */
    na_sm_mem_handle->iov = (struct iovec *) malloc(na_sm_mem_handle->iovcnt *
        sizeof(struct iovec));
    if (!na_sm_mem_handle->iov) {
        NA_LOG_ERROR("Could not allocate iovec");
        ret = NA_NOMEM_ERROR;
        free(na_sm_mem_handle);
        goto done;
    }
    for (i = 0; i < na_sm_mem_handle->iovcnt; i++) {
        memcpy(&na_sm_mem_handle->iov[i].iov_base, buf_ptr, sizeof(void *));
        buf_ptr += sizeof(void *);
        memcpy(&na_sm_mem_handle->iov[i].iov_len, buf_ptr, sizeof(size_t));
        buf_ptr += sizeof(size_t);
    }

    *mem_handle = (na_mem_handle_t) na_sm_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    struct na_sm_mem_handle *na_sm_mem_handle_local =
        (struct na_sm_mem_handle *) local_mem_handle;
    struct na_sm_mem_handle *na_sm_mem_handle_remote =
        (struct na_sm_mem_handle *) remote_mem_handle;
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) remote_addr;
    struct iovec *local_iov, *remote_iov;
    unsigned long liovcnt, riovcnt;
    na_return_t ret = NA_SUCCESS;
#if defined(NA_SM_HAS_CMA)
    ssize_t nwrite;
#elif defined(__APPLE__)
    kern_return_t kret;
    mach_port_name_t remote_task;
#endif

#if !defined(NA_SM_HAS_CMA) && !defined(__APPLE__)
    (void) na_sm_addr;
    NA_LOG_ERROR("Not implemented for this platform");
    ret = NA_PROTOCOL_ERROR;
    goto done;
#endif

    switch (na_sm_mem_handle_remote->flags) {
        case NA_MEM_READ_ONLY:
            NA_LOG_ERROR("Registered memory requires write permission");
            ret = NA_PERMISSION_ERROR;
            goto done;
        case NA_MEM_WRITE_ONLY:
        case NA_MEM_READWRITE:
            break;
        default:
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_PUT;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Translate local offset, skip this step if not necessary */
    if (local_offset || length != na_sm_mem_handle_local->len) {
        /* TODO fix allocation */
        local_iov = (struct iovec *) alloca(
            na_sm_mem_handle_local->iovcnt * sizeof(struct iovec));
        na_sm_offset_translate(na_sm_mem_handle_local, local_offset, length,
            local_iov, &liovcnt);
    } else {
        local_iov = na_sm_mem_handle_local->iov;
        liovcnt = na_sm_mem_handle_local->iovcnt;
    }

    /* Translate remote offset, skip this step if not necessary */
    if (remote_offset || length != na_sm_mem_handle_remote->len) {
        /* TODO fix allocation */
        remote_iov = (struct iovec *) alloca(
            na_sm_mem_handle_remote->iovcnt * sizeof(struct iovec));
        na_sm_offset_translate(na_sm_mem_handle_remote, remote_offset, length,
            remote_iov, &riovcnt);
    } else {
        remote_iov = na_sm_mem_handle_remote->iov;
        riovcnt = na_sm_mem_handle_remote->iovcnt;
    }

#if defined(NA_SM_HAS_CMA)
    nwrite = process_vm_writev(na_sm_addr->pid, local_iov, liovcnt, remote_iov,
        riovcnt, /* unused */0);
    if (nwrite < 0) {
        NA_LOG_ERROR("process_vm_writev() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
    if ((na_size_t)nwrite != length) {
        NA_LOG_ERROR("Wrote %ld bytes, was expecting %lu bytes", nwrite, length);
        ret = NA_SIZE_ERROR;
        goto done;
    }
#elif defined(__APPLE__)
    kret = task_for_pid(mach_task_self(), na_sm_addr->pid, &remote_task);
    if (kret != KERN_SUCCESS) {
        NA_LOG_ERROR("task_for_pid() failed (%s)\n"
                     "Permission must be set to access remote memory, please refer to the documentation for instructions.", mach_error_string(kret));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (liovcnt > 1 || riovcnt > 1) {
        NA_LOG_ERROR("Non-contiguous transfers are not supported");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    kret = mach_vm_write(remote_task, remote_iov->iov_base, local_iov->iov_base, length);
    if (kret != KERN_SUCCESS) {
        NA_LOG_ERROR("mach_vm_write() failed (%s)", mach_error_string(kret));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#endif

    /* Immediate completion */
    ret = na_sm_complete(na_sm_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

    /* Notify local completion */
    hg_atomic_incr32(&NA_SM_PRIVATE_DATA(na_class)->notify_count);
    if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->polling)
        && (hg_event_set(NA_SM_PRIVATE_DATA(na_class)->self_addr->local_notify)
        != HG_UTIL_SUCCESS)) {
        NA_LOG_ERROR("Could not signal local completion");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct na_sm_op_id *na_sm_op_id = NULL;
    struct na_sm_mem_handle *na_sm_mem_handle_local =
        (struct na_sm_mem_handle *) local_mem_handle;
    struct na_sm_mem_handle *na_sm_mem_handle_remote =
        (struct na_sm_mem_handle *) remote_mem_handle;
    struct na_sm_addr *na_sm_addr = (struct na_sm_addr *) remote_addr;
    struct iovec *local_iov, *remote_iov;
    unsigned long liovcnt, riovcnt;
    na_return_t ret = NA_SUCCESS;
#if defined(NA_SM_HAS_CMA)
    ssize_t nread;
#elif defined(__APPLE__)
    mach_vm_size_t nread;
    kern_return_t kret;
    mach_port_name_t remote_task;
#endif

#if !defined(NA_SM_HAS_CMA) && !defined(__APPLE__)
    (void) na_sm_addr;
    NA_LOG_ERROR("Not implemented for this platform");
    ret = NA_PROTOCOL_ERROR;
    goto done;
#endif

    switch (na_sm_mem_handle_remote->flags) {
        case NA_MEM_WRITE_ONLY:
            NA_LOG_ERROR("Registered memory requires read permission");
            ret = NA_PERMISSION_ERROR;
            goto done;
        case NA_MEM_READ_ONLY:
        case NA_MEM_READWRITE:
            break;
        default:
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto done;
    }

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_sm_op_id = (struct na_sm_op_id *) *op_id;
        hg_atomic_incr32(&na_sm_op_id->ref_count);
    } else {
        na_sm_op_id = (struct na_sm_op_id *) na_sm_op_create(na_class);
        if (!na_sm_op_id) {
            NA_LOG_ERROR("Could not allocate NA SM operation ID");
            ret = NA_NOMEM_ERROR;
            goto done;
        }
    }
    na_sm_op_id->context = context;
    na_sm_op_id->completion_data.callback_info.type = NA_CB_GET;
    na_sm_op_id->completion_data.callback = callback;
    na_sm_op_id->completion_data.callback_info.arg = arg;
    hg_atomic_set32(&na_sm_op_id->completed, NA_FALSE);
    hg_atomic_set32(&na_sm_op_id->canceled, NA_FALSE);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = na_sm_op_id;

    /* Translate local offset, skip this step if not necessary */
    if (local_offset || length != na_sm_mem_handle_local->len) {
        /* TODO fix allocation */
        local_iov = (struct iovec *) alloca(
            na_sm_mem_handle_local->iovcnt * sizeof(struct iovec));
        na_sm_offset_translate(na_sm_mem_handle_local, local_offset, length,
            local_iov, &liovcnt);
    } else {
        local_iov = na_sm_mem_handle_local->iov;
        liovcnt = na_sm_mem_handle_local->iovcnt;
    }

    /* Translate remote offset, skip this step if not necessary */
    if (remote_offset || length != na_sm_mem_handle_remote->len) {
        /* TODO fix allocation */
        remote_iov = (struct iovec *) alloca(
            na_sm_mem_handle_remote->iovcnt * sizeof(struct iovec));
        na_sm_offset_translate(na_sm_mem_handle_remote, remote_offset, length,
            remote_iov, &riovcnt);
    } else {
        remote_iov = na_sm_mem_handle_remote->iov;
        riovcnt = na_sm_mem_handle_remote->iovcnt;
    }

#if defined(NA_SM_HAS_CMA)
    nread = process_vm_readv(na_sm_addr->pid, local_iov, liovcnt, remote_iov,
        riovcnt, /* unused */0);
    if (nread < 0) {
        NA_LOG_ERROR("process_vm_readv() failed (%s)", strerror(errno));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#elif defined(__APPLE__)
    kret = task_for_pid(mach_task_self(), na_sm_addr->pid, &remote_task);
    if (kret != KERN_SUCCESS) {
        NA_LOG_ERROR("task_for_pid() failed (%s)\n"
                     "Permission must be set to access remote memory, please refer to the documentation for instructions.", mach_error_string(kret));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (liovcnt > 1 || riovcnt > 1) {
        NA_LOG_ERROR("Non-contiguous transfers are not supported");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    kret = mach_vm_read_overwrite(remote_task, remote_iov->iov_base, length,
        local_iov->iov_base, &nread);
    if (kret != KERN_SUCCESS) {
        NA_LOG_ERROR("mach_vm_read_overwrite() failed (%s)", mach_error_string(kret));
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }
#endif
#if defined(NA_SM_HAS_CMA) || defined(__APPLE__)
    if ((na_size_t)nread != length) {
        NA_LOG_ERROR("Read %ld bytes, was expecting %lu bytes", nread, length);
        ret = NA_SIZE_ERROR;
        goto done;
    }
#endif

    /* Immediate completion */
    ret = na_sm_complete(na_sm_op_id);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto done;
    }

    /* Notify local completion */
    hg_atomic_incr32(&NA_SM_PRIVATE_DATA(na_class)->notify_count);
    if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->polling)
        && (hg_event_set(NA_SM_PRIVATE_DATA(na_class)->self_addr->local_notify)
        != HG_UTIL_SUCCESS)) {
        NA_LOG_ERROR("Could not signal local completion");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

done:
    if (ret != NA_SUCCESS) {
        na_sm_op_destroy(na_class, (na_op_id_t) na_sm_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_sm_poll_get_fd(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    int fd;

    fd = hg_poll_get_fd(NA_SM_PRIVATE_DATA(na_class)->poll_set);
    if (fd == HG_UTIL_FAIL) {
        NA_LOG_ERROR("Could not get poll fd from poll set");
    }

    return fd;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_sm_poll_try_wait(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_sm_addr *na_sm_addr;
    na_bool_t ret = NA_TRUE;

    /* We're going to poll so we must receive notifications (we must enable
     * polling notifications first so that there is no race between the time
     * we enable polling and then check for notifications) */
    hg_atomic_cas32(&NA_SM_PRIVATE_DATA(na_class)->polling, NA_FALSE, NA_TRUE);

    hg_thread_spin_lock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    HG_QUEUE_FOREACH(na_sm_addr, &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue,
        poll_entry)
        hg_atomic_cas32(&na_sm_addr->na_sm_recv_ring_buf->polling.val, NA_FALSE,
            NA_TRUE);
    hg_thread_spin_unlock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);

    /* Do not block if something is already in and skip polling */
    if (hg_atomic_get32(&NA_SM_PRIVATE_DATA(na_class)->notify_count)) {
        ret = NA_FALSE;
        goto done;
    }
    hg_thread_spin_lock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    HG_QUEUE_FOREACH(na_sm_addr, &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue,
        poll_entry) {
        if (hg_atomic_get32(
            &na_sm_addr->na_sm_recv_ring_buf->notify_count.val)) {
            ret = NA_FALSE;
            hg_thread_spin_unlock(
                &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
            goto done;
        }
    }
    hg_thread_spin_unlock(&NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_progress(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout)
{
    double remaining = timeout / 1000.0; /* Convert timeout in ms into seconds */
    na_return_t ret = NA_TIMEOUT;

    do {
        hg_time_t t1, t2;
        hg_util_bool_t progressed;

        if (timeout)
            hg_time_get_current(&t1);

        if (hg_poll_wait(NA_SM_PRIVATE_DATA(na_class)->poll_set,
            (unsigned int) (remaining * 1000.0), &progressed) != HG_UTIL_SUCCESS) {
            NA_LOG_ERROR("hg_poll_wait() failed");
            ret = NA_PROTOCOL_ERROR;
            goto done;
        }

        /* We progressed, return success */
        if (progressed) {
            ret = NA_SUCCESS;
            break;
        }

        if (timeout) {
            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
        }
    } while ((int)(remaining * 1000.0) > 0);

    /* We were polling/blocking */
    /* TODO make incr/decr instead? */
    if (timeout && (hg_atomic_cas32(&NA_SM_PRIVATE_DATA(na_class)->polling,
        NA_TRUE, NA_FALSE))) {
        struct na_sm_addr *na_sm_addr;

        hg_thread_spin_lock(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
        HG_QUEUE_FOREACH(na_sm_addr,
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue, poll_entry) {
            hg_atomic_set32(&na_sm_addr->na_sm_recv_ring_buf->polling.val,
                NA_FALSE);
        }
        hg_thread_spin_unlock(
            &NA_SM_PRIVATE_DATA(na_class)->poll_addr_queue_lock);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_sm_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
    na_op_id_t op_id)
{
    struct na_sm_op_id *na_sm_op_id = (struct na_sm_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    if (hg_atomic_get32(&na_sm_op_id->completed))
        goto done;

    switch (na_sm_op_id->completion_data.callback_info.type) {
        case NA_CB_LOOKUP:
            /* Nothing */
            break;
        case NA_CB_SEND_UNEXPECTED:
            /* Nothing */
            break;
        case NA_CB_RECV_UNEXPECTED: {
            struct na_sm_op_id *na_sm_var_op_id = NULL;

            /* Must remove op_id from unexpected op_id queue */
            hg_thread_spin_lock(
                &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);
            HG_QUEUE_FOREACH(na_sm_var_op_id,
                &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue, entry) {
                if (na_sm_var_op_id == na_sm_op_id) {
                    HG_QUEUE_REMOVE(&NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue,
                        na_sm_var_op_id, na_sm_op_id, entry);
                    break;
                }
            }
            hg_thread_spin_unlock(
                &NA_SM_PRIVATE_DATA(na_class)->unexpected_op_queue_lock);

            /* Cancel op id */
            if (na_sm_var_op_id == na_sm_op_id) {
                hg_atomic_set32(&na_sm_op_id->canceled, NA_TRUE);
                ret = na_sm_complete(na_sm_op_id);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not complete operation");
                    goto done;
                }
            }
        }
            break;
        case NA_CB_SEND_EXPECTED:
            /* Nothing */
            break;
        case NA_CB_RECV_EXPECTED: {
            struct na_sm_op_id *na_sm_var_op_id = NULL;

            /* Must remove op_id from unexpected op_id queue */
            hg_thread_spin_lock(
                &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);
            HG_QUEUE_FOREACH(na_sm_var_op_id,
                &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue, entry) {
                if (na_sm_var_op_id == na_sm_op_id) {
                    HG_QUEUE_REMOVE(&NA_SM_PRIVATE_DATA(na_class)->expected_op_queue,
                        na_sm_var_op_id, na_sm_op_id, entry);
                    break;
                }
            }
            hg_thread_spin_unlock(
                &NA_SM_PRIVATE_DATA(na_class)->expected_op_queue_lock);

            /* Cancel op id */
            if (na_sm_var_op_id == na_sm_op_id) {
                hg_atomic_set32(&na_sm_op_id->canceled, NA_TRUE);
                ret = na_sm_complete(na_sm_op_id);
                if (ret != NA_SUCCESS) {
                    NA_LOG_ERROR("Could not complete operation");
                    goto done;
                }
            }
        }
            break;
        case NA_CB_PUT:
            /* Nothing */
            break;
        case NA_CB_GET:
            /* Nothing */
            break;
        default:
            NA_LOG_ERROR("Operation not supported");
            ret = NA_INVALID_PARAM;
            break;
    }

done:
    return ret;
}
