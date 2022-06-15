/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_plugin.h"

#include "na_ip.h"
#include "na_loc.h"

#include "mercury_hash_string.h"
#include "mercury_hash_table.h"
#include "mercury_inet.h"
#include "mercury_list.h"
#include "mercury_mem.h"
#include "mercury_mem_pool.h"
#include "mercury_thread.h"
#include "mercury_thread_rwlock.h"
#include "mercury_thread_spin.h"
#include "mercury_time.h"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#ifdef NA_OFI_HAS_EXT_GNI_H
#    include <rdma/fi_ext_gni.h>
#endif
#ifdef NA_OFI_HAS_EXT_CXI_H
#    include <rdma/fi_cxi_ext.h>
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h> /* for struct iovec */
#include <unistd.h>

/****************/
/* Local Macros */
/****************/

/**
 * FI VERSION provides binary backward and forward compatibility support.
 * Specify the version of OFI is coded to, the provider will select struct
 * layouts that are compatible with this version.
 */
#define NA_OFI_VERSION FI_VERSION(1, 9)

/* Fallback for undefined OPX values */
#if FI_VERSION_LT(FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION),              \
    FI_VERSION(1, 15))
#    define FI_ADDR_OPX  -1
#    define FI_PROTO_OPX -1
#endif

/* Fallback for undefined CXI values */
#if FI_VERSION_LT(FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION),              \
    FI_VERSION(1, 15))
#    define FI_ADDR_CXI  (FI_ADDR_PSMX3 + 1)
#    define FI_PROTO_CXI (FI_PROTO_PSMX3 + 1)
#else
#    define FI_ADDR_CXI  (FI_ADDR_OPX + 1)
#    define FI_PROTO_CXI (FI_PROTO_OPX + 1)
#endif

/* Default basic bits */
#define NA_OFI_MR_BASIC_REQ (FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY)

/* flags that control na_ofi behavior (in the X macro below for each
 * provider)
 */
#define NA_OFI_DOM_IFACE  (1 << 0) /* domain name is interface name */
#define NA_OFI_WAIT_SET   (1 << 1) /* supports FI_WAIT_SET */
#define NA_OFI_WAIT_FD    (1 << 2) /* supports FI_WAIT_FD */
#define NA_OFI_SIGNAL     (1 << 3) /* supports fi_signal() */
#define NA_OFI_SEP        (1 << 4) /* supports SEPs */
#define NA_OFI_SOURCE_MSG (1 << 5) /* requires source info in the MSG */
#define NA_OFI_LOC_INFO   (1 << 6) /* supports locality info */
#define NA_OFI_CONTEXT2   (1 << 7) /* requires FI_CONTEXT2 */
#define NA_OFI_HMEM       (1 << 8) /* supports FI_HMEM */

/* X-macro to define the following for each supported provider:
 * - enum type
 * - name
 * - alternate (alias) names for convenience
 * - preferred address format if unspecified
 * - native address format
 * - progress mode
 * - endpoint protocol
 * - additional capabilities used (beyond the base set required by NA)
 * - misc flags to control na_ofi behavior and workarounds with this provider
 *
 * The purpose of this is to aggregate settings for all providers into a
 * single location so that it is easier to alter them.
 */
/* clang-format off */
#define NA_OFI_PROV_TYPES                                                      \
    X(NA_OFI_PROV_NULL, "", "", 0, 0, 0, 0, 0, 0)                              \
    X(NA_OFI_PROV_SHM,                                                         \
      "shm",                                                                   \
      "sm",                                                                    \
      FI_ADDR_STR,                                                             \
      FI_ADDR_STR,                                                             \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_SHM,                                                            \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_SOURCE_MSG | NA_OFI_HMEM                                          \
    )                                                                          \
    X(NA_OFI_PROV_SOCKETS,                                                     \
      "sockets",                                                               \
      "",                                                                      \
      FI_SOCKADDR_IN,                                                          \
      FI_SOCKADDR_IN,                                                          \
      FI_PROGRESS_AUTO,                                                        \
      FI_PROTO_SOCK_TCP,                                                       \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_DOM_IFACE | NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG | NA_OFI_SEP       \
    )                                                                          \
    X(NA_OFI_PROV_TCP,                                                         \
      "tcp;ofi_rxm",                                                           \
      "tcp",                                                                   \
      FI_SOCKADDR_IN,                                                          \
      FI_SOCKADDR_IN,                                                          \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_RXM,                                                            \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_DOM_IFACE | NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG                    \
    )                                                                          \
    X(NA_OFI_PROV_PSM,                                                         \
      "psm",                                                                   \
      "",                                                                      \
      FI_ADDR_PSMX,                                                            \
      FI_ADDR_PSMX,                                                            \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_PSMX,                                                           \
      0,                                                                       \
      NA_OFI_WAIT_SET | NA_OFI_SOURCE_MSG                                      \
    )                                                                          \
    X(NA_OFI_PROV_PSM2,                                                        \
      "psm2",                                                                  \
      "",                                                                      \
      FI_ADDR_PSMX2,                                                           \
      FI_ADDR_PSMX2,                                                           \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_PSMX2,                                                          \
      FI_SOURCE | FI_SOURCE_ERR | FI_DIRECTED_RECV,                            \
      NA_OFI_SIGNAL | NA_OFI_SEP | NA_OFI_LOC_INFO                             \
    )                                                                          \
    X(NA_OFI_PROV_OPX,                                                         \
      "opx",                                                                   \
      "",                                                                      \
      FI_ADDR_OPX,                                                             \
      FI_ADDR_OPX,                                                             \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_OPX,                                                            \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_SEP | NA_OFI_SOURCE_MSG | NA_OFI_CONTEXT2                         \
    )                                                                          \
    X(NA_OFI_PROV_VERBS,                                                       \
      "verbs;ofi_rxm",                                                         \
      "verbs",                                                                 \
      FI_SOCKADDR_IN,                                                          \
      FI_SOCKADDR_IB,                                                          \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_RXM,                                                            \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG | NA_OFI_LOC_INFO | NA_OFI_HMEM       \
    )                                                                          \
    X(NA_OFI_PROV_GNI,                                                         \
      "gni",                                                                   \
      "",                                                                      \
      FI_ADDR_GNI,                                                             \
      FI_ADDR_GNI,                                                             \
      FI_PROGRESS_AUTO,                                                        \
      FI_PROTO_GNI,                                                            \
      FI_SOURCE | FI_SOURCE_ERR | FI_DIRECTED_RECV,                            \
      NA_OFI_WAIT_SET | NA_OFI_SIGNAL | NA_OFI_SEP                             \
    )                                                                          \
    X(NA_OFI_PROV_CXI,                                                         \
      "cxi",                                                                   \
      "",                                                                      \
      FI_ADDR_CXI,                                                             \
      FI_ADDR_CXI,                                                             \
      FI_PROGRESS_MANUAL,                                                      \
      FI_PROTO_CXI,                                                            \
      FI_SOURCE | FI_DIRECTED_RECV,                                            \
      NA_OFI_SOURCE_MSG | NA_OFI_LOC_INFO | NA_OFI_HMEM                        \
    )                                                                          \
    X(NA_OFI_PROV_MAX, "", "", 0, 0, 0, 0, 0, 0)
/* clang-format on */

#define X(a, b, c, d, e, f, g, h, i) a,
enum na_ofi_prov_type { NA_OFI_PROV_TYPES };
#undef X
#define X(a, b, c, d, e, f, g, h, i) b,
static const char *const na_ofi_prov_name[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) c,
static const char *const na_ofi_prov_alt_name[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) d,
static int const na_ofi_prov_addr_format_pref[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) e,
static int const na_ofi_prov_addr_format_native[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) f,
static enum fi_progress const na_ofi_prov_progress[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) g,
static int const na_ofi_prov_ep_proto[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) h,
static unsigned long const na_ofi_prov_extra_caps[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g, h, i) i,
static unsigned long const na_ofi_prov_flags[] = {NA_OFI_PROV_TYPES};
#undef X

/* Address / URI max len */
#define NA_OFI_MAX_URI_LEN (128)

/* IB */
#ifndef AF_IB
#    define AF_IB 27
#endif
/* Values taken from librdmacm/rdma_cma.h */
#define NA_OFI_IB_IP_PS_MASK   0xFFFFFFFFFFFF0000ULL
#define NA_OFI_IB_IP_PORT_MASK 0x000000000000FFFFULL

/* GNI */
#define NA_OFI_GNI_AV_STR_ADDR_VERSION (1)
#define NA_OFI_GNI_UDREG_REG_LIMIT     (2048)

/* Address pool (enabled by default, comment out to disable) */
#define NA_OFI_HAS_ADDR_POOL
#define NA_OFI_ADDR_POOL_COUNT (64)

/* Memory pool (enabled by default, comment out to disable) */
#define NA_OFI_HAS_MEM_POOL
#define NA_OFI_MEM_CHUNK_COUNT (256)
#define NA_OFI_MEM_BLOCK_COUNT (2)

/* Max tag */
#define NA_OFI_MAX_TAG UINT32_MAX

/* Unexpected size */
#define NA_OFI_MSG_SIZE       (4096)
#define NA_OFI_UNEXPECTED_TAG ((uint64_t) 0x100000000)
#define NA_OFI_TAG_MASK       ((uint64_t) 0x0FFFFFFFF)

/* Number of CQ event provided for fi_cq_read() */
#define NA_OFI_CQ_EVENT_NUM (16)
/* CQ depth (the socket provider's default value is 256 */
#define NA_OFI_CQ_DEPTH (8192)
/* CQ max err data size (fix to 48 to work around bug in gni provider code) */
#define NA_OFI_CQ_MAX_ERR_DATA_SIZE (48)

/* Uncomment to register SGL regions */
// #define NA_OFI_USE_REGV

/* Maximum number of pre-allocated IOV entries */
#define NA_OFI_IOV_STATIC_MAX (8)

/* The completion flags for PUT/GET operations */
#define NA_OFI_PUT_COMPLETION (FI_COMPLETION | FI_DELIVERY_COMPLETE)
#define NA_OFI_GET_COMPLETION (FI_COMPLETION)

/* Receive context bits for SEP */
#define NA_OFI_SEP_RX_CTX_BITS (8)

/* Op ID status bits */
#define NA_OFI_OP_COMPLETED (1 << 0)
#define NA_OFI_OP_CANCELING (1 << 1)
#define NA_OFI_OP_CANCELED  (1 << 2)
#define NA_OFI_OP_QUEUED    (1 << 3)
#define NA_OFI_OP_ERRORED   (1 << 4)

/* Timeout (ms) until we give up on retry */
#define NA_OFI_OP_RETRY_TIMEOUT (90 * 1000)

/* Private data access */
#define NA_OFI_CLASS(x)   ((struct na_ofi_class *) ((x)->plugin_class))
#define NA_OFI_CONTEXT(x) ((struct na_ofi_context *) ((x)->plugin_context))

/* Get IOV */
#define NA_OFI_IOV(x)                                                          \
    ((x)->desc.info.iovcnt > NA_OFI_IOV_STATIC_MAX) ? (x)->desc.iov.d          \
                                                    : (x)->desc.iov.s

/* Get msg IOV */
#define NA_OFI_MSG_IOV(x)                                                      \
    ((x)->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX)                       \
        ? (x)->info.rma.local_iov.d                                            \
        : (x)->info.rma.local_iov.s

/* Get rma IOV */
#define NA_OFI_RMA_IOV(x)                                                      \
    ((x)->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX)                      \
        ? (x)->info.rma.remote_iov.d                                           \
        : (x)->info.rma.remote_iov.s

/* Set RMA msg */
#define NA_OFI_MSG_RMA_SET(fi_msg_rma, local_iov, remote_iov, na_ofi_op_id)    \
    do {                                                                       \
        fi_msg_rma = (struct fi_msg_rma){.msg_iov = local_iov,                 \
            .desc = &na_ofi_op_id->info.rma.local_desc,                        \
            .iov_count = na_ofi_op_id->info.rma.local_iovcnt,                  \
            .addr = na_ofi_op_id->info.rma.fi_addr,                            \
            .rma_iov = remote_iov,                                             \
            .rma_iov_count = na_ofi_op_id->info.rma.remote_iovcnt,             \
            .context = &na_ofi_op_id->fi_ctx,                                  \
            .data = 0};                                                        \
    } while (0)

/* Reset op ID */
#define NA_OFI_OP_RESET(                                                       \
    _op, _context, _fi_op_flags, _cb_type, _cb, _arg, _addr)                   \
    do {                                                                       \
        _op->context = _context;                                               \
        _op->completion_data = (struct na_cb_completion_data){                 \
            .callback_info =                                                   \
                (struct na_cb_info){.info.recv_unexpected =                    \
                                        (struct na_cb_info_recv_unexpected){   \
                                            .actual_buf_size = 0,              \
                                            .source = NA_ADDR_NULL,            \
                                            .tag = 0},                         \
                    .arg = _arg,                                               \
                    .type = _cb_type,                                          \
                    .ret = NA_SUCCESS},                                        \
            .callback = _cb,                                                   \
            .plugin_callback = na_ofi_release,                                 \
            .plugin_callback_args = _op};                                      \
        _op->addr = _addr;                                                     \
        if (_addr)                                                             \
            na_ofi_addr_ref_incr(_addr);                                       \
        _op->fi_op_flags = _fi_op_flags;                                       \
        hg_atomic_set32(&_op->status, 0);                                      \
    } while (0)

#define NA_OFI_OP_RELEASE(_op)                                                 \
    do {                                                                       \
        if (_op->addr)                                                         \
            na_ofi_addr_ref_decr(_op->addr);                                   \
        hg_atomic_set32(&_op->status, NA_OFI_OP_COMPLETED);                    \
    } while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* IB address */
struct na_ofi_sockaddr_ib {
    unsigned short int sib_family; /* AF_IB */
    uint16_t sib_pkey;
    uint32_t sib_flowinfo;
    uint8_t sib_addr[16];
    uint64_t sib_sid;
    uint64_t sib_sid_mask;
    uint64_t sib_scope_id;
};

/* PSM address */
struct na_ofi_psm_addr {
    uint64_t addr0;
};

/* PSM2 address */
struct na_ofi_psm2_addr {
    uint64_t addr0;
    uint64_t addr1;
};

/* OPX address */
NA_PACKED(union na_ofi_opx_addr {
    uint64_t raw;
    NA_PACKED(struct {
        uint8_t hfi1_rx;
        uint8_t hfi1_unit;
        uint8_t reliability_rx;
        uint16_t endpoint_id;
        uint16_t lid;
        uint8_t rx_index;
    });
});

/* GNI address */
struct na_ofi_gni_addr {
    struct {
        uint32_t device_addr; /* physical NIC address     */
        uint32_t cdm_id;      /* user supplied id         */
    };
    struct {
        uint32_t name_type : 8;      /* bound, unbound           */
        uint32_t cm_nic_cdm_id : 24; /* CM nic ID                */
        uint32_t cookie;             /* CDM identifier           */
    };
    struct {
        uint32_t rx_ctx_cnt : 8;  /* number of contexts       */
        uint32_t key_offset : 12; /* auth key offset          */
        uint32_t unused1 : 12;
        uint32_t unused2;
    };
    uint64_t reserved[3];
};

/* CXI address */
struct na_ofi_cxi_addr {
    union {
        struct {
            uint32_t pid : 9;  /* C_DFA_PID_BITS_MAX */
            uint32_t nic : 20; /* C_DFA_NIC_BITS */
            uint32_t valid : 1;
            uint32_t unused : 2;
        } detail;
        uint32_t raw;
    } caddr;
};

/* String address */
struct na_ofi_str_addr {
    char buf[NA_OFI_MAX_URI_LEN];
};

/* Raw address */
union na_ofi_raw_addr {
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct na_ofi_sockaddr_ib sib;
    struct na_ofi_psm_addr psm;
    struct na_ofi_psm2_addr psm2;
    union na_ofi_opx_addr opx;
    struct na_ofi_gni_addr gni;
    struct na_ofi_cxi_addr cxi;
    struct na_ofi_str_addr str;
};

/* Address key */
struct na_ofi_addr_key {
    union na_ofi_raw_addr addr;
    uint64_t val; /* Keep a 64-bit value for now to simplify hashing */
};

/* Address */
struct na_ofi_addr {
    struct na_ofi_addr_key addr_key;   /* Address key               */
    HG_QUEUE_ENTRY(na_ofi_addr) entry; /* Entry in addr pool        */
    struct na_ofi_class *class;        /* Class                     */
    fi_addr_t fi_addr;                 /* FI address                */
    hg_atomic_int32_t refcount;        /* Reference counter         */
};

/* Memory descriptor info */
struct na_ofi_mem_desc_info {
    uint64_t fi_mr_key;   /* FI MR key                   */
    size_t len;           /* Size of region              */
    unsigned long iovcnt; /* Segment count               */
    uint8_t flags;        /* Flag of operation access    */
};

/* Memory descriptor */
struct na_ofi_mem_desc {
    struct na_ofi_mem_desc_info info; /* Segment info */
    union {
        struct iovec s[NA_OFI_IOV_STATIC_MAX]; /* Single segment */
        struct iovec *d;                       /* Multiple segments */
    } iov;                                     /* Remain last */
};

/* Memory handle */
struct na_ofi_mem_handle {
    struct na_ofi_mem_desc desc; /* Memory descriptor        */
    struct fid_mr *fi_mr;        /* FI MR handle             */
};

/* Msg info */
struct na_ofi_msg_info {
    union {
        const void *const_ptr;
        void *ptr;
    } buf;
    struct fid_mr *fi_mr;
    size_t buf_size;
    fi_addr_t fi_addr;
    uint64_t tag;
    uint64_t tag_mask;
};

/* OFI RMA op (put/get) */
typedef ssize_t (*na_ofi_rma_op_t)(
    struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags);

/* RMA info */
struct na_ofi_rma_info {
    na_ofi_rma_op_t fi_rma_op;
    uint64_t fi_rma_flags;
    union {
        struct iovec s[NA_OFI_IOV_STATIC_MAX]; /* Single segment */
        struct iovec *d;                       /* Multiple segments */
    } local_iov;
    void *local_desc;
    size_t local_iovcnt;
    fi_addr_t fi_addr;
    union {
        struct fi_rma_iov s[NA_OFI_IOV_STATIC_MAX]; /* Single segment */
        struct fi_rma_iov *d;                       /* Multiple segments */
    } remote_iov;
    size_t remote_iovcnt;
    void *context;
};

/* Operation ID */
struct na_ofi_op_id {
    struct na_cb_completion_data completion_data; /* Completion data    */
    union {
        struct na_ofi_msg_info msg;
        struct na_ofi_rma_info rma;
    } info;                             /* Op info                  */
    HG_QUEUE_ENTRY(na_ofi_op_id) entry; /* Entry in queue           */
    struct fi_context fi_ctx[2];        /* Context handle           */
    hg_time_t retry_deadline;           /* Retry deadline           */
    struct na_ofi_class *na_ofi_class;  /* NA class associated      */
    na_context_t *context;              /* NA context associated    */
    struct na_ofi_addr *addr;           /* Address associated       */
    uint64_t fi_op_flags;               /* Operation flags          */
    hg_atomic_int32_t status;           /* Operation status         */
};

/* Op ID queue */
struct na_ofi_op_queue {
    HG_QUEUE_HEAD(na_ofi_op_id) queue;
    hg_thread_spin_t lock;
};

/* Event queue */
struct na_ofi_eq {
    struct fid_cq *fi_cq;                   /* CQ handle                */
    struct na_ofi_op_queue *retry_op_queue; /* Retry op queue           */
    struct fid_wait *fi_wait;               /* Optional wait set handle */
};

/* Context */
struct na_ofi_context {
    struct fid_ep *fi_tx; /* Transmit context handle */
    struct fid_ep *fi_rx; /* Receive context handle  */
    struct na_ofi_eq *eq; /* Event queues            */
    uint8_t idx;          /* Context index           */
};

/* Endpoint */
struct na_ofi_endpoint {
    struct fid_ep *fi_ep;         /* Endpoint handle  */
    struct na_ofi_eq *eq;         /* Event queues     */
    struct na_ofi_addr *src_addr; /* Endpoint address */
};

/* Map (used to cache addresses) */
struct na_ofi_map {
    hg_thread_rwlock_t lock;
    hg_hash_table_t *key_map; /* Primary */
    hg_hash_table_t *fi_map;  /* Secondary */
};

/* Domain */
struct na_ofi_domain {
    struct na_ofi_map addr_map; /* Address map */
#if defined(NA_OFI_HAS_EXT_GNI_H)
    struct fi_gni_auth_key fi_gni_auth_key; /* GNI auth key */
#elif defined(NA_OFI_HAS_EXT_CXI_H)
    struct cxi_auth_key cxi_auth_key; /* CXI auth key */
#endif
    struct fid_domain *fi_domain;    /* Domain handle */
    struct fid_av *fi_av;            /* Address vector handle */
    size_t context_max;              /* Max contexts available */
    size_t eager_msg_size_max;       /* Max eager msg size */
    hg_atomic_int64_t requested_key; /* Requested key if not FI_MR_PROV_KEY */
    int64_t max_key;                 /* Max key if not FI_MR_PROV_KEY */
    bool no_wait;                    /* Wait disabled on domain */
    hg_atomic_int32_t *mr_reg_count; /* Number of MR registered */
} HG_LOCK_CAPABILITY("domain");

/* Addr pool */
struct na_ofi_addr_pool {
    HG_QUEUE_HEAD(na_ofi_addr) queue;
    hg_thread_spin_t lock;
};

/* Fabric */
struct na_ofi_fabric {
    HG_LIST_ENTRY(na_ofi_fabric) entry; /* Entry in fabric list */
    struct fid_fabric *fi_fabric;       /* Fabric handle */
    char *name;                         /* Fabric name */
    char *prov_name;                    /* Provider name */
    enum na_ofi_prov_type prov_type;    /* Provider type */
    int32_t refcount;                   /* Refcount of this fabric */
} HG_LOCK_CAPABILITY("fabric");

/* Get info */
struct na_ofi_info {
    char *node;         /* Node/host IP info */
    char *service;      /* Service/port info */
    int addr_format;    /* Address format */
    void *src_addr;     /* Native src addr */
    size_t src_addrlen; /* Native src addr len */
    bool use_hmem;      /* Use FI_HMEM */
};

/* Verify info */
struct na_ofi_verify_info {
    const struct na_loc_info *loc_info; /* Loc info */
    const char *domain_name;            /* Domain name */
    int addr_format;                    /* Addr format */
    enum na_ofi_prov_type prov_type;    /* Provider type */
};

/* OFI class */
struct na_ofi_class {
    hg_thread_mutex_t mutex;           /* Mutex (for verbs prov)   */
    struct na_ofi_addr_pool addr_pool; /* Addr pool                */
    struct fi_info *fi_info;           /* OFI info                 */
    struct na_ofi_fabric *fabric;      /* Fabric pointer           */
    struct na_ofi_domain *domain;      /* Domain pointer           */
    struct na_ofi_endpoint *endpoint;  /* Endpoint pointer         */
    struct hg_mem_pool *mem_pool;      /* Msg buf pool             */
    size_t unexpected_size_max;        /* Max unexpected size      */
    size_t expected_size_max;          /* Max expected size        */
    hg_atomic_int32_t n_contexts;      /* Number of context        */
    uint8_t context_max;               /* Max number of contexts   */
    bool no_wait;                      /* Ignore wait object       */
    bool finalizing;                   /* Class being destroyed    */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Convert FI errno to NA return values.
 */
static na_return_t
na_ofi_errno_to_na(int rc);

/**
 * Convert provider name to enum type.
 */
static NA_INLINE enum na_ofi_prov_type
na_ofi_prov_name_to_type(const char *prov_name);

/**
 * Determine addr format to use based on preferences.
 */
static NA_INLINE int
na_ofi_prov_addr_format(
    enum na_ofi_prov_type prov_type, enum na_addr_format na_init_format);

/**
 * Get provider encoded address size.
 */
static NA_INLINE size_t
na_ofi_prov_addr_size(int addr_format);

/**
 * Uses Scalable endpoints (SEP).
 */
static NA_INLINE bool
na_ofi_with_sep(const struct na_ofi_class *na_ofi_class);

/**
 * Requires message header with address info.
 */
static NA_INLINE bool
na_ofi_with_msg_hdr(const struct na_ofi_class *na_ofi_class);

/**
 * Get provider type encoded in string.
 */
static NA_INLINE enum na_ofi_prov_type
na_ofi_addr_prov(const char *str);

/**
 * Get native address from string.
 */
static NA_INLINE na_return_t
na_ofi_str_to_raw_addr(
    const char *str, int addr_format, union na_ofi_raw_addr *addr);
static na_return_t
na_ofi_str_to_sin(const char *str, struct sockaddr_in *sin_addr);
static na_return_t
na_ofi_str_to_sin6(const char *str, struct sockaddr_in6 *sin6_addr);
static na_return_t
na_ofi_str_to_sib(const char *str, struct na_ofi_sockaddr_ib *sib_addr);
static na_return_t
na_ofi_str_to_psm(const char *str, struct na_ofi_psm_addr *psm_addr);
static na_return_t
na_ofi_str_to_psm2(const char *str, struct na_ofi_psm2_addr *psm2_addr);
static na_return_t
na_ofi_str_to_opx(const char *str, union na_ofi_opx_addr *opx_addr);
static na_return_t
na_ofi_str_to_gni(const char *str, struct na_ofi_gni_addr *gni_addr);
static na_return_t
na_ofi_str_to_cxi(const char *str, struct na_ofi_cxi_addr *cxi_addr);
static na_return_t
na_ofi_str_to_str(const char *str, struct na_ofi_str_addr *str_addr);

/**
 * Convert the address to a 64-bit key to search corresponding FI addr.
 */
static NA_INLINE uint64_t
na_ofi_raw_addr_to_key(int addr_format, const union na_ofi_raw_addr *addr);
static NA_INLINE uint64_t
na_ofi_sin_to_key(const struct sockaddr_in *addr);
static NA_INLINE uint64_t
na_ofi_sin6_to_key(const struct sockaddr_in6 *addr);
static NA_INLINE uint64_t
na_ofi_sib_to_key(const struct na_ofi_sockaddr_ib *addr);
static NA_INLINE uint64_t
na_ofi_psm_to_key(const struct na_ofi_psm_addr *addr);
static NA_INLINE uint64_t
na_ofi_psm2_to_key(const struct na_ofi_psm2_addr *addr);
static NA_INLINE uint64_t
na_ofi_opx_to_key(const union na_ofi_opx_addr *addr);
static NA_INLINE uint64_t
na_ofi_gni_to_key(const struct na_ofi_gni_addr *addr);
static NA_INLINE uint64_t
na_ofi_cxi_to_key(const struct na_ofi_cxi_addr *addr);
static NA_INLINE uint64_t
na_ofi_str_to_key(const struct na_ofi_str_addr *addr);

/**
 * Convert a key back to an address. (only for sin serialization)
 */
static NA_INLINE void
na_ofi_key_to_sin(struct sockaddr_in *addr, uint64_t key);

/**
 * Size required to serialize raw addr.
 */
static NA_INLINE size_t
na_ofi_raw_addr_serialize_size(int addr_format);

/**
 * Serialize addr key.
 */
static na_return_t
na_ofi_raw_addr_serialize(int addr_format, void *buf, size_t buf_size,
    const union na_ofi_raw_addr *addr);

/**
 * Deserialize addr key.
 */
static na_return_t
na_ofi_raw_addr_deserialize(int addr_format, union na_ofi_raw_addr *addr,
    const void *buf, size_t buf_size);

/**
 * Lookup addr and insert key if not present.
 */
static na_return_t
na_ofi_addr_key_lookup(struct na_ofi_class *na_ofi_class,
    struct na_ofi_addr_key *addr_key, struct na_ofi_addr **na_ofi_addr_p);

/**
 * Key hash for hash table.
 */
static NA_INLINE unsigned int
na_ofi_addr_key_hash(hg_hash_table_key_t key);

/**
 * Compare key.
 */
static NA_INLINE int
na_ofi_addr_key_equal_default(
    hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Compare IPv6 address keys.
 */
static NA_INLINE int
na_ofi_addr_key_equal_sin6(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Compare IB address keys.
 */
static NA_INLINE int
na_ofi_addr_key_equal_sib(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Lookup addr key from map.
 */
static NA_INLINE struct na_ofi_addr *
na_ofi_addr_map_lookup(
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key);

/**
 * Insert new addr key into map and return addr.
 */
static na_return_t
na_ofi_addr_map_insert(struct na_ofi_class *na_ofi_class,
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key,
    struct na_ofi_addr **na_ofi_addr_p);

/**
 * Remove addr key from map.
 */
static na_return_t
na_ofi_addr_map_remove(
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key);

/**
 * Key hash for hash table.
 */
static NA_INLINE unsigned int
na_ofi_fi_addr_hash(hg_hash_table_key_t key);

/**
 * Compare key.
 */
static NA_INLINE int
na_ofi_fi_addr_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Lookup addr key from map.
 */
static NA_INLINE struct na_ofi_addr *
na_ofi_fi_addr_map_lookup(struct na_ofi_map *na_ofi_map, fi_addr_t *fi_addr);

/**
 * Get info caps from providers and return matching providers.
 */
static na_return_t
na_ofi_getinfo(enum na_ofi_prov_type prov_type, const struct na_ofi_info *info,
    struct fi_info **fi_info_p);

/**
 * Match provider name with domain.
 */
static bool
na_ofi_match_provider(const struct na_ofi_verify_info *verify_info,
    const struct fi_info *fi_info);

/**
 * Parse hostname info.
 */
static na_return_t
na_ofi_parse_hostname_info(enum na_ofi_prov_type prov_type,
    const char *hostname_info, int addr_format, char **domain_name_p,
    char **node_p, char **service_p, void **src_addr_p, size_t *src_addrlen_p);

/**
 * Free hostname info.
 */
static void
na_ofi_free_hostname_info(
    char *domain_name, char *node, char *service, void *src_addr);

/**
 * Parse IPv4 info.
 */
static na_return_t
na_ofi_parse_sin_info(const char *hostname_info, char **resolve_name_p,
    uint16_t *port_p, char **domain_name_p);

/**
 * Parse CXI info.
 */
static na_return_t
na_ofi_parse_cxi_info(
    const char *hostname_info, char **node_p, char **service_p);

/**
 * Allocate new OFI class.
 */
static struct na_ofi_class *
na_ofi_class_alloc(void);

/**
 * Free OFI class.
 */
static na_return_t
na_ofi_class_free(struct na_ofi_class *na_ofi_class);

/**
 * Open fabric.
 */
na_return_t
na_ofi_fabric_open(enum na_ofi_prov_type prov_type, struct fi_info *fi_info,
    struct na_ofi_fabric **na_ofi_fabric_p);

/**
 * Close fabric.
 */
na_return_t
na_ofi_fabric_close(struct na_ofi_fabric *na_ofi_fabric);

#ifdef NA_OFI_HAS_EXT_GNI_H
/**
 * Optional domain set op value for GNI provider.
 */
static na_return_t
na_ofi_gni_set_domain_op_value(
    struct na_ofi_domain *na_ofi_domain, int op, void *value);

/**
 * Optional domain get op value for GNI provider.
 */
static na_return_t
na_ofi_gni_get_domain_op_value(
    struct na_ofi_domain *na_ofi_domain, int op, void *value);
#endif

/**
 * Open domain.
 */
static na_return_t
na_ofi_domain_open(const struct na_ofi_fabric *na_ofi_fabric,
    const char *auth_key, bool no_wait, struct fi_info *fi_info,
    struct na_ofi_domain **na_ofi_domain_p);

/**
 * Close domain.
 */
static na_return_t
na_ofi_domain_close(struct na_ofi_domain *na_ofi_domain);

/**
 * Open endpoint.
 */
static na_return_t
na_ofi_endpoint_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, bool no_wait,
    uint8_t max_contexts, struct fi_info *fi_info,
    struct na_ofi_endpoint **na_ofi_endpoint_p);

/**
 * Open basic endpoint.
 */
static na_return_t
na_ofi_basic_ep_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, struct fi_info *fi_info,
    bool no_wait, struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Open scalable endpoint.
 */
static na_return_t
na_ofi_sep_open(const struct na_ofi_domain *na_ofi_domain,
    struct fi_info *fi_info, uint8_t max_contexts,
    struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Close endpoint.
 */
static na_return_t
na_ofi_endpoint_close(struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Open event queues.
 */
static na_return_t
na_ofi_eq_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, bool no_wait,
    struct na_ofi_eq **na_ofi_eq_p);

/**
 * Close event queues.
 */
static na_return_t
na_ofi_eq_close(struct na_ofi_eq *na_ofi_eq);

/**
 * Get EP src address.
 */
static na_return_t
na_ofi_endpoint_get_src_addr(struct na_ofi_class *na_ofi_class);

/**
 * Get EP URI.
 */
static na_return_t
na_ofi_get_uri(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, char *buf, size_t *buf_size_p,
    const struct na_ofi_addr_key *addr_key);

/**
 * Allocate empty address.
 */
static struct na_ofi_addr *
na_ofi_addr_alloc(struct na_ofi_class *na_ofi_class);

/**
 * Destroy address.
 */
static void
na_ofi_addr_destroy(struct na_ofi_addr *na_ofi_addr);

#ifdef NA_OFI_HAS_ADDR_POOL
/**
 * Retrieve address from pool.
 */
static struct na_ofi_addr *
na_ofi_addr_pool_get(struct na_ofi_class *na_ofi_class);
#endif

/**
 * Release address without destroying it.
 */
static void
na_ofi_addr_release(struct na_ofi_addr *na_ofi_addr);

/**
 * Reset address.
 */
static void
na_ofi_addr_reset(
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_addr_key *addr_key);

/**
 * Create address.
 */
static na_return_t
na_ofi_addr_create(struct na_ofi_class *na_ofi_class,
    struct na_ofi_addr_key *addr_key, struct na_ofi_addr **na_ofi_addr_p);

/**
 * Increment address refcount.
 */
static NA_INLINE void
na_ofi_addr_ref_incr(struct na_ofi_addr *na_ofi_addr);

/**
 * Decrement address refcount.
 */
static void
na_ofi_addr_ref_decr(struct na_ofi_addr *na_ofi_addr);

#ifndef NA_OFI_HAS_MEM_POOL

/**
 * Allocate memory for transfers.
 */
static NA_INLINE void *
na_ofi_mem_alloc(
    struct na_ofi_class *na_ofi_class, size_t size, struct fid_mr **mr_hdl);

/**
 * Free memory.
 */
static NA_INLINE void
na_ofi_mem_free(
    struct na_ofi_class *na_ofi_class, void *mem_ptr, struct fid_mr *mr_hdl);

#endif /* NA_OFI_HAS_MEM_POOL */

/**
 * Register memory buffer.
 */
static int
na_ofi_mem_buf_register(const void *buf, size_t len, void **handle, void *arg);

/**
 * Deregister memory buffer.
 */
static int
na_ofi_mem_buf_deregister(void *handle, void *arg);

/**
 * Generate key for memory registration.
 */
static uint64_t
na_ofi_mem_key_gen(struct na_ofi_domain *na_ofi_domain);

/**
 * Msg send.
 */
static na_return_t
na_ofi_msg_send(na_context_t *context, na_cb_type_t cb_type, na_cb_t callback,
    void *arg, const struct na_ofi_msg_info *msg_info,
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id);

/**
 * Msg recv.
 */
static na_return_t
na_ofi_msg_recv(na_context_t *context, na_cb_type_t cb_type, na_cb_t callback,
    void *arg, const struct na_ofi_msg_info *msg_info,
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id);

/**
 * Get IOV index and offset pair from an absolute offset.
 */
static NA_INLINE void
na_ofi_iov_get_index_offset(const struct iovec *iov, unsigned long iovcnt,
    na_offset_t offset, unsigned long *iov_start_index,
    na_offset_t *iov_start_offset);

/**
 * Get IOV count for a given length.
 */
static NA_INLINE unsigned long
na_ofi_iov_get_count(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, size_t len);

/**
 * Create new IOV for transferring length data.
 */
static NA_INLINE void
na_ofi_iov_translate(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, size_t len,
    struct iovec *new_iov, unsigned long new_iovcnt);

/**
 * Create new RMA IOV for transferring length data.
 */
static NA_INLINE void
na_ofi_rma_iov_translate(const struct fi_info *fi_info, const struct iovec *iov,
    unsigned long iovcnt, uint64_t key, unsigned long iov_start_index,
    na_offset_t iov_start_offset, size_t len, struct fi_rma_iov *new_iov,
    unsigned long new_iovcnt);

/**
 * Do RMA operation (put/get).
 */
static na_return_t
na_ofi_rma(struct na_ofi_class *na_ofi_class, na_context_t *context,
    na_cb_type_t op, na_cb_t callback, void *arg, na_ofi_rma_op_t fi_rma_op,
    uint64_t fi_rma_flags, struct na_ofi_mem_handle *na_ofi_mem_handle_local,
    na_offset_t local_offset,
    struct na_ofi_mem_handle *na_ofi_mem_handle_remote,
    na_offset_t remote_offset, size_t length, struct na_ofi_addr *na_ofi_addr,
    uint8_t remote_id, struct na_ofi_op_id *na_ofi_op_id);

/**
 * Read from CQ.
 */
static na_return_t
na_ofi_cq_read(na_context_t *context, size_t max_count,
    struct fi_cq_tagged_entry cq_events[], fi_addr_t src_addrs[],
    void **src_err_addr, size_t *src_err_addrlen, size_t *actual_count);

/**
 * Process event from CQ.
 */
static na_return_t
na_ofi_cq_process_event(struct na_ofi_class *na_ofi_class,
    const struct fi_cq_tagged_entry *cq_event, fi_addr_t src_addr,
    void *err_addr, size_t err_addrlen);

/**
 * Recv unexpected operation events.
 */
static na_return_t
na_ofi_cq_process_recv_unexpected_event(struct na_ofi_class *na_ofi_class,
    struct na_ofi_op_id *na_ofi_op_id, fi_addr_t src_addr, void *src_err_addr,
    size_t src_err_addrlen, uint64_t tag, size_t len);

/**
 * Recv expected operation events.
 */
static NA_INLINE na_return_t
na_ofi_cq_process_recv_expected_event(
    struct na_ofi_op_id *na_ofi_op_id, uint64_t tag, size_t len);

/**
 * RMA operation events.
 */
static NA_INLINE void
na_ofi_cq_process_rma_event(struct na_ofi_op_id *na_ofi_op_id);

/**
 * Process retries.
 */
static na_return_t
na_ofi_cq_process_retries(struct na_ofi_context *na_ofi_context);

/**
 * Push op for retry.
 */
static void
na_ofi_op_retry(
    struct na_ofi_context *na_ofi_context, struct na_ofi_op_id *na_ofi_op_id);

/**
 * Abort all operations targeted at fi_addr.
 */
static void
na_ofi_op_retry_abort_addr(
    struct na_ofi_context *na_ofi_context, fi_addr_t fi_addr, na_return_t ret);

/**
 * Complete operation ID.
 */
static NA_INLINE void
na_ofi_complete(struct na_ofi_op_id *na_ofi_op_id, na_return_t cb_ret);

/**
 * Release OP ID resources.
 */
static NA_INLINE void
na_ofi_release(void *arg);

/**
 * Cancel OP ID.
 */
static na_return_t
na_ofi_op_cancel(struct na_ofi_op_id *na_ofi_op_id);

/********************/
/* Plugin callbacks */
/********************/

/* check_protocol */
static bool
na_ofi_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_ofi_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool listen);

/* finalize */
static na_return_t
na_ofi_finalize(na_class_t *na_class);

/* context_create */
static na_return_t
na_ofi_context_create(na_class_t *na_class, void **context_p, uint8_t id);

/* context_destroy */
static na_return_t
na_ofi_context_destroy(na_class_t *na_class, void *context);

/* op_create */
static na_op_id_t *
na_ofi_op_create(na_class_t *na_class);

/* op_destroy */
static na_return_t
na_ofi_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_ofi_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p);

/* addr_free */
static NA_INLINE na_return_t
na_ofi_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_set_remove */
static NA_INLINE na_return_t
na_ofi_addr_set_remove(na_class_t *na_class, na_addr_t addr);

/* addr_self */
static NA_INLINE na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr_p);

/* addr_dup */
static NA_INLINE na_return_t
na_ofi_addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr_p);

/* addr_dup */
static bool
na_ofi_addr_cmp(na_class_t *na_class, na_addr_t addr1, na_addr_t addr2);

/* addr_is_self */
static NA_INLINE bool
na_ofi_addr_is_self(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t
na_ofi_addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size, na_addr_t addr);

/* addr_get_serialize_size */
static NA_INLINE size_t
na_ofi_addr_get_serialize_size(na_class_t *na_class, na_addr_t addr);

/* addr_serialize */
static na_return_t
na_ofi_addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t addr);

/* addr_deserialize */
static na_return_t
na_ofi_addr_deserialize(
    na_class_t *na_class, na_addr_t *addr_p, const void *buf, size_t buf_size);

/* msg_get_max_unexpected_size */
static NA_INLINE size_t
na_ofi_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static NA_INLINE size_t
na_ofi_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_unexpected_header_size */
static NA_INLINE size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class);

/* msg_get_max_tag */
static NA_INLINE na_tag_t
na_ofi_msg_get_max_tag(const na_class_t *na_class);

/* msg_buf_alloc */
static void *
na_ofi_msg_buf_alloc(na_class_t *na_class, size_t size, void **plugin_data);

/* msg_buf_free */
static na_return_t
na_ofi_msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data);

/* msg_init_unexpected */
static na_return_t
na_ofi_msg_init_unexpected(na_class_t *na_class, void *buf, size_t buf_size);

/* msg_send_unexpected */
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size, void *plugin_data,
    na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size, void *plugin_data,
    na_addr_t source_addr, uint8_t source_id, na_tag_t tag, na_op_id_t *op_id);

/* mem_handle */
static na_return_t
na_ofi_mem_handle_create(na_class_t *na_class, void *buf, size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle);

static na_return_t
na_ofi_mem_handle_create_segments(na_class_t *na_class,
    struct na_segment *segments, size_t segment_count, unsigned long flags,
    na_mem_handle_t *mem_handle);

static na_return_t
na_ofi_mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle);

static NA_INLINE size_t
na_ofi_mem_handle_get_max_segments(const na_class_t *na_class);

static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle,
    enum na_mem_type mem_type, uint64_t device);

static na_return_t
na_ofi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle);

/* mem_handle serialization */
static NA_INLINE size_t
na_ofi_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_serialize(na_class_t *na_class, void *buf, size_t buf_size,
    na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
    const void *buf, size_t buf_size);

/* put */
static na_return_t
na_ofi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset, size_t length,
    na_addr_t remote_addr, uint8_t remote_id, na_op_id_t *op_id);

/* get */
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset, size_t length,
    na_addr_t remote_addr, uint8_t remote_id, na_op_id_t *op_id);

/* poll_get_fd */
static NA_INLINE int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static NA_INLINE bool
na_ofi_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* progress */
static na_return_t
na_ofi_progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout);

/* cancel */
static na_return_t
na_ofi_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/*******************/
/* Local Variables */
/*******************/

const struct na_class_ops NA_PLUGIN_OPS(ofi) = {
    "ofi",                                 /* name */
    na_ofi_check_protocol,                 /* check_protocol */
    na_ofi_initialize,                     /* initialize */
    na_ofi_finalize,                       /* finalize */
    NULL,                                  /* cleanup */
    na_ofi_context_create,                 /* context_create */
    na_ofi_context_destroy,                /* context_destroy */
    na_ofi_op_create,                      /* op_create */
    na_ofi_op_destroy,                     /* op_destroy */
    na_ofi_addr_lookup,                    /* addr_lookup */
    na_ofi_addr_free,                      /* addr_free */
    na_ofi_addr_set_remove,                /* addr_set_remove */
    na_ofi_addr_self,                      /* addr_self */
    na_ofi_addr_dup,                       /* addr_dup */
    na_ofi_addr_cmp,                       /* addr_cmp */
    na_ofi_addr_is_self,                   /* addr_is_self */
    na_ofi_addr_to_string,                 /* addr_to_string */
    na_ofi_addr_get_serialize_size,        /* addr_get_serialize_size */
    na_ofi_addr_serialize,                 /* addr_serialize */
    na_ofi_addr_deserialize,               /* addr_deserialize */
    na_ofi_msg_get_max_unexpected_size,    /* msg_get_max_unexpected_size */
    na_ofi_msg_get_max_expected_size,      /* msg_get_max_expected_size */
    na_ofi_msg_get_unexpected_header_size, /* msg_get_unexpected_header_size */
    NULL,                                  /* msg_get_expected_header_size */
    na_ofi_msg_get_max_tag,                /* msg_get_max_tag */
    na_ofi_msg_buf_alloc,                  /* msg_buf_alloc */
    na_ofi_msg_buf_free,                   /* msg_buf_free */
    na_ofi_msg_init_unexpected,            /* msg_init_unexpected */
    na_ofi_msg_send_unexpected,            /* msg_send_unexpected */
    na_ofi_msg_recv_unexpected,            /* msg_recv_unexpected */
    NULL,                                  /* msg_init_expected */
    na_ofi_msg_send_expected,              /* msg_send_expected */
    na_ofi_msg_recv_expected,              /* msg_recv_expected */
    na_ofi_mem_handle_create,              /* mem_handle_create */
    na_ofi_mem_handle_create_segments,     /* mem_handle_create_segment */
    na_ofi_mem_handle_free,                /* mem_handle_free */
    na_ofi_mem_handle_get_max_segments,    /* mem_handle_get_max_segments */
    na_ofi_mem_register,                   /* mem_register */
    na_ofi_mem_deregister,                 /* mem_deregister */
    na_ofi_mem_handle_get_serialize_size,  /* mem_handle_get_serialize_size */
    na_ofi_mem_handle_serialize,           /* mem_handle_serialize */
    na_ofi_mem_handle_deserialize,         /* mem_handle_deserialize */
    na_ofi_put,                            /* put */
    na_ofi_get,                            /* get */
    na_ofi_poll_get_fd,                    /* poll_get_fd */
    na_ofi_poll_try_wait,                  /* poll_try_wait */
    na_ofi_progress,                       /* progress */
    na_ofi_cancel                          /* cancel */
};

/* Fabric list */
static HG_LIST_HEAD(na_ofi_fabric)
    na_ofi_fabric_list_g = HG_LIST_HEAD_INITIALIZER(na_ofi_fabric);

/* Fabric list lock */
static hg_thread_mutex_t na_ofi_fabric_list_mutex_g =
    HG_THREAD_MUTEX_INITIALIZER;

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_errno_to_na(int rc)
{
    na_return_t ret;

    switch (rc) {
        case FI_EPERM:
            ret = NA_PERMISSION;
            break;
        case FI_ENOENT:
            ret = NA_NOENTRY;
            break;
        case FI_EINTR:
            ret = NA_INTERRUPT;
            break;
        case FI_EAGAIN:
            ret = NA_AGAIN;
            break;
        case FI_ENOMEM:
            ret = NA_NOMEM;
            break;
        case FI_EACCES:
            ret = NA_ACCESS;
            break;
        case FI_EFAULT:
            ret = NA_FAULT;
            break;
        case FI_EBUSY:
            ret = NA_BUSY;
            break;
        case FI_ENODEV:
            ret = NA_NODEV;
            break;
        case FI_EINVAL:
            ret = NA_INVALID_ARG;
            break;
        case FI_EOVERFLOW:
            ret = NA_OVERFLOW;
            break;
        case FI_EMSGSIZE:
            ret = NA_MSGSIZE;
            break;
        case FI_ENOPROTOOPT:
            ret = NA_PROTONOSUPPORT;
            break;
        case FI_EOPNOTSUPP:
            ret = NA_OPNOTSUPPORTED;
            break;
        case FI_EADDRINUSE:
            ret = NA_ADDRINUSE;
            break;
        case FI_EADDRNOTAVAIL:
            ret = NA_ADDRNOTAVAIL;
            break;
        case FI_ENETDOWN:
        case FI_ENETUNREACH:
        case FI_ENOTCONN:
        case FI_ECONNABORTED:
        case FI_ECONNREFUSED:
        case FI_ECONNRESET:
        case FI_ESHUTDOWN:
        case FI_EHOSTDOWN:
        case FI_EHOSTUNREACH:
            ret = NA_HOSTUNREACH;
            break;
        case FI_ETIMEDOUT:
            ret = NA_TIMEOUT;
            break;
        case FI_ECANCELED:
            ret = NA_CANCELED;
            break;
        default:
            ret = NA_PROTOCOL_ERROR;
            break;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE enum na_ofi_prov_type
na_ofi_prov_name_to_type(const char *prov_name)
{
    enum na_ofi_prov_type i = 0;

    while (strcmp(na_ofi_prov_name[i], prov_name) &&
           strcmp(na_ofi_prov_alt_name[i], prov_name) && i != NA_OFI_PROV_MAX) {
        i++;
    }

    return ((i == NA_OFI_PROV_MAX) ? NA_OFI_PROV_NULL : i);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_prov_addr_format(
    enum na_ofi_prov_type prov_type, enum na_addr_format na_init_format)
{
    switch (na_init_format) {
        case NA_ADDR_IPV4:
            return FI_SOCKADDR_IN;
        case NA_ADDR_IPV6:
            return FI_SOCKADDR_IN6;
        case NA_ADDR_NATIVE:
            return na_ofi_prov_addr_format_native[prov_type];
        case NA_ADDR_UNSPEC:
            return na_ofi_prov_addr_format_pref[prov_type];
        default:
            NA_LOG_SUBSYS_ERROR(fatal, "Unsupported address format");
            return FI_FORMAT_UNSPEC;
    }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_prov_addr_size(int addr_format)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return sizeof(struct sockaddr_in);
        case FI_SOCKADDR_IN6:
            return sizeof(struct sockaddr_in6);
        case FI_SOCKADDR_IB:
            return sizeof(struct na_ofi_sockaddr_ib);
        case FI_ADDR_PSMX:
            return sizeof(struct na_ofi_psm_addr);
        case FI_ADDR_PSMX2:
            return sizeof(struct na_ofi_psm2_addr);
        case FI_ADDR_OPX:
            return sizeof(union na_ofi_opx_addr);
        case FI_ADDR_GNI:
            return sizeof(struct na_ofi_gni_addr);
        case FI_ADDR_CXI:
            return sizeof(struct na_ofi_cxi_addr);
        case FI_ADDR_STR:
            return sizeof(struct na_ofi_str_addr);
        default:
            NA_LOG_SUBSYS_ERROR(fatal, "Unsupported address format");
            return 0;
    }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE bool
na_ofi_with_sep(const struct na_ofi_class *na_ofi_class)
{
    return (na_ofi_prov_flags[na_ofi_class->fabric->prov_type] & NA_OFI_SEP) &&
           (na_ofi_class->context_max > 1);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE bool
na_ofi_with_msg_hdr(const struct na_ofi_class *na_ofi_class)
{
    return na_ofi_prov_flags[na_ofi_class->fabric->prov_type] &
           NA_OFI_SOURCE_MSG;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE enum na_ofi_prov_type
na_ofi_addr_prov(const char *str)
{
    char fmt[19];
    int ret;

    ret = sscanf(str, "%16[^:]://", fmt);
    if (ret != 1)
        return NA_OFI_PROV_NULL;

    fmt[sizeof(fmt) - 1] = '\0';

    return na_ofi_prov_name_to_type(fmt);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_str_to_raw_addr(
    const char *str, int addr_format, union na_ofi_raw_addr *addr)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return na_ofi_str_to_sin(str, &addr->sin);
        case FI_SOCKADDR_IN6:
            return na_ofi_str_to_sin6(str, &addr->sin6);
        case FI_SOCKADDR_IB:
            return na_ofi_str_to_sib(str, &addr->sib);
        case FI_ADDR_PSMX:
            return na_ofi_str_to_psm(str, &addr->psm);
        case FI_ADDR_PSMX2:
            return na_ofi_str_to_psm2(str, &addr->psm2);
        case FI_ADDR_OPX:
            return na_ofi_str_to_opx(str, &addr->opx);
        case FI_ADDR_GNI:
            return na_ofi_str_to_gni(str, &addr->gni);
        case FI_ADDR_CXI:
            return na_ofi_str_to_cxi(str, &addr->cxi);
        case FI_ADDR_STR:
            return na_ofi_str_to_str(str, &addr->str);
        default:
            NA_LOG_SUBSYS_ERROR(
                fatal, "Unsupported address format: %d", addr_format);
            return NA_PROTONOSUPPORT;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_sin(const char *str, struct sockaddr_in *sin_addr)
{
    char ip[17];
    na_return_t ret;

    sin_addr->sin_family = AF_INET;
    if (sscanf(str, "%*[^:]://:%" SCNu16, &sin_addr->sin_port) == 1) {
        NA_LOG_SUBSYS_DEBUG(addr, "port=%" PRIu16, sin_addr->sin_port);
    } else if ((sscanf(str, "%*[^:]://%16[^:]:%" SCNu16, ip,
                    &sin_addr->sin_port) == 2) ||
               (sscanf(str, "%*[^:]://%16[^:/]", ip) == 1)) {
        int rc;

        ip[sizeof(ip) - 1] = '\0';
        rc = inet_pton(AF_INET, ip, &sin_addr->sin_addr);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 1, error, ret, NA_PROTONOSUPPORT,
            "Unable to convert IPv4 address: %s", ip);
        NA_LOG_SUBSYS_DEBUG(
            addr, "ip=%s, port=%" PRIu16, ip, sin_addr->sin_port);
    } else
        NA_GOTO_SUBSYS_ERROR(addr, error, ret, NA_PROTONOSUPPORT,
            "Malformed FI_ADDR_STR: %s", str);

    sin_addr->sin_port = htons(sin_addr->sin_port);
    /* Make sure `sin_zero` is set to 0 */
    memset(&sin_addr->sin_zero, 0, sizeof(sin_addr->sin_zero));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_sin6(const char *str, struct sockaddr_in6 *sin6_addr)
{
    char ip[65];
    na_return_t ret;

    /* Make sure unused fields are set to 0 */
    memset(sin6_addr, 0, sizeof(*sin6_addr));

    sin6_addr->sin6_family = AF_INET6;
    if (sscanf(str, "%*[^:]://:%" SCNu16, &sin6_addr->sin6_port) == 1) {
        NA_LOG_SUBSYS_DEBUG(addr, "port=%" PRIu16, sin6_addr->sin6_port);
    } else if ((sscanf(str, "%*[^:]://[%64[^]]]:%" SCNu16, ip,
                    &sin6_addr->sin6_port) == 2) ||
               (sscanf(str, "%*[^:]://[%64[^]]", ip) == 1)) {
        int rc;

        ip[sizeof(ip) - 1] = '\0';
        rc = inet_pton(AF_INET6, ip, &sin6_addr->sin6_addr);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 1, error, ret, NA_PROTONOSUPPORT,
            "Unable to convert IPv6 address: %s", ip);
        NA_LOG_SUBSYS_DEBUG(
            addr, "ip=%s, port=%" PRIu16, ip, sin6_addr->sin6_port);
    } else
        NA_GOTO_SUBSYS_ERROR(addr, error, ret, NA_PROTONOSUPPORT,
            "Malformed FI_ADDR_STR: %s", str);

    sin6_addr->sin6_port = htons(sin6_addr->sin6_port);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_sib(const char *str, struct na_ofi_sockaddr_ib *sib_addr)
{
    char *tok, *endptr, *saveptr;
    uint16_t pkey, ps, port;
    uint64_t scope_id;
    char gid[64 + 1];
    char extra_str[64 + 1];
    na_return_t ret;
    int rc;

    memset(gid, 0, sizeof(gid));

    rc = sscanf(str,
        "%*[^:]://[%64[^]]]" /* GID */
        ":%64s",             /* P_Key : port_space : Scope ID : port */
        gid, extra_str);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 2, error, ret, NA_PROTONOSUPPORT,
        "Invalid GID in address: %s", str);

    tok = strtok_r(extra_str, ":", &saveptr);
    NA_CHECK_SUBSYS_ERROR(addr, tok == NULL, error, ret, NA_PROTONOSUPPORT,
        "Invalid pkey in address: %s", str);

    pkey = strtoul(tok, &endptr, 0) & 0xffff;
    NA_CHECK_SUBSYS_ERROR(addr, !pkey, error, ret, NA_PROTONOSUPPORT,
        "Invalid pkey in address: %s", str);

    tok = strtok_r(NULL, ":", &saveptr);
    NA_CHECK_SUBSYS_ERROR(addr, tok == NULL, error, ret, NA_PROTONOSUPPORT,
        "Invalid port space in address: %s", str);

    ps = strtoul(tok, &endptr, 0) & 0xffff;
    NA_CHECK_SUBSYS_ERROR(addr, *endptr, error, ret, NA_PROTONOSUPPORT,
        "Invalid port space in address: %s", str);

    tok = strtok_r(NULL, ":", &saveptr);
    NA_CHECK_SUBSYS_ERROR(addr, tok == NULL, error, ret, NA_PROTONOSUPPORT,
        "Invalid scope id in address: %s", str);

    scope_id = strtoul(tok, &endptr, 0);
    NA_CHECK_SUBSYS_ERROR(addr, *endptr, error, ret, NA_PROTONOSUPPORT,
        "Invalid scope id in address: %s", str);

    /* Port is optional */
    tok = strtok_r(NULL, ":", &saveptr);
    if (tok)
        port = strtoul(tok, &endptr, 0) & 0xffff;
    else
        port = 0;

    /* Make sure unused fields are set to 0 */
    memset(sib_addr, 0, sizeof(*sib_addr));

    rc = inet_pton(AF_INET6, gid, &sib_addr->sib_addr);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 1, error, ret, NA_PROTONOSUPPORT,
        "Unable to convert GID: %s", gid);

    sib_addr->sib_family = AF_IB;
    sib_addr->sib_pkey = htons(pkey);
    if (ps && port) {
        sib_addr->sib_sid = htonll(((uint64_t) ps << 16) + port);
        sib_addr->sib_sid_mask =
            htonll(NA_OFI_IB_IP_PS_MASK | NA_OFI_IB_IP_PORT_MASK);
    }
    sib_addr->sib_scope_id = htonll(scope_id);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_psm(const char *str, struct na_ofi_psm_addr *psm_addr)
{
    na_return_t ret;
    int rc;

    rc = sscanf(str, "%*[^:]://%" SCNx64, (uint64_t *) &psm_addr->addr0);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 1, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to PSM addr format");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_psm2(const char *str, struct na_ofi_psm2_addr *psm2_addr)
{
    na_return_t ret;
    int rc;

    rc = sscanf(str, "%*[^:]://%" SCNx64 ":%" SCNx64,
        (uint64_t *) &psm2_addr->addr0, (uint64_t *) &psm2_addr->addr1);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 2, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to PSM2 addr format");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_opx(const char *str, union na_ofi_opx_addr *opx_addr)
{
    uint8_t rx_index, hfi1_rx, hfi1_unit, reliability_rx;
    uint16_t lid, endpoint_id;
    na_return_t ret;
    int rc;

    rc = sscanf(str, "%*[^:]://%04hx.%04hx.%02hhx.%02hhx.%02hhx.%02hhx", &lid,
        &endpoint_id, &rx_index, &hfi1_rx, &hfi1_unit, &reliability_rx);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 6, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to OPX addr format");
    *opx_addr = (union na_ofi_opx_addr){.lid = lid,
        .endpoint_id = endpoint_id,
        .rx_index = rx_index,
        .hfi1_rx = hfi1_rx,
        .hfi1_unit = hfi1_unit,
        .reliability_rx = reliability_rx};

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_gni(const char *str, struct na_ofi_gni_addr *gni_addr)
{
    unsigned int version, name_type, rx_ctx_cnt;
    uint32_t device_addr, cdm_id, cm_nic_cdm_id, cookie;
    na_return_t ret;
    int rc;

    /* Make sure unused fields are set to 0 */
    memset(gni_addr, 0, sizeof(*gni_addr));

    rc = sscanf(str,
        "%*[^:]://%04u:0x%08" PRIx32 ":0x%08" PRIx32 ":%02u:0x%06" PRIx32
        ":0x%08" PRIx32 ":%02u",
        &version, &device_addr, &cdm_id, &name_type, &cm_nic_cdm_id, &cookie,
        &rx_ctx_cnt);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 7, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to GNI addr format");
    NA_CHECK_SUBSYS_ERROR(addr, version != NA_OFI_GNI_AV_STR_ADDR_VERSION,
        error, ret, NA_PROTONOSUPPORT, "Unsupported GNI string addr format");

    gni_addr->device_addr = device_addr;
    gni_addr->cdm_id = cdm_id;
    gni_addr->name_type = name_type & 0xff;
    gni_addr->cm_nic_cdm_id = cm_nic_cdm_id & 0xffffff;
    gni_addr->cookie = cookie;
    gni_addr->rx_ctx_cnt = rx_ctx_cnt & 0xff;
    NA_LOG_SUBSYS_DEBUG(addr,
        "GNI addr is: device_addr=%x, cdm_id=%x, name_type=%x, "
        "cm_nic_cdm_id=%x, cookie=%x, rx_ctx_cnt=%u",
        gni_addr->device_addr, gni_addr->cdm_id, gni_addr->name_type,
        gni_addr->cm_nic_cdm_id, gni_addr->cookie, gni_addr->rx_ctx_cnt);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_cxi(const char *str, struct na_ofi_cxi_addr *cxi_addr)
{
    na_return_t ret;
    int rc;

    rc = sscanf(str, "%*[^:]://%" SCNx32, &cxi_addr->caddr.raw);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 1, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to CXI addr format");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_str(const char *str, struct na_ofi_str_addr *str_addr)
{
    na_return_t ret;
    int rc;

    rc = snprintf(str_addr->buf, sizeof(str_addr->buf), "fi_%s", str);
    NA_CHECK_SUBSYS_ERROR(addr, rc < 0 || rc > (int) sizeof(str_addr->buf),
        error, ret, NA_OVERFLOW,
        "snprintf() failed or name truncated, rc: %d (expected %zu)", rc,
        sizeof(str_addr->buf));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_raw_addr_to_key(int addr_format, const union na_ofi_raw_addr *addr)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return na_ofi_sin_to_key(&addr->sin);
        case FI_SOCKADDR_IN6:
            return na_ofi_sin6_to_key(&addr->sin6);
        case FI_SOCKADDR_IB:
            return na_ofi_sib_to_key(&addr->sib);
        case FI_ADDR_PSMX:
            return na_ofi_psm_to_key(&addr->psm);
        case FI_ADDR_PSMX2:
            return na_ofi_psm2_to_key(&addr->psm2);
        case FI_ADDR_OPX:
            return na_ofi_opx_to_key(&addr->opx);
        case FI_ADDR_GNI:
            return na_ofi_gni_to_key(&addr->gni);
        case FI_ADDR_CXI:
            return na_ofi_cxi_to_key(&addr->cxi);
        case FI_ADDR_STR:
            return na_ofi_str_to_key(&addr->str);
        default:
            NA_LOG_SUBSYS_ERROR(fatal, "Unsupported address format");
            return 0;
    }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_sin_to_key(const struct sockaddr_in *addr)
{
    return ((uint64_t) addr->sin_addr.s_addr) << 32 | addr->sin_port;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_sin6_to_key(const struct sockaddr_in6 *addr)
{
    return *((const uint64_t *) &addr->sin6_addr.s6_addr);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_sib_to_key(const struct na_ofi_sockaddr_ib *addr)
{
    return *((const uint64_t *) &addr->sib_addr);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_psm_to_key(const struct na_ofi_psm_addr *addr)
{
    return addr->addr0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_psm2_to_key(const struct na_ofi_psm2_addr *addr)
{
    /* Only need the psm2_epid, i.e. the first 64 bits */
    return addr->addr0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_opx_to_key(const union na_ofi_opx_addr *addr)
{
    return addr->raw;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_gni_to_key(const struct na_ofi_gni_addr *addr)
{
    return ((uint64_t) addr->device_addr) << 32 | addr->cdm_id;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_cxi_to_key(const struct na_ofi_cxi_addr *addr)
{
    return (uint64_t) addr->caddr.raw;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint64_t
na_ofi_str_to_key(const struct na_ofi_str_addr *addr)
{
    return (uint64_t) hg_hash_string(addr->buf);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_key_to_sin(struct sockaddr_in *addr, uint64_t key)
{
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = (in_addr_t) (key >> 32);
    addr->sin_port = (in_port_t) (key & 0xffffffff);
    memset(&addr->sin_zero, 0, sizeof(addr->sin_zero));
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_raw_addr_serialize_size(int addr_format)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return sizeof(uint64_t);
        case FI_SOCKADDR_IN6:
            return sizeof(struct in6_addr) + sizeof(in_port_t);
        case FI_SOCKADDR_IB:
            return sizeof(struct na_ofi_sockaddr_ib);
        case FI_ADDR_PSMX:
            return sizeof(struct na_ofi_psm_addr);
        case FI_ADDR_PSMX2:
            return sizeof(struct na_ofi_psm2_addr);
        case FI_ADDR_OPX:
            return sizeof(union na_ofi_opx_addr);
        case FI_ADDR_GNI:
            return sizeof(struct na_ofi_gni_addr);
        case FI_ADDR_CXI:
            return sizeof(struct na_ofi_cxi_addr);
        case FI_ADDR_STR:
            return sizeof(struct na_ofi_str_addr);
        default:
            NA_LOG_SUBSYS_ERROR(fatal, "Unsupported address format");
            return 0;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_raw_addr_serialize(int addr_format, void *buf, size_t buf_size,
    const union na_ofi_raw_addr *addr)
{
    na_return_t ret;

    switch (addr_format) {
        case FI_SOCKADDR_IN: {
            uint64_t val = na_ofi_sin_to_key(&addr->sin);

            NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(val), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &val, sizeof(val));
            break;
        }
        case FI_SOCKADDR_IN6: {
            char *buf_ptr = (char *) buf;
            size_t buf_size_left = (size_t) buf_size;

            NA_ENCODE(error, ret, buf_ptr, buf_size_left, &addr->sin6.sin6_addr,
                struct in6_addr);
            NA_ENCODE(error, ret, buf_ptr, buf_size_left, &addr->sin6.sin6_port,
                in_port_t);
            break;
        }
        case FI_SOCKADDR_IB:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_sockaddr_ib), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->sib, sizeof(addr->sib));
            break;
        case FI_ADDR_PSMX:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_psm_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->psm, sizeof(addr->psm));
            break;
        case FI_ADDR_PSMX2:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_psm2_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->psm2, sizeof(addr->psm2));
            break;
        case FI_ADDR_OPX:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(union na_ofi_opx_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->opx, sizeof(addr->opx));
            break;
        case FI_ADDR_GNI:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_gni_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->gni, sizeof(addr->gni));
            break;
        case FI_ADDR_CXI:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_cxi_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(buf, &addr->cxi, sizeof(addr->cxi));
            break;
        case FI_ADDR_STR:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_str_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            strncpy(buf, addr->str.buf, sizeof(addr->str));
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(addr, error, ret, NA_PROTONOSUPPORT,
                "Unsupported address format");
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_raw_addr_deserialize(int addr_format, union na_ofi_raw_addr *addr,
    const void *buf, size_t buf_size)
{
    na_return_t ret;

    switch (addr_format) {
        case FI_SOCKADDR_IN: {
            uint64_t val;

            NA_CHECK_SUBSYS_ERROR(addr, buf_size < sizeof(val), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&val, buf, sizeof(val));
            na_ofi_key_to_sin(&addr->sin, val);
            break;
        }
        case FI_SOCKADDR_IN6: {
            const char *buf_ptr = (const char *) buf;
            size_t buf_size_left = (size_t) buf_size;

            memset(&addr->sin6, 0, sizeof(addr->sin6));
            NA_DECODE(error, ret, buf_ptr, buf_size_left, &addr->sin6.sin6_addr,
                struct in6_addr);
            NA_DECODE(error, ret, buf_ptr, buf_size_left, &addr->sin6.sin6_port,
                in_port_t);
            break;
        }
        case FI_SOCKADDR_IB:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_sockaddr_ib), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->sib, buf, sizeof(addr->sib));
            break;
        case FI_ADDR_PSMX:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_psm_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->psm, buf, sizeof(addr->psm));
            break;
        case FI_ADDR_PSMX2:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_psm2_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->psm2, buf, sizeof(addr->psm2));
            break;
        case FI_ADDR_OPX:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(union na_ofi_opx_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->opx, buf, sizeof(addr->opx));
            break;
        case FI_ADDR_GNI:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_gni_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->gni, buf, sizeof(addr->gni));
            break;
        case FI_ADDR_CXI:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_cxi_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            memcpy(&addr->cxi, buf, sizeof(addr->cxi));
            break;
        case FI_ADDR_STR:
            NA_CHECK_SUBSYS_ERROR(addr,
                buf_size < sizeof(struct na_ofi_str_addr), error, ret,
                NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
                buf_size);
            strncpy(addr->str.buf, buf, sizeof(addr->str) - 1);
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(addr, error, ret, NA_PROTONOSUPPORT,
                "Unsupported address format");
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_key_lookup(struct na_ofi_class *na_ofi_class,
    struct na_ofi_addr_key *addr_key, struct na_ofi_addr **na_ofi_addr_p)
{
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret;

    /* Lookup address */
    na_ofi_addr =
        na_ofi_addr_map_lookup(&na_ofi_class->domain->addr_map, addr_key);
    if (na_ofi_addr == NULL) {
        na_return_t na_ret;

        NA_LOG_SUBSYS_DEBUG(
            addr, "Address was not found, attempting to insert it");

        /* Insert new entry and create new address if needed */
        na_ret = na_ofi_addr_map_insert(na_ofi_class,
            &na_ofi_class->domain->addr_map, addr_key, &na_ofi_addr);
        NA_CHECK_SUBSYS_ERROR(addr, na_ret != NA_SUCCESS && na_ret != NA_EXIST,
            error, ret, na_ret, "Could not insert new address");
    }

    na_ofi_addr_ref_incr(na_ofi_addr);

    *na_ofi_addr_p = na_ofi_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
na_ofi_addr_key_hash(hg_hash_table_key_t key)
{
    struct na_ofi_addr_key *addr_key = (struct na_ofi_addr_key *) key;
    uint32_t hi, lo;

    hi = (uint32_t) (addr_key->val >> 32);
    lo = (addr_key->val & 0xFFFFFFFFU);

    return ((hi & 0xFFFF0000U) | (lo & 0xFFFFU));
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_addr_key_equal_default(
    hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    /* Only when 64-bit unique keys can be generated */
    return ((struct na_ofi_addr_key *) key1)->val ==
           ((struct na_ofi_addr_key *) key2)->val;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_addr_key_equal_sin6(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    struct na_ofi_addr_key *addr_key1 = (struct na_ofi_addr_key *) key1,
                           *addr_key2 = (struct na_ofi_addr_key *) key2;

    if (addr_key1->addr.sin6.sin6_port != addr_key2->addr.sin6.sin6_port)
        return 0;

    return (
        memcmp(&addr_key1->addr.sin6.sin6_addr, &addr_key2->addr.sin6.sin6_addr,
            sizeof(addr_key1->addr.sin6.sin6_addr)) == 0);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_addr_key_equal_sib(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    struct na_ofi_addr_key *addr_key1 = (struct na_ofi_addr_key *) key1,
                           *addr_key2 = (struct na_ofi_addr_key *) key2;

    if (addr_key1->addr.sib.sib_pkey != addr_key2->addr.sib.sib_pkey ||
        addr_key1->addr.sib.sib_scope_id != addr_key2->addr.sib.sib_scope_id ||
        addr_key1->addr.sib.sib_sid != addr_key2->addr.sib.sib_sid)
        return 0;

    return (memcmp(&addr_key1->addr.sib.sib_addr, &addr_key2->addr.sib.sib_addr,
                sizeof(addr_key1->addr.sib.sib_addr)) == 0);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE struct na_ofi_addr *
na_ofi_addr_map_lookup(
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key)
{
    hg_hash_table_value_t value = NULL;

    /* Lookup key */
    hg_thread_rwlock_rdlock(&na_ofi_map->lock);
    value = hg_hash_table_lookup(
        na_ofi_map->key_map, (hg_hash_table_key_t) addr_key);
    hg_thread_rwlock_release_rdlock(&na_ofi_map->lock);

    return (value == HG_HASH_TABLE_NULL) ? NULL : (struct na_ofi_addr *) value;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_map_insert(struct na_ofi_class *na_ofi_class,
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key,
    struct na_ofi_addr **na_ofi_addr_p)
{
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ofi_map->lock);

    /* Look up again to prevent race between lock release/acquire */
    na_ofi_addr = (struct na_ofi_addr *) hg_hash_table_lookup(
        na_ofi_map->key_map, (hg_hash_table_key_t) addr_key);
    if (na_ofi_addr) {
        ret = NA_EXIST; /* Entry already exists */
        goto out;
    }

    /* Allocate address */
    ret = na_ofi_addr_create(na_ofi_class, addr_key, &na_ofi_addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not allocate address");

    /* Insert addr into AV if key not found */
    rc = fi_av_insert(na_ofi_class->domain->fi_av, &na_ofi_addr->addr_key.addr,
        1, &na_ofi_addr->fi_addr, 0 /* flags */, NULL);
    NA_CHECK_SUBSYS_ERROR(addr, rc < 1, error, ret, na_ofi_errno_to_na(-rc),
        "fi_av_insert() failed, inserted: %d", rc);

    NA_LOG_SUBSYS_DEBUG(
        addr, "Inserted new addr, FI addr is %" PRIu64, na_ofi_addr->fi_addr);

    /* Insert new value to secondary map to look up by FI addr and prevent
     * fi_av_lookup() followed by map lookup call */
    rc = hg_hash_table_insert(na_ofi_map->fi_map,
        (hg_hash_table_key_t) &na_ofi_addr->fi_addr,
        (hg_hash_table_value_t) na_ofi_addr);
    NA_CHECK_SUBSYS_ERROR(
        addr, rc == 0, out, ret, NA_NOMEM, "hg_hash_table_insert() failed");

    /* Insert new value to primary map */
    rc = hg_hash_table_insert(na_ofi_map->key_map,
        (hg_hash_table_key_t) &na_ofi_addr->addr_key,
        (hg_hash_table_value_t) na_ofi_addr);
    NA_CHECK_SUBSYS_ERROR(
        addr, rc == 0, error, ret, NA_NOMEM, "hg_hash_table_insert() failed");

out:
    hg_thread_rwlock_release_wrlock(&na_ofi_map->lock);

    *na_ofi_addr_p = na_ofi_addr;

    return ret;

error:
    hg_thread_rwlock_release_wrlock(&na_ofi_map->lock);
    if (na_ofi_addr)
        na_ofi_addr_destroy(na_ofi_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_map_remove(
    struct na_ofi_map *na_ofi_map, struct na_ofi_addr_key *addr_key)
{
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ofi_map->lock);

    na_ofi_addr = (struct na_ofi_addr *) hg_hash_table_lookup(
        na_ofi_map->key_map, (hg_hash_table_key_t) addr_key);
    if (na_ofi_addr == NULL)
        goto unlock;

    /* Remove addr key from primary map */
    rc = hg_hash_table_remove(
        na_ofi_map->key_map, (hg_hash_table_key_t) addr_key);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 1, unlock, ret, NA_NOENTRY,
        "hg_hash_table_remove() failed");

    /* Remove FI addr from secondary map */
    rc = hg_hash_table_remove(
        na_ofi_map->fi_map, (hg_hash_table_key_t) &na_ofi_addr->fi_addr);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 1, unlock, ret, NA_NOENTRY,
        "hg_hash_table_remove() failed");

    /* Remove address from AV */
    rc = fi_av_remove(na_ofi_addr->class->domain->fi_av, &na_ofi_addr->fi_addr,
        1, 0 /* flags */);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, unlock, ret, na_ofi_errno_to_na(-rc),
        "fi_av_remove() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    NA_LOG_SUBSYS_DEBUG(
        addr, "Removed addr for FI addr %" PRIu64, na_ofi_addr->fi_addr);

    na_ofi_addr->fi_addr = 0;

unlock:
    hg_thread_rwlock_release_wrlock(&na_ofi_map->lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
na_ofi_fi_addr_hash(hg_hash_table_key_t key)
{
    fi_addr_t fi_addr = *((fi_addr_t *) key);
    uint32_t hi, lo;

    hi = (uint32_t) (fi_addr >> 32);
    lo = (fi_addr & 0xFFFFFFFFU);

    return ((hi & 0xFFFF0000U) | (lo & 0xFFFFU));
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_fi_addr_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    return *((fi_addr_t *) key1) == *((fi_addr_t *) key2);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE struct na_ofi_addr *
na_ofi_fi_addr_map_lookup(struct na_ofi_map *na_ofi_map, fi_addr_t *fi_addr)
{
    hg_hash_table_value_t value = NULL;

    /* Lookup key */
    hg_thread_rwlock_rdlock(&na_ofi_map->lock);
    value =
        hg_hash_table_lookup(na_ofi_map->fi_map, (hg_hash_table_key_t) fi_addr);
    hg_thread_rwlock_release_rdlock(&na_ofi_map->lock);

    return (value == HG_HASH_TABLE_NULL) ? NULL : (struct na_ofi_addr *) value;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_provider_check(
    enum na_ofi_prov_type prov_type, const char *user_requested_protocol)
{
    int rc;
    struct fi_info *cur;
    struct fi_info *prev = NULL;
    size_t avail_len = 0;
    char *avail;
    struct fi_info *providers = NULL;

    /* Query OFI without hints to determine which providers are present. */
    rc = fi_getinfo(NA_OFI_VERSION, NULL, NULL, 0, NULL, &providers);
    if (rc != 0)
        return;

    /* look for match */
    for (cur = providers; cur; cur = cur->next) {
        if (!strcmp(cur->fabric_attr->prov_name, na_ofi_prov_name[prov_type])) {
            /* The provider is there at least; follow normal error
             * handling path rather than printing a special message.
             */
            fi_freeinfo(providers);
            return;
        }
        if (!prev ||
            strcmp(prev->fabric_attr->prov_name, cur->fabric_attr->prov_name)) {
            /* calculate how large of a string we need to hold
             * provider list for potential error message */
            avail_len += strlen(cur->fabric_attr->prov_name) + 1;
        }
        prev = cur;
    }

    prev = NULL;
    avail = calloc(avail_len + 1, 1);
    if (!avail) {
        /* This function is best effort; don't further obfuscate root error
         * with a memory allocation problem.  Just return.
         */
        fi_freeinfo(providers);
        return;
    }

    /* generate list of available providers */
    for (cur = providers; cur; cur = cur->next) {
        if (!prev ||
            strcmp(prev->fabric_attr->prov_name, cur->fabric_attr->prov_name)) {
            /* construct comma delimited list */
            strcat(avail, cur->fabric_attr->prov_name);
            strcat(avail, " ");
        }
        prev = cur;
    }
    /* truncate final comma */
    avail[strlen(avail) - 1] = '\0';

    /* display error message */
    NA_LOG_SUBSYS_ERROR(fatal,
        "Requested OFI provider \"%s\" (derived from \"%s\"\n"
        "   protocol) is not available. Please re-compile libfabric with "
        "support for\n"
        "   \"%s\" or use one of the following available providers:\n"
        "   %s",
        na_ofi_prov_name[prov_type], user_requested_protocol,
        na_ofi_prov_name[prov_type], avail);

    free(avail);
    fi_freeinfo(providers);

    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_getinfo(enum na_ofi_prov_type prov_type, const struct na_ofi_info *info,
    struct fi_info **fi_info_p)
{
    struct fi_info *hints = NULL;
    const char *node = NULL, *service = NULL;
    uint64_t flags = 0;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Hints to query and filter providers */
    hints = fi_allocinfo();
    NA_CHECK_SUBSYS_ERROR(
        cls, hints == NULL, out, ret, NA_NOMEM, "fi_allocinfo() failed");

    /* Protocol name is provider name, filter out providers within libfabric */
    hints->fabric_attr->prov_name = strdup(na_ofi_prov_name[prov_type]);
    NA_CHECK_SUBSYS_ERROR(cls, hints->fabric_attr->prov_name == NULL, cleanup,
        ret, NA_NOMEM, "Could not duplicate name");

    /**
     * FI_ASYNC_IOV mode indicates  that  the  application  must  provide  the
     * buffering needed for the IO vectors. When set, an application must not
     * modify an IO vector  of  length  >  1, including  any  related  memory
     * descriptor array, until the associated operation has completed.
     */
    hints->mode = FI_ASYNC_IOV;
    if (na_ofi_prov_flags[prov_type] & NA_OFI_CONTEXT2)
        hints->mode |= FI_CONTEXT2;
    else
        hints->mode |= FI_CONTEXT;

    /* ep_type: reliable datagram (connection-less) */
    hints->ep_attr->type = FI_EP_RDM;

    /* set endpoint protocol */
    NA_CHECK_SUBSYS_ERROR(cls,
        na_ofi_prov_ep_proto[prov_type] <= FI_PROTO_UNSPEC, cleanup, ret,
        NA_PROTONOSUPPORT, "Unsupported endpoint protocol (%d)",
        na_ofi_prov_ep_proto[prov_type]);
    hints->ep_attr->protocol = (uint32_t) na_ofi_prov_ep_proto[prov_type];

    /* caps: capabilities required for all providers */
    hints->caps = FI_TAGGED | FI_RMA;

    /* add any additional caps that are particular to this provider */
    hints->caps |= na_ofi_prov_extra_caps[prov_type];

    /**
     * msg_order: guarantee that messages with same tag are ordered.
     * (FI_ORDER_SAS - Send after send. If set, message send operations,
     *  including tagged sends, are transmitted in the order submitted relative
     *  to other message send. If not set, message sends may be transmitted out
     *  of order from their submission).
     */
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->tx_attr->comp_order = FI_ORDER_NONE; /* No send completion order */
    /* Generate completion event when it is safe to re-use buffer */
    hints->tx_attr->op_flags = FI_INJECT_COMPLETE | FI_COMPLETION;
    hints->rx_attr->op_flags = FI_COMPLETION;

    /* all providers should support this */
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->domain_attr->av_type = FI_AV_MAP;

    /* Resource management will be enabled for this provider domain. */
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;

    /**
     * this is the requested MR mode (i.e., what we currently support),
     * cleared MR mode bits (depending on provider) are later checked at the
     * appropriate time.
     */
    hints->domain_attr->mr_mode =
        NA_OFI_MR_BASIC_REQ | FI_MR_LOCAL | FI_MR_ENDPOINT;

    /* set default progress mode */
    hints->domain_attr->control_progress = na_ofi_prov_progress[prov_type];
    hints->domain_attr->data_progress = na_ofi_prov_progress[prov_type];

    if (info) {
        /* Use addr format if not FI_FORMAT_UNSPEC */
        NA_CHECK_SUBSYS_ERROR(cls, info->addr_format <= FI_FORMAT_UNSPEC,
            cleanup, ret, NA_PROTONOSUPPORT, "Unsupported address format (%d)",
            info->addr_format);
        hints->addr_format = (uint32_t) info->addr_format;

        /* Ask for HMEM support */
        if (info->use_hmem && (na_ofi_prov_flags[prov_type] & NA_OFI_HMEM)) {
            hints->caps |= FI_HMEM;
            hints->domain_attr->mr_mode |= FI_MR_HMEM;
        }

        /* Set src addr hints (FI_SOURCE must not be set in that case) */
        if (info->src_addr) {
            hints->src_addr = info->src_addr;
            hints->src_addrlen = info->src_addrlen;
        } else if (info->node && info->service) {
            /* For provider node resolution (always pass a numeric address) */
            flags = FI_SOURCE | FI_NUMERICHOST;
            node = info->node;
            service = info->service;
            NA_LOG_SUBSYS_DEBUG(cls,
                "Passing node/service (%s,%s) to fi_getinfo()", node, service);
        }
    }

    /* Retrieve list of all providers supported with above requirement hints */
    rc = fi_getinfo(NA_OFI_VERSION, node, service, flags, hints, fi_info_p);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, cleanup, ret, na_ofi_errno_to_na(-rc),
        "fi_getinfo(%s) failed, rc: %d (%s)", hints->fabric_attr->prov_name, rc,
        fi_strerror(-rc));

cleanup:
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = NULL;
    fi_freeinfo(hints);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_freeinfo(struct fi_info *fi_info)
{
    /* Prevent fi_freeinfo from attempting to free the key */
    if (fi_info->domain_attr->auth_key)
        fi_info->domain_attr->auth_key = NULL;
    if (fi_info->domain_attr->auth_key_size)
        fi_info->domain_attr->auth_key_size = 0;

    fi_freeinfo(fi_info);
}

/*---------------------------------------------------------------------------*/
static bool
na_ofi_match_provider(
    const struct na_ofi_verify_info *verify_info, const struct fi_info *fi_info)
{
    /* Domain must match expected address format (keep this check as OFI does
     * not seem to filter providers on addr_format) */
    if ((uint32_t) verify_info->addr_format != fi_info->addr_format)
        return false;

    /* Does not match provider name */
    if (strcmp(na_ofi_prov_name[verify_info->prov_type],
            fi_info->fabric_attr->prov_name) != 0)
        return false;

    /* Does not match domain name (if provided) */
    if (verify_info->domain_name && verify_info->domain_name[0] != '\0' &&
        strcmp(verify_info->domain_name, fi_info->domain_attr->name) != 0)
        return false;

        /* Match loc info as a last resort if nothing else was provided */
#ifdef NA_HAS_HWLOC
    if (verify_info->loc_info && fi_info->nic && fi_info->nic->bus_attr &&
        fi_info->nic->bus_attr->bus_type == FI_BUS_PCI) {
        const struct fi_pci_attr *pci = &fi_info->nic->bus_attr->attr.pci;
        return na_loc_check_pcidev(verify_info->loc_info, pci->domain_id,
            pci->bus_id, pci->device_id, pci->function_id);
    }
#endif

    /* Nothing prevents us from not picking that provider */
    return true;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_verify_info(enum na_ofi_prov_type prov_type, struct na_ofi_info *info,
    const char *domain_name, const struct na_loc_info *loc_info,
    struct fi_info **fi_info_p)
{
    struct fi_info *prov, *providers = NULL;
    struct na_ofi_verify_info verify_info =
        (struct na_ofi_verify_info){.prov_type = prov_type,
            .addr_format = info->addr_format,
            .domain_name = domain_name,
            .loc_info = loc_info};
#ifdef NA_HAS_DEBUG
    unsigned int count = 0;
#endif
    na_return_t ret;

    ret = na_ofi_getinfo(prov_type, info, &providers);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "na_ofi_getinfo() failed");

#ifdef NA_HAS_DEBUG
    for (prov = providers; prov != NULL; prov = prov->next) {
        if (na_ofi_match_provider(&verify_info, prov)) {
            // NA_LOG_SUBSYS_DEBUG_EXT(cls, "Verbose FI info for provider",
            //     "#%u %s", count, fi_tostr(prov, FI_TYPE_INFO));
            count++;
        }
    }
    NA_LOG_SUBSYS_DEBUG(
        cls, "na_ofi_getinfo() returned %u candidate(s)", count);
#endif

    /* Try to find provider that matches protocol and domain/host name */
    for (prov = providers; prov != NULL; prov = prov->next) {
        if (na_ofi_match_provider(&verify_info, prov)) {
            NA_LOG_SUBSYS_DEBUG_EXT(cls, "FI info for selected provider", "%s",
                fi_tostr(prov, FI_TYPE_INFO));
            break;
        }
    }
    NA_CHECK_SUBSYS_ERROR(fatal, prov == NULL, error, ret, NA_NOENTRY,
        "No provider found for \"%s\" provider on domain \"%s\"",
        na_ofi_prov_name[prov_type], domain_name);

    /* Keep fi_info */
    *fi_info_p = fi_dupinfo(prov);
    NA_CHECK_SUBSYS_ERROR(cls, *fi_info_p == NULL, error, ret, NA_NOMEM,
        "Could not duplicate fi_info");

    /* Give ownshership of src_addr to FI info */
    info->src_addr = NULL;

    fi_freeinfo(providers);

    return NA_SUCCESS;

error:
    if (providers)
        fi_freeinfo(providers);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_parse_hostname_info(enum na_ofi_prov_type prov_type,
    const char *hostname_info, int addr_format, char **domain_name_p,
    char **node_p, char **service_p, void **src_addr_p, size_t *src_addrlen_p)
{
    char *hostname = NULL;
    char *domain_name = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Parse hostname info */
    switch (addr_format) {
        case FI_SOCKADDR_IN:
        case FI_SOCKADDR_IN6: {
            uint16_t port = 0;
            struct sockaddr *sa = NULL;
            char **ifa_name_p = NULL;
            socklen_t salen = 0;
            na_return_t na_ret;

            ret = na_ofi_parse_sin_info(
                hostname_info, &hostname, &port, &domain_name);
            NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Could not parse sin info");

            NA_LOG_SUBSYS_DEBUG(cls,
                "Found hostname: %s, port %" PRIu16 ", domain %s", hostname,
                port, domain_name);

            if (hostname == NULL) {
                char host[NA_OFI_MAX_URI_LEN];
                int rc;

                if (!port)
                    break; /* nothing to do */

                rc = gethostname(host, sizeof(host));
                NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, NA_PROTOCOL_ERROR,
                    "gethostname() failed (%s)", strerror(errno));

                hostname = strdup(host);
                NA_CHECK_SUBSYS_ERROR(cls, hostname == NULL, out, ret, NA_NOMEM,
                    "strdup() of host failed");
            }

            /* Attempt to resolve hostname / iface */
            NA_LOG_SUBSYS_DEBUG(
                cls, "Resolving name %s with port %" PRIu16, hostname, port);

            /* Only query interface name if domain name was not provided */
            if (domain_name == NULL &&
                (na_ofi_prov_flags[prov_type] & NA_OFI_DOM_IFACE))
                ifa_name_p = &domain_name;

            na_ret = na_ip_check_interface(hostname, port,
                (addr_format == FI_SOCKADDR_IN6) ? AF_INET6 : AF_INET,
                ifa_name_p, &sa, &salen);
            if (na_ret != NA_SUCCESS && domain_name == NULL) {
                NA_LOG_SUBSYS_WARNING(cls,
                    "Could not find matching interface for %s, "
                    "attempting to use it as domain name",
                    hostname);

                /* Pass domain name as hostname if not set */
                domain_name = strdup(hostname);
                NA_CHECK_SUBSYS_ERROR(cls, domain_name == NULL, out, ret,
                    NA_NOMEM, "strdup() of hostname failed");
            }

            /* Pass src addr information to avoid name resolution */
            *src_addr_p = (void *) sa;
            *src_addrlen_p = (size_t) salen;
            break;
        }
        case FI_ADDR_PSMX:
        case FI_ADDR_PSMX2:
        case FI_ADDR_OPX:
        case FI_ADDR_GNI:
        case FI_ADDR_STR:
            /* Nothing to do */
            break;
        case FI_SOCKADDR_IB:
            /* TODO we could potentially add support for native addresses */
            /* Simply dup info */
            domain_name = strdup(hostname_info);
            NA_CHECK_SUBSYS_ERROR(cls, domain_name == NULL, out, ret, NA_NOMEM,
                "strdup() of hostname_info failed");
            break;

        case FI_ADDR_CXI:
            ret = na_ofi_parse_cxi_info(hostname_info, node_p, service_p);
            NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Could not parse cxi info");

            /* Manually set domain name and use that for matching info if no
             * specific port was passed. */
            if ((*node_p != NULL) && (*service_p == NULL)) {
                domain_name = strdup(*node_p);
                NA_CHECK_SUBSYS_ERROR(cls, domain_name == NULL, out, ret,
                    NA_NOMEM, "strdup() of %s failed", *node_p);
            }
            break;

        default:
            NA_LOG_SUBSYS_ERROR(
                fatal, "Unsupported address format: %d", addr_format);
            return NA_PROTONOSUPPORT;
    }

    *domain_name_p = domain_name;

out:
    free(hostname);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_free_hostname_info(
    char *domain_name, char *node, char *service, void *src_addr)
{
    free(domain_name);
    free(node);
    free(service);
    free(src_addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_parse_sin_info(const char *hostname_info, char **resolve_name_p,
    uint16_t *port_p, char **domain_name_p)
{
    char domain_name[65];
    char *hostname = NULL;
    na_return_t ret;

    if (sscanf(hostname_info, ":%" SCNu16, port_p) == 1) {
        NA_LOG_SUBSYS_DEBUG(cls, "port=%" PRIu16, *port_p);
        /* Only port, e.g. ":12345" */
    } else if (sscanf(hostname_info, "%64[^/]/:%" SCNu16, domain_name,
                   port_p) == 2) {
        NA_LOG_SUBSYS_DEBUG(
            cls, "domain: %s, port: %" PRIu16, domain_name, *port_p);
        /* Domain and port, e.g. "lo/:12345" */
        *domain_name_p = strdup(domain_name);
        NA_CHECK_SUBSYS_ERROR(cls, *domain_name_p == NULL, error, ret, NA_NOMEM,
            "strdup() of host_name failed");
    } else {
        hostname = strdup(hostname_info);
        NA_CHECK_SUBSYS_ERROR(cls, hostname == NULL, error, ret, NA_NOMEM,
            "strdup() of host_name failed");

        /* Domain, hostname and port, e.g. "lo/localhost:12345" */
        if (strchr(hostname, ':')) {
            char *port_str = NULL;
            strtok_r(hostname, ":", &port_str);
            *port_p = (uint16_t) strtoul(port_str, NULL, 10);
        }

        /* Extract domain */
        if (strchr(hostname, '/')) {
            char *host_str = NULL;
            strtok_r(hostname, "/", &host_str);

            *domain_name_p = hostname;
            if (host_str && host_str[0] != '\0') {
                *resolve_name_p = strdup(host_str);
                NA_CHECK_SUBSYS_ERROR(cls, *resolve_name_p == NULL, error, ret,
                    NA_NOMEM, "strdup() of hostname failed");
            }
        } else
            *resolve_name_p = hostname;
    }

    return NA_SUCCESS;

error:
    free(hostname);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_parse_cxi_info(
    const char *hostname_info, char **node_p, char **service_p)
{
    char nic_name[5] = {"cxiX"}; /* cxi[0-9] */
    char pid_name[4];
    uint16_t pid = 0; /* [0-510] */
    uint16_t pid_mask = 0x1ff;
    char *node = NULL;
    na_return_t ret;

    /* Only port, e.g. ":510" */
    if ((sscanf(hostname_info, ":%" SCNu16, &pid) == 1) && (pid < pid_mask)) {
        NA_LOG_SUBSYS_DEBUG(cls, "PID: %" PRIu16, pid);
    }
    /* cxi[0-9]:port or cxi[0-9] */
    else if (((sscanf(hostname_info, "cxi%1[0-9]:%" SCNu16, &nic_name[3],
                   &pid) == 2) &&
                 (pid < pid_mask)) ||
             (sscanf(hostname_info, "cxi%1[0-9]", &nic_name[3]) == 1)) {
        NA_LOG_SUBSYS_DEBUG(cls, "NIC name: %s, PID: %" PRIu16, nic_name, pid);

        node = strdup(nic_name);
        NA_CHECK_SUBSYS_ERROR(cls, node == NULL, error, ret, NA_NOMEM,
            "strdup() of nic_name failed");
    } else
        NA_GOTO_SUBSYS_ERROR(cls, error, ret, NA_PROTONOSUPPORT,
            "Malformed CXI info, format is: cxi[0-9]:[0-510]");

    /* Let the service string be NULL if PID is 0 to prevent CXI failure on
     * endpoint open when same PID is used */
    if (pid > 0) {
        snprintf(pid_name, sizeof(pid_name), "%" PRIu16,
            (uint16_t) (pid & pid_mask));

        *service_p = strdup(pid_name);
        NA_CHECK_SUBSYS_ERROR(cls, *service_p == NULL, error, ret, NA_NOMEM,
            "strdup() of pid_name failed");
    }

    *node_p = node;

    return NA_SUCCESS;

error:
    free(node);
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_class *
na_ofi_class_alloc(void)
{
    struct na_ofi_class *na_ofi_class = NULL;
    int rc;

    /* Create private data */
    na_ofi_class = (struct na_ofi_class *) malloc(sizeof(*na_ofi_class));
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ofi_class == NULL, error,
        "Could not allocate NA private data class");
    memset(na_ofi_class, 0, sizeof(*na_ofi_class));
    hg_atomic_init32(&na_ofi_class->n_contexts, 0);

    /* Initialize queue / mutex */
    rc = hg_thread_mutex_init(&na_ofi_class->mutex);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_mutex_init() failed");

    /* Initialize addr pool */
    rc = hg_thread_spin_init(&na_ofi_class->addr_pool.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_spin_init() failed");
    HG_QUEUE_INIT(&na_ofi_class->addr_pool.queue);

    return na_ofi_class;

error:
    if (na_ofi_class)
        na_ofi_class_free(na_ofi_class);

    return NULL;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_class_free(struct na_ofi_class *na_ofi_class)
{
    na_return_t ret = NA_SUCCESS;

#ifdef NA_OFI_HAS_ADDR_POOL
    /* Free addresses */
    while (!HG_QUEUE_IS_EMPTY(&na_ofi_class->addr_pool.queue)) {
        struct na_ofi_addr *na_ofi_addr =
            HG_QUEUE_FIRST(&na_ofi_class->addr_pool.queue);
        HG_QUEUE_POP_HEAD(&na_ofi_class->addr_pool.queue, entry);

        na_ofi_addr_destroy(na_ofi_addr);
    }
#endif

    /* Close endpoint */
    if (na_ofi_class->endpoint) {
        ret = na_ofi_endpoint_close(na_ofi_class->endpoint);
        NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Could not close endpoint");
        na_ofi_class->endpoint = NULL;
    }

#ifdef NA_OFI_HAS_MEM_POOL
    if (na_ofi_class->mem_pool) {
        hg_mem_pool_destroy(na_ofi_class->mem_pool);
        na_ofi_class->mem_pool = NULL;
    }
#endif

    /* Close domain */
    if (na_ofi_class->domain) {
        ret = na_ofi_domain_close(na_ofi_class->domain);
        NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Could not close domain");
        na_ofi_class->domain = NULL;
    }

    /* Close fabric */
    if (na_ofi_class->fabric) {
        ret = na_ofi_fabric_close(na_ofi_class->fabric);
        NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Could not close fabric");
        na_ofi_class->fabric = NULL;
    }

    /* Free info */
    if (na_ofi_class->fi_info)
        na_ofi_freeinfo(na_ofi_class->fi_info);

    (void) hg_thread_mutex_destroy(&na_ofi_class->mutex);
    (void) hg_thread_spin_destroy(&na_ofi_class->addr_pool.lock);

    free(na_ofi_class);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_ofi_fabric_open(enum na_ofi_prov_type prov_type, struct fi_info *fi_info,
    struct na_ofi_fabric **na_ofi_fabric_p)
{
    struct na_ofi_fabric *na_ofi_fabric = NULL;
    na_return_t ret;
    int rc;

    /**
     * Look for existing fabrics. A fabric domain represents a collection of
     * hardware and software resources that access a single physical or virtual
     * network.
     */
    hg_thread_mutex_lock(&na_ofi_fabric_list_mutex_g);
    HG_LIST_FOREACH (na_ofi_fabric, &na_ofi_fabric_list_g, entry) {
        if ((strcmp(fi_info->fabric_attr->name, na_ofi_fabric->name) == 0) &&
            (strcmp(fi_info->fabric_attr->prov_name,
                 na_ofi_fabric->prov_name) == 0)) {
            na_ofi_fabric->refcount++;
            break;
        }
    }
    hg_thread_mutex_unlock(&na_ofi_fabric_list_mutex_g);

    if (na_ofi_fabric != NULL) {
        NA_LOG_SUBSYS_DEBUG_EXT(cls, "using existing fi_fabric", "%s",
            fi_tostr(fi_info->fabric_attr, FI_TYPE_FABRIC_ATTR));
        *na_ofi_fabric_p = na_ofi_fabric;
        return NA_SUCCESS;
    }

    na_ofi_fabric = (struct na_ofi_fabric *) malloc(sizeof(*na_ofi_fabric));
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_fabric == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_fabric");
    memset(na_ofi_fabric, 0, sizeof(*na_ofi_fabric));
    na_ofi_fabric->prov_type = prov_type;
    na_ofi_fabric->refcount = 1;

    /* Dup name */
    na_ofi_fabric->name = strdup(fi_info->fabric_attr->name);
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_fabric->name == NULL, error, ret,
        NA_NOMEM, "Could not duplicate fabric name");

    /* Dup provider name */
    na_ofi_fabric->prov_name = strdup(fi_info->fabric_attr->prov_name);
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_fabric->prov_name == NULL, error, ret,
        NA_NOMEM, "Could not duplicate prov_name");

    /* Open fi fabric */
    rc = fi_fabric(fi_info->fabric_attr, &na_ofi_fabric->fi_fabric, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_fabric() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    NA_LOG_SUBSYS_DEBUG_EXT(cls, "fi_fabric opened", "%s",
        fi_tostr(fi_info->fabric_attr, FI_TYPE_FABRIC_ATTR));

    /* Insert to global fabric list */
    hg_thread_mutex_lock(&na_ofi_fabric_list_mutex_g);
    HG_LIST_INSERT_HEAD(&na_ofi_fabric_list_g, na_ofi_fabric, entry);
    hg_thread_mutex_unlock(&na_ofi_fabric_list_mutex_g);

    *na_ofi_fabric_p = na_ofi_fabric;

    return NA_SUCCESS;

error:
    if (na_ofi_fabric) {
        free(na_ofi_fabric->name);
        free(na_ofi_fabric->prov_name);
        free(na_ofi_fabric);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_ofi_fabric_close(struct na_ofi_fabric *na_ofi_fabric)
{
    na_return_t ret;
    int rc;

    if (!na_ofi_fabric)
        return NA_SUCCESS;

    /* Remove from fabric list */
    hg_thread_mutex_lock(&na_ofi_fabric_list_mutex_g);
    if (--na_ofi_fabric->refcount > 0) {
        hg_thread_mutex_unlock(&na_ofi_fabric_list_mutex_g);
        return NA_SUCCESS;
    }

    /* Close fabric */
    if (na_ofi_fabric->fi_fabric) {
        rc = fi_close(&na_ofi_fabric->fi_fabric->fid);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_close() fabric failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_fabric->fi_fabric = NULL;
    }
    HG_LIST_REMOVE(na_ofi_fabric, entry);
    hg_thread_mutex_unlock(&na_ofi_fabric_list_mutex_g);

    free(na_ofi_fabric->name);
    free(na_ofi_fabric->prov_name);
    free(na_ofi_fabric);

    return NA_SUCCESS;

error:
    na_ofi_fabric->refcount++;
    hg_thread_mutex_unlock(&na_ofi_fabric_list_mutex_g);

    return ret;
}

/*---------------------------------------------------------------------------*/
#ifdef NA_OFI_HAS_EXT_GNI_H
static na_return_t
na_ofi_gni_set_domain_op_value(
    struct na_ofi_domain *na_ofi_domain, int op, void *value)
{
    struct fi_gni_ops_domain *gni_domain_ops;
    na_return_t ret = NA_SUCCESS;
    int rc;

    rc = fi_open_ops(&na_ofi_domain->fi_domain->fid, FI_GNI_DOMAIN_OPS_1, 0,
        (void **) &gni_domain_ops, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
        "fi_open_ops() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = gni_domain_ops->set_val(&na_ofi_domain->fi_domain->fid, op, value);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
        "gni_domain_ops->set_val() failed, rc: %d (%s)", rc, fi_strerror(-rc));

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_gni_get_domain_op_value(
    struct na_ofi_domain *na_ofi_domain, int op, void *value)
{
    struct fi_gni_ops_domain *gni_domain_ops;
    na_return_t ret = NA_SUCCESS;
    int rc;

    rc = fi_open_ops(&na_ofi_domain->fi_domain->fid, FI_GNI_DOMAIN_OPS_1, 0,
        (void **) &gni_domain_ops, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
        "fi_open_ops() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = gni_domain_ops->get_val(&na_ofi_domain->fi_domain->fid, op, value);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
        "gni_domain_ops->get_val() failed, rc: %d (%s)", rc, fi_strerror(-rc));

out:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_domain_open(const struct na_ofi_fabric *na_ofi_fabric,
    const char *auth_key, bool no_wait, struct fi_info *fi_info,
    struct na_ofi_domain **na_ofi_domain_p)
{
    struct na_ofi_domain *na_ofi_domain = NULL;
    struct fi_av_attr av_attr = {0};
    hg_hash_table_equal_func_t map_key_equal_func;
    na_return_t ret;
    int rc;

    na_ofi_domain = (struct na_ofi_domain *) malloc(sizeof(*na_ofi_domain));
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_domain == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_domain");
    memset(na_ofi_domain, 0, sizeof(*na_ofi_domain));
    hg_atomic_init64(&na_ofi_domain->requested_key, 0);

    HG_LOG_ADD_COUNTER32(
        na, &na_ofi_domain->mr_reg_count, "mr_reg_count", "MR reg count");

    /* Init rw lock */
    rc = hg_thread_rwlock_init(&na_ofi_domain->addr_map.lock);
    NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_rwlock_init() failed");

#if defined(NA_OFI_HAS_EXT_GNI_H)
    if (na_ofi_fabric->prov_type == NA_OFI_PROV_GNI && auth_key &&
        auth_key[0] != '\0') {
        na_ofi_domain->fi_gni_auth_key.type = GNIX_AKT_RAW;
        na_ofi_domain->fi_gni_auth_key.raw.protection_key =
            (uint32_t) strtoul(auth_key, NULL, 10);

        fi_info->domain_attr->auth_key =
            (void *) &na_ofi_domain->fi_gni_auth_key;
        fi_info->domain_attr->auth_key_size =
            sizeof(na_ofi_domain->fi_gni_auth_key);
    }
#elif defined(NA_OFI_HAS_EXT_CXI_H)
    /* Keep CXI auth key using the following format svc_id:vni */
    if (na_ofi_fabric->prov_type == NA_OFI_PROV_CXI && auth_key) {
        rc = sscanf(auth_key, "%" SCNu32 ":%" SCNu16,
            &na_ofi_domain->cxi_auth_key.svc_id,
            &na_ofi_domain->cxi_auth_key.vni);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 2, error, ret, NA_PROTONOSUPPORT,
            "Could not retrieve CXI auth key, format is \"svc_id:vni\"");

        fi_info->domain_attr->auth_key = (void *) &na_ofi_domain->cxi_auth_key;
        fi_info->domain_attr->auth_key_size =
            sizeof(na_ofi_domain->cxi_auth_key);
    }
#else
    (void) auth_key;
#endif

    /* Force manual progress if no wait set or do not support
     * FI_WAIT_FD/FI_WAIT_SET. */
    if (no_wait || !(na_ofi_prov_flags[na_ofi_fabric->prov_type] &
                       (NA_OFI_WAIT_SET | NA_OFI_WAIT_FD))) {
        na_ofi_domain->no_wait = true;

        fi_info->domain_attr->control_progress = FI_PROGRESS_MANUAL;
        fi_info->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    }

    /* Create the fi access domain */
    rc = fi_domain(
        na_ofi_fabric->fi_fabric, fi_info, &na_ofi_domain->fi_domain, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_domain() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Cache max number of contexts */
    na_ofi_domain->context_max =
        MIN(fi_info->domain_attr->tx_ctx_cnt, fi_info->domain_attr->rx_ctx_cnt);

    /* Cache max key */
    NA_CHECK_SUBSYS_ERROR(cls, fi_info->domain_attr->mr_key_size > 8, error,
        ret, NA_OVERFLOW, "MR key size (%zu) is not supported",
        fi_info->domain_attr->mr_key_size);

    na_ofi_domain->max_key =
        (fi_info->domain_attr->mr_key_size == 8)
            ? INT64_MAX
            : (int64_t) (1UL << (fi_info->domain_attr->mr_key_size * 8)) - 1;
    NA_LOG_SUBSYS_DEBUG(cls, "MR max key is %" PRId64, na_ofi_domain->max_key);

    NA_LOG_SUBSYS_DEBUG_EXT(cls, "fi_domain opened", "%s",
        fi_tostr(fi_info->domain_attr, FI_TYPE_DOMAIN_ATTR));

#ifdef NA_OFI_HAS_EXT_GNI_H
    if (na_ofi_fabric->prov_type == NA_OFI_PROV_GNI) {
        int32_t enable = 1;
#    ifdef NA_OFI_GNI_HAS_UDREG
        char *other_reg_type = "udreg";
        int32_t udreg_limit = NA_OFI_GNI_UDREG_REG_LIMIT;

        /* Enable use of udreg instead of internal MR cache */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_CACHE, &other_reg_type);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "Could not set domain op value for GNI_MR_CACHE");

        /* Experiments on Theta showed default value of 2048 too high if
         * launching multiple clients on one node */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_UDREG_REG_LIMIT, &udreg_limit);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
            "Could not set domain op value for GNI_MR_UDREG_REG_LIMIT");
#    endif

        /* Enable lazy deregistration in MR cache */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_CACHE_LAZY_DEREG, &enable);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
            "Could not set domain op value for GNI_MR_CACHE_LAZY_DEREG");

        /* Get mbox max msg size */
        ret = na_ofi_gni_get_domain_op_value(na_ofi_domain,
            GNI_MBOX_MSG_MAX_SIZE, &na_ofi_domain->eager_msg_size_max);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
            "Could not get domain op value for GNI_MBOX_MSG_MAX_SIZE");
    }
#endif

    /* Open fi address vector */
    av_attr.type = FI_AV_MAP;
    av_attr.rx_ctx_bits = NA_OFI_SEP_RX_CTX_BITS;
    rc = fi_av_open(
        na_ofi_domain->fi_domain, &av_attr, &na_ofi_domain->fi_av, NULL);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_av_open() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Create primary addr hash-table */
    switch ((int) fi_info->addr_format) {
        case FI_SOCKADDR_IN6:
            map_key_equal_func = na_ofi_addr_key_equal_sin6;
            break;
        case FI_SOCKADDR_IB:
            map_key_equal_func = na_ofi_addr_key_equal_sib;
            break;
        case FI_SOCKADDR_IN:
        case FI_ADDR_PSMX:
        case FI_ADDR_PSMX2:
        case FI_ADDR_OPX:
        case FI_ADDR_GNI:
        case FI_ADDR_CXI:
        case FI_ADDR_STR:
        default:
            map_key_equal_func = na_ofi_addr_key_equal_default;
            break;
    }

    na_ofi_domain->addr_map.key_map =
        hg_hash_table_new(na_ofi_addr_key_hash, map_key_equal_func);
    NA_CHECK_SUBSYS_ERROR(addr, na_ofi_domain->addr_map.key_map == NULL, error,
        ret, NA_NOMEM, "Could not allocate key map");

    /* Create secondary hash-table to lookup by fi_addr */
    na_ofi_domain->addr_map.fi_map =
        hg_hash_table_new(na_ofi_fi_addr_hash, na_ofi_fi_addr_equal);
    NA_CHECK_SUBSYS_ERROR(addr, na_ofi_domain->addr_map.fi_map == NULL, error,
        ret, NA_NOMEM, "Could not allocate FI addr map");

    *na_ofi_domain_p = na_ofi_domain;

    return NA_SUCCESS;

error:
    if (na_ofi_domain) {
        if (na_ofi_domain->fi_av)
            (void) fi_close(&na_ofi_domain->fi_av->fid);
        if (na_ofi_domain->fi_domain)
            (void) fi_close(&na_ofi_domain->fi_domain->fid);
        if (na_ofi_domain->addr_map.key_map)
            hg_hash_table_free(na_ofi_domain->addr_map.key_map);
        if (na_ofi_domain->addr_map.fi_map)
            hg_hash_table_free(na_ofi_domain->addr_map.fi_map);

        hg_thread_rwlock_destroy(&na_ofi_domain->addr_map.lock);
        free(na_ofi_domain);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_domain_close(struct na_ofi_domain *na_ofi_domain)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    if (!na_ofi_domain)
        goto out;

    /* Close AV */
    if (na_ofi_domain->fi_av) {
        rc = fi_close(&na_ofi_domain->fi_av->fid);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() AV failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_av = NULL;
    }

    /* Close domain */
    if (na_ofi_domain->fi_domain) {
        rc = fi_close(&na_ofi_domain->fi_domain->fid);
        NA_CHECK_SUBSYS_ERROR(cls, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() domain failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_domain = NULL;
    }

    if (na_ofi_domain->addr_map.key_map)
        hg_hash_table_free(na_ofi_domain->addr_map.key_map);
    if (na_ofi_domain->addr_map.fi_map)
        hg_hash_table_free(na_ofi_domain->addr_map.fi_map);

    hg_thread_rwlock_destroy(&na_ofi_domain->addr_map.lock);

    free(na_ofi_domain);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, bool no_wait,
    uint8_t max_contexts, struct fi_info *fi_info,
    struct na_ofi_endpoint **na_ofi_endpoint_p)
{
    struct na_ofi_endpoint *na_ofi_endpoint = NULL;
    na_return_t ret;

    na_ofi_endpoint =
        (struct na_ofi_endpoint *) malloc(sizeof(*na_ofi_endpoint));
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_endpoint == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_endpoint");
    memset(na_ofi_endpoint, 0, sizeof(*na_ofi_endpoint));

    if ((na_ofi_prov_flags[na_ofi_fabric->prov_type] & NA_OFI_SEP) &&
        max_contexts > 1) {
        ret = na_ofi_sep_open(
            na_ofi_domain, fi_info, max_contexts, na_ofi_endpoint);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "na_ofi_sep_open() failed");
    } else {
        ret = na_ofi_basic_ep_open(
            na_ofi_fabric, na_ofi_domain, fi_info, no_wait, na_ofi_endpoint);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "na_ofi_basic_ep_open() failed");
    }

    *na_ofi_endpoint_p = na_ofi_endpoint;

    return NA_SUCCESS;

error:
    free(na_ofi_endpoint);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_basic_ep_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, struct fi_info *fi_info,
    bool no_wait, struct na_ofi_endpoint *na_ofi_endpoint)
{
    na_return_t ret;
    int rc;

    NA_LOG_SUBSYS_DEBUG(cls, "Opening standard endpoint");

    /* Create a transport level communication endpoint */
    rc = fi_endpoint(
        na_ofi_domain->fi_domain, fi_info, &na_ofi_endpoint->fi_ep, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_endpoint() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Create event queues (CQ, wait sets) */
    ret = na_ofi_eq_open(
        na_ofi_fabric, na_ofi_domain, no_wait, &na_ofi_endpoint->eq);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not open event queues");

    /* Bind the CQ and AV to the endpoint */
    rc = fi_ep_bind(na_ofi_endpoint->fi_ep, &na_ofi_endpoint->eq->fi_cq->fid,
        FI_TRANSMIT | FI_RECV);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = fi_ep_bind(na_ofi_endpoint->fi_ep, &na_ofi_domain->fi_av->fid, 0);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Enable the endpoint for communication, and commits the bind operations */
    rc = fi_enable(na_ofi_endpoint->fi_ep);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_enable() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    NA_LOG_SUBSYS_DEBUG_EXT(cls, "fi_endpoint opened", "%s",
        fi_tostr(fi_info->ep_attr, FI_TYPE_EP_ATTR));

    return NA_SUCCESS;

error:
    if (na_ofi_endpoint->fi_ep != NULL) {
        (void) fi_close(&na_ofi_endpoint->fi_ep->fid);
        na_ofi_endpoint->fi_ep = NULL;
    }
    if (na_ofi_endpoint->eq != NULL) {
        (void) na_ofi_eq_close(na_ofi_endpoint->eq);
        na_ofi_endpoint->eq = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_sep_open(const struct na_ofi_domain *na_ofi_domain,
    struct fi_info *fi_info, uint8_t max_contexts,
    struct na_ofi_endpoint *na_ofi_endpoint)
{
    na_return_t ret;
    int rc;

    NA_LOG_SUBSYS_DEBUG(cls, "Opening SEP endpoint");

    /* Set max contexts */
    fi_info->ep_attr->tx_ctx_cnt = max_contexts;
    fi_info->ep_attr->rx_ctx_cnt = max_contexts;

    /* Create a transport level communication endpoint (sep) */
    rc = fi_scalable_ep(
        na_ofi_domain->fi_domain, fi_info, &na_ofi_endpoint->fi_ep, NULL);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_scalable_ep() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = fi_scalable_ep_bind(
        na_ofi_endpoint->fi_ep, &na_ofi_domain->fi_av->fid, 0);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Enable the endpoint for communication, and commits the bind operations */
    rc = fi_enable(na_ofi_endpoint->fi_ep);
    NA_CHECK_SUBSYS_ERROR(cls, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_enable() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    return NA_SUCCESS;

error:
    if (na_ofi_endpoint->fi_ep != NULL) {
        (void) fi_close(&na_ofi_endpoint->fi_ep->fid);
        na_ofi_endpoint->fi_ep = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_close(struct na_ofi_endpoint *na_ofi_endpoint)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    if (!na_ofi_endpoint)
        goto out;

    /* Valid only when not using SEP */
    if (na_ofi_endpoint->eq && na_ofi_endpoint->eq->retry_op_queue) {
        /* Check that unexpected op queue is empty */
        bool empty =
            HG_QUEUE_IS_EMPTY(&na_ofi_endpoint->eq->retry_op_queue->queue);
        NA_CHECK_SUBSYS_ERROR(ctx, empty == false, out, ret, NA_BUSY,
            "Retry op queue should be empty");
    }

    /* Close endpoint */
    if (na_ofi_endpoint->fi_ep) {
        rc = fi_close(&na_ofi_endpoint->fi_ep->fid);
        NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() endpoint failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_endpoint->fi_ep = NULL;
    }

    /* Close event queues */
    if (na_ofi_endpoint->eq) {
        ret = na_ofi_eq_close(na_ofi_endpoint->eq);
        NA_CHECK_SUBSYS_NA_ERROR(ctx, out, ret, "Could not close event queues");
    }

    /* Destroy source address */
    if (na_ofi_endpoint->src_addr)
        na_ofi_addr_destroy(na_ofi_endpoint->src_addr);

    free(na_ofi_endpoint);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_eq_open(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, bool no_wait,
    struct na_ofi_eq **na_ofi_eq_p)
{
    struct na_ofi_eq *na_ofi_eq = NULL;
    struct fi_cq_attr cq_attr = {0};
    na_return_t ret;
    int rc;

    na_ofi_eq = (struct na_ofi_eq *) malloc(sizeof(*na_ofi_eq));
    NA_CHECK_SUBSYS_ERROR(ctx, na_ofi_eq == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_eq");
    memset(na_ofi_eq, 0, sizeof(*na_ofi_eq));

    /* Initialize queue / mutex */
    na_ofi_eq->retry_op_queue = malloc(sizeof(*na_ofi_eq->retry_op_queue));
    NA_CHECK_SUBSYS_ERROR(ctx, na_ofi_eq->retry_op_queue == NULL, error, ret,
        NA_NOMEM, "Could not allocate retry_op_queue");
    HG_QUEUE_INIT(&na_ofi_eq->retry_op_queue->queue);
    hg_thread_spin_init(&na_ofi_eq->retry_op_queue->lock);

    if (!no_wait) {
        if (na_ofi_prov_flags[na_ofi_fabric->prov_type] & NA_OFI_WAIT_FD)
            cq_attr.wait_obj = FI_WAIT_FD; /* Wait on fd */
        else {
            struct fi_wait_attr wait_attr = {0};

            /* Open wait set for other providers. */
            wait_attr.wait_obj = FI_WAIT_UNSPEC;
            rc = fi_wait_open(
                na_ofi_fabric->fi_fabric, &wait_attr, &na_ofi_eq->fi_wait);
            NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, error, ret,
                na_ofi_errno_to_na(-rc), "fi_wait_open() failed, rc: %d (%s)",
                rc, fi_strerror(-rc));
            cq_attr.wait_obj = FI_WAIT_SET; /* Wait on wait set */
            cq_attr.wait_set = na_ofi_eq->fi_wait;
        }
    }
    cq_attr.wait_cond = FI_CQ_COND_NONE;
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    cq_attr.size = NA_OFI_CQ_DEPTH;
    rc =
        fi_cq_open(na_ofi_domain->fi_domain, &cq_attr, &na_ofi_eq->fi_cq, NULL);
    NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_cq_open failed, rc: %d (%s)", rc, fi_strerror(-rc));

    *na_ofi_eq_p = na_ofi_eq;

    return NA_SUCCESS;

error:
    if (na_ofi_eq != NULL) {
        if (na_ofi_eq->fi_cq != NULL) {
            (void) fi_close(&na_ofi_eq->fi_cq->fid);
            na_ofi_eq->fi_cq = NULL;
        }
        if (na_ofi_eq->fi_wait != NULL) {
            (void) fi_close(&na_ofi_eq->fi_wait->fid);
            na_ofi_eq->fi_wait = NULL;
        }
        if (na_ofi_eq->retry_op_queue) {
            hg_thread_spin_destroy(&na_ofi_eq->retry_op_queue->lock);
            free(na_ofi_eq->retry_op_queue);
            na_ofi_eq->retry_op_queue = NULL;
        }
        free(na_ofi_eq);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_eq_close(struct na_ofi_eq *na_ofi_eq)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Close completion queue */
    if (na_ofi_eq->fi_cq) {
        rc = fi_close(&na_ofi_eq->fi_cq->fid);
        NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() CQ failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_eq->fi_cq = NULL;
    }

    /* Close wait set */
    if (na_ofi_eq->fi_wait) {
        rc = fi_close(&na_ofi_eq->fi_wait->fid);
        NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() wait failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_eq->fi_wait = NULL;
    }

    if (na_ofi_eq->retry_op_queue) {
        hg_thread_spin_destroy(&na_ofi_eq->retry_op_queue->lock);
        free(na_ofi_eq->retry_op_queue);
    }

    free(na_ofi_eq);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_get_src_addr(struct na_ofi_class *na_ofi_class)
{
    struct na_ofi_addr_key addr_key;
    int addr_format = (int) na_ofi_class->fi_info->addr_format;
    size_t addrlen = na_ofi_prov_addr_size(addr_format);
    na_return_t ret;
    int rc;

    /* Make sure expected addr format len is same as OFI addr len. In the case
     * of FI_ADDR_STR, just make sure we do not exceed the max string length */
    if (addr_format == FI_ADDR_STR)
        NA_CHECK_SUBSYS_ERROR(addr,
            addrlen < na_ofi_class->fi_info->src_addrlen, error, ret,
            NA_PROTONOSUPPORT,
            "Address lengths do not match (expected %zu, got %zu)", addrlen,
            na_ofi_class->fi_info->src_addrlen);
    else
        NA_CHECK_SUBSYS_ERROR(addr,
            addrlen != na_ofi_class->fi_info->src_addrlen, error, ret,
            NA_PROTONOSUPPORT,
            "Address lengths do not match (expected %zu, got %zu)", addrlen,
            na_ofi_class->fi_info->src_addrlen);

    /* Retrieve endpoint addr */
    rc = fi_getname(
        &na_ofi_class->endpoint->fi_ep->fid, &addr_key.addr, &addrlen);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_getname() failed, rc: %d (%s), addrlen: %zu", rc, fi_strerror(-rc),
        addrlen);

    /* Create key from addr for faster lookups */
    addr_key.val = na_ofi_raw_addr_to_key(addr_format, &addr_key.addr);
    NA_CHECK_SUBSYS_ERROR(addr, addr_key.val == 0, error, ret,
        NA_PROTONOSUPPORT, "Could not generate key from addr");

    /* Lookup/insert self address so that we can use it to send to ourself */
    ret = na_ofi_addr_map_insert(na_ofi_class, &na_ofi_class->domain->addr_map,
        &addr_key, &na_ofi_class->endpoint->src_addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not insert src address");

    na_ofi_addr_ref_incr(na_ofi_class->endpoint->src_addr);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get_uri(const struct na_ofi_fabric *na_ofi_fabric,
    const struct na_ofi_domain *na_ofi_domain, char *buf, size_t *buf_size_p,
    const struct na_ofi_addr_key *addr_key)
{
    char fi_addr_str[NA_OFI_MAX_URI_LEN] = {'\0'}, *fi_addr_str_ptr;
    size_t fi_addr_strlen = NA_OFI_MAX_URI_LEN;
    size_t addr_strlen;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Convert FI address to a printable string */
    fi_av_straddr(
        na_ofi_domain->fi_av, &addr_key->addr, fi_addr_str, &fi_addr_strlen);
    NA_CHECK_SUBSYS_ERROR(addr, fi_addr_strlen > NA_OFI_MAX_URI_LEN, out, ret,
        NA_OVERFLOW, "fi_av_straddr() address truncated, addrlen: %zu",
        fi_addr_strlen);

    NA_LOG_SUBSYS_DEBUG(addr, "fi_av_straddr() returned %s", fi_addr_str);

    /* Remove unnecessary "://" prefix from string if present */
    if (strstr(fi_addr_str, "://")) {
        strtok_r(fi_addr_str, ":", &fi_addr_str_ptr);
        rc = strncmp(fi_addr_str_ptr, "//", 2);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 0, out, ret, NA_PROTONOSUPPORT,
            "Bad address string format");
        fi_addr_str_ptr += 2;
    } else
        fi_addr_str_ptr = fi_addr_str;

    addr_strlen =
        strlen(fi_addr_str_ptr) + strlen(na_ofi_fabric->prov_name) + 3;
    if (buf) {
        NA_CHECK_SUBSYS_ERROR(addr, addr_strlen >= *buf_size_p, out, ret,
            NA_OVERFLOW, "Buffer size (%zu) too small to copy addr",
            *buf_size_p);

        /* Generate URI */
        rc = snprintf(buf, *buf_size_p, "%s://%s", na_ofi_fabric->prov_name,
            fi_addr_str_ptr);
        NA_CHECK_SUBSYS_ERROR(addr, rc < 0 || rc > (int) *buf_size_p, out, ret,
            NA_OVERFLOW,
            "snprintf() failed or name truncated, rc: %d (expected %zu)", rc,
            (size_t) *buf_size_p);
    }
    *buf_size_p = addr_strlen + 1;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_addr *
na_ofi_addr_alloc(struct na_ofi_class *na_ofi_class)
{
    struct na_ofi_addr *na_ofi_addr;

    na_ofi_addr = calloc(1, sizeof(*na_ofi_addr));
    if (na_ofi_addr)
        na_ofi_addr->class = na_ofi_class;

    return na_ofi_addr;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_destroy(struct na_ofi_addr *na_ofi_addr)
{
    NA_LOG_SUBSYS_DEBUG(addr, "Destroying address %p", (void *) na_ofi_addr);

    na_ofi_addr_release(na_ofi_addr);
    free(na_ofi_addr);
}

/*---------------------------------------------------------------------------*/
#ifdef NA_OFI_HAS_ADDR_POOL
static struct na_ofi_addr *
na_ofi_addr_pool_get(struct na_ofi_class *na_ofi_class)
{
    struct na_ofi_addr *na_ofi_addr = NULL;

    hg_thread_spin_lock(&na_ofi_class->addr_pool.lock);
    na_ofi_addr = HG_QUEUE_FIRST(&na_ofi_class->addr_pool.queue);
    if (na_ofi_addr) {
        HG_QUEUE_POP_HEAD(&na_ofi_class->addr_pool.queue, entry);
        hg_thread_spin_unlock(&na_ofi_class->addr_pool.lock);
    } else {
        hg_thread_spin_unlock(&na_ofi_class->addr_pool.lock);
        /* Fallback to allocation if pool is empty */
        na_ofi_addr = na_ofi_addr_alloc(na_ofi_class);
    }

    return na_ofi_addr;
}
#endif

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_release(struct na_ofi_addr *na_ofi_addr)
{
    if (na_ofi_addr->addr_key.val) {
        /* Removal is not needed when finalizing */
        if (!na_ofi_addr->class->finalizing)
            na_ofi_addr_map_remove(
                &na_ofi_addr->class->domain->addr_map, &na_ofi_addr->addr_key);
        na_ofi_addr->addr_key.val = 0;
    }
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_reset(
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_addr_key *addr_key)
{
    /* One refcount for the caller to hold until addr_free */
    hg_atomic_init32(&na_ofi_addr->refcount, 1);

    /* Keep copy of the key */
    na_ofi_addr->addr_key = *addr_key;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_create(struct na_ofi_class *na_ofi_class,
    struct na_ofi_addr_key *addr_key, struct na_ofi_addr **na_ofi_addr_p)
{
    struct na_ofi_addr *na_ofi_addr;
    na_return_t ret;

#ifdef NA_OFI_HAS_ADDR_POOL
    na_ofi_addr = na_ofi_addr_pool_get(na_ofi_class);
#else
    na_ofi_addr = na_ofi_addr_alloc(na_ofi_class);
#endif
    NA_CHECK_SUBSYS_ERROR(addr, na_ofi_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate addr");

    na_ofi_addr_reset(na_ofi_addr, addr_key);

    NA_LOG_SUBSYS_DEBUG(addr, "Created address %p", (void *) na_ofi_addr);

    *na_ofi_addr_p = na_ofi_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_addr_ref_incr(struct na_ofi_addr *na_ofi_addr)
{
    hg_atomic_incr32(&na_ofi_addr->refcount);
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_ref_decr(struct na_ofi_addr *na_ofi_addr)
{
    /* If there are more references, return */
    if (hg_atomic_decr32(&na_ofi_addr->refcount))
        return;

#ifdef NA_OFI_HAS_ADDR_POOL
    na_ofi_addr_release(na_ofi_addr);

    /* Push address back to addr pool */
    hg_thread_spin_lock(&na_ofi_addr->class->addr_pool.lock);
    HG_QUEUE_PUSH_TAIL(
        &na_ofi_addr->class->addr_pool.queue, na_ofi_addr, entry);
    hg_thread_spin_unlock(&na_ofi_addr->class->addr_pool.lock);
#else
    na_ofi_addr_destroy(na_ofi_addr);
#endif
}

#ifndef NA_OFI_HAS_MEM_POOL
/*---------------------------------------------------------------------------*/
static NA_INLINE void *
na_ofi_mem_alloc(
    struct na_ofi_class *na_ofi_class, size_t size, struct fid_mr **mr_hdl)
{
    size_t page_size = (size_t) hg_mem_get_page_size();
    void *mem_ptr = NULL;
    int rc;

    /* Allocate backend buffer */
    mem_ptr = hg_mem_aligned_alloc(page_size, size);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, mem_ptr == NULL, out, "Could not allocate %d bytes", (int) size);
    memset(mem_ptr, 0, size);

    /* Register buffer */
    rc = na_ofi_mem_buf_register(
        mem_ptr, (size_t) size, (void **) mr_hdl, (void *) na_ofi_class);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, rc != 0, error, "Could not register buffer");

out:
    return mem_ptr;

error:
    hg_mem_aligned_free(mem_ptr);
    return NULL;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_mem_free(
    struct na_ofi_class *na_ofi_class, void *mem_ptr, struct fid_mr *mr_hdl)
{
    int rc;

    /* Release MR handle is there was any */
    rc = na_ofi_mem_buf_deregister((void *) mr_hdl, (void *) na_ofi_class);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, rc != 0, out, "Could not deregister buffer");

out:
    hg_mem_aligned_free(mem_ptr);
    return;
}
#endif /* NA_OFI_HAS_MEM_POOL */

/*---------------------------------------------------------------------------*/
static int
na_ofi_mem_buf_register(const void *buf, size_t len, void **handle, void *arg)
{
    struct na_ofi_class *na_ofi_class = (struct na_ofi_class *) arg;
    int ret = HG_UTIL_SUCCESS;

    /* Register memory if FI_MR_LOCAL is set and provider uses it */
    if (na_ofi_class->fi_info->domain_attr->mr_mode & FI_MR_LOCAL) {
        struct fid_mr *mr_hdl = NULL;
        int rc;

        rc = fi_mr_reg(na_ofi_class->domain->fi_domain, buf, len,
            FI_SEND | FI_RECV, 0 /* offset */, 0 /* requested key */,
            0 /* flags */, &mr_hdl, NULL /* context */);
        NA_CHECK_SUBSYS_ERROR(mem, rc != 0, out, ret, HG_UTIL_FAIL,
            "fi_mr_reg() failed, rc: %d (%s), mr_reg_count: %d", rc,
            fi_strerror(-rc),
            hg_atomic_get32(na_ofi_class->domain->mr_reg_count));
        hg_atomic_incr32(na_ofi_class->domain->mr_reg_count);
        *handle = (void *) mr_hdl;
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_ofi_mem_buf_deregister(void *handle, void *arg)
{
    int ret = HG_UTIL_SUCCESS;

    /* Release MR handle is there was any */
    if (handle) {
        struct fid_mr *mr_hdl = (struct fid_mr *) handle;
        struct na_ofi_class *na_ofi_class = (struct na_ofi_class *) arg;
        int rc = fi_close(&mr_hdl->fid);
        NA_CHECK_SUBSYS_ERROR(mem, rc != 0, out, ret, HG_UTIL_FAIL,
            "fi_close() mr_hdl failed, rc: %d (%s)", rc, fi_strerror(-rc));
        hg_atomic_decr32(na_ofi_class->domain->mr_reg_count);
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static uint64_t
na_ofi_mem_key_gen(struct na_ofi_domain *na_ofi_domain)
{
    return (hg_atomic_cas64(
               &na_ofi_domain->requested_key, na_ofi_domain->max_key, 0))
               ? 1 /* Incremented value */
               : (uint64_t) hg_atomic_incr64(&na_ofi_domain->requested_key);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send(na_context_t *context, na_cb_type_t cb_type, na_cb_t callback,
    void *arg, const struct na_ofi_msg_info *msg_info,
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_context *na_ofi_context = NA_OFI_CONTEXT(context);
    na_return_t ret;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_OFI_OP_RESET(
        na_ofi_op_id, context, FI_SEND, cb_type, callback, arg, na_ofi_addr);

    /* Keep copy of msg_info */
    na_ofi_op_id->info.msg = *msg_info;

    NA_LOG_SUBSYS_DEBUG(msg, "Posting msg send with tag=%" PRIu64 " (op id=%p)",
        msg_info->tag, (void *) na_ofi_op_id);

    /* Post the FI unexpected send request */
    rc = fi_tsend(na_ofi_context->fi_tx, msg_info->buf.const_ptr,
        msg_info->buf_size, msg_info->fi_mr, msg_info->fi_addr, msg_info->tag,
        &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN))
        na_ofi_op_retry(na_ofi_context, na_ofi_op_id);
    else
        NA_CHECK_SUBSYS_ERROR(msg, rc != 0, release, ret,
            na_ofi_errno_to_na((int) -rc), "fi_tsend() failed, rc: %zd (%s)",
            rc, fi_strerror((int) -rc));

    return NA_SUCCESS;

release:
    NA_OFI_OP_RELEASE(na_ofi_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv(na_context_t *context, na_cb_type_t cb_type, na_cb_t callback,
    void *arg, const struct na_ofi_msg_info *msg_info,
    struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_context *na_ofi_context = NA_OFI_CONTEXT(context);
    na_return_t ret;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_OFI_OP_RESET(
        na_ofi_op_id, context, FI_RECV, cb_type, callback, arg, na_ofi_addr);

    /* Keep copy of msg_info */
    na_ofi_op_id->info.msg = *msg_info;

    NA_LOG_SUBSYS_DEBUG(msg, "Posting msg recv with tag=%" PRIu64 " (op id=%p)",
        msg_info->tag, (void *) na_ofi_op_id);

    /* Post the FI expected recv request */
    rc = fi_trecv(na_ofi_context->fi_rx, msg_info->buf.ptr, msg_info->buf_size,
        msg_info->fi_mr, msg_info->fi_addr, msg_info->tag, msg_info->tag_mask,
        &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN))
        na_ofi_op_retry(na_ofi_context, na_ofi_op_id);
    else
        NA_CHECK_SUBSYS_ERROR(msg, rc != 0, release, ret,
            na_ofi_errno_to_na((int) -rc), "fi_trecv() failed, rc: %zd (%s)",
            rc, fi_strerror((int) -rc));

    return NA_SUCCESS;

release:
    NA_OFI_OP_RELEASE(na_ofi_op_id);

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_iov_get_index_offset(const struct iovec *iov, unsigned long iovcnt,
    na_offset_t offset, unsigned long *iov_start_index,
    na_offset_t *iov_start_offset)
{
    na_offset_t new_iov_offset = offset, next_offset = 0;
    unsigned long i, new_iov_start_index = 0;

    /* Get start index and handle offset */
    for (i = 0; i < iovcnt; i++) {
        next_offset += iov[i].iov_len;

        if (offset < next_offset) {
            new_iov_start_index = i;
            break;
        }
        new_iov_offset -= iov[i].iov_len;
    }

    *iov_start_index = new_iov_start_index;
    *iov_start_offset = new_iov_offset;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned long
na_ofi_iov_get_count(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, size_t len)
{
    size_t remaining_len =
        len - MIN(len, iov[iov_start_index].iov_len - iov_start_offset);
    unsigned long i, iov_index;

    for (i = 1, iov_index = iov_start_index + 1;
         remaining_len > 0 && iov_index < iovcnt; i++, iov_index++) {
        /* Decrease remaining len from the len of data */
        remaining_len -= MIN(remaining_len, iov[iov_index].iov_len);
    }

    return i;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_iov_translate(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, size_t len,
    struct iovec *new_iov, unsigned long new_iovcnt)
{
    size_t remaining_len = len;
    unsigned long i, iov_index;

    /* Offset is only within first segment */
    new_iov[0].iov_base =
        (char *) iov[iov_start_index].iov_base + iov_start_offset;
    new_iov[0].iov_len =
        MIN(remaining_len, iov[iov_start_index].iov_len - iov_start_offset);
    remaining_len -= new_iov[0].iov_len;

    for (i = 1, iov_index = iov_start_index + 1;
         remaining_len > 0 && i < new_iovcnt && iov_index < iovcnt;
         i++, iov_index++) {
        new_iov[i].iov_base = iov[iov_index].iov_base;
        new_iov[i].iov_len = MIN(remaining_len, iov[iov_index].iov_len);

        /* Decrease remaining len from the len of data */
        remaining_len -= new_iov[i].iov_len;
    }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_rma_iov_translate(const struct fi_info *fi_info, const struct iovec *iov,
    unsigned long iovcnt, uint64_t key, unsigned long iov_start_index,
    na_offset_t iov_start_offset, size_t len, struct fi_rma_iov *new_iov,
    unsigned long new_iovcnt)
{
    uint64_t addr;
    size_t remaining_len = len;
    unsigned long i, iov_index;

    /* Reference by virtual address, rather than a 0-based offset */
    addr = (fi_info->domain_attr->mr_mode & FI_MR_VIRT_ADDR)
               ? (uint64_t) iov[iov_start_index].iov_base
               : (uint64_t) iov[iov_start_index].iov_base -
                     (uint64_t) iov[0].iov_base;

    /* Offset is only within first segment */
    new_iov[0].addr = addr + iov_start_offset;
    new_iov[0].len =
        MIN(remaining_len, iov[iov_start_index].iov_len - iov_start_offset);
    new_iov[0].key = key;
    remaining_len -= new_iov[0].len;

    for (i = 1, iov_index = iov_start_index + 1;
         remaining_len > 0 && i < new_iovcnt && iov_index < iovcnt;
         i++, iov_index++) {
        addr = (fi_info->domain_attr->mr_mode & FI_MR_VIRT_ADDR)
                   ? (uint64_t) iov[iov_index].iov_base
                   : (uint64_t) iov[iov_index].iov_base -
                         (uint64_t) iov[0].iov_base;
        new_iov[i].addr = addr;
        new_iov[i].len = MIN(remaining_len, iov[iov_index].iov_len);
        new_iov[i].key = key;

        /* Decrease remaining len from the len of data */
        remaining_len -= new_iov[i].len;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_rma(struct na_ofi_class *na_ofi_class, na_context_t *context,
    na_cb_type_t cb_type, na_cb_t callback, void *arg,
    na_ofi_rma_op_t fi_rma_op, uint64_t fi_rma_flags,
    struct na_ofi_mem_handle *na_ofi_mem_handle_local, na_offset_t local_offset,
    struct na_ofi_mem_handle *na_ofi_mem_handle_remote,
    na_offset_t remote_offset, size_t length, struct na_ofi_addr *na_ofi_addr,
    uint8_t remote_id, struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_context *na_ofi_context = NA_OFI_CONTEXT(context);
    struct iovec *local_iov = NA_OFI_IOV(na_ofi_mem_handle_local),
                 *remote_iov = NA_OFI_IOV(na_ofi_mem_handle_remote);
    unsigned long local_iovcnt = na_ofi_mem_handle_local->desc.info.iovcnt,
                  remote_iovcnt = na_ofi_mem_handle_remote->desc.info.iovcnt;
    uint64_t remote_key = na_ofi_mem_handle_remote->desc.info.fi_mr_key;
    unsigned long local_iov_start_index = 0, remote_iov_start_index = 0;
    na_offset_t local_iov_start_offset = 0, remote_iov_start_offset = 0;
    struct iovec *liov;
    struct fi_rma_iov *riov;
    struct fi_msg_rma fi_msg_rma;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_OFI_OP_RESET(
        na_ofi_op_id, context, FI_RMA, cb_type, callback, arg, na_ofi_addr);

    na_ofi_op_id->info.rma.fi_rma_op = fi_rma_op;
    na_ofi_op_id->info.rma.fi_rma_flags = fi_rma_flags;

    /* Translate local offset */
    if (local_offset > 0)
        na_ofi_iov_get_index_offset(local_iov, local_iovcnt, local_offset,
            &local_iov_start_index, &local_iov_start_offset);

    if (length != na_ofi_mem_handle_local->desc.info.len)
        na_ofi_op_id->info.rma.local_iovcnt =
            na_ofi_iov_get_count(local_iov, local_iovcnt, local_iov_start_index,
                local_iov_start_offset, length);
    else
        na_ofi_op_id->info.rma.local_iovcnt = local_iovcnt;

    if (na_ofi_op_id->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX) {
        na_ofi_op_id->info.rma.local_iov.d = (struct iovec *) malloc(
            na_ofi_op_id->info.rma.local_iovcnt * sizeof(struct iovec));
        liov = na_ofi_op_id->info.rma.local_iov.d;
        NA_CHECK_SUBSYS_ERROR(rma, liov == NULL, error, ret, NA_NOMEM,
            "Could not allocate iovec");
    } else
        liov = na_ofi_op_id->info.rma.local_iov.s;

    na_ofi_iov_translate(local_iov, local_iovcnt, local_iov_start_index,
        local_iov_start_offset, length, liov,
        na_ofi_op_id->info.rma.local_iovcnt);

    /* Set local desc */
    na_ofi_op_id->info.rma.local_desc =
        fi_mr_desc(na_ofi_mem_handle_local->fi_mr);

    /* Translate remote offset */
    if (remote_offset > 0)
        na_ofi_iov_get_index_offset(remote_iov, remote_iovcnt, remote_offset,
            &remote_iov_start_index, &remote_iov_start_offset);

    if (length != na_ofi_mem_handle_remote->desc.info.len)
        na_ofi_op_id->info.rma.remote_iovcnt =
            na_ofi_iov_get_count(remote_iov, remote_iovcnt,
                remote_iov_start_index, remote_iov_start_offset, length);
    else
        na_ofi_op_id->info.rma.remote_iovcnt = remote_iovcnt;

    if (na_ofi_op_id->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX) {
        na_ofi_op_id->info.rma.remote_iov.d = (struct fi_rma_iov *) malloc(
            na_ofi_op_id->info.rma.remote_iovcnt * sizeof(struct fi_rma_iov));
        riov = na_ofi_op_id->info.rma.remote_iov.d;
        NA_CHECK_SUBSYS_ERROR(rma, riov == NULL, error, ret, NA_NOMEM,
            "Could not allocate rma iovec");
    } else
        riov = na_ofi_op_id->info.rma.remote_iov.s;

    na_ofi_rma_iov_translate(na_ofi_class->fi_info, remote_iov, remote_iovcnt,
        remote_key, remote_iov_start_index, remote_iov_start_offset, length,
        riov, na_ofi_op_id->info.rma.remote_iovcnt);

    na_ofi_op_id->info.rma.fi_addr =
        fi_rx_addr(na_ofi_addr->fi_addr, remote_id, NA_OFI_SEP_RX_CTX_BITS);

    /* Set RMA msg */
    NA_OFI_MSG_RMA_SET(fi_msg_rma, liov, riov, na_ofi_op_id);

    NA_LOG_SUBSYS_DEBUG(rma,
        "Posting RMA op (%s, op id=%p), iov_count=%zu, desc[0]=%p, "
        "msg_iov[0].iov_base=%p, msg_iov[0].iov_len=%zu, addr=%" PRIu64
        ", rma_iov_count=%zu, rma_iov[0].addr=%" PRIu64
        ", rma_iov[0].len=%zu, rma_iov[0].key=%" PRIu64
        ", context=%p, data=%" PRIu64,
        cb_type == NA_CB_GET ? "fi_readmsg" : "fi_writemsg",
        (void *) na_ofi_op_id, fi_msg_rma.iov_count, fi_msg_rma.desc[0],
        fi_msg_rma.msg_iov[0].iov_base, fi_msg_rma.msg_iov[0].iov_len,
        fi_msg_rma.addr, fi_msg_rma.rma_iov_count, fi_msg_rma.rma_iov[0].addr,
        fi_msg_rma.rma_iov[0].len, fi_msg_rma.rma_iov[0].key,
        fi_msg_rma.context, fi_msg_rma.data);

    /* Post the OFI RMA operation */
    rc = fi_rma_op(na_ofi_context->fi_tx, &fi_msg_rma, fi_rma_flags);
    if (unlikely(rc == -FI_EAGAIN))
        na_ofi_op_retry(na_ofi_context, na_ofi_op_id);
    else
        NA_CHECK_SUBSYS_ERROR(rma, rc != 0, error, ret,
            na_ofi_errno_to_na((int) -rc),
            "%s() failed, rc: %zd (%s), iov_count=%zu, desc[0]=%p, "
            "msg_iov[0].iov_base=%p, msg_iov[0].iov_len=%zu, addr=%" PRIu64
            ", rma_iov_count=%zu, rma_iov[0].addr=%" PRIu64
            ", rma_iov[0].len=%zu, rma_iov[0].key=%" PRIu64
            ", context=%p, data=%" PRIu64,
            cb_type == NA_CB_GET ? "fi_readmsg" : "fi_writemsg", rc,
            fi_strerror((int) -rc), fi_msg_rma.iov_count, fi_msg_rma.desc[0],
            fi_msg_rma.msg_iov[0].iov_base, fi_msg_rma.msg_iov[0].iov_len,
            fi_msg_rma.addr, fi_msg_rma.rma_iov_count,
            fi_msg_rma.rma_iov[0].addr, fi_msg_rma.rma_iov[0].len,
            fi_msg_rma.rma_iov[0].key, fi_msg_rma.context, fi_msg_rma.data);

out:
    return ret;

error:
    if (na_ofi_op_id->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX)
        free(na_ofi_op_id->info.rma.local_iov.d);
    if (na_ofi_op_id->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX)
        free(na_ofi_op_id->info.rma.remote_iov.d);

    NA_OFI_OP_RELEASE(na_ofi_op_id);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_read(na_context_t *context, size_t max_count,
    struct fi_cq_tagged_entry cq_events[], fi_addr_t src_addrs[],
    void **src_err_addr, size_t *src_err_addrlen, size_t *actual_count)
{
    struct fid_cq *cq_hdl = NA_OFI_CONTEXT(context)->eq->fi_cq;
    struct fi_cq_err_entry cq_err;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    rc = fi_cq_readfrom(cq_hdl, cq_events, max_count, src_addrs);
    if (rc > 0) { /* events available */
        *src_err_addrlen = 0;
        *actual_count = (size_t) rc;
        goto out;
    }
    if (rc == -FI_EAGAIN) { /* no event available */
        *src_err_addrlen = 0;
        *actual_count = 0;
        goto out;
    }
    NA_CHECK_SUBSYS_ERROR(poll, rc != -FI_EAVAIL, out, ret,
        na_ofi_errno_to_na((int) -rc), "fi_cq_readfrom() failed, rc: %zd (%s)",
        rc, fi_strerror((int) -rc));

    memset(&cq_err, 0, sizeof(cq_err));

    /* Prevent provider from internally allocating resources */
    cq_err.err_data = *src_err_addr;
    cq_err.err_data_size = *src_err_addrlen;

    /* Read error entry */
    rc = fi_cq_readerr(cq_hdl, &cq_err, 0 /* flags */);
    NA_CHECK_SUBSYS_ERROR(poll, rc != 1, out, ret,
        na_ofi_errno_to_na((int) -rc), "fi_cq_readerr() failed, rc: %zd (%s)",
        rc, fi_strerror((int) -rc));

    switch (cq_err.err) {
        case FI_ECANCELED: {
            struct na_ofi_op_id *na_ofi_op_id = NULL;

            NA_CHECK_SUBSYS_ERROR(op, cq_err.op_context == NULL, out, ret,
                NA_INVALID_ARG, "Invalid operation context");
            na_ofi_op_id =
                container_of(cq_err.op_context, struct na_ofi_op_id, fi_ctx);
            NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, out, ret,
                NA_INVALID_ARG, "Invalid operation ID");

            NA_CHECK_SUBSYS_ERROR(op,
                hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED,
                out, ret, NA_FAULT, "Operation ID was completed");
            NA_LOG_SUBSYS_DEBUG(op, "FI_ECANCELED event on operation ID %p",
                (void *) na_ofi_op_id);

            /* When tearing down connections, it is possible that operations
            will be canceled by libfabric itself.

            NA_CHECK_SUBSYS_WARNING(op,
                !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELED),
                "Operation ID was not canceled by user");
            */

            /* Complete operation in canceled state */
            na_ofi_complete(na_ofi_op_id, NA_CANCELED);
        } break;

        case FI_EADDRNOTAVAIL:
            /* Only one error event processed in that case */
            memcpy(&cq_events[0], &cq_err, sizeof(cq_events[0]));
            *src_err_addr = cq_err.err_data;
            *src_err_addrlen = cq_err.err_data_size;
            *actual_count = 1;
            break;

        default:
            NA_LOG_SUBSYS_WARNING(poll,
                "fi_cq_readerr() got err: %d (%s), "
                "prov_errno: %d (%s)",
                cq_err.err, fi_strerror(cq_err.err), cq_err.prov_errno,
                fi_cq_strerror(
                    cq_hdl, cq_err.prov_errno, cq_err.err_data, NULL, 0));

            if (cq_err.op_context == NULL)
                break;
            else {
                struct na_ofi_op_id *na_ofi_op_id = container_of(
                    cq_err.op_context, struct na_ofi_op_id, fi_ctx);
                na_return_t na_ret = na_ofi_errno_to_na(cq_err.err);

                NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, out, ret,
                    NA_INVALID_ARG, "Invalid operation ID");
                NA_LOG_SUBSYS_DEBUG(op, "error event on operation ID %p",
                    (void *) na_ofi_op_id);

                NA_CHECK_SUBSYS_ERROR(op,
                    hg_atomic_get32(&na_ofi_op_id->status) &
                        NA_OFI_OP_COMPLETED,
                    out, ret, NA_FAULT, "Operation ID was completed");

                if (hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_ERRORED) &
                    NA_OFI_OP_CANCELED)
                    break;

                /* Abort other retries if peer is unreachable */
                if (na_ret == NA_HOSTUNREACH && na_ofi_op_id->addr)
                    na_ofi_op_retry_abort_addr(NA_OFI_CONTEXT(context),
                        na_ofi_op_id->addr->fi_addr, NA_HOSTUNREACH);

                /* Complete operation in error state */
                na_ofi_complete(na_ofi_op_id, na_ret);
            }
            break;
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_event(struct na_ofi_class *na_ofi_class,
    const struct fi_cq_tagged_entry *cq_event, fi_addr_t src_addr,
    void *src_err_addr, size_t src_err_addrlen)
{
    struct na_ofi_op_id *na_ofi_op_id =
        container_of(cq_event->op_context, struct na_ofi_op_id, fi_ctx);
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(op, na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    /* Cannot have an already completed operation ID, sanity check */
    NA_CHECK_SUBSYS_ERROR(op,
        hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED, out, ret,
        NA_FAULT, "Operation ID was completed");
    NA_CHECK_SUBSYS_ERROR(op, !(cq_event->flags & na_ofi_op_id->fi_op_flags),
        out, ret, NA_PROTONOSUPPORT,
        "Unsupported CQ event flags: 0x%" PRIx64 ", expected 0x%" PRIx64,
        cq_event->flags, na_ofi_op_id->fi_op_flags);

    NA_LOG_SUBSYS_DEBUG(op, "%s CQ event (op id=%p, len=%zu, tag=%" PRIu64 ")",
        na_cb_type_to_string(na_ofi_op_id->completion_data.callback_info.type),
        (void *) na_ofi_op_id, cq_event->len, cq_event->tag);

    switch (na_ofi_op_id->completion_data.callback_info.type) {
        case NA_CB_SEND_UNEXPECTED:
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_RECV_UNEXPECTED:
            ret = na_ofi_cq_process_recv_unexpected_event(na_ofi_class,
                na_ofi_op_id, src_addr, src_err_addr, src_err_addrlen,
                cq_event->tag, cq_event->len);
            NA_CHECK_SUBSYS_NA_ERROR(
                msg, out, ret, "Could not process unexpected recv event");
            break;
        case NA_CB_RECV_EXPECTED:
            ret = na_ofi_cq_process_recv_expected_event(
                na_ofi_op_id, cq_event->tag, cq_event->len);
            NA_CHECK_SUBSYS_NA_ERROR(
                msg, out, ret, "Could not process expected recv event");
            break;
        case NA_CB_PUT:
        case NA_CB_GET:
            na_ofi_cq_process_rma_event(na_ofi_op_id);
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(op, out, ret, NA_INVALID_ARG,
                "Operation type %d not supported",
                na_ofi_op_id->completion_data.callback_info.type);
    }

    /* Complete operation */
    na_ofi_complete(na_ofi_op_id, NA_SUCCESS);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_recv_unexpected_event(struct na_ofi_class *na_ofi_class,
    struct na_ofi_op_id *na_ofi_op_id, fi_addr_t src_addr, void *src_err_addr,
    size_t src_err_addrlen, uint64_t tag, size_t len)
{
    struct na_cb_info_recv_unexpected *recv_unexpected_info =
        &na_ofi_op_id->completion_data.callback_info.info.recv_unexpected;
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret;

    NA_CHECK_SUBSYS_ERROR(msg, (tag & ~NA_OFI_UNEXPECTED_TAG) > NA_OFI_MAX_TAG,
        error, ret, NA_OVERFLOW, "Invalid tag value %" PRIu64, tag);

    /* Use src_addr when available */
    if ((na_ofi_prov_extra_caps[na_ofi_class->fabric->prov_type] & FI_SOURCE) &&
        src_addr != FI_ADDR_UNSPEC) {
        NA_LOG_SUBSYS_DEBUG(
            addr, "Retrieving address for FI addr %" PRIu64, src_addr);

        na_ofi_addr = na_ofi_fi_addr_map_lookup(
            &na_ofi_class->domain->addr_map, &src_addr);
        NA_CHECK_SUBSYS_ERROR(addr, na_ofi_addr == NULL, error, ret, NA_NOENTRY,
            "No entry found for previously inserted src addr");

        na_ofi_addr_ref_incr(na_ofi_addr);
    } else {
        struct na_ofi_addr_key addr_key;
        int addr_format = (int) na_ofi_class->fi_info->addr_format;

        if (src_err_addr && src_err_addrlen) {
            NA_CHECK_SUBSYS_ERROR(addr, src_err_addrlen > sizeof(addr_key.addr),
                error, ret, NA_PROTONOSUPPORT,
                "src addr len (%zu) greater than max supported (%zu)",
                src_err_addrlen, sizeof(addr_key.addr));
            memcpy(&addr_key.addr, src_err_addr, src_err_addrlen);
        } else if (na_ofi_with_msg_hdr(na_ofi_class)) {
            ret = na_ofi_raw_addr_deserialize(addr_format, &addr_key.addr,
                na_ofi_op_id->info.msg.buf.ptr, len);
            NA_CHECK_SUBSYS_NA_ERROR(
                addr, error, ret, "Could not deserialize address key");
        } else
            NA_GOTO_SUBSYS_ERROR(addr, error, ret, NA_PROTONOSUPPORT,
                "Insufficient address information");

        /* Create key from addr for faster lookups */
        addr_key.val = na_ofi_raw_addr_to_key(addr_format, &addr_key.addr);
        NA_CHECK_SUBSYS_ERROR(addr, addr_key.val == 0, error, ret,
            NA_PROTONOSUPPORT, "Could not generate key from addr");

        /* Lookup key and create new addr if it does not exist */
        ret = na_ofi_addr_key_lookup(na_ofi_class, &addr_key, &na_ofi_addr);
        NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not lookup address");
    }

    /* Fill unexpected info */
    recv_unexpected_info->tag = (na_tag_t) (tag & NA_OFI_TAG_MASK);
    recv_unexpected_info->actual_buf_size = (size_t) len;
    recv_unexpected_info->source = (na_addr_t) na_ofi_addr;

    return NA_SUCCESS;

error:
    if (na_ofi_addr)
        na_ofi_addr_ref_decr(na_ofi_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_cq_process_recv_expected_event(
    struct na_ofi_op_id *na_ofi_op_id, uint64_t tag, size_t len)
{
    struct na_cb_info_recv_expected *recv_expected_info =
        &na_ofi_op_id->completion_data.callback_info.info.recv_expected;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(
        msg, tag > NA_OFI_MAX_TAG, out, ret, NA_OVERFLOW, "Invalid tag value");

    /* Check buf_size and msg_size */
    NA_CHECK_SUBSYS_ERROR(msg, len > na_ofi_op_id->info.msg.buf_size, out, ret,
        NA_MSGSIZE, "Expected recv msg size too large for buffer");
    recv_expected_info->actual_buf_size = (size_t) len;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_cq_process_rma_event(struct na_ofi_op_id *na_ofi_op_id)
{
    /* Can free extra IOVs here */
    if (na_ofi_op_id->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX) {
        free(na_ofi_op_id->info.rma.local_iov.d);
        na_ofi_op_id->info.rma.local_iov.d = NULL;
    }
    if (na_ofi_op_id->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX) {
        free(na_ofi_op_id->info.rma.remote_iov.d);
        na_ofi_op_id->info.rma.remote_iov.d = NULL;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_retries(struct na_ofi_context *na_ofi_context)
{
    struct na_ofi_op_queue *op_queue = na_ofi_context->eq->retry_op_queue;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    na_return_t ret;

    do {
        bool canceled = false;
        na_cb_type_t cb_type;
        ssize_t rc = 0;

        hg_thread_spin_lock(&op_queue->lock);
        na_ofi_op_id = HG_QUEUE_FIRST(&op_queue->queue);
        if (!na_ofi_op_id) {
            hg_thread_spin_unlock(&op_queue->lock);
            /* Queue is empty */
            break;
        }
        /* Dequeue OP ID */
        HG_QUEUE_POP_HEAD(&op_queue->queue, entry);
        hg_atomic_and32(&na_ofi_op_id->status, ~NA_OFI_OP_QUEUED);

        /* Check if OP ID was canceled */
        if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELING) {
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED);
            canceled = true;
        }
        hg_thread_spin_unlock(&op_queue->lock);

        if (canceled) {
            na_ofi_complete(na_ofi_op_id, NA_CANCELED);
            /* Try again */
            continue;
        }

        cb_type = na_ofi_op_id->completion_data.callback_info.type;
        NA_LOG_SUBSYS_DEBUG(op, "Attempting to retry operation %p (%s)",
            (void *) na_ofi_op_id, na_cb_type_to_string(cb_type));

        /* Retry operation */
        switch (cb_type) {
            case NA_CB_SEND_UNEXPECTED:
            case NA_CB_SEND_EXPECTED:
                rc = fi_tsend(na_ofi_context->fi_tx,
                    na_ofi_op_id->info.msg.buf.const_ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr, na_ofi_op_id->info.msg.tag,
                    &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_RECV_UNEXPECTED:
            case NA_CB_RECV_EXPECTED:
                rc = fi_trecv(na_ofi_context->fi_rx,
                    na_ofi_op_id->info.msg.buf.ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr, na_ofi_op_id->info.msg.tag,
                    na_ofi_op_id->info.msg.tag_mask, &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_PUT:
            case NA_CB_GET: {
                struct iovec *msg_iov = NA_OFI_MSG_IOV(na_ofi_op_id);
                struct fi_rma_iov *rma_iov = NA_OFI_RMA_IOV(na_ofi_op_id);
                struct fi_msg_rma fi_msg_rma;

                /* Set RMA msg */
                NA_OFI_MSG_RMA_SET(fi_msg_rma, msg_iov, rma_iov, na_ofi_op_id);
                rc = na_ofi_op_id->info.rma.fi_rma_op(na_ofi_context->fi_tx,
                    &fi_msg_rma, na_ofi_op_id->info.rma.fi_rma_flags);
                break;
            }
            default:
                NA_GOTO_SUBSYS_ERROR(op, error, ret, NA_INVALID_ARG,
                    "Operation type %d not supported", cb_type);
        }

        if (rc == 0) {
            /* If the operation got canceled while we retried it, attempt to
             * cancel it */
            if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELING) {
                ret = na_ofi_op_cancel(na_ofi_op_id);
                NA_CHECK_SUBSYS_NA_ERROR(
                    op, error, ret, "Could not cancel operation");
            }
            continue;
        } else if (rc == -FI_EAGAIN) {
            hg_time_t now;

            /* Do not retry past deadline */
            hg_time_get_current_ms(&now);
            if (hg_time_less(na_ofi_op_id->retry_deadline, now)) {
                NA_LOG_SUBSYS_ERROR(op,
                    "Retry time elapsed, aborting operation %p (%s)",
                    (void *) na_ofi_op_id, na_cb_type_to_string(cb_type));
                hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_ERRORED);
                na_ofi_complete(na_ofi_op_id, NA_TIMEOUT);
                continue;
            }

            hg_thread_spin_lock(&op_queue->lock);
            /* Do not repush OP ID if it was canceled in the meantime */
            if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELING) {
                hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED);
                canceled = true;
            } else {
                NA_LOG_SUBSYS_DEBUG(
                    op, "Re-pushing %p for retry", (void *) na_ofi_op_id);
                /* Re-push op ID to retry queue */
                HG_QUEUE_PUSH_TAIL(&op_queue->queue, na_ofi_op_id, entry);
                hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            }
            hg_thread_spin_unlock(&op_queue->lock);

            if (canceled) {
                na_ofi_complete(na_ofi_op_id, NA_CANCELED);
                /* Try again */
                continue;
            } else
                /* Do not attempt to retry again and continue making progress,
                 * otherwise we could loop indefinitely */
                break;
        } else {
            NA_LOG_SUBSYS_ERROR(op,
                "retry operation of %p (%s) failed, rc: %zd (%s)",
                (void *) na_ofi_op_id, na_cb_type_to_string(cb_type), rc,
                fi_strerror((int) -rc));

            /* Force internal completion in error mode */
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_ERRORED);
            na_ofi_complete(na_ofi_op_id, na_ofi_errno_to_na((int) -rc));
        }
    } while (1);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_retry(
    struct na_ofi_context *na_ofi_context, struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_op_queue *retry_op_queue = na_ofi_context->eq->retry_op_queue;

    NA_LOG_SUBSYS_DEBUG(op, "Pushing %p for retry (%s)", (void *) na_ofi_op_id,
        na_cb_type_to_string(na_ofi_op_id->completion_data.callback_info.type));

    /* Set retry deadline */
    hg_time_get_current_ms(&na_ofi_op_id->retry_deadline);
    na_ofi_op_id->retry_deadline = hg_time_add(
        na_ofi_op_id->retry_deadline, hg_time_from_ms(NA_OFI_OP_RETRY_TIMEOUT));

    /* Push op ID to retry queue */
    hg_thread_spin_lock(&retry_op_queue->lock);
    HG_QUEUE_PUSH_TAIL(&retry_op_queue->queue, na_ofi_op_id, entry);
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
    hg_thread_spin_unlock(&retry_op_queue->lock);
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_retry_abort_addr(
    struct na_ofi_context *na_ofi_context, fi_addr_t fi_addr, na_return_t ret)
{
    struct na_ofi_op_queue *op_queue = na_ofi_context->eq->retry_op_queue;
    struct na_ofi_op_id *na_ofi_op_id;

    NA_LOG_SUBSYS_ERROR(op,
        "Aborting all operations in retry queue to FI addr %" PRIu64, fi_addr);

    hg_thread_spin_lock(&op_queue->lock);
    HG_QUEUE_FOREACH (na_ofi_op_id, &op_queue->queue, entry) {
        if (!na_ofi_op_id->addr || na_ofi_op_id->addr->fi_addr != fi_addr)
            continue;

        HG_QUEUE_REMOVE(&op_queue->queue, na_ofi_op_id, na_ofi_op_id, entry);
        NA_LOG_SUBSYS_ERROR(op,
            "Aborting operation ID %p (%s) in retry queue to FI addr %" PRIu64,
            (void *) na_ofi_op_id,
            na_cb_type_to_string(
                na_ofi_op_id->completion_data.callback_info.type),
            fi_addr);
        hg_atomic_and32(&na_ofi_op_id->status, ~NA_OFI_OP_QUEUED);
        hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_ERRORED);
        na_ofi_complete(na_ofi_op_id, ret);
    }
    hg_thread_spin_unlock(&op_queue->lock);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_complete(struct na_ofi_op_id *na_ofi_op_id, na_return_t cb_ret)
{
    /* Mark op id as completed (independent of cb_ret) */
    hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    /* Set callback ret */
    na_ofi_op_id->completion_data.callback_info.ret = cb_ret;

    /* Add OP to NA completion queue */
    na_cb_completion_add(na_ofi_op_id->context, &na_ofi_op_id->completion_data);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_release(void *arg)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) arg;

    NA_CHECK_SUBSYS_WARNING(op,
        na_ofi_op_id &&
            (!(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED)),
        "Releasing resources from an uncompleted operation");

    if (na_ofi_op_id->addr) {
        na_ofi_addr_ref_decr(na_ofi_op_id->addr);
        na_ofi_op_id->addr = NULL;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_op_cancel(struct na_ofi_op_id *na_ofi_op_id)
{
    struct fid_ep *fi_ep = NULL;
    ssize_t rc;
    na_return_t ret;

    /* Let only one thread call fi_cancel() */
    if (hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED) &
        NA_OFI_OP_CANCELED)
        return NA_SUCCESS;

    switch (na_ofi_op_id->completion_data.callback_info.type) {
        case NA_CB_RECV_UNEXPECTED:
        case NA_CB_RECV_EXPECTED:
            fi_ep = NA_OFI_CONTEXT(na_ofi_op_id->context)->fi_rx;
            break;
        case NA_CB_SEND_UNEXPECTED:
        case NA_CB_SEND_EXPECTED:
        case NA_CB_PUT:
        case NA_CB_GET:
            fi_ep = NA_OFI_CONTEXT(na_ofi_op_id->context)->fi_tx;
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(op, error, ret, NA_INVALID_ARG,
                "Operation type %d not supported",
                na_ofi_op_id->completion_data.callback_info.type);
            break;
    }

    /* fi_cancel() is an asynchronous operation, either the operation
     * will be canceled and an FI_ECANCELED event will be generated
     * or it will show up in the regular completion queue.
     */
    rc = fi_cancel(&fi_ep->fid, &na_ofi_op_id->fi_ctx);
    NA_LOG_SUBSYS_DEBUG(
        op, "fi_cancel() rc: %d (%s)", (int) rc, fi_strerror((int) -rc));
    (void) rc;

    /* Work around segfault on fi_cq_signal() in some providers */
    if (na_ofi_prov_flags[na_ofi_op_id->na_ofi_class->fabric->prov_type] &
        NA_OFI_SIGNAL) {
        /* Signal CQ to wake up and no longer wait on FD */
        int rc_signal =
            fi_cq_signal(NA_OFI_CONTEXT(na_ofi_op_id->context)->eq->fi_cq);
        NA_CHECK_SUBSYS_ERROR(op, rc_signal != 0 && rc_signal != -ENOSYS, error,
            ret, na_ofi_errno_to_na(-rc_signal),
            "fi_cq_signal (op type %d) failed, rc: %d (%s)",
            na_ofi_op_id->completion_data.callback_info.type, rc_signal,
            fi_strerror(-rc_signal));
    }

    return NA_SUCCESS;

error:
    return ret;
}

/********************/
/* Plugin callbacks */
/********************/

static bool
na_ofi_check_protocol(const char *protocol_name)
{
    struct fi_info *prov, *providers = NULL;
    enum na_ofi_prov_type type;
    bool accept;
    na_return_t na_ret;

    type = na_ofi_prov_name_to_type(protocol_name);
    NA_CHECK_SUBSYS_ERROR(cls, type == NA_OFI_PROV_NULL, out, accept, false,
        "Protocol %s not supported", protocol_name);

/* Only the sockets provider is currently supported on macOS */
#ifdef __APPLE__
    NA_CHECK_SUBSYS_ERROR(fatal, type == NA_OFI_PROV_TCP, out, accept, false,
        "Protocol \"tcp\" not supported on macOS, please use \"sockets\" "
        "instead");
#endif

    /* Get info from provider (no node info) */
    na_ret = na_ofi_getinfo(type, NULL, &providers);
    if (na_ret != NA_SUCCESS) {
        /* getinfo failed.  This could be because Mercury was
         * linked against a libfabric library that was not compiled with
         * support for the desired provider.  Attempt to detect this case
         * and display a user-friendly error message.
         */
        na_ofi_provider_check(type, protocol_name);
        NA_GOTO_SUBSYS_ERROR(
            cls, out, accept, false, "na_ofi_getinfo() failed");
    }

    for (prov = providers; prov != NULL; prov = prov->next) {
        if (strcmp(na_ofi_prov_name[type], prov->fabric_attr->prov_name) == 0) {
            NA_LOG_SUBSYS_DEBUG(
                cls, "Matched provider: %s", prov->fabric_attr->prov_name);
            break;
        }
    }
    accept = (bool) (prov != NULL);

    fi_freeinfo(providers);

out:
    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_initialize(
    na_class_t *na_class, const struct na_info *na_info, bool NA_UNUSED listen)
{
    struct na_init_info na_init_info = NA_INIT_INFO_INITIALIZER;
    struct na_ofi_class *na_ofi_class = NULL;
    enum na_ofi_prov_type prov_type;
    bool no_wait;
    size_t msg_size_max;
    char *domain_name = NULL;
    struct na_ofi_info info = {.addr_format = FI_FORMAT_UNSPEC,
        .node = NULL,
        .service = NULL,
        .src_addr = NULL,
        .src_addrlen = 0,
        .use_hmem = false};
    struct na_loc_info *loc_info = NULL;
    na_return_t ret;
#ifdef NA_OFI_HAS_ADDR_POOL
    unsigned int i;
#endif

    NA_LOG_SUBSYS_DEBUG(cls,
        "Entering na_ofi_initialize() protocol_name \"%s\", host_name \"%s\"",
        na_info->protocol_name, na_info->host_name);

    /* Get init info and overwrite defaults */
    if (na_info->na_init_info)
        na_init_info = *na_info->na_init_info;

    /* Get provider type */
    prov_type = na_ofi_prov_name_to_type(na_info->protocol_name);
    NA_CHECK_SUBSYS_ERROR(fatal, prov_type == NA_OFI_PROV_NULL, error, ret,
        NA_INVALID_ARG, "Protocol %s not supported", na_info->protocol_name);

#if defined(NA_OFI_HAS_EXT_GNI_H) && defined(NA_OFI_GNI_HAS_UDREG)
    /* In case of GNI using udreg, we check to see whether
     * MPICH_GNI_NDREG_ENTRIES environment variable is set or not.  If not, this
     * code is not likely to work if Cray MPI is also used. Print error msg
     * suggesting workaround.
     */
    NA_CHECK_SUBSYS_ERROR(fatal,
        prov_type == NA_OFI_PROV_GNI && !getenv("MPICH_GNI_NDREG_ENTRIES"),
        error, ret, NA_INVALID_ARG,
        "ofi+gni provider requested, but the MPICH_GNI_NDREG_ENTRIES "
        "environment variable is not set.\n"
        "Please run this executable with "
        "\"export MPICH_GNI_NDREG_ENTRIES=1024\" to ensure compatibility.");
#endif

    /* Get addr format */
    info.addr_format =
        na_ofi_prov_addr_format(prov_type, na_init_info.addr_format);
    NA_CHECK_SUBSYS_ERROR(cls, info.addr_format <= FI_FORMAT_UNSPEC, error, ret,
        NA_PROTONOSUPPORT, "Unsupported address format");

    /* Use HMEM */
    if (na_init_info.request_mem_device) {
        NA_LOG_SUBSYS_DEBUG(cls, "Requesting use of memory devices");
        info.use_hmem = na_init_info.request_mem_device;
    }

    /* Parse hostname info and get domain name etc */
    if (na_info->host_name != NULL) {
        ret = na_ofi_parse_hostname_info(prov_type, na_info->host_name,
            info.addr_format, &domain_name, &info.node, &info.service,
            &info.src_addr, &info.src_addrlen);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "na_ofi_parse_hostname_info() failed");
    }

    /* Create new OFI class */
    na_ofi_class = na_ofi_class_alloc();
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_class == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI class");

#ifdef NA_HAS_HWLOC
    /* Use autodetect if we can't guess which domain to use */
    if ((na_ofi_prov_flags[prov_type] & NA_OFI_LOC_INFO) && !domain_name &&
        !info.src_addr && !info.node) {
        ret = na_loc_info_init(&loc_info);
        NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could init loc info");
    }
#endif

    /* Verify info */
    ret = na_ofi_verify_info(
        prov_type, &info, domain_name, loc_info, &na_ofi_class->fi_info);
#ifdef NA_HAS_HWLOC
    if (loc_info)
        na_loc_info_destroy(loc_info);
#endif
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not verify info for %s",
        na_ofi_prov_name[prov_type]);

    /* Open fabric */
    ret = na_ofi_fabric_open(
        prov_type, na_ofi_class->fi_info, &na_ofi_class->fabric);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not open fabric for %s",
        na_ofi_prov_name[prov_type]);

    /* Open domain */
    no_wait = na_init_info.progress_mode & NA_NO_BLOCK;
    ret = na_ofi_domain_open(na_ofi_class->fabric, na_init_info.auth_key,
        no_wait, na_ofi_class->fi_info, &na_ofi_class->domain);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret,
        "Could not open domain for %s, %s", na_ofi_prov_name[prov_type],
        na_ofi_class->fi_info->domain_attr->name);

    /* Make sure that domain is configured as no_wait */
    NA_CHECK_SUBSYS_WARNING(cls, no_wait != na_ofi_class->domain->no_wait,
        "Requested no_wait=%d, domain no_wait=%d", no_wait,
        na_ofi_class->domain->no_wait);
    na_ofi_class->no_wait = na_ofi_class->domain->no_wait || no_wait;

    /* Set context limits */
    NA_CHECK_SUBSYS_ERROR(fatal,
        na_init_info.max_contexts > na_ofi_class->domain->context_max, error,
        ret, NA_INVALID_ARG,
        "Maximum number of requested contexts (%" PRIu8 ") exceeds provider "
        "limitation(%zu)",
        na_init_info.max_contexts, na_ofi_class->domain->context_max);
    na_ofi_class->context_max = na_init_info.max_contexts;

    /* Set msg size limits */
    msg_size_max = na_ofi_class->domain->eager_msg_size_max
                       ? na_ofi_class->domain->eager_msg_size_max
                       : NA_OFI_MSG_SIZE;
    na_ofi_class->unexpected_size_max = na_init_info.max_unexpected_size
                                            ? na_init_info.max_unexpected_size
                                            : msg_size_max;
    na_ofi_class->expected_size_max = na_init_info.max_expected_size
                                          ? na_init_info.max_expected_size
                                          : msg_size_max;

#ifdef NA_OFI_HAS_MEM_POOL
    /* Register initial mempool */
    na_ofi_class->mem_pool = hg_mem_pool_create(
        MAX(na_ofi_class->unexpected_size_max, na_ofi_class->expected_size_max),
        NA_OFI_MEM_CHUNK_COUNT, NA_OFI_MEM_BLOCK_COUNT, na_ofi_mem_buf_register,
        na_ofi_mem_buf_deregister, (void *) na_ofi_class);
    NA_CHECK_SUBSYS_ERROR(cls, na_ofi_class->mem_pool == NULL, error, ret,
        NA_NOMEM,
        "Could not create memory pool with %d blocks of size %d x %zu bytes",
        NA_OFI_MEM_BLOCK_COUNT, NA_OFI_MEM_CHUNK_COUNT,
        MAX(na_ofi_class->unexpected_size_max,
            na_ofi_class->expected_size_max));
#endif

    /* Create endpoint */
    ret = na_ofi_endpoint_open(na_ofi_class->fabric, na_ofi_class->domain,
        na_ofi_class->no_wait, na_ofi_class->context_max, na_ofi_class->fi_info,
        &na_ofi_class->endpoint);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create endpoint");

#ifdef NA_OFI_HAS_ADDR_POOL
    /* Create pool of addresses */
    for (i = 0; i < NA_OFI_ADDR_POOL_COUNT; i++) {
        struct na_ofi_addr *na_ofi_addr = na_ofi_addr_alloc(na_ofi_class);
        NA_CHECK_SUBSYS_ERROR(cls, na_ofi_addr == NULL, error, ret, NA_NOMEM,
            "Could not create address");
        HG_QUEUE_PUSH_TAIL(&na_ofi_class->addr_pool.queue, na_ofi_addr, entry);
    }
#endif

    /* Get address from endpoint */
    ret = na_ofi_endpoint_get_src_addr(na_ofi_class);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "Could not get endpoint src address");

    na_class->plugin_class = (void *) na_ofi_class;

    na_ofi_free_hostname_info(
        domain_name, info.node, info.service, info.src_addr);

    return NA_SUCCESS;

error:
    na_ofi_free_hostname_info(
        domain_name, info.node, info.service, info.src_addr);

    if (na_ofi_class)
        na_ofi_class_free(na_ofi_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_finalize(na_class_t *na_class)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    hg_hash_table_iter_t addr_table_iter;
    na_return_t ret = NA_SUCCESS;

    if (na_ofi_class == NULL)
        return ret;

    /* Class is now finalizing */
    na_ofi_class->finalizing = true;

    /* Iterate over remaining addresses and free them */
    hg_hash_table_iterate(
        na_ofi_class->domain->addr_map.key_map, &addr_table_iter);
    while (hg_hash_table_iter_has_more(&addr_table_iter)) {
        struct na_ofi_addr *na_ofi_addr =
            (struct na_ofi_addr *) hg_hash_table_iter_next(&addr_table_iter);
        na_ofi_addr_ref_decr(na_ofi_addr);
    }

    /* Free class */
    ret = na_ofi_class_free(na_ofi_class);
    NA_CHECK_SUBSYS_NA_ERROR(cls, out, ret, "Coult not free NA OFI class");

    na_class->plugin_class = NULL;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_context_create(na_class_t *na_class, void **context_p, uint8_t id)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_context *na_ofi_context = NULL;
    na_return_t ret;
    int rc;

    na_ofi_context = (struct na_ofi_context *) malloc(sizeof(*na_ofi_context));
    NA_CHECK_SUBSYS_ERROR(ctx, na_ofi_context == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_context");
    memset(na_ofi_context, 0, sizeof(*na_ofi_context));
    na_ofi_context->idx = id;

    /* If not using SEP, just point to class' endpoint */
    if (!na_ofi_with_sep(na_ofi_class)) {
        na_ofi_context->fi_tx = na_ofi_class->endpoint->fi_ep;
        na_ofi_context->fi_rx = na_ofi_class->endpoint->fi_ep;
        na_ofi_context->eq = na_ofi_class->endpoint->eq;
    } else {
        int32_t n_contexts = hg_atomic_get32(&na_ofi_class->n_contexts);
        NA_CHECK_SUBSYS_ERROR(fatal,
            n_contexts >= (int32_t) na_ofi_class->context_max ||
                id >= na_ofi_class->context_max,
            error, ret, NA_OPNOTSUPPORTED,
            "n_contexts %" PRId32 ", context id %" PRIu8
            ", max_contexts %" PRIu8,
            n_contexts, id, na_ofi_class->context_max);

        /* Create Tx / Rx contexts */
        rc = fi_tx_context(na_ofi_class->endpoint->fi_ep, id, NULL,
            &na_ofi_context->fi_tx, NULL);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_tx_context() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_rx_context(na_ofi_class->endpoint->fi_ep, id, NULL,
            &na_ofi_context->fi_rx, NULL);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_rx_context() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        /* Create event queues (CQ, wait sets) */
        ret = na_ofi_eq_open(na_ofi_class->fabric, na_ofi_class->domain,
            na_ofi_class->no_wait, &na_ofi_context->eq);
        NA_CHECK_SUBSYS_NA_ERROR(
            ctx, error, ret, "Could not open event queues");

        rc = fi_ep_bind(na_ofi_context->fi_tx, &na_ofi_context->eq->fi_cq->fid,
            FI_TRANSMIT);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_ep_bind() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_ep_bind(
            na_ofi_context->fi_rx, &na_ofi_context->eq->fi_cq->fid, FI_RECV);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_ep_bind() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_enable(na_ofi_context->fi_tx);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_enable() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_enable(na_ofi_context->fi_rx);
        NA_CHECK_SUBSYS_ERROR(ctx, rc < 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_enable() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));
    }

    hg_atomic_incr32(&na_ofi_class->n_contexts);

    *context_p = (void *) na_ofi_context;

    return NA_SUCCESS;

error:
    if (na_ofi_context) {
        if (na_ofi_with_sep(na_ofi_class)) {
            if (na_ofi_context->fi_tx)
                (void) fi_close(&na_ofi_context->fi_tx->fid);
            if (na_ofi_context->fi_rx)
                (void) fi_close(&na_ofi_context->fi_rx->fid);
            if (na_ofi_context->eq)
                (void) na_ofi_eq_close(na_ofi_context->eq);
        }
        free(na_ofi_context);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_context_destroy(na_class_t *na_class, void *context)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_context *na_ofi_context = (struct na_ofi_context *) context;
    na_return_t ret = NA_SUCCESS;
    int rc;

    if (na_ofi_with_sep(na_ofi_class)) {
        bool empty;

        /* Check that retry op queue is empty */
        empty = HG_QUEUE_IS_EMPTY(&na_ofi_context->eq->retry_op_queue->queue);
        NA_CHECK_SUBSYS_ERROR(ctx, empty == false, out, ret, NA_BUSY,
            "Retry op queue should be empty");

        if (na_ofi_context->fi_tx) {
            rc = fi_close(&na_ofi_context->fi_tx->fid);
            NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, out, ret,
                na_ofi_errno_to_na(-rc),
                "fi_close() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));
            na_ofi_context->fi_tx = NULL;
        }

        if (na_ofi_context->fi_rx) {
            rc = fi_close(&na_ofi_context->fi_rx->fid);
            NA_CHECK_SUBSYS_ERROR(ctx, rc != 0, out, ret,
                na_ofi_errno_to_na(-rc),
                "fi_close() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));
            na_ofi_context->fi_rx = NULL;
        }

        /* Close wait set */
        if (na_ofi_context->eq) {
            ret = na_ofi_eq_close(na_ofi_context->eq);
            NA_CHECK_SUBSYS_NA_ERROR(
                ctx, out, ret, "Could not close event queues");
            na_ofi_context->eq = NULL;
        }
    }

    free(na_ofi_context);
    hg_atomic_decr32(&na_ofi_class->n_contexts);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_ofi_op_create(na_class_t *na_class)
{
    struct na_ofi_op_id *na_ofi_op_id = NULL;

    na_ofi_op_id = (struct na_ofi_op_id *) calloc(1, sizeof(*na_ofi_op_id));
    NA_CHECK_SUBSYS_ERROR_NORET(op, na_ofi_op_id == NULL, error,
        "Could not allocate NA OFI operation ID");
    na_ofi_op_id->na_ofi_class = NA_OFI_CLASS(na_class);

    /* Completed by default */
    hg_atomic_init32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return (na_op_id_t *) na_ofi_op_id;

error:
    return NULL;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to free OP ID that was not completed");

    free(na_ofi_op_id);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_addr_key addr_key;
    int addr_format = (int) na_ofi_class->fi_info->addr_format;
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Check provider from name */
    NA_CHECK_SUBSYS_ERROR(fatal,
        na_ofi_addr_prov(name) != NA_OFI_CLASS(na_class)->fabric->prov_type,
        error, ret, NA_INVALID_ARG, "Unrecognized provider type found from: %s",
        name);

    /* Convert name to raw address */
    ret = na_ofi_str_to_raw_addr(name, addr_format, &addr_key.addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not convert string to address");

    /* Create key from addr for faster lookups */
    addr_key.val = na_ofi_raw_addr_to_key(addr_format, &addr_key.addr);
    NA_CHECK_SUBSYS_ERROR(addr, addr_key.val == 0, error, ret,
        NA_PROTONOSUPPORT, "Could not generate key from addr");

    /* Lookup key and create new addr if it does not exist */
    ret = na_ofi_addr_key_lookup(na_ofi_class, &addr_key, &na_ofi_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not lookup address key for %s", name);

    *addr_p = (na_addr_t) na_ofi_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ofi_addr_ref_decr((struct na_ofi_addr *) addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_set_remove(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ofi_addr_ref_decr((struct na_ofi_addr *) addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr_p)
{
    struct na_ofi_endpoint *ep = NA_OFI_CLASS(na_class)->endpoint;

    na_ofi_addr_ref_incr(ep->src_addr); /* decref in na_ofi_addr_free() */
    *addr_p = (na_addr_t) ep->src_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_dup(
    na_class_t NA_UNUSED *na_class, na_addr_t addr, na_addr_t *new_addr_p)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;

    na_ofi_addr_ref_incr(na_ofi_addr); /* decref in na_ofi_addr_free() */
    *new_addr_p = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static bool
na_ofi_addr_cmp(
    na_class_t NA_UNUSED *na_class, na_addr_t addr1, na_addr_t addr2)
{
    return addr1 == addr2;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE bool
na_ofi_addr_is_self(na_class_t *na_class, na_addr_t addr)
{
    return NA_OFI_CLASS(na_class)->endpoint->src_addr ==
           (struct na_ofi_addr *) addr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_to_string(
    na_class_t *na_class, char *buf, size_t *buf_size_p, na_addr_t addr)
{
    return na_ofi_get_uri(NA_OFI_CLASS(na_class)->fabric,
        NA_OFI_CLASS(na_class)->domain, buf, buf_size_p,
        &((struct na_ofi_addr *) addr)->addr_key);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_addr_get_serialize_size(na_class_t *na_class, na_addr_t NA_UNUSED addr)
{
    return na_ofi_raw_addr_serialize_size(
        (int) NA_OFI_CLASS(na_class)->fi_info->addr_format);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_serialize(
    na_class_t *na_class, void *buf, size_t buf_size, na_addr_t addr)
{
    const struct na_ofi_addr_key *addr_key =
        &((struct na_ofi_addr *) addr)->addr_key;

    return na_ofi_raw_addr_serialize(
        (int) NA_OFI_CLASS(na_class)->fi_info->addr_format, buf, buf_size,
        &addr_key->addr);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_deserialize(
    na_class_t *na_class, na_addr_t *addr_p, const void *buf, size_t buf_size)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_addr_key addr_key;
    int addr_format = (int) na_ofi_class->fi_info->addr_format;
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret;

    /* Deserialize raw address */
    ret =
        na_ofi_raw_addr_deserialize(addr_format, &addr_key.addr, buf, buf_size);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not deserialize address key");

    /* Create key from addr for faster lookups */
    addr_key.val = na_ofi_raw_addr_to_key(addr_format, &addr_key.addr);
    NA_CHECK_SUBSYS_ERROR(addr, addr_key.val == 0, error, ret,
        NA_PROTONOSUPPORT, "Could not generate key from addr");

    /* Lookup key and create new addr if it does not exist */
    ret = na_ofi_addr_key_lookup(na_ofi_class, &addr_key, &na_ofi_addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, error, ret, "Could not lookup address key");

    *addr_p = (na_addr_t) na_ofi_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_OFI_CLASS(na_class)->unexpected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_OFI_CLASS(na_class)->expected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class)
{
    if (na_ofi_with_msg_hdr(NA_OFI_CLASS(na_class)))
        return na_ofi_raw_addr_serialize_size(
            (int) NA_OFI_CLASS(na_class)->fi_info->addr_format);

    return 0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_tag_t
na_ofi_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_OFI_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static void *
na_ofi_msg_buf_alloc(na_class_t *na_class, size_t size, void **plugin_data)
{
    struct fid_mr *mr_hdl = NULL;
    void *mem_ptr = NULL;

#ifdef NA_OFI_HAS_MEM_POOL
    mem_ptr = hg_mem_pool_alloc(
        NA_OFI_CLASS(na_class)->mem_pool, size, (void **) &mr_hdl);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, mem_ptr == NULL, out, "Could not allocate buffer from pool");
#else
    mem_ptr = na_ofi_mem_alloc(NA_OFI_CLASS(na_class), size, &mr_hdl);
    NA_CHECK_SUBSYS_ERROR_NORET(
        mem, mem_ptr == NULL, out, "Could not allocate %d bytes", (int) size);
#endif
    *plugin_data = mr_hdl;

out:
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data)
{
    struct fid_mr *mr_hdl = plugin_data;

#ifdef NA_OFI_HAS_MEM_POOL
    hg_mem_pool_free(NA_OFI_CLASS(na_class)->mem_pool, buf, (void *) mr_hdl);
#else
    na_ofi_mem_free(NA_OFI_CLASS(na_class), buf, mr_hdl);
#endif

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_init_unexpected(na_class_t *na_class, void *buf, size_t buf_size)
{
    /*
     * For those providers that don't support FI_SOURCE/FI_SOURCE_ERR, insert
     * the msg header to piggyback the source address for unexpected message.
     */
    if (na_ofi_with_msg_hdr(NA_OFI_CLASS(na_class)))
        return na_ofi_raw_addr_serialize(
            (int) NA_OFI_CLASS(na_class)->fi_info->addr_format, buf, buf_size,
            &NA_OFI_CLASS(na_class)->endpoint->src_addr->addr_key.addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_unexpected(na_class_t NA_UNUSED *na_class,
    na_context_t *context, na_cb_t callback, void *arg, const void *buf,
    size_t buf_size, void *plugin_data, na_addr_t dest_addr, uint8_t dest_id,
    na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) dest_addr;
    struct na_ofi_msg_info msg_info = {.buf.const_ptr = buf,
        .buf_size = buf_size,
        .fi_addr =
            fi_rx_addr(na_ofi_addr->fi_addr, dest_id, NA_OFI_SEP_RX_CTX_BITS),
        .fi_mr = plugin_data,
        .tag = (uint64_t) tag | NA_OFI_UNEXPECTED_TAG,
        .tag_mask = 0};

    return na_ofi_msg_send(context, NA_CB_SEND_UNEXPECTED, callback, arg,
        &msg_info, na_ofi_addr, (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t NA_UNUSED *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void *plugin_data, na_op_id_t *op_id)
{
    struct na_ofi_msg_info msg_info = {.buf.ptr = buf,
        .buf_size = buf_size,
        .fi_addr = FI_ADDR_UNSPEC,
        .fi_mr = plugin_data,
        .tag = NA_OFI_UNEXPECTED_TAG,
        .tag_mask = NA_OFI_TAG_MASK};

    return na_ofi_msg_recv(context, NA_CB_RECV_UNEXPECTED, callback, arg,
        &msg_info, NULL, (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_expected(na_class_t NA_UNUSED *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) dest_addr;
    struct na_ofi_msg_info msg_info = {.buf.const_ptr = buf,
        .buf_size = buf_size,
        .fi_addr =
            fi_rx_addr(na_ofi_addr->fi_addr, dest_id, NA_OFI_SEP_RX_CTX_BITS),
        .fi_mr = plugin_data,
        .tag = tag,
        .tag_mask = 0};

    return na_ofi_msg_send(context, NA_CB_SEND_EXPECTED, callback, arg,
        &msg_info, na_ofi_addr, (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_expected(na_class_t NA_UNUSED *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, size_t buf_size, void *plugin_data,
    na_addr_t source_addr, uint8_t source_id, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) source_addr;
    struct na_ofi_msg_info msg_info = {.buf.ptr = buf,
        .buf_size = buf_size,
        .fi_addr =
            fi_rx_addr(na_ofi_addr->fi_addr, source_id, NA_OFI_SEP_RX_CTX_BITS),
        .fi_mr = plugin_data,
        .tag = tag,
        .tag_mask = 0};

    return na_ofi_msg_recv(context, NA_CB_RECV_EXPECTED, callback, arg,
        &msg_info, na_ofi_addr, (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle */
    na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) calloc(1, sizeof(*na_ofi_mem_handle));
    NA_CHECK_SUBSYS_ERROR(mem, na_ofi_mem_handle == NULL, out, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");

    na_ofi_mem_handle->desc.iov.s[0].iov_base = buf;
    na_ofi_mem_handle->desc.iov.s[0].iov_len = buf_size;
    na_ofi_mem_handle->desc.info.iovcnt = 1;
    na_ofi_mem_handle->desc.info.flags = flags & 0xff;
    na_ofi_mem_handle->desc.info.len = buf_size;

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_create_segments(na_class_t *na_class,
    struct na_segment *segments, size_t segment_count, unsigned long flags,
    na_mem_handle_t *mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    struct iovec *iov = NULL;
    na_return_t ret = NA_SUCCESS;
    size_t i;

    NA_CHECK_SUBSYS_WARNING(mem, segment_count == 1, "Segment count is 1");

    /* Check that we do not exceed IOV limit */
    NA_CHECK_SUBSYS_ERROR(fatal,
        segment_count >
            NA_OFI_CLASS(na_class)->fi_info->domain_attr->mr_iov_limit,
        error, ret, NA_INVALID_ARG,
        "Segment count exceeds provider limit (%zu)",
        NA_OFI_CLASS(na_class)->fi_info->domain_attr->mr_iov_limit);

    /* Allocate memory handle */
    na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) calloc(1, sizeof(*na_ofi_mem_handle));
    NA_CHECK_SUBSYS_ERROR(mem, na_ofi_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");

    if (segment_count > NA_OFI_IOV_STATIC_MAX) {
        /* Allocate IOVs */
        na_ofi_mem_handle->desc.iov.d =
            (struct iovec *) calloc(segment_count, sizeof(struct iovec));
        NA_CHECK_SUBSYS_ERROR(mem, na_ofi_mem_handle->desc.iov.d == NULL, error,
            ret, NA_NOMEM, "Could not allocate IOV array");

        iov = na_ofi_mem_handle->desc.iov.d;
    } else
        iov = na_ofi_mem_handle->desc.iov.s;

    na_ofi_mem_handle->desc.info.len = 0;
    for (i = 0; i < segment_count; i++) {
        iov[i].iov_base = (void *) segments[i].base;
        iov[i].iov_len = segments[i].len;
        na_ofi_mem_handle->desc.info.len += iov[i].iov_len;
    }
    na_ofi_mem_handle->desc.info.iovcnt = segment_count;
    na_ofi_mem_handle->desc.info.flags = flags & 0xff;

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

    return ret;

error:
    if (na_ofi_mem_handle) {
        if (segment_count > NA_OFI_IOV_STATIC_MAX)
            free(na_ofi_mem_handle->desc.iov.d);
        free(na_ofi_mem_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_free(
    na_class_t NA_UNUSED *na_class, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;

    if (na_ofi_mem_handle->desc.info.iovcnt > NA_OFI_IOV_STATIC_MAX)
        free(na_ofi_mem_handle->desc.iov.d);
    free(na_ofi_mem_handle);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_mem_handle_get_max_segments(const na_class_t *na_class)
{
#ifdef NA_OFI_USE_REGV
    return NA_OFI_CLASS(na_class)->fi_info->domain_attr->mr_iov_limit;
#else
    (void) na_class;
    return 1;
#endif
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle,
    enum na_mem_type mem_type, uint64_t device)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;
    struct na_ofi_fabric *fabric = NA_OFI_CLASS(na_class)->fabric;
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    const struct fi_info *fi_info = NA_OFI_CLASS(na_class)->fi_info;
    struct fi_mr_attr fi_mr_attr = {.mr_iov = NA_OFI_IOV(na_ofi_mem_handle),
        .iov_count = na_ofi_mem_handle->desc.info.iovcnt,
        .context = NULL,
        .auth_key_size = 0,
        .auth_key = NULL,
        .iface = FI_HMEM_SYSTEM,
        .device.reserved = 0};
    na_return_t ret;
    int rc;

    /* Set access mode */
    switch (na_ofi_mem_handle->desc.info.flags) {
        case NA_MEM_READ_ONLY:
            fi_mr_attr.access = FI_REMOTE_READ | FI_WRITE;
            break;
        case NA_MEM_WRITE_ONLY:
            fi_mr_attr.access = FI_REMOTE_WRITE | FI_READ;
            break;
        case NA_MEM_READWRITE:
            fi_mr_attr.access =
                FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(
                mem, error, ret, NA_INVALID_ARG, "Invalid memory access flag");
            break;
    }

    /* Set memory type */
    switch (mem_type) {
        case NA_MEM_TYPE_CUDA:
            fi_mr_attr.iface = FI_HMEM_CUDA;
            fi_mr_attr.device.cuda = (int) device;
            break;
        case NA_MEM_TYPE_ROCM:
            fi_mr_attr.iface = FI_HMEM_ROCR;
            break;
        case NA_MEM_TYPE_ZE:
            fi_mr_attr.iface = FI_HMEM_ZE;
            fi_mr_attr.device.ze = (int) device;
            break;
        case NA_MEM_TYPE_HOST:
        case NA_MEM_TYPE_UNKNOWN:
        default:
            break;
    }
    NA_CHECK_SUBSYS_ERROR(mem,
        !(na_ofi_prov_extra_caps[fabric->prov_type] & FI_HMEM) &&
            (fi_mr_attr.iface != FI_HMEM_SYSTEM),
        error, ret, NA_OPNOTSUPPORTED,
        "selected provider does not support device registration");

    /* Let the provider provide its own key otherwise generate our own */
    fi_mr_attr.requested_key = (fi_info->domain_attr->mr_mode & FI_MR_PROV_KEY)
                                   ? 0
                                   : na_ofi_mem_key_gen(domain);

    /* Register region */
    rc = fi_mr_regattr(domain->fi_domain, &fi_mr_attr, 0 /* flags */,
        &na_ofi_mem_handle->fi_mr);
    NA_CHECK_SUBSYS_ERROR(mem, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
        "fi_mr_regattr() failed, rc: %d (%s), mr_reg_count: %d", rc,
        fi_strerror(-rc), hg_atomic_get32(domain->mr_reg_count));
    hg_atomic_incr32(domain->mr_reg_count);

    /* Retrieve key */
    na_ofi_mem_handle->desc.info.fi_mr_key =
        fi_mr_key(na_ofi_mem_handle->fi_mr);

    /* Attach MR to endpoint when provider requests it */
    if (fi_info->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        struct na_ofi_endpoint *endpoint = NA_OFI_CLASS(na_class)->endpoint;

        rc = fi_mr_bind(na_ofi_mem_handle->fi_mr, &endpoint->fi_ep->fid, 0);
        NA_CHECK_SUBSYS_ERROR(mem, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_mr_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_mr_enable(na_ofi_mem_handle->fi_mr);
        NA_CHECK_SUBSYS_ERROR(mem, rc != 0, error, ret, na_ofi_errno_to_na(-rc),
            "fi_mr_enable() failed, rc: %d (%s)", rc, fi_strerror(-rc));
    }

    return NA_SUCCESS;

error:
    if (na_ofi_mem_handle->fi_mr) {
        (void) fi_close(&na_ofi_mem_handle->fi_mr->fid);
        hg_atomic_decr32(domain->mr_reg_count);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* close MR handle */
    if (na_ofi_mem_handle->fi_mr != NULL) {
        rc = fi_close(&na_ofi_mem_handle->fi_mr->fid);
        NA_CHECK_SUBSYS_ERROR(mem, rc != 0, out, ret, na_ofi_errno_to_na(-rc),
            "fi_close() mr_hdl failed, rc: %d (%s)", rc, fi_strerror(-rc));
        hg_atomic_decr32(domain->mr_reg_count);
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE size_t
na_ofi_mem_handle_get_serialize_size(
    na_class_t NA_UNUSED *na_class, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;

    return sizeof(na_ofi_mem_handle->desc.info) +
           na_ofi_mem_handle->desc.info.iovcnt * sizeof(struct iovec);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;
    struct iovec *iov = NA_OFI_IOV(na_ofi_mem_handle);
    char *buf_ptr = (char *) buf;
    size_t buf_size_left = buf_size;
    na_return_t ret = NA_SUCCESS;

    /* Descriptor info */
    NA_ENCODE(out, ret, buf_ptr, buf_size_left, &na_ofi_mem_handle->desc.info,
        struct na_ofi_mem_desc_info);

    /* IOV */
    NA_ENCODE_ARRAY(out, ret, buf_ptr, buf_size_left, iov, struct iovec,
        na_ofi_mem_handle->desc.info.iovcnt);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t *mem_handle, const void *buf, size_t buf_size)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    const char *buf_ptr = (const char *) buf;
    size_t buf_size_left = buf_size;
    struct iovec *iov = NULL;
    na_return_t ret = NA_SUCCESS;

    na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) malloc(sizeof(*na_ofi_mem_handle));
    NA_CHECK_SUBSYS_ERROR(mem, na_ofi_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");
    na_ofi_mem_handle->desc.iov.d = NULL;
    na_ofi_mem_handle->fi_mr = NULL;
    na_ofi_mem_handle->desc.info.iovcnt = 0;

    /* Descriptor info */
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &na_ofi_mem_handle->desc.info,
        struct na_ofi_mem_desc_info);

    /* IOV */
    if (na_ofi_mem_handle->desc.info.iovcnt > NA_OFI_IOV_STATIC_MAX) {
        /* Allocate IOV */
        na_ofi_mem_handle->desc.iov.d = (struct iovec *) malloc(
            na_ofi_mem_handle->desc.info.iovcnt * sizeof(struct iovec));
        NA_CHECK_SUBSYS_ERROR(mem, na_ofi_mem_handle->desc.iov.d == NULL, error,
            ret, NA_NOMEM, "Could not allocate segment array");

        iov = na_ofi_mem_handle->desc.iov.d;
    } else
        iov = na_ofi_mem_handle->desc.iov.s;

    NA_DECODE_ARRAY(error, ret, buf_ptr, buf_size_left, iov, struct iovec,
        na_ofi_mem_handle->desc.info.iovcnt);

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

    return ret;

error:
    if (na_ofi_mem_handle) {
        if (na_ofi_mem_handle->desc.info.iovcnt > NA_OFI_IOV_STATIC_MAX)
            free(na_ofi_mem_handle->desc.iov.d);
        free(na_ofi_mem_handle);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset, size_t length,
    na_addr_t remote_addr, uint8_t remote_id, na_op_id_t *op_id)
{
    return na_ofi_rma(NA_OFI_CLASS(na_class), context, NA_CB_PUT, callback, arg,
        fi_writemsg, NA_OFI_PUT_COMPLETION,
        (struct na_ofi_mem_handle *) local_mem_handle, local_offset,
        (struct na_ofi_mem_handle *) remote_mem_handle, remote_offset, length,
        (struct na_ofi_addr *) remote_addr, remote_id,
        (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset, size_t length,
    na_addr_t remote_addr, uint8_t remote_id, na_op_id_t *op_id)
{
    return na_ofi_rma(NA_OFI_CLASS(na_class), context, NA_CB_GET, callback, arg,
        fi_readmsg, NA_OFI_GET_COMPLETION,
        (struct na_ofi_mem_handle *) local_mem_handle, local_offset,
        (struct na_ofi_mem_handle *) remote_mem_handle, remote_offset, length,
        (struct na_ofi_addr *) remote_addr, remote_id,
        (struct na_ofi_op_id *) op_id);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t *context)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_context *na_ofi_context = NA_OFI_CONTEXT(context);
    int fd = -1, rc;

    if (na_ofi_class->no_wait ||
        (na_ofi_prov_flags[na_ofi_class->fabric->prov_type] & NA_OFI_WAIT_SET))
        goto out;

    rc = fi_control(&na_ofi_context->eq->fi_cq->fid, FI_GETWAIT, &fd);
    NA_CHECK_SUBSYS_ERROR_NORET(poll, rc != 0 && rc != -FI_ENOSYS, out,
        "fi_control() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));
    NA_CHECK_SUBSYS_ERROR_NORET(
        poll, fd < 0, out, "Returned fd is not valid (%d), will not block", fd);

out:
    return fd;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE bool
na_ofi_poll_try_wait(na_class_t *na_class, na_context_t *context)
{
    struct na_ofi_class *na_ofi_class = NA_OFI_CLASS(na_class);
    struct na_ofi_context *na_ofi_context = NA_OFI_CONTEXT(context);
    struct fid *fids[1];
    bool retry_queue_empty;
    int rc;

    if (na_ofi_class->no_wait)
        return false;

    /* Keep making progress if retry queue is not empty */
    hg_thread_spin_lock(&na_ofi_context->eq->retry_op_queue->lock);
    retry_queue_empty =
        HG_QUEUE_IS_EMPTY(&na_ofi_context->eq->retry_op_queue->queue);
    hg_thread_spin_unlock(&na_ofi_context->eq->retry_op_queue->lock);
    if (!retry_queue_empty)
        return false;

    /* Assume it is safe to block if provider is using wait set */
    if ((na_ofi_prov_flags[na_ofi_class->fabric->prov_type] & NA_OFI_WAIT_SET)
        /* PSM2 shows very slow performance with fi_trywait() */
        || na_ofi_class->fabric->prov_type == NA_OFI_PROV_PSM2)
        return true;

    fids[0] = &na_ofi_context->eq->fi_cq->fid;
    /* Check whether it is safe to block on that fd */
    rc = fi_trywait(na_ofi_class->fabric->fi_fabric, fids, 1);
    if (rc == FI_SUCCESS)
        return true;
    else if (rc == -FI_EAGAIN)
        return false;
    else {
        NA_LOG_SUBSYS_ERROR(poll, "fi_trywait() failed, rc: %d (%s)", rc,
            fi_strerror((int) -rc));
        return false;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout_ms)
{
    hg_time_t deadline, now = hg_time_from_ms(0);
    na_return_t ret;

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    do {
        struct fi_cq_tagged_entry cq_events[NA_OFI_CQ_EVENT_NUM];
        fi_addr_t src_addrs[NA_OFI_CQ_EVENT_NUM] = {FI_ADDR_UNSPEC};
        char src_err_addr[NA_OFI_CQ_MAX_ERR_DATA_SIZE] = {0};
        void *src_err_addr_ptr = src_err_addr;
        size_t src_err_addrlen = NA_OFI_CQ_MAX_ERR_DATA_SIZE;
        size_t i, actual_count = 0;

        if (timeout_ms != 0) {
            struct fid_wait *wait_hdl = NA_OFI_CONTEXT(context)->eq->fi_wait;

            if (wait_hdl) {
                /* Wait in wait set if provider does not support wait on FDs */
                int rc = fi_wait(wait_hdl,
                    (int) hg_time_to_ms(hg_time_subtract(deadline, now)));

                if (rc == -FI_EINTR) {
                    hg_time_get_current_ms(&now);
                    continue;
                }

                if (rc == -FI_ETIMEDOUT)
                    break;

                NA_CHECK_SUBSYS_ERROR(poll, rc != 0, error, ret,
                    na_ofi_errno_to_na(-rc), "fi_wait() failed, rc: %d (%s)",
                    rc, fi_strerror(-rc));
            }
        }

        /* Read from CQ and process events */
        ret = na_ofi_cq_read(context, NA_OFI_CQ_EVENT_NUM, cq_events, src_addrs,
            &src_err_addr_ptr, &src_err_addrlen, &actual_count);
        NA_CHECK_SUBSYS_NA_ERROR(
            poll, error, ret, "Could not read events from context CQ");

        for (i = 0; i < actual_count; i++) {
            ret = na_ofi_cq_process_event(NA_OFI_CLASS(na_class), &cq_events[i],
                src_addrs[i], src_err_addr_ptr, src_err_addrlen);
            NA_CHECK_SUBSYS_NA_ERROR(
                poll, error, ret, "Could not process event");
        }

        /* Attempt to process retries */
        ret = na_ofi_cq_process_retries(NA_OFI_CONTEXT(context));
        NA_CHECK_SUBSYS_NA_ERROR(poll, error, ret, "Could not process retries");

        if (actual_count > 0)
            return NA_SUCCESS;

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
    } while (hg_time_less(now, deadline));

    /* PSM2 is a user-level interface, to prevent busy-spin and allow
     * other threads to be scheduled, we need to yield here. */
    if (NA_OFI_CLASS(na_class)->fabric->prov_type == NA_OFI_PROV_PSM2)
        hg_thread_yield();

    return NA_TIMEOUT;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cancel(
    na_class_t NA_UNUSED *na_class, na_context_t *context, na_op_id_t *op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    int32_t status;
    na_return_t ret;

    /* Exit if op has already completed */
    status = hg_atomic_get32(&na_ofi_op_id->status);
    if ((status & NA_OFI_OP_COMPLETED) || (status & NA_OFI_OP_ERRORED) ||
        (status & NA_OFI_OP_CANCELED) || (status & NA_OFI_OP_CANCELING))
        return NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(op, "Canceling operation ID %p (%s)",
        (void *) na_ofi_op_id,
        na_cb_type_to_string(na_ofi_op_id->completion_data.callback_info.type));

    /* Must set canceling before we check for the retry queue */
    hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELING);

    /* Check if op_id is in retry queue */
    if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_QUEUED) {
        struct na_ofi_op_queue *op_queue =
            NA_OFI_CONTEXT(context)->eq->retry_op_queue;
        bool canceled = false;

        /* If dequeued by process_retries() in the meantime, we'll just let it
         * cancel there */

        hg_thread_spin_lock(&op_queue->lock);
        if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_QUEUED) {
            HG_QUEUE_REMOVE(
                &op_queue->queue, na_ofi_op_id, na_ofi_op_id, entry);
            hg_atomic_and32(&na_ofi_op_id->status, ~NA_OFI_OP_QUEUED);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED);
            canceled = true;
        }
        hg_thread_spin_unlock(&op_queue->lock);

        if (canceled)
            na_ofi_complete(na_ofi_op_id, NA_CANCELED);
    } else {
        ret = na_ofi_op_cancel(na_ofi_op_id);
        NA_CHECK_SUBSYS_NA_ERROR(op, error, ret, "Could not cancel operation");
    }

    return NA_SUCCESS;

error:
    return ret;
}
