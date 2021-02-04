/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

/* Copyright (C) 2017 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for any purpose (including commercial purposes)
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions, and the following disclaimer in the
 *    documentation and/or materials provided with the distribution.
 *
 * 3. In addition, redistributions of modified forms of the source or binary
 *    code must carry prominent notices stating that the original code was
 *    changed and the date of the change.
 *
 *  4. All publications or advertising materials mentioning features or use of
 *     this software are asked, but not required, to acknowledge that it was
 *     developed by Intel Corporation and credit the contributors.
 *
 * 5. Neither the name of Intel Corporation, nor the name of any Contributor
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "na_plugin.h"

#include "mercury_hash_table.h"
#include "mercury_list.h"
#include "mercury_mem.h"
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

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <inttypes.h>
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
#define NA_OFI_VERSION FI_VERSION(1, 5)

/* Default basic bits */
#define NA_OFI_MR_BASIC_REQ (FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY)

/* flags that control na_ofi behavior (in the X macro below for each
 * provider)
 */
#define NA_OFI_VERIFY_PROV_DOM (1 << 0) /* requires domain verification */
#define NA_OFI_WAIT_SET        (1 << 1) /* supports FI_WAIT_SET */
#define NA_OFI_WAIT_FD         (1 << 2) /* supports FI_WAIT_FD */
#define NA_OFI_SIGNAL          (1 << 4) /* supports fi_signal() */
#define NA_OFI_DOMAIN_LOCK     (1 << 5) /* serialize domain access */
#define NA_OFI_SEP             (1 << 6) /* supports SEPs */
#define NA_OFI_SOURCE_MSG      (1 << 7) /* requires source info in the MSG */

/* X-macro to define the following for each supported provider:
 * - enum type
 * - name
 * - alternate (alias) names for convenience
 * - address format
 * - progress mode
 * - additional capabilities used (beyond the base set required by NA)
 * - misc flags to control na_ofi behavior and workarounds with this provider
 *
 * The purpose of this is to aggregate settings for all providers into a
 * single location so that it is easier to alter them.
 */
#define NA_OFI_PROV_TYPES                                                      \
    X(NA_OFI_PROV_NULL, "", "", 0, 0, 0, 0)                                    \
    X(NA_OFI_PROV_SOCKETS, "sockets", "", FI_SOCKADDR_IN, FI_PROGRESS_AUTO,    \
        FI_SOURCE | FI_DIRECTED_RECV,                                          \
        NA_OFI_VERIFY_PROV_DOM | NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG |          \
            NA_OFI_SEP)                                                        \
    X(NA_OFI_PROV_TCP, "tcp;ofi_rxm", "tcp", FI_SOCKADDR_IN, FI_PROGRESS_AUTO, \
        FI_SOURCE | FI_DIRECTED_RECV, NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG)      \
    X(NA_OFI_PROV_PSM, "psm", "", FI_ADDR_PSMX, FI_PROGRESS_MANUAL, 0,         \
        NA_OFI_WAIT_SET | NA_OFI_SOURCE_MSG)                                   \
    X(NA_OFI_PROV_PSM2, "psm2", "", FI_ADDR_PSMX2, FI_PROGRESS_MANUAL,         \
        FI_SOURCE | FI_SOURCE_ERR | FI_DIRECTED_RECV,                          \
        NA_OFI_DOMAIN_LOCK | NA_OFI_SIGNAL | NA_OFI_SEP)                       \
    X(NA_OFI_PROV_VERBS, "verbs;ofi_rxm", "verbs", FI_SOCKADDR_IN,             \
        FI_PROGRESS_MANUAL, FI_SOURCE | FI_DIRECTED_RECV,                      \
        NA_OFI_VERIFY_PROV_DOM | NA_OFI_WAIT_FD | NA_OFI_SOURCE_MSG)           \
    X(NA_OFI_PROV_GNI, "gni", "", FI_ADDR_GNI, FI_PROGRESS_AUTO,               \
        FI_SOURCE | FI_SOURCE_ERR | FI_DIRECTED_RECV,                          \
        NA_OFI_WAIT_SET | NA_OFI_SIGNAL | NA_OFI_SEP)                          \
    X(NA_OFI_PROV_MAX, "", "", 0, 0, 0, 0)

#define X(a, b, c, d, e, f, g) a,
enum na_ofi_prov_type { NA_OFI_PROV_TYPES };
#undef X
#define X(a, b, c, d, e, f, g) b,
static const char *const na_ofi_prov_name[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g) c,
static const char *const na_ofi_prov_alt_name[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g) d,
static na_uint32_t const na_ofi_prov_addr_format[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g) e,
static unsigned long const na_ofi_prov_progress[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g) f,
static unsigned long const na_ofi_prov_extra_caps[] = {NA_OFI_PROV_TYPES};
#undef X
#define X(a, b, c, d, e, f, g) g,
static unsigned long const na_ofi_prov_flags[] = {NA_OFI_PROV_TYPES};
#undef X

/* Address / URI max len */
#define NA_OFI_MAX_URI_LEN             (128)
#define NA_OFI_GNI_AV_STR_ADDR_VERSION (1)
#define NA_OFI_GNI_IFACE_DEFAULT       "ipogif0"
#define NA_OFI_GNI_UDREG_REG_LIMIT     (2048)

/* Memory pool (enabled by default, comment out to disable) */
#define NA_OFI_HAS_MEM_POOL
#define NA_OFI_MEM_BLOCK_COUNT (256)

/* Max tag */
#define NA_OFI_MAX_TAG UINT32_MAX

/* Unexpected size */
#define NA_OFI_UNEXPECTED_SIZE (4096)
#define NA_OFI_UNEXPECTED_TAG  (0x100000000ULL)
#define NA_OFI_TAG_MASK        (0x0FFFFFFFFULL)

/* Number of CQ event provided for fi_cq_read() */
#define NA_OFI_CQ_EVENT_NUM (16)
/* CQ depth (the socket provider's default value is 256 */
#define NA_OFI_CQ_DEPTH (8192)
/* CQ max err data size (fix to 48 to work around bug in gni provider code) */
#define NA_OFI_CQ_MAX_ERR_DATA_SIZE (48)

/* The predefined RMA KEY for MR_SCALABLE */
#define NA_OFI_RMA_KEY (0x0F1B0F1BULL)

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
#define NA_OFI_OP_CANCELED  (1 << 1)
#define NA_OFI_OP_QUEUED    (1 << 2)
#define NA_OFI_OP_ERRORED   (1 << 3)

/* Private data access */
#define NA_OFI_CLASS(na_class)                                                 \
    ((struct na_ofi_class *) ((na_class)->plugin_class))
#define NA_OFI_CONTEXT(na_context)                                             \
    ((struct na_ofi_context *) ((na_context)->plugin_context))

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
        fi_msg_rma.msg_iov = local_iov;                                        \
        fi_msg_rma.desc = &na_ofi_op_id->info.rma.local_desc;                  \
        fi_msg_rma.iov_count = na_ofi_op_id->info.rma.local_iovcnt;            \
        fi_msg_rma.addr = na_ofi_op_id->info.rma.fi_addr;                      \
        fi_msg_rma.rma_iov = remote_iov;                                       \
        fi_msg_rma.rma_iov_count = na_ofi_op_id->info.rma.remote_iovcnt;       \
        fi_msg_rma.context = &na_ofi_op_id->fi_ctx;                            \
        fi_msg_rma.data = 0;                                                   \
    } while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Address */
struct na_ofi_addr {
    struct na_ofi_domain *domain; /* Domain                   */
    void *addr;                   /* Native address           */
    na_size_t addrlen;            /* Native address len       */
    char *uri;                    /* Generated URI            */
    fi_addr_t fi_addr;            /* FI address               */
    na_uint64_t ht_key;           /* Key in hash-table        */
    hg_atomic_int32_t refcount;   /* Reference counter        */
    na_bool_t remove;             /* Remove from AV on free   */
};

/* SIN address */
struct na_ofi_sin_addr {
    struct sockaddr_in sin;
};

/* PSM address */
struct na_ofi_psm_addr {
    na_uint64_t addr0;
};

/* PSM2 address */
struct na_ofi_psm2_addr {
    na_uint64_t addr0;
    na_uint64_t addr1;
};

/* GNI address */
struct na_ofi_gni_addr {
    struct {
        na_uint32_t device_addr; /* physical NIC address     */
        na_uint32_t cdm_id;      /* user supplied id         */
    };
    struct {
        na_uint32_t name_type : 8;      /* bound, unbound           */
        na_uint32_t cm_nic_cdm_id : 24; /* CM nic ID                */
        na_uint32_t cookie;             /* CDM identifier           */
    };
    struct {
        na_uint32_t rx_ctx_cnt : 8;  /* number of contexts       */
        na_uint32_t key_offset : 12; /* auth key offset          */
        na_uint32_t unused1 : 12;
        na_uint32_t unused2;
    };
    na_uint64_t reserved[3];
};

/* Memory descriptor info */
struct na_ofi_mem_desc_info {
    na_uint64_t fi_mr_key; /* FI MR key                   */
    size_t len;            /* Size of region              */
    unsigned long iovcnt;  /* Segment count               */
    na_uint8_t flags;      /* Flag of operation access    */
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
    na_size_t actual_buf_size;
    fi_addr_t fi_addr;
    na_tag_t tag;
};

/* RMA info */
struct na_ofi_rma_info {
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
    struct fi_context fi_ctx;           /* Context handle           */
    na_context_t *context;              /* NA context associated    */
    struct na_ofi_addr *addr;           /* Address associated       */
    hg_atomic_int32_t status;           /* Operation status         */
};

/* Op queue */
struct na_ofi_queue {
    hg_thread_mutex_t mutex;
    HG_QUEUE_HEAD(na_ofi_op_id) queue;
};

/* Context */
struct na_ofi_context {
    struct fid_ep *fi_tx;                /* Transmit context handle  */
    struct fid_ep *fi_rx;                /* Receive context handle   */
    struct fid_cq *fi_cq;                /* CQ handle                */
    struct fid_wait *fi_wait;            /* Wait set handle          */
    struct na_ofi_queue *retry_op_queue; /* Retry op queue           */
    na_uint8_t idx;                      /* Context index            */
};

/* Endpoint */
struct na_ofi_endpoint {
    struct na_ofi_addr *src_addr;        /* Endpoint address         */
    struct fi_info *fi_prov;             /* Provider info            */
    struct fid_ep *fi_ep;                /* Endpoint handle          */
    struct fid_wait *fi_wait;            /* Wait set handle          */
    struct fid_cq *fi_cq;                /* CQ handle                */
    struct na_ofi_queue *retry_op_queue; /* Retry op queue           */
    na_bool_t sep;                       /* Scalable endpoint        */
};

/* Domain */
struct na_ofi_domain {
    hg_thread_mutex_t mutex;            /* Mutex for AV etc         */
    hg_thread_rwlock_t rwlock;          /* RW lock for addr_ht      */
    HG_LIST_ENTRY(na_ofi_domain) entry; /* Entry in domain list     */
#ifdef NA_OFI_HAS_EXT_GNI_H
    struct fi_gni_auth_key fi_gni_auth_key; /* GNI auth key             */
#endif
    struct fid_fabric *fi_fabric;    /* Fabric handle            */
    struct fid_domain *fi_domain;    /* Domain handle            */
    struct fi_info *fi_prov;         /* Provider info            */
    struct fid_mr *fi_mr;            /* Global MR handle         */
    na_uint64_t fi_mr_key;           /* Global MR key            */
    struct fid_av *fi_av;            /* Address vector handle    */
    hg_hash_table_t *addr_ht;        /* Address hash_table       */
    char *prov_name;                 /* Provider name            */
    enum na_ofi_prov_type prov_type; /* Provider type            */
    hg_atomic_int32_t mr_reg_count;  /* Number of MR registered  */
    hg_atomic_int32_t refcount;      /* Refcount of this domain  */
};

/**
 * Memory node (points to actual data).
 */
struct na_ofi_mem_node {
    HG_QUEUE_ENTRY(na_ofi_mem_node) entry; /* Entry in node_list       */
    char *block;                           /* Must be last             */
};

/**
 * Memory pool. Each pool has a fixed block size, the underlying memory
 * buffer is registered and its MR handle can be passed to fi_tsend/fi_trecv
 * functions.
 */
struct na_ofi_mem_pool {
    HG_QUEUE_HEAD(na_ofi_mem_node) node_list; /* Node list               */
    HG_QUEUE_ENTRY(na_ofi_mem_pool) entry;    /* Entry in pool list      */
    struct fid_mr *mr_hdl;                    /* MR handle               */
    na_size_t block_size;                     /* Node block size         */
    hg_thread_spin_t node_list_lock;          /* Node list lock          */
};

/* Private data */
struct na_ofi_class {
    hg_thread_mutex_t mutex;                 /* Mutex (for verbs prov)   */
    HG_QUEUE_HEAD(na_ofi_mem_pool) buf_pool; /* Msg buf pool head        */
    struct na_ofi_domain *domain;            /* Domain pointer           */
    struct na_ofi_endpoint *endpoint;        /* Endpoint pointer         */
    hg_thread_spin_t buf_pool_lock;          /* Buf pool lock            */
    na_size_t iov_max;                       /* Max number of IOVs       */
    na_uint8_t contexts;                     /* Number of context        */
    na_uint8_t context_max;                  /* Max number of contexts   */
    na_bool_t no_wait;                       /* Ignore wait object       */
    na_bool_t no_retry;                      /* Do not retry operations  */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Convert provider name to enum type.
 */
static NA_INLINE enum na_ofi_prov_type
na_ofi_prov_name_to_type(const char *prov_name);

/**
 * Get provider encoded address size.
 */
static NA_INLINE size_t
na_ofi_prov_addr_size(na_uint32_t addr_format);

/**
 * Domain lock.
 */
static NA_INLINE void
na_ofi_domain_lock(struct na_ofi_domain *domain);

/**
 * Domain unlock.
 */
static NA_INLINE void
na_ofi_domain_unlock(struct na_ofi_domain *domain);

/**
 * Uses Scalable endpoints (SEP).
 */
static NA_INLINE na_bool_t
na_ofi_with_sep(const na_class_t *na_class);

/**
 * Requires message header with address info.
 */
static NA_INLINE na_bool_t
na_ofi_with_msg_hdr(const na_class_t *na_class);

/**
 * Get provider type encoded in string.
 */
static NA_INLINE enum na_ofi_prov_type
na_ofi_addr_prov(const char *str);

/**
 * Get native address from string.
 */
static NA_INLINE na_return_t
na_ofi_str_to_addr(
    const char *str, na_uint32_t addr_format, void **addr, na_size_t *len);
static na_return_t
na_ofi_str_to_sin(const char *str, void **addr, na_size_t *len);
static na_return_t
na_ofi_str_to_psm(const char *str, void **addr, na_size_t *len);
static na_return_t
na_ofi_str_to_psm2(const char *str, void **addr, na_size_t *len);
static na_return_t
na_ofi_str_to_gni(const char *str, void **addr, na_size_t *len);

/**
 * Convert the address to a 64-bit key to search corresponding FI addr.
 */
static NA_INLINE na_uint64_t
na_ofi_addr_to_key(na_uint32_t addr_format, const void *addr, na_size_t len);
static NA_INLINE na_uint64_t
na_ofi_sin_to_key(const struct na_ofi_sin_addr *addr);
static NA_INLINE na_uint64_t
na_ofi_psm_to_key(const struct na_ofi_psm_addr *addr);
static NA_INLINE na_uint64_t
na_ofi_psm2_to_key(const struct na_ofi_psm2_addr *addr);
static NA_INLINE na_uint64_t
na_ofi_gni_to_key(const struct na_ofi_gni_addr *addr);

/**
 * Key hash for hash table.
 */
static NA_INLINE unsigned int
na_ofi_addr_ht_key_hash(hg_hash_table_key_t vlocation);

/**
 * Compare key.
 */
static NA_INLINE int
na_ofi_addr_ht_key_equal(
    hg_hash_table_key_t vlocation1, hg_hash_table_key_t vlocation2);

/**
 * Lookup the address in the hash-table. Insert it into the AV if it does not
 * already exist.
 */
static na_return_t
na_ofi_addr_ht_lookup(struct na_ofi_domain *domain, na_uint32_t addr_format,
    const void *addr, na_size_t addrlen, fi_addr_t *fi_addr,
    na_uint64_t *addr_key);

/**
 * Remove an addr from the AV and the hash-table.
 */
static na_return_t
na_ofi_addr_ht_remove(
    struct na_ofi_domain *domain, fi_addr_t *fi_addr, na_uint64_t *addr_key);

/**
 * Lookup an FI addr from the AV.
 */
static na_return_t
na_ofi_av_lookup(struct na_ofi_domain *na_ofi_domain, fi_addr_t fi_addr,
    void **addr_ptr, size_t *addrlen_ptr);

/**
 * Get info caps from providers and return matching providers.
 */
static na_return_t
na_ofi_getinfo(enum na_ofi_prov_type prov_type, struct fi_info **providers,
    const char *user_requested_protocol);

/**
 * Check and resolve interfaces from hostname.
 */
static na_return_t
na_ofi_check_interface(const char *hostname, unsigned int port, char **ifa_name,
    struct na_ofi_sin_addr **na_ofi_sin_addr_ptr);

/**
 * Match provider name with domain.
 */
static NA_INLINE na_bool_t
na_ofi_verify_provider(enum na_ofi_prov_type prov_type, const char *domain_name,
    const struct fi_info *fi_info);

#ifdef NA_OFI_HAS_EXT_GNI_H
/**
 * Optional domain set op value for GNI provider.
 */
static na_return_t
na_ofi_gni_set_domain_op_value(
    struct na_ofi_domain *na_ofi_domain, int op, void *value);
#endif

/**
 * Open domain.
 */
static na_return_t
na_ofi_domain_open(na_class_t *na_class, enum na_ofi_prov_type prov_type,
    const char *domain_name, const char *auth_key,
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
na_ofi_endpoint_open(const struct na_ofi_domain *na_ofi_domain,
    const char *node, void *src_addr, na_size_t src_addrlen, na_bool_t no_wait,
    na_uint8_t max_contexts, struct na_ofi_endpoint **na_ofi_endpoint_p);

/**
 * Open basic endpoint.
 */
static na_return_t
na_ofi_basic_ep_open(const struct na_ofi_domain *na_ofi_domain,
    na_bool_t no_wait, struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Open scalable endpoint.
 */
static na_return_t
na_ofi_sep_open(const struct na_ofi_domain *na_ofi_domain,
    struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Close endpoint.
 */
static na_return_t
na_ofi_endpoint_close(struct na_ofi_endpoint *na_ofi_endpoint);

/**
 * Get EP address.
 */
static na_return_t
na_ofi_get_ep_addr(na_class_t *na_class, struct na_ofi_addr **na_ofi_addr_ptr);

/**
 * Get EP URI.
 *
 * Generated URIs examples:
 * sockets://fi_sockaddr_in://127.0.0.1:38053
 * verbs;ofi_rxm://fi_sockaddr_in://172.23.100.175:58664
 * psm2://fi_addr_psmx2://15b0602:0
 * gni://fi_addr_gni://0001:0x00000020:0x000056ce:02:0x000000:0x33f20000:00
 */
static na_return_t
na_ofi_get_uri(na_class_t *na_class, const void *addr, char **uri_ptr);

/**
 * Allocate address.
 */
static struct na_ofi_addr *
na_ofi_addr_alloc(struct na_ofi_domain *na_ofi_domain);

/**
 * Increment address refcount.
 */
static NA_INLINE void
na_ofi_addr_addref(struct na_ofi_addr *na_ofi_addr);

/**
 * Decrement address refcount.
 */
static NA_INLINE void
na_ofi_addr_decref(struct na_ofi_addr *na_ofi_addr);

/**
 * Create memory pool.
 */
static struct na_ofi_mem_pool *
na_ofi_mem_pool_create(
    na_class_t *na_class, na_size_t block_size, na_size_t block_count);

/**
 * Destroy memory pool.
 */
static void
na_ofi_mem_pool_destroy(
    na_class_t *na_class, struct na_ofi_mem_pool *na_ofi_mem_pool);

/**
 * Allocate memory for transfers.
 */
static NA_INLINE void *
na_ofi_mem_alloc(na_class_t *na_class, na_size_t size, struct fid_mr **mr_hdl);

/**
 * Free memory.
 */
static NA_INLINE void
na_ofi_mem_free(na_class_t *na_class, void *mem_ptr, struct fid_mr *mr_hdl);

/**
 * Allocate memory pool and register memory.
 */
static void *
na_ofi_mem_pool_alloc(
    na_class_t *na_class, na_size_t size, struct fid_mr **mr_hdl);

/**
 * Free memory pool and release memory.
 */
static void
na_ofi_mem_pool_free(
    na_class_t *na_class, void *mem_ptr, struct fid_mr *mr_hdl);

/**
 * Get IOV index and offset pair from an absolute offset.
 */
static NA_INLINE void
na_ofi_iov_get_index_offset(const struct iovec *iov, unsigned long iovcnt,
    na_offset_t offset, unsigned long *iov_start_index,
    unsigned long *iov_start_offset);

/**
 * Get IOV count for a given length.
 */
static NA_INLINE unsigned long
na_ofi_iov_get_count(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, na_size_t len);

/**
 * Create new IOV for transferring length data.
 */
static NA_INLINE void
na_ofi_iov_translate(const struct iovec *iov, unsigned long iovcnt,
    unsigned long iov_start_index, na_offset_t iov_start_offset, na_size_t len,
    struct iovec *new_iov, unsigned long new_iovcnt);

/**
 * Create new RMA IOV for transferring length data.
 */
static NA_INLINE void
na_ofi_rma_iov_translate(const struct iovec *iov, unsigned long iovcnt,
    na_uint64_t key, unsigned long iov_start_index,
    na_offset_t iov_start_offset, na_size_t len, struct fi_rma_iov *new_iov,
    unsigned long new_iovcnt);

/**
 * Do RMA operation (put/get).
 */
static na_return_t
na_ofi_rma(na_class_t *na_class, na_context_t *context, na_cb_type_t op,
    na_cb_t callback, void *arg,
    ssize_t (*fi_rma_op)(
        struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags),
    na_uint64_t fi_rma_flags, struct na_ofi_mem_handle *na_ofi_mem_handle_local,
    na_offset_t local_offset,
    struct na_ofi_mem_handle *na_ofi_mem_handle_remote,
    na_offset_t remote_offset, na_size_t length,
    struct na_ofi_addr *na_ofi_addr, na_uint8_t remote_id,
    struct na_ofi_op_id *na_ofi_op_id);

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
na_ofi_cq_process_event(na_class_t *na_class,
    const struct fi_cq_tagged_entry *cq_event, fi_addr_t src_addr,
    void *err_addr, size_t err_addrlen);

/**
 * Send operation events.
 */
static NA_INLINE na_return_t
na_ofi_cq_process_send_event(struct na_ofi_op_id *na_ofi_op_id);

/**
 * Recv unexpected operation events.
 */
static na_return_t
na_ofi_cq_process_recv_unexpected_event(na_class_t *na_class,
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
static NA_INLINE na_return_t
na_ofi_cq_process_rma_event(struct na_ofi_op_id *na_ofi_op_id);

/**
 * Process retries.
 */
static na_return_t
na_ofi_cq_process_retries(na_context_t *context);

/**
 * Complete operation ID.
 */
static na_return_t
na_ofi_complete(struct na_ofi_op_id *na_ofi_op_id);

/**
 * Release OP ID resources.
 */
static NA_INLINE void
na_ofi_release(void *arg);

/********************/
/* Plugin callbacks */
/********************/

/* check_protocol */
static na_bool_t
na_ofi_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_ofi_initialize(
    na_class_t *na_class, const struct na_info *na_info, na_bool_t listen);

/* finalize */
static na_return_t
na_ofi_finalize(na_class_t *na_class);

/* context_create */
static na_return_t
na_ofi_context_create(na_class_t *na_class, void **context, na_uint8_t id);

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
na_ofi_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr);

/* addr_free */
static NA_INLINE na_return_t
na_ofi_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_set_remove */
static NA_INLINE na_return_t
na_ofi_addr_set_remove(na_class_t *na_class, na_addr_t addr);

/* addr_self */
static NA_INLINE na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr);

/* addr_dup */
static NA_INLINE na_return_t
na_ofi_addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr);

/* addr_dup */
static na_bool_t
na_ofi_addr_cmp(na_class_t *na_class, na_addr_t addr1, na_addr_t addr2);

/* addr_is_self */
static NA_INLINE na_bool_t
na_ofi_addr_is_self(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t
na_ofi_addr_to_string(
    na_class_t *na_class, char *buf, na_size_t *buf_size, na_addr_t addr);

/* addr_get_serialize_size */
static NA_INLINE na_size_t
na_ofi_addr_get_serialize_size(na_class_t *na_class, na_addr_t addr);

/* addr_serialize */
static na_return_t
na_ofi_addr_serialize(
    na_class_t *na_class, void *buf, na_size_t buf_size, na_addr_t addr);

/* addr_deserialize */
static na_return_t
na_ofi_addr_deserialize(
    na_class_t *na_class, na_addr_t *addr, const void *buf, na_size_t buf_size);

/* msg_get_max_unexpected_size */
static NA_INLINE na_size_t
na_ofi_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static NA_INLINE na_size_t
na_ofi_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_unexpected_header_size */
static NA_INLINE na_size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class);

/* msg_get_max_tag */
static NA_INLINE na_tag_t
na_ofi_msg_get_max_tag(const na_class_t *na_class);

/* msg_buf_alloc */
static void *
na_ofi_msg_buf_alloc(na_class_t *na_class, na_size_t size, void **plugin_data);

/* msg_buf_free */
static na_return_t
na_ofi_msg_buf_free(na_class_t *na_class, void *buf, void *plugin_data);

/* msg_init_unexpected */
static na_return_t
na_ofi_msg_init_unexpected(na_class_t *na_class, void *buf, na_size_t buf_size);

/* msg_send_unexpected */
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source_addr, na_uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id);

/* mem_handle */
static na_return_t
na_ofi_mem_handle_create(na_class_t *na_class, void *buf, na_size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle);

static na_return_t
na_ofi_mem_handle_create_segments(na_class_t NA_UNUSED *na_class,
    struct na_segment *segments, na_size_t segment_count, unsigned long flags,
    na_mem_handle_t *mem_handle);

static na_return_t
na_ofi_mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle);

static NA_INLINE na_size_t
na_ofi_mem_handle_get_max_segments(const na_class_t *na_class);

static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle);

/* mem_handle serialization */
static NA_INLINE na_size_t
na_ofi_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_serialize(na_class_t *na_class, void *buf, na_size_t buf_size,
    na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
    const void *buf, na_size_t buf_size);

/* put */
static na_return_t
na_ofi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static NA_INLINE int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static NA_INLINE na_bool_t
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

/* OFI access domain list */
static HG_LIST_HEAD(na_ofi_domain)
    na_ofi_domain_list_g = HG_LIST_HEAD_INITIALIZER(na_ofi_domain);

/* Protects domain list */
static hg_thread_mutex_t na_ofi_domain_list_mutex_g =
    HG_THREAD_MUTEX_INITIALIZER;

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
static NA_INLINE size_t
na_ofi_prov_addr_size(na_uint32_t addr_format)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return sizeof(struct na_ofi_sin_addr);
        case FI_ADDR_PSMX:
            return sizeof(struct na_ofi_psm_addr);
        case FI_ADDR_PSMX2:
            return sizeof(struct na_ofi_psm2_addr);
        case FI_ADDR_GNI:
            return sizeof(struct na_ofi_gni_addr);
        default:
            NA_LOG_ERROR("Unsupported address format");
            return 0;
    }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_domain_lock(struct na_ofi_domain *domain)
{
    if (na_ofi_prov_flags[domain->prov_type] & NA_OFI_DOMAIN_LOCK)
        hg_thread_mutex_lock(&domain->mutex);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_domain_unlock(struct na_ofi_domain *domain)
{
    if (na_ofi_prov_flags[domain->prov_type] & NA_OFI_DOMAIN_LOCK)
        hg_thread_mutex_unlock(&domain->mutex);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_with_sep(const na_class_t *na_class)
{
    struct na_ofi_endpoint *ep = NA_OFI_CLASS(na_class)->endpoint;

    return ep->sep;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_with_msg_hdr(const na_class_t *na_class)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;

    return (na_ofi_prov_flags[domain->prov_type] & NA_OFI_SOURCE_MSG);
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
na_ofi_str_to_addr(
    const char *str, na_uint32_t addr_format, void **addr, na_size_t *len)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            return na_ofi_str_to_sin(str, addr, len);
        case FI_ADDR_PSMX:
            return na_ofi_str_to_psm(str, addr, len);
        case FI_ADDR_PSMX2:
            return na_ofi_str_to_psm2(str, addr, len);
        case FI_ADDR_GNI:
            return na_ofi_str_to_gni(str, addr, len);
        default:
            NA_LOG_ERROR("Unsupported address format");
            return NA_PROTONOSUPPORT;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_sin(const char *str, void **addr, na_size_t *len)
{
    struct na_ofi_sin_addr *sin_addr;
    char ip[16];
    na_return_t ret = NA_SUCCESS;

    *len = sizeof(*sin_addr);
    sin_addr = calloc(1, *len);
    NA_CHECK_ERROR(sin_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate sin address");

    sin_addr->sin.sin_family = AF_INET;
    if (sscanf(str, "%*[^:]://:%" SCNu16, &sin_addr->sin.sin_port) == 1) {
        /* nothing */
    } else if ((sscanf(str, "%*[^:]://%15[^:]:%" SCNu16, ip,
                    &sin_addr->sin.sin_port) == 2) ||
               (sscanf(str, "%*[^:]://%15[^:/]", ip) == 1)) {
        int rc;

        ip[sizeof(ip) - 1] = '\0';
        rc = inet_pton(AF_INET, ip, &sin_addr->sin.sin_addr);
        NA_CHECK_ERROR(rc != 1, error, ret, NA_PROTONOSUPPORT,
            "Unable to convert IPv4 address: %s\n", ip);
    } else
        NA_GOTO_ERROR(
            error, ret, NA_PROTONOSUPPORT, "Malformed FI_ADDR_STR: %s\n", str);

    sin_addr->sin.sin_port = htons(sin_addr->sin.sin_port);
    *addr = sin_addr;

    return ret;

error:
    free(sin_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_psm(const char *str, void **addr, na_size_t *len)
{
    struct na_ofi_psm_addr *psm_addr;
    na_return_t ret = NA_SUCCESS;
    int rc;

    *len = sizeof(*psm_addr);
    psm_addr = calloc(1, *len);
    NA_CHECK_ERROR(psm_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate psm address");

    rc = sscanf(str, "%*[^:]://%" SCNx64, (uint64_t *) &psm_addr->addr0);
    NA_CHECK_ERROR(rc != 1, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to PSM addr format");

    *addr = psm_addr;

    return ret;

error:
    free(psm_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_psm2(const char *str, void **addr, na_size_t *len)
{
    struct na_ofi_psm2_addr *psm2_addr;
    na_return_t ret = NA_SUCCESS;
    int rc;

    *len = sizeof(*psm2_addr);
    psm2_addr = calloc(1, *len);
    NA_CHECK_ERROR(psm2_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate psm2 address");

    rc = sscanf(str, "%*[^:]://%" SCNx64 ":%" SCNx64,
        (uint64_t *) &psm2_addr->addr0, (uint64_t *) &psm2_addr->addr1);
    NA_CHECK_ERROR(rc != 2, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to PSM2 addr format");

    *addr = psm2_addr;

    return ret;

error:
    free(psm2_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_str_to_gni(const char *str, void **addr, na_size_t *len)
{
    struct na_ofi_gni_addr *gni_addr;
    unsigned int version, name_type, rx_ctx_cnt;
    na_uint32_t device_addr, cdm_id, cm_nic_cdm_id, cookie;
    na_return_t ret = NA_SUCCESS;
    int rc;

    *len = sizeof(*gni_addr);
    gni_addr = calloc(1, *len);
    NA_CHECK_ERROR(gni_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate gni address");

    rc = sscanf(str,
        "%*[^:]://%04u:0x%08" PRIx32 ":0x%08" PRIx32 ":%02u:0x%06" PRIx32
        ":0x%08" PRIx32 ":%02u",
        &version, &device_addr, &cdm_id, &name_type, &cm_nic_cdm_id, &cookie,
        &rx_ctx_cnt);
    NA_CHECK_ERROR(rc != 7, error, ret, NA_PROTONOSUPPORT,
        "Could not convert addr string to GNI addr format");
    NA_CHECK_ERROR(version != NA_OFI_GNI_AV_STR_ADDR_VERSION, error, ret,
        NA_PROTONOSUPPORT, "Unsupported GNI string addr format");

    gni_addr->device_addr = device_addr;
    gni_addr->cdm_id = cdm_id;
    gni_addr->name_type = name_type & 0xff;
    gni_addr->cm_nic_cdm_id = cm_nic_cdm_id & 0xffffff;
    gni_addr->cookie = cookie;
    gni_addr->rx_ctx_cnt = rx_ctx_cnt & 0xff;
    NA_LOG_DEBUG("GNI addr is: device_addr=%x, cdm_id=%x, name_type=%x, "
                 "cm_nic_cdm_id=%x, cookie=%x, rx_ctx_cnt=%u",
        gni_addr->device_addr, gni_addr->cdm_id, gni_addr->name_type,
        gni_addr->cm_nic_cdm_id, gni_addr->cookie, gni_addr->rx_ctx_cnt);

    *addr = gni_addr;

    return ret;

error:
    free(gni_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_uint64_t
na_ofi_addr_to_key(na_uint32_t addr_format, const void *addr, na_size_t len)
{
    switch (addr_format) {
        case FI_SOCKADDR_IN:
            NA_CHECK_ERROR_NORET(len != sizeof(struct na_ofi_sin_addr), out,
                "Addr len (%zu) does not match for FI_SOCKADDR_IN (%zu)", len,
                sizeof(struct na_ofi_sin_addr));
            return na_ofi_sin_to_key((const struct na_ofi_sin_addr *) addr);
        case FI_ADDR_PSMX:
            NA_CHECK_ERROR_NORET(len != sizeof(struct na_ofi_psm_addr), out,
                "Addr len (%zu) does not match for FI_ADDR_PSMX (%zu)", len,
                sizeof(struct na_ofi_psm_addr));
            return na_ofi_psm_to_key((const struct na_ofi_psm_addr *) addr);
        case FI_ADDR_PSMX2:
            NA_CHECK_ERROR_NORET(len != sizeof(struct na_ofi_psm2_addr), out,
                "Addr len (%zu) does not match for FI_ADDR_PSMX2 (%zu)", len,
                sizeof(struct na_ofi_psm2_addr));
            return na_ofi_psm2_to_key((const struct na_ofi_psm2_addr *) addr);
        case FI_ADDR_GNI:
            NA_CHECK_ERROR_NORET(len != sizeof(struct na_ofi_gni_addr), out,
                "Addr len (%zu) does not match for FI_ADDR_GNI (%zu)", len,
                sizeof(struct na_ofi_gni_addr));
            return na_ofi_gni_to_key((const struct na_ofi_gni_addr *) addr);
        default:
            NA_LOG_ERROR("Unsupported address format");
            break;
    }

out:
    return 0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_uint64_t
na_ofi_sin_to_key(const struct na_ofi_sin_addr *addr)
{
    return (
        ((na_uint64_t) addr->sin.sin_addr.s_addr) << 32 | addr->sin.sin_port);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_uint64_t
na_ofi_psm_to_key(const struct na_ofi_psm_addr *addr)
{
    return addr->addr0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_uint64_t
na_ofi_psm2_to_key(const struct na_ofi_psm2_addr *addr)
{
    /* Only need the psm2_epid, i.e. the first 64 bits */
    return addr->addr0;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_uint64_t
na_ofi_gni_to_key(const struct na_ofi_gni_addr *addr)
{
    return (((na_uint64_t) addr->device_addr) << 32 | addr->cdm_id);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE unsigned int
na_ofi_addr_ht_key_hash(hg_hash_table_key_t vlocation)
{
    na_uint64_t key = *((na_uint64_t *) vlocation);
    na_uint32_t hi, lo;

    hi = (na_uint32_t)(key >> 32);
    lo = (key & 0xFFFFFFFFU);

    return ((hi & 0xFFFF0000U) | (lo & 0xFFFFU));
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_addr_ht_key_equal(
    hg_hash_table_key_t vlocation1, hg_hash_table_key_t vlocation2)
{
    return *((na_uint64_t *) vlocation1) == *((na_uint64_t *) vlocation2);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_ht_lookup(struct na_ofi_domain *domain, na_uint32_t addr_format,
    const void *addr, na_size_t addrlen, fi_addr_t *fi_addr,
    na_uint64_t *addr_key)
{
    hg_hash_table_key_t ht_key = addr_key;
    hg_hash_table_value_t ht_value = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Generate key */
    *addr_key = na_ofi_addr_to_key(addr_format, addr, addrlen);
    NA_CHECK_ERROR(*addr_key == 0, out, ret, NA_PROTONOSUPPORT,
        "Could not generate key from addr");

    /* Lookup key */
    hg_thread_rwlock_rdlock(&domain->rwlock);
    ht_value = hg_hash_table_lookup(domain->addr_ht, ht_key);
    if (ht_value != HG_HASH_TABLE_NULL) {
        /* Found */
        *fi_addr = *(fi_addr_t *) ht_value;
        hg_thread_rwlock_release_rdlock(&domain->rwlock);
        goto out;
    }
    hg_thread_rwlock_release_rdlock(&domain->rwlock);

    /* Insert addr into AV if key not found */
    na_ofi_domain_lock(domain);
    rc = fi_av_insert(domain->fi_av, addr, 1, fi_addr, 0 /* flags */, NULL);
    na_ofi_domain_unlock(domain);
    NA_CHECK_ERROR(rc < 1, out, ret, NA_PROTOCOL_ERROR,
        "fi_av_insert() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));

    hg_thread_rwlock_wrlock(&domain->rwlock);

    ht_value = hg_hash_table_lookup(domain->addr_ht, ht_key);
    if (ht_value != HG_HASH_TABLE_NULL) {
        /* race condition that same source inserted to AV and hash_table, if the
         * fi_addr is different then remove the newly inserted and reuse the
         * fi_addr in hash-table.
         */
        if (*(fi_addr_t *) ht_value != *fi_addr) {
            rc = fi_av_remove(domain->fi_av, fi_addr, 1, 0 /* flags */);
            NA_CHECK_ERROR(rc != 0, unlock, ret, NA_PROTOCOL_ERROR,
                "fi_av_remove() failed, rc: %d (%s)", rc,
                fi_strerror((int) -rc));
        }
        *fi_addr = *(fi_addr_t *) ht_value;
        goto unlock;
    }

    /* Allocate new key */
    ht_key = malloc(sizeof(na_uint64_t));
    NA_CHECK_ERROR(ht_key == NULL, error, ret, NA_NOMEM,
        "Cannot allocate memory for ht_key");

    /* Allocate new value */
    ht_value = malloc(sizeof(*fi_addr));
    NA_CHECK_ERROR(ht_value == NULL, error, ret, NA_NOMEM,
        "cannot allocate memory for ht_key");

    *((na_uint64_t *) ht_key) = *addr_key;
    *((na_uint64_t *) ht_value) = *fi_addr;

    /* Insert new value */
    rc = hg_hash_table_insert(domain->addr_ht, ht_key, ht_value);
    NA_CHECK_ERROR(
        rc == 0, error, ret, NA_NOMEM, "hg_hash_table_insert() failed");

unlock:
    hg_thread_rwlock_release_wrlock(&domain->rwlock);

out:
    return ret;

error:
    hg_thread_rwlock_release_wrlock(&domain->rwlock);
    free(ht_key);
    free(ht_value);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_ht_remove(
    struct na_ofi_domain *domain, fi_addr_t *fi_addr, na_uint64_t *addr_key)
{
    hg_hash_table_value_t ht_value = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&domain->rwlock);
    ht_value =
        hg_hash_table_lookup(domain->addr_ht, (hg_hash_table_key_t) addr_key);
    if (ht_value == HG_HASH_TABLE_NULL)
        goto unlock;

    rc = hg_hash_table_remove(domain->addr_ht, (hg_hash_table_key_t) addr_key);
    NA_CHECK_ERROR(
        rc != 1, unlock, ret, NA_NOENTRY, "hg_hash_table_remove() failed");

    rc = fi_av_remove(domain->fi_av, fi_addr, 1, 0 /* flags */);
    NA_CHECK_ERROR(rc != 0, unlock, ret, NA_PROTOCOL_ERROR,
        "fi_av_remove() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));

unlock:
    hg_thread_rwlock_release_wrlock(&domain->rwlock);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_av_lookup(struct na_ofi_domain *na_ofi_domain, fi_addr_t fi_addr,
    void **addr_ptr, size_t *addrlen_ptr)
{
    void *addr = NULL;
    size_t addrlen = na_ofi_domain->fi_prov->src_addrlen;
    na_bool_t retried = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    int rc;

retry:
    addr = malloc(addrlen);
    NA_CHECK_ERROR(addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate %zu bytes for address", addrlen);

    /* Lookup address from AV */
    na_ofi_domain_lock(na_ofi_domain);
    rc = fi_av_lookup(na_ofi_domain->fi_av, fi_addr, addr, &addrlen);
    na_ofi_domain_unlock(na_ofi_domain);
    if (rc == -FI_ETOOSMALL && retried == NA_FALSE) {
        retried = NA_TRUE;
        free(addr);
        goto retry;
    }
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "fi_av_lookup() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));

    *addr_ptr = addr;
    *addrlen_ptr = addrlen;

    return ret;

error:
    free(addr);
    return ret;
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

    /* query libfabric with no restrictions to determine what providers
     * are present
     */
    rc = fi_getinfo(NA_OFI_VERSION, /* OFI version requested */
        NULL,                       /* Optional name or fabric to resolve */
        NULL,                       /* Optional service name to request */
        0ULL,                       /* Optional flag */
        NULL,                       /* Optional hints to filter providers */
        &providers);                /* Out: List of matching providers */
    if (rc != 0)
        return;

    /* look for match */
    for (cur = providers; cur; cur = cur->next) {
        if (!strcmp(cur->fabric_attr->prov_name, na_ofi_prov_name[prov_type])) {
            /* The provider is there at least; follow normal error
             * handling path rather than printing a special message.
             */
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
         * with an memory allocation problem.  Just return.
         */
        return;
    }

    /* generate list of available providers */
    for (cur = providers; cur; cur = cur->next) {
        if (!prev ||
            strcmp(prev->fabric_attr->prov_name, cur->fabric_attr->prov_name)) {
            /* construct comma delimited list */
            strcat(avail, cur->fabric_attr->prov_name);
            strcat(avail, ",");
        }
        prev = cur;
    }
    /* truncate final comma */
    avail[strlen(avail) - 1] = '\0';

    /* display error message */
    NA_LOG_ERROR("Requested OFI provider \"%s\" (derived from\n"
                 "  \"%s\" Mercury protocol) is not available.",
        na_ofi_prov_name[prov_type], user_requested_protocol);
    NA_LOG_ERROR("Please re-compile libfabric with support for\n"
                 "  \"%s\" or use one of the following available providers:\n"
                 "  %s",
        na_ofi_prov_name[prov_type], avail);

    free(avail);

    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_getinfo(enum na_ofi_prov_type prov_type, struct fi_info **providers,
    const char *user_requested_protocol)
{
    struct fi_info *hints = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /**
     * Hints to query && filter providers.
     */
    hints = fi_allocinfo();
    NA_CHECK_ERROR(hints == NULL, out, ret, NA_NOMEM, "fi_allocinfo() failed");

    /* Protocol name is provider name, filter out providers within libfabric */
    hints->fabric_attr->prov_name = strdup(na_ofi_prov_name[prov_type]);
    NA_CHECK_ERROR(hints->fabric_attr->prov_name == NULL, cleanup, ret,
        NA_NOMEM, "Could not duplicate name");

    /* mode: operational mode, NA_OFI passes in context for communication calls.
     */
    /* FI_ASYNC_IOV mode indicates  that  the  application  must  provide  the
       buffering needed for the IO vectors. When set, an application must not
       modify an IO vector  of  length  >  1, including  any  related  memory
       descriptor array, until the associated operation has completed. */
    hints->mode = FI_CONTEXT | FI_ASYNC_IOV;

    /* ep_type: reliable datagram (connection-less). */
    hints->ep_attr->type = FI_EP_RDM;

    /* caps: capabilities required. */
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
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;

    /**
     * this is the requested MR mode (i.e., what we currently support).
     * Cleared MR mode bits (depending on provider) are later checked at the
     * appropriate time.
     */
    hints->domain_attr->mr_mode = (NA_OFI_MR_BASIC_REQ | FI_MR_LOCAL);

    /* set default progress mode */
    hints->domain_attr->control_progress = na_ofi_prov_progress[prov_type];
    hints->domain_attr->data_progress = na_ofi_prov_progress[prov_type];

    /* only use sockets provider with tcp for now */
    if (prov_type == NA_OFI_PROV_SOCKETS)
        hints->ep_attr->protocol = FI_PROTO_SOCK_TCP;

    /**
     * fi_getinfo:  returns information about fabric services.
     * Pass NULL for name/service to list all providers supported with above
     * requirement hints.
     */
    rc = fi_getinfo(NA_OFI_VERSION, /* OFI version requested */
        NULL,                       /* Optional name or fabric to resolve */
        NULL,                       /* Optional service name to request */
        0ULL,                       /* Optional flag */
        hints,                      /* In: Hints to filter providers */
        providers);                 /* Out: List of matching providers */
    if (rc != 0) {
        /* getinfo failed.  This could be because Mercury was
         * linked against a libfabric library that was not compiled with
         * support for the desired provider.  Attempt to detect this case
         * and display a user-friendly error message.
         */
        na_ofi_provider_check(prov_type, user_requested_protocol);
    }
    NA_CHECK_ERROR(rc != 0, cleanup, ret, NA_PROTOCOL_ERROR,
        "fi_getinfo() failed, rc: %d (%s)", rc, fi_strerror(-rc));

cleanup:
    free(hints->fabric_attr->prov_name);
    hints->fabric_attr->prov_name = NULL;
    fi_freeinfo(hints);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_check_interface(const char *hostname, unsigned int port, char **ifa_name,
    struct na_ofi_sin_addr **na_ofi_sin_addr_ptr)
{
    struct ifaddrs *ifaddrs = NULL, *ifaddr;
    struct addrinfo hints, *hostname_res = NULL;
    struct na_ofi_sin_addr *na_ofi_sin_addr = NULL;
    char ip_res[INET_ADDRSTRLEN] = {
        '\0'}; /* This restricts to ipv4 addresses */
    na_return_t ret = NA_SUCCESS;
    na_bool_t found = NA_FALSE;
    int s;

    /* Allocate new sin addr to store result */
    na_ofi_sin_addr = calloc(1, sizeof(*na_ofi_sin_addr));
    NA_CHECK_ERROR(na_ofi_sin_addr == NULL, out, ret, NA_NOMEM,
        "Could not allocate sin address");
    na_ofi_sin_addr->sin.sin_family = AF_INET;
    na_ofi_sin_addr->sin.sin_port = htons(port & 0xffff);

    /* Try to resolve hostname first so that we can later compare the IP */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = na_ofi_sin_addr->sin.sin_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    s = getaddrinfo(hostname, NULL, &hints, &hostname_res);
    if (s == 0) {
        struct addrinfo *rp;

        /* Get IP */
        for (rp = hostname_res; rp != NULL; rp = rp->ai_next) {
            const char *ptr = inet_ntop(rp->ai_addr->sa_family,
                &((struct sockaddr_in *) rp->ai_addr)->sin_addr, ip_res,
                INET_ADDRSTRLEN);
            NA_CHECK_ERROR(ptr == NULL, out, ret, NA_ADDRNOTAVAIL,
                "IP could not be resolved");
            break;
        }
    }

    /* Check and compare interfaces */
    s = getifaddrs(&ifaddrs);
    NA_CHECK_ERROR(s == -1, out, ret, NA_ADDRNOTAVAIL, "getifaddrs() failed");

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        char ip[INET_ADDRSTRLEN] = {
            '\0'}; /* This restricts to ipv4 addresses */
        const char *ptr;

        if (ifaddr->ifa_addr == NULL)
            continue;

        if (ifaddr->ifa_addr->sa_family != AF_INET)
            continue;

        /* Get IP */
        ptr = inet_ntop(ifaddr->ifa_addr->sa_family,
            &((struct sockaddr_in *) ifaddr->ifa_addr)->sin_addr, ip,
            INET_ADDRSTRLEN);
        NA_CHECK_ERROR(ptr == NULL, out, ret, NA_ADDRNOTAVAIL,
            "IP could not be resolved for: %s", ifaddr->ifa_name);

        /* Compare hostnames / device names */
        if (!strcmp(ip, ip_res) || !strcmp(ifaddr->ifa_name, hostname)) {
            na_ofi_sin_addr->sin.sin_addr =
                ((struct sockaddr_in *) ifaddr->ifa_addr)->sin_addr;
            found = NA_TRUE;
            break;
        }
    }

    if (found) {
        *na_ofi_sin_addr_ptr = na_ofi_sin_addr;
        if (ifa_name) {
            *ifa_name = strdup(ifaddr->ifa_name);
            NA_CHECK_ERROR(*ifa_name == NULL, out, ret, NA_NOMEM,
                "Could not dup ifa_name");
        }
    }

out:
    if (!found || ret != NA_SUCCESS)
        free(na_ofi_sin_addr);
    freeifaddrs(ifaddrs);
    if (hostname_res)
        freeaddrinfo(hostname_res);

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_verify_provider(enum na_ofi_prov_type prov_type, const char *domain_name,
    const struct fi_info *fi_info)
{
    /* Does not match provider name */
    if (strcmp(na_ofi_prov_name[prov_type], fi_info->fabric_attr->prov_name))
        return NA_FALSE;

    /* for some providers the provider name is ambiguous and we must check
     * the domain name as well
     */
    if (na_ofi_prov_flags[prov_type] & NA_OFI_VERIFY_PROV_DOM) {
        /* Does not match domain name */
        if (domain_name && strcmp("\0", domain_name) &&
            strcmp(domain_name, fi_info->domain_attr->name))
            return NA_FALSE;
    }

    return NA_TRUE;
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
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_open_ops() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = gni_domain_ops->set_val(&na_ofi_domain->fi_domain->fid, op, value);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "gni_domain_ops->set_val() failed, rc: %d (%s)", rc, fi_strerror(-rc));

out:
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_domain_open(na_class_t *na_class, enum na_ofi_prov_type prov_type,
    const char *domain_name, const char *auth_key,
    struct na_ofi_domain **na_ofi_domain_p)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_domain *na_ofi_domain;
    struct fi_av_attr av_attr = {0};
    struct fi_info *prov, *providers = NULL;
    na_bool_t domain_found = NA_FALSE, prov_found = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /**
     * Look for existing domain. It allows to create endpoints with different
     * providers. The endpoints with same provider name can reuse the same
     * na_ofi_domain.
     */
    hg_thread_mutex_lock(&na_ofi_domain_list_mutex_g);
    HG_LIST_FOREACH (na_ofi_domain, &na_ofi_domain_list_g, entry) {
        if (na_ofi_verify_provider(
                prov_type, domain_name, na_ofi_domain->fi_prov)) {
            hg_atomic_incr32(&na_ofi_domain->refcount);
            domain_found = NA_TRUE;
            break;
        }
    }
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);
    if (domain_found) {
        NA_LOG_DEBUG("Found existing domain (%s)", na_ofi_domain->prov_name);
        *na_ofi_domain_p = na_ofi_domain;
        return ret;
    }

    /* If no pre-existing domain, get OFI providers info */
    ret = na_ofi_getinfo(prov_type, &providers, NULL);
    NA_CHECK_NA_ERROR(error, ret, "na_ofi_getinfo() failed");

    /* Try to find provider that matches protocol and domain/host name */
    prov = providers;
    while (prov != NULL) {
        if (na_ofi_verify_provider(prov_type, domain_name, prov)) {
            NA_LOG_DEBUG("mode 0x%llx, fabric_attr -> prov_name: %s, name: %s; "
                         "domain_attr -> name: %s, threading: %d.",
                prov->mode, prov->fabric_attr->prov_name,
                prov->fabric_attr->name, prov->domain_attr->name,
                prov->domain_attr->threading);
            prov_found = NA_TRUE;
            break;
        }
        prov = prov->next;
    }
    NA_CHECK_ERROR(!prov_found, error, ret, NA_NOENTRY,
        "No provider found for \"%s\" provider on domain \"%s\"",
        na_ofi_prov_name[prov_type], domain_name);

    na_ofi_domain =
        (struct na_ofi_domain *) malloc(sizeof(struct na_ofi_domain));
    NA_CHECK_ERROR(na_ofi_domain == NULL, error, ret, NA_NOMEM,
        "Could not allocate na_ofi_domain");
    memset(na_ofi_domain, 0, sizeof(struct na_ofi_domain));
    hg_atomic_init32(&na_ofi_domain->mr_reg_count, 0);
    hg_atomic_init32(&na_ofi_domain->refcount, 1);

    /* Init mutex */
    rc = hg_thread_mutex_init(&na_ofi_domain->mutex);
    NA_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_mutex_init() failed");

    /* Init rw lock */
    rc = hg_thread_rwlock_init(&na_ofi_domain->rwlock);
    NA_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, NA_NOMEM,
        "hg_thread_rwlock_init() failed");

    /* Keep fi_info */
    na_ofi_domain->fi_prov = fi_dupinfo(prov);
    NA_CHECK_ERROR(na_ofi_domain->fi_prov == NULL, error, ret, NA_NOMEM,
        "Could not duplicate fi_info");

    /* Dup provider name */
    na_ofi_domain->prov_name = strdup(prov->fabric_attr->prov_name);
    NA_CHECK_ERROR(na_ofi_domain->prov_name == NULL, error, ret, NA_NOMEM,
        "Could not duplicate name");

    na_ofi_domain->prov_type = prov_type;

#if defined(NA_OFI_HAS_EXT_GNI_H)
    if (prov_type == NA_OFI_PROV_GNI && auth_key) {
        na_ofi_domain->fi_gni_auth_key.type = GNIX_AKT_RAW;
        na_ofi_domain->fi_gni_auth_key.raw.protection_key =
            (uint32_t) strtoul(auth_key, NULL, 10);

        na_ofi_domain->fi_prov->domain_attr->auth_key =
            (void *) &na_ofi_domain->fi_gni_auth_key;
        na_ofi_domain->fi_prov->domain_attr->auth_key_size =
            sizeof(na_ofi_domain->fi_gni_auth_key);
    }
#else
    (void) auth_key;
#endif

    /* Force no wait if do not support FI_WAIT_FD/FI_WAIT_SET */
    if (!(na_ofi_prov_flags[prov_type] & (NA_OFI_WAIT_SET | NA_OFI_WAIT_FD)))
        priv->no_wait = NA_TRUE;

    /* Force manual progress if no wait is set */
    if (priv->no_wait) {
        na_ofi_domain->fi_prov->domain_attr->control_progress =
            FI_PROGRESS_MANUAL;
        na_ofi_domain->fi_prov->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    }

    /* Open fi fabric */
    rc = fi_fabric(
        na_ofi_domain->fi_prov->fabric_attr, /* In:  Fabric attributes */
        &na_ofi_domain->fi_fabric,           /* Out: Fabric handle */
        NULL); /* Optional context for fabric events */
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "fi_fabric() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Create the fi access domain */
    rc = fi_domain(na_ofi_domain->fi_fabric, /* In:  Fabric object */
        na_ofi_domain->fi_prov,              /* In:  Provider */
        &na_ofi_domain->fi_domain,           /* Out: Domain object */
        NULL); /* Optional context for domain events */
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "fi_domain() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    if (priv->context_max > 1) {
        size_t min_ctx_cnt =
            MIN(na_ofi_domain->fi_prov->domain_attr->tx_ctx_cnt,
                na_ofi_domain->fi_prov->domain_attr->rx_ctx_cnt);
        NA_CHECK_ERROR(priv->context_max > min_ctx_cnt, error, ret,
            NA_INVALID_ARG,
            "Maximum number of requested contexts (%" PRIu8
	    ") exceeds provider limitation (%zu)",
            priv->context_max, min_ctx_cnt);
        NA_LOG_DEBUG("fi_domain created, tx_ctx_cnt %d, rx_ctx_cnt %d",
            na_ofi_domain->fi_prov->domain_attr->tx_ctx_cnt,
            na_ofi_domain->fi_prov->domain_attr->rx_ctx_cnt);
    }

#ifdef NA_OFI_HAS_EXT_GNI_H
    if (na_ofi_domain->prov_type == NA_OFI_PROV_GNI) {
        int32_t enable = 1;
#    ifdef NA_OFI_GNI_HAS_UDREG
        char *other_reg_type = "udreg";
        int32_t udreg_limit = NA_OFI_GNI_UDREG_REG_LIMIT;

        /* Enable use of udreg instead of internal MR cache */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_CACHE, &other_reg_type);
        NA_CHECK_NA_ERROR(
            error, ret, "Could not set domain op value for GNI_MR_CACHE");

        /* Experiments on Theta showed default value of 2048 too high if
         * launching multiple clients on one node */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_UDREG_REG_LIMIT, &udreg_limit);
        NA_CHECK_NA_ERROR(error, ret,
            "Could not set domain op value for GNI_MR_UDREG_REG_LIMIT");
#    endif

        /* Enable lazy deregistration in MR cache */
        ret = na_ofi_gni_set_domain_op_value(
            na_ofi_domain, GNI_MR_CACHE_LAZY_DEREG, &enable);
        NA_CHECK_NA_ERROR(error, ret,
            "Could not set domain op value for GNI_MR_CACHE_LAZY_DEREG");
    }
#endif

    /* If memory does not need to be backed up by physical pages at the time of
     * registration, export all memory range for RMA
     * (this is equivalent to FI_MR_SCALABLE) */
    if (!(na_ofi_domain->fi_prov->domain_attr->mr_mode & FI_MR_ALLOCATED)) {
        uint64_t requested_key =
            (!(na_ofi_domain->fi_prov->domain_attr->mr_mode & FI_MR_PROV_KEY))
                ? NA_OFI_RMA_KEY
                : 0;

        rc = fi_mr_reg(na_ofi_domain->fi_domain, NULL, UINT64_MAX,
            FI_REMOTE_READ | FI_REMOTE_WRITE | FI_SEND | FI_RECV | FI_READ |
                FI_WRITE,
            0 /* offset */, requested_key, 0 /* flags */, &na_ofi_domain->fi_mr,
            NULL /* context */);
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_mr_reg failed(), rc: %d (%s), mr_reg_count: %d", rc,
            fi_strerror(-rc), hg_atomic_get32(&na_ofi_domain->mr_reg_count));
        hg_atomic_incr32(&na_ofi_domain->mr_reg_count);

        /* Requested key may not be the same, currently RxM provider forces
         * the underlying provider to provide keys and ignores user-provided
         * key.
         */
        na_ofi_domain->fi_mr_key = fi_mr_key(na_ofi_domain->fi_mr);
    }

    /* Open fi address vector */
    av_attr.type = FI_AV_MAP;
    av_attr.rx_ctx_bits = NA_OFI_SEP_RX_CTX_BITS;
    rc = fi_av_open(
        na_ofi_domain->fi_domain, &av_attr, &na_ofi_domain->fi_av, NULL);
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "fi_av_open() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Create addr hash-table */
    na_ofi_domain->addr_ht =
        hg_hash_table_new(na_ofi_addr_ht_key_hash, na_ofi_addr_ht_key_equal);
    NA_CHECK_ERROR(na_ofi_domain->addr_ht == NULL, error, ret, NA_NOMEM,
        "hg_hash_table_new() failed");
    hg_hash_table_register_free_functions(na_ofi_domain->addr_ht, free, free);

    /* Insert to global domain list */
    hg_thread_mutex_lock(&na_ofi_domain_list_mutex_g);
    HG_LIST_INSERT_HEAD(&na_ofi_domain_list_g, na_ofi_domain, entry);
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);

    *na_ofi_domain_p = na_ofi_domain;

    fi_freeinfo(providers);

    return ret;

error:
    na_ofi_domain_close(na_ofi_domain);
    if (providers)
        fi_freeinfo(providers);

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

    /* Remove from global domain list if not used anymore */
    if (hg_atomic_decr32(&na_ofi_domain->refcount))
        /* Cannot free yet */
        goto out;

    /* Remove from domain list */
    hg_thread_mutex_lock(&na_ofi_domain_list_mutex_g);
    if (na_ofi_domain->entry.next || na_ofi_domain->entry.prev)
        HG_LIST_REMOVE(na_ofi_domain, entry);
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);

    /* Close MR */
    if (na_ofi_domain->fi_mr) {
        rc = fi_close(&na_ofi_domain->fi_mr->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() MR failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_mr = NULL;
        hg_atomic_decr32(&na_ofi_domain->mr_reg_count);
    }

    /* Close AV */
    if (na_ofi_domain->fi_av) {
        rc = fi_close(&na_ofi_domain->fi_av->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() AV failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_av = NULL;
    }

    /* Close domain */
    if (na_ofi_domain->fi_domain) {
        rc = fi_close(&na_ofi_domain->fi_domain->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() domain failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_domain = NULL;
    }

    /* Close fabric */
    if (na_ofi_domain->fi_fabric) {
        rc = fi_close(&na_ofi_domain->fi_fabric->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() fabric failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_domain->fi_fabric = NULL;
    }

    /* Free OFI info */
    if (na_ofi_domain->fi_prov) {
        /* Prevent fi_freeinfo from attempting to free the key */
        if (na_ofi_domain->fi_prov->domain_attr->auth_key)
            na_ofi_domain->fi_prov->domain_attr->auth_key = NULL;
        if (na_ofi_domain->fi_prov->domain_attr->auth_key_size)
            na_ofi_domain->fi_prov->domain_attr->auth_key_size = 0;
        fi_freeinfo(na_ofi_domain->fi_prov);
        na_ofi_domain->fi_prov = NULL;
    }

    if (na_ofi_domain->addr_ht)
        hg_hash_table_free(na_ofi_domain->addr_ht);

    hg_thread_mutex_destroy(&na_ofi_domain->mutex);
    hg_thread_rwlock_destroy(&na_ofi_domain->rwlock);

    free(na_ofi_domain->prov_name);
    free(na_ofi_domain);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_open(const struct na_ofi_domain *na_ofi_domain,
    const char *node, void *src_addr, na_size_t src_addrlen, na_bool_t no_wait,
    na_uint8_t max_contexts, struct na_ofi_endpoint **na_ofi_endpoint_p)
{
    struct na_ofi_endpoint *na_ofi_endpoint;
    struct fi_info *hints = NULL;
    na_return_t ret = NA_SUCCESS;
    /* For provider node resolution (always pass a numeric address) */
    na_uint64_t flags = (node) ? FI_SOURCE | FI_NUMERICHOST : 0;
    int rc;

    na_ofi_endpoint =
        (struct na_ofi_endpoint *) malloc(sizeof(struct na_ofi_endpoint));
    NA_CHECK_ERROR(na_ofi_endpoint == NULL, out, ret, NA_NOMEM,
        "Could not allocate na_ofi_endpoint");
    memset(na_ofi_endpoint, 0, sizeof(struct na_ofi_endpoint));

    /* Dup fi_info */
    hints = fi_dupinfo(na_ofi_domain->fi_prov);
    NA_CHECK_ERROR(
        hints == NULL, out, ret, NA_NOMEM, "Could not duplicate fi_info");

    if (src_addr) {
        /* Set src addr hints (FI_SOURCE must not be set in that case) */
        free(hints->src_addr);
        hints->addr_format = na_ofi_prov_addr_format[na_ofi_domain->prov_type];
        hints->src_addr = src_addr;
        hints->src_addrlen = src_addrlen;
    }

    /* Set max contexts to EP attrs */
    hints->ep_attr->tx_ctx_cnt = max_contexts;
    hints->ep_attr->rx_ctx_cnt = max_contexts;

    rc = fi_getinfo(
        NA_OFI_VERSION, node, NULL, flags, hints, &na_ofi_endpoint->fi_prov);

    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_getinfo(%s) failed, rc: %d (%s)", node, rc, fi_strerror(-rc));

    if ((na_ofi_prov_flags[na_ofi_domain->prov_type] & NA_OFI_SEP) &&
        max_contexts > 1) {
        ret = na_ofi_sep_open(na_ofi_domain, na_ofi_endpoint);
        NA_CHECK_NA_ERROR(out, ret, "na_ofi_sep_open() failed");
    } else {
        ret = na_ofi_basic_ep_open(na_ofi_domain, no_wait, na_ofi_endpoint);
        NA_CHECK_NA_ERROR(out, ret, "na_ofi_basic_ep_open() failed");
    }

    *na_ofi_endpoint_p = na_ofi_endpoint;

out:
    if (hints) {
        /* Prevent fi_freeinfo() from freeing src_addr */
        if (src_addr)
            hints->src_addr = NULL;
        fi_freeinfo(hints);
    }
    if (ret != NA_SUCCESS) {
        na_ofi_endpoint_close(na_ofi_endpoint);
        *na_ofi_endpoint_p = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_basic_ep_open(const struct na_ofi_domain *na_ofi_domain,
    na_bool_t no_wait, struct na_ofi_endpoint *na_ofi_endpoint)
{
    struct fi_cq_attr cq_attr = {0};
    na_return_t ret = NA_SUCCESS;
    int rc;

    NA_LOG_DEBUG("Opening standard endpoint");

    /* Create a transport level communication endpoint */
    rc = fi_endpoint(na_ofi_domain->fi_domain, /* In:  Domain object */
        na_ofi_endpoint->fi_prov,              /* In:  Provider */
        &na_ofi_endpoint->fi_ep,               /* Out: Endpoint object */
        NULL);                                 /* Optional context */
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_endpoint() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Initialize queue / mutex */
    na_ofi_endpoint->retry_op_queue = malloc(sizeof(struct na_ofi_queue));
    NA_CHECK_ERROR(na_ofi_endpoint->retry_op_queue == NULL, out, ret, NA_NOMEM,
        "Could not allocate retry_op_queue");
    HG_QUEUE_INIT(&na_ofi_endpoint->retry_op_queue->queue);
    hg_thread_mutex_init(&na_ofi_endpoint->retry_op_queue->mutex);

    if (!no_wait) {
        if (na_ofi_prov_flags[na_ofi_domain->prov_type] & NA_OFI_WAIT_FD)
            cq_attr.wait_obj = FI_WAIT_FD; /* Wait on fd */
        else {
            struct fi_wait_attr wait_attr = {0};

            /* Open wait set for other providers. */
            wait_attr.wait_obj = FI_WAIT_UNSPEC;
            rc = fi_wait_open(na_ofi_domain->fi_fabric, &wait_attr,
                &na_ofi_endpoint->fi_wait);
            NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
                "fi_wait_open() failed, rc: %d (%s)", rc, fi_strerror(-rc));
            cq_attr.wait_obj = FI_WAIT_SET; /* Wait on wait set */
            cq_attr.wait_set = na_ofi_endpoint->fi_wait;
        }
    }
    cq_attr.wait_cond = FI_CQ_COND_NONE;
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    cq_attr.size = NA_OFI_CQ_DEPTH;
    rc = fi_cq_open(
        na_ofi_domain->fi_domain, &cq_attr, &na_ofi_endpoint->fi_cq, NULL);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_cq_open failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Bind the CQ and AV to the endpoint */
    rc = fi_ep_bind(na_ofi_endpoint->fi_ep, &na_ofi_endpoint->fi_cq->fid,
        FI_TRANSMIT | FI_RECV);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = fi_ep_bind(na_ofi_endpoint->fi_ep, &na_ofi_domain->fi_av->fid, 0);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Enable the endpoint for communication, and commits the bind operations */
    rc = fi_enable(na_ofi_endpoint->fi_ep);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_enable() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    na_ofi_endpoint->sep = NA_FALSE;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_sep_open(const struct na_ofi_domain *na_ofi_domain,
    struct na_ofi_endpoint *na_ofi_endpoint)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    NA_LOG_DEBUG("Opening SEP endpoint");

    /* Create a transport level communication endpoint (sep) */
    rc = fi_scalable_ep(na_ofi_domain->fi_domain, /* In:  Domain object */
        na_ofi_endpoint->fi_prov,                 /* In:  Provider */
        &na_ofi_endpoint->fi_ep,                  /* Out: Endpoint object */
        NULL);                                    /* Optional context */
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_scalable_ep() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    rc = fi_scalable_ep_bind(
        na_ofi_endpoint->fi_ep, &na_ofi_domain->fi_av->fid, 0);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_ep_bind() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    /* Enable the endpoint for communication, and commits the bind operations */
    ret = fi_enable(na_ofi_endpoint->fi_ep);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_enable() failed, rc: %d (%s)", rc, fi_strerror(-rc));

    na_ofi_endpoint->sep = NA_TRUE;

out:
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

    /* When not using SEP */
    if (na_ofi_endpoint->retry_op_queue) {
        /* Check that unexpected op queue is empty */
        na_bool_t empty =
            HG_QUEUE_IS_EMPTY(&na_ofi_endpoint->retry_op_queue->queue);
        NA_CHECK_ERROR(empty == NA_FALSE, out, ret, NA_BUSY,
            "Retry op queue should be empty");
        hg_thread_mutex_destroy(&na_ofi_endpoint->retry_op_queue->mutex);
        free(na_ofi_endpoint->retry_op_queue);
    }

    /* Close endpoint */
    if (na_ofi_endpoint->fi_ep) {
        rc = fi_close(&na_ofi_endpoint->fi_ep->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() endpoint failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_endpoint->fi_ep = NULL;
    }

    /* Close completion queue */
    if (na_ofi_endpoint->fi_cq) {
        rc = fi_close(&na_ofi_endpoint->fi_cq->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() CQ failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_endpoint->fi_cq = NULL;
    }

    /* Close wait set */
    if (na_ofi_endpoint->fi_wait) {
        rc = fi_close(&na_ofi_endpoint->fi_wait->fid);
        NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
            "fi_close() wait failed, rc: %d (%s)", rc, fi_strerror(-rc));
        na_ofi_endpoint->fi_wait = NULL;
    }

    /* Free OFI info */
    if (na_ofi_endpoint->fi_prov) {
        fi_freeinfo(na_ofi_endpoint->fi_prov);
        na_ofi_endpoint->fi_prov = NULL;
    }

    if (na_ofi_endpoint->src_addr)
        na_ofi_addr_decref(na_ofi_endpoint->src_addr);
    free(na_ofi_endpoint);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get_ep_addr(na_class_t *na_class, struct na_ofi_addr **na_ofi_addr_ptr)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_domain *na_ofi_domain = priv->domain;
    struct na_ofi_endpoint *na_ofi_endpoint = priv->endpoint;
    struct na_ofi_addr *na_ofi_addr = NULL;
    void *addr = NULL;
    size_t addrlen = na_ofi_domain->fi_prov->src_addrlen;
    na_bool_t retried = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    int rc;

    na_ofi_addr = na_ofi_addr_alloc(priv->domain);
    NA_CHECK_ERROR(na_ofi_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI addr");

retry:
    addr = malloc(addrlen);
    NA_CHECK_ERROR(
        addr == NULL, error, ret, NA_NOMEM, "Could not allocate addr");

    rc = fi_getname(&na_ofi_endpoint->fi_ep->fid, addr, &addrlen);
    if (rc == -FI_ETOOSMALL && retried == NA_FALSE) {
        retried = NA_TRUE;
        free(addr);
        goto retry;
    }
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "fi_getname() failed, rc: %d (%s), addrlen: %zu", rc, fi_strerror(-rc),
        addrlen);

    na_ofi_addr->addr = addr;
    na_ofi_addr->addrlen = addrlen;

    /* Get URI from address */
    ret = na_ofi_get_uri(na_class, na_ofi_addr->addr, &na_ofi_addr->uri);
    NA_CHECK_NA_ERROR(error, ret, "Could not get URI from endpoint address");

    /* TODO check address size */
    *na_ofi_addr_ptr = na_ofi_addr;

    return ret;

error:
    free(addr);
    free(na_ofi_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get_uri(na_class_t *na_class, const void *addr, char **uri_ptr)
{
    struct na_ofi_domain *na_ofi_domain = NA_OFI_CLASS(na_class)->domain;
    char addr_str[NA_OFI_MAX_URI_LEN] = {'\0'},
         fi_addr_str[NA_OFI_MAX_URI_LEN] = {'\0'}, *fi_addr_str_ptr,
         *uri = NULL;
    size_t fi_addr_strlen = NA_OFI_MAX_URI_LEN;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Convert FI address to a printable string */
    fi_av_straddr(na_ofi_domain->fi_av, addr, fi_addr_str, &fi_addr_strlen);
    NA_CHECK_ERROR(fi_addr_strlen > NA_OFI_MAX_URI_LEN, out, ret,
        NA_PROTOCOL_ERROR, "fi_av_straddr() address truncated, addrlen: %zu",
        fi_addr_strlen);

    /* Remove unnecessary "://" prefix from string if present */
    if (strstr(fi_addr_str, "://")) {
        strtok_r(fi_addr_str, ":", &fi_addr_str_ptr);
        rc = strncmp(fi_addr_str_ptr, "//", 2);
        NA_CHECK_ERROR(
            rc != 0, out, ret, NA_PROTONOSUPPORT, "Bad address string format");
        fi_addr_str_ptr += 2;
    } else
        fi_addr_str_ptr = fi_addr_str;

    /* Generate URI */
    rc = snprintf(addr_str, NA_OFI_MAX_URI_LEN, "%s://%s",
        na_ofi_domain->fi_prov->fabric_attr->prov_name, fi_addr_str_ptr);
    NA_CHECK_ERROR(rc < 0 || rc > NA_OFI_MAX_URI_LEN, out, ret, NA_OVERFLOW,
        "snprintf() failed or name truncated, rc: %d", rc);

    /* Dup URI */
    uri = strdup(addr_str);
    NA_CHECK_ERROR(
        uri == NULL, out, ret, NA_NOMEM, "Could not strdup address string");

    *uri_ptr = uri;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_addr *
na_ofi_addr_alloc(struct na_ofi_domain *na_ofi_domain)
{
    struct na_ofi_addr *na_ofi_addr;

    na_ofi_addr = (struct na_ofi_addr *) calloc(1, sizeof(*na_ofi_addr));
    NA_CHECK_ERROR_NORET(na_ofi_addr == NULL, out, "Could not allocate addr");

    /* Keep reference to domain */
    na_ofi_addr->domain = na_ofi_domain;
    hg_atomic_incr32(&na_ofi_domain->refcount);

    /* One refcount for the caller to hold until addr_free */
    hg_atomic_init32(&na_ofi_addr->refcount, 1);

out:
    return na_ofi_addr;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_addr_addref(struct na_ofi_addr *na_ofi_addr)
{
    hg_atomic_incr32(&na_ofi_addr->refcount);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_addr_decref(struct na_ofi_addr *na_ofi_addr)
{
    /* If there are more references, return */
    if (hg_atomic_decr32(&na_ofi_addr->refcount))
        return;

    /* Do not call fi_av_remove() here to prevent multiple insert/remove calls
     * into AV */
    if (na_ofi_addr->remove) {
        NA_LOG_DEBUG("fi_addr=%" SCNx64 " ht_key=%" SCNx64,
            na_ofi_addr->fi_addr, na_ofi_addr->ht_key);
        na_ofi_addr_ht_remove(
            na_ofi_addr->domain, &na_ofi_addr->fi_addr, &na_ofi_addr->ht_key);
    }
    na_ofi_domain_close(na_ofi_addr->domain);
    free(na_ofi_addr->addr);
    free(na_ofi_addr->uri);
    free(na_ofi_addr);
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_mem_pool *
na_ofi_mem_pool_create(
    na_class_t *na_class, na_size_t block_size, na_size_t block_count)
{
    struct na_ofi_mem_pool *na_ofi_mem_pool = NULL;
    na_size_t pool_size =
        block_size * block_count + sizeof(struct na_ofi_mem_pool) +
        block_count * (offsetof(struct na_ofi_mem_node, block));
    struct fid_mr *mr_hdl = NULL;
    na_size_t i;

    na_ofi_mem_pool = (struct na_ofi_mem_pool *) na_ofi_mem_alloc(
        na_class, pool_size, &mr_hdl);
    NA_CHECK_ERROR_NORET(na_ofi_mem_pool == NULL, out,
        "Could not allocate %d bytes", (int) pool_size);

    HG_QUEUE_INIT(&na_ofi_mem_pool->node_list);
    hg_thread_spin_init(&na_ofi_mem_pool->node_list_lock);
    na_ofi_mem_pool->mr_hdl = mr_hdl;
    na_ofi_mem_pool->block_size = block_size;

    /* Assign nodes and insert them to free list */
    for (i = 0; i < block_count; i++) {
        struct na_ofi_mem_node *na_ofi_mem_node = (struct na_ofi_mem_node
                *) ((char *) na_ofi_mem_pool + sizeof(struct na_ofi_mem_pool) +
                    i * (offsetof(struct na_ofi_mem_node, block) + block_size));
        HG_QUEUE_PUSH_TAIL(&na_ofi_mem_pool->node_list, na_ofi_mem_node, entry);
    }

out:
    return na_ofi_mem_pool;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_mem_pool_destroy(
    na_class_t *na_class, struct na_ofi_mem_pool *na_ofi_mem_pool)
{
    na_ofi_mem_free(na_class, na_ofi_mem_pool, na_ofi_mem_pool->mr_hdl);
    hg_thread_spin_destroy(&na_ofi_mem_pool->node_list_lock);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void *
na_ofi_mem_alloc(na_class_t *na_class, na_size_t size, struct fid_mr **mr_hdl)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    na_size_t page_size = (na_size_t) hg_mem_get_page_size();
    void *mem_ptr = NULL;

    /* Allocate backend buffer */
    mem_ptr = hg_mem_aligned_alloc(page_size, size);
    NA_CHECK_ERROR_NORET(
        mem_ptr == NULL, out, "Could not allocate %d bytes", (int) size);
    memset(mem_ptr, 0, size);

    /* Register memory if FI_MR_LOCAL is set and provider uses it */
    if (domain->fi_prov->domain_attr->mr_mode & FI_MR_LOCAL) {
        int rc;

        rc = fi_mr_reg(domain->fi_domain, mem_ptr, size,
            FI_REMOTE_READ | FI_REMOTE_WRITE | FI_SEND | FI_RECV | FI_READ |
                FI_WRITE,
            0 /* offset */, 0 /* requested key */, 0 /* flags */, mr_hdl,
            NULL /* context */);
        if (unlikely(rc != 0)) {
            hg_mem_aligned_free(mem_ptr);
            NA_GOTO_ERROR(out, mem_ptr, NULL,
                "fi_mr_reg() failed, rc: %d (%s), mr_reg_count: %d", rc,
                fi_strerror(-rc), hg_atomic_get32(&domain->mr_reg_count));
        }
        hg_atomic_incr32(&domain->mr_reg_count);
    }

out:
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_mem_free(na_class_t *na_class, void *mem_ptr, struct fid_mr *mr_hdl)
{
    /* Release MR handle is there was any */
    if (mr_hdl) {
        int rc = fi_close(&mr_hdl->fid);
        NA_CHECK_ERROR_NORET(rc != 0, out,
            "fi_close() mr_hdl failed, rc: %d (%s)", rc, fi_strerror(-rc));
        hg_atomic_decr32(&NA_OFI_CLASS(na_class)->domain->mr_reg_count);
    }

out:
    hg_mem_aligned_free(mem_ptr);
    return;
}

/*---------------------------------------------------------------------------*/
static void *
na_ofi_mem_pool_alloc(
    na_class_t *na_class, na_size_t size, struct fid_mr **mr_hdl)
{
    struct na_ofi_mem_pool *na_ofi_mem_pool;
    struct na_ofi_mem_node *na_ofi_mem_node;
    void *mem_ptr = NULL;
    na_bool_t found = NA_FALSE;

retry:
    /* Check whether we can get a block from one of the pools */
    hg_thread_spin_lock(&NA_OFI_CLASS(na_class)->buf_pool_lock);
    HG_QUEUE_FOREACH (
        na_ofi_mem_pool, &NA_OFI_CLASS(na_class)->buf_pool, entry) {
        hg_thread_spin_lock(&na_ofi_mem_pool->node_list_lock);
        found = !HG_QUEUE_IS_EMPTY(&na_ofi_mem_pool->node_list);
        hg_thread_spin_unlock(&na_ofi_mem_pool->node_list_lock);
        if (found)
            break;
    }
    hg_thread_spin_unlock(&NA_OFI_CLASS(na_class)->buf_pool_lock);

    /* If not, allocate and register a new pool */
    if (!found) {
        na_ofi_mem_pool = na_ofi_mem_pool_create(na_class,
            na_ofi_msg_get_max_unexpected_size(na_class),
            NA_OFI_MEM_BLOCK_COUNT);
        hg_thread_spin_lock(&NA_OFI_CLASS(na_class)->buf_pool_lock);
        HG_QUEUE_PUSH_TAIL(
            &NA_OFI_CLASS(na_class)->buf_pool, na_ofi_mem_pool, entry);
        hg_thread_spin_unlock(&NA_OFI_CLASS(na_class)->buf_pool_lock);
    }

    NA_CHECK_ERROR(size > na_ofi_mem_pool->block_size, out, mem_ptr, NULL,
        "Block size is too small for requested size");

    /* Pick a node from one of the available pools */
    hg_thread_spin_lock(&na_ofi_mem_pool->node_list_lock);
    na_ofi_mem_node = HG_QUEUE_FIRST(&na_ofi_mem_pool->node_list);
    if (!na_ofi_mem_node) {
        hg_thread_spin_unlock(&na_ofi_mem_pool->node_list_lock);
        goto retry;
    }
    HG_QUEUE_POP_HEAD(&na_ofi_mem_pool->node_list, entry);
    hg_thread_spin_unlock(&na_ofi_mem_pool->node_list_lock);
    mem_ptr = &na_ofi_mem_node->block;
    *mr_hdl = na_ofi_mem_pool->mr_hdl;

out:
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_mem_pool_free(na_class_t *na_class, void *mem_ptr, struct fid_mr *mr_hdl)
{
    struct na_ofi_mem_pool *na_ofi_mem_pool;
    struct na_ofi_mem_node *na_ofi_mem_node =
        container_of(mem_ptr, struct na_ofi_mem_node, block);

    /* Put the node back to the pool */
    hg_thread_spin_lock(&NA_OFI_CLASS(na_class)->buf_pool_lock);
    HG_QUEUE_FOREACH (
        na_ofi_mem_pool, &NA_OFI_CLASS(na_class)->buf_pool, entry) {
        /* If MR handle is NULL, it does not really matter which pool we push
         * the node back to.
         */
        if (na_ofi_mem_pool->mr_hdl == mr_hdl) {
            hg_thread_spin_lock(&na_ofi_mem_pool->node_list_lock);
            HG_QUEUE_PUSH_TAIL(
                &na_ofi_mem_pool->node_list, na_ofi_mem_node, entry);
            hg_thread_spin_unlock(&na_ofi_mem_pool->node_list_lock);
            break;
        }
    }
    hg_thread_spin_unlock(&NA_OFI_CLASS(na_class)->buf_pool_lock);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_iov_get_index_offset(const struct iovec *iov, unsigned long iovcnt,
    na_offset_t offset, unsigned long *iov_start_index,
    unsigned long *iov_start_offset)
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
    unsigned long iov_start_index, na_offset_t iov_start_offset, na_size_t len)
{
    na_size_t remaining_len =
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
    unsigned long iov_start_index, na_offset_t iov_start_offset, na_size_t len,
    struct iovec *new_iov, unsigned long new_iovcnt)
{
    na_size_t remaining_len = len;
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
na_ofi_rma_iov_translate(const struct iovec *iov, unsigned long iovcnt,
    na_uint64_t key, unsigned long iov_start_index,
    na_offset_t iov_start_offset, na_size_t len, struct fi_rma_iov *new_iov,
    unsigned long new_iovcnt)
{
    na_size_t remaining_len = len;
    unsigned long i, iov_index;

    /* Offset is only within first segment */
    new_iov[0].addr =
        (uint64_t) iov[iov_start_index].iov_base + iov_start_offset;
    new_iov[0].len =
        MIN(remaining_len, iov[iov_start_index].iov_len - iov_start_offset);
    new_iov[0].key = key;
    remaining_len -= new_iov[0].len;

    for (i = 1, iov_index = iov_start_index + 1;
         remaining_len > 0 && i < new_iovcnt && iov_index < iovcnt;
         i++, iov_index++) {
        new_iov[i].addr = (uint64_t) iov[iov_index].iov_base;
        new_iov[i].len = MIN(remaining_len, iov[iov_index].iov_len);
        new_iov[i].key = key;

        /* Decrease remaining len from the len of data */
        remaining_len -= new_iov[i].len;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_rma(na_class_t *na_class, na_context_t *context, na_cb_type_t cb_type,
    na_cb_t callback, void *arg,
    ssize_t (*fi_rma_op)(
        struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags),
    na_uint64_t fi_rma_flags, struct na_ofi_mem_handle *na_ofi_mem_handle_local,
    na_offset_t local_offset,
    struct na_ofi_mem_handle *na_ofi_mem_handle_remote,
    na_offset_t remote_offset, na_size_t length,
    struct na_ofi_addr *na_ofi_addr, na_uint8_t remote_id,
    struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct iovec *local_iov = NA_OFI_IOV(na_ofi_mem_handle_local),
                 *remote_iov = NA_OFI_IOV(na_ofi_mem_handle_remote);
    unsigned long local_iovcnt = na_ofi_mem_handle_local->desc.info.iovcnt,
                  remote_iovcnt = na_ofi_mem_handle_remote->desc.info.iovcnt;
    na_uint64_t remote_key = na_ofi_mem_handle_remote->desc.info.fi_mr_key;
    unsigned long local_iov_start_index = 0, remote_iov_start_index = 0;
    na_offset_t local_iov_start_offset = 0, remote_iov_start_offset = 0;
    struct iovec *liov;
    struct fi_rma_iov *riov;
    struct fi_msg_rma fi_msg_rma;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    na_ofi_op_id->context = context;
    na_ofi_op_id->completion_data.callback_info.type = cb_type;
    na_ofi_op_id->completion_data.callback = callback;
    na_ofi_op_id->completion_data.callback_info.arg = arg;
    na_ofi_addr_addref(na_ofi_addr);
    na_ofi_op_id->addr = na_ofi_addr;
    hg_atomic_set32(&na_ofi_op_id->status, 0);

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
        NA_CHECK_ERROR(na_ofi_op_id->info.rma.local_iov.d == NULL, error, ret,
            NA_NOMEM, "Could not allocate iovec");

        liov = na_ofi_op_id->info.rma.local_iov.d;
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
        NA_CHECK_ERROR(na_ofi_op_id->info.rma.remote_iov.d == NULL, error, ret,
            NA_NOMEM, "Could not allocate rma iovec");

        riov = na_ofi_op_id->info.rma.remote_iov.d;
    } else
        riov = na_ofi_op_id->info.rma.remote_iov.s;

    na_ofi_rma_iov_translate(remote_iov, remote_iovcnt, remote_key,
        remote_iov_start_index, remote_iov_start_offset, length, riov,
        na_ofi_op_id->info.rma.remote_iovcnt);

    na_ofi_op_id->info.rma.fi_addr =
        fi_rx_addr(na_ofi_addr->fi_addr, remote_id, NA_OFI_SEP_RX_CTX_BITS);

    /* Set RMA msg */
    NA_OFI_MSG_RMA_SET(fi_msg_rma, liov, riov, na_ofi_op_id);

    NA_LOG_DEBUG("Posting RMA op (op id=%p)", na_ofi_op_id);

    /* Post the OFI RMA operation */
    rc = fi_rma_op(ctx->fi_tx, &fi_msg_rma, fi_rma_flags);
    if (unlikely(rc == -FI_EAGAIN)) {
        if (NA_OFI_CLASS(na_class)->no_retry)
            /* Do not attempt to retry */
            NA_GOTO_DONE(error, ret, NA_AGAIN);
        else {
            NA_LOG_DEBUG("Pushing %p for retry", na_ofi_op_id);

            /* Push op ID to retry queue */
            hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
            HG_QUEUE_PUSH_TAIL(
                &ctx->retry_op_queue->queue, na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        }
    } else
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_rma_op() failed, rc: %zd (%s)", rc, fi_strerror((int) -rc));

out:
    return ret;

error:
    if (na_ofi_op_id->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX)
        free(na_ofi_op_id->info.rma.local_iov.d);
    if (na_ofi_op_id->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX)
        free(na_ofi_op_id->info.rma.remote_iov.d);

    na_ofi_addr_decref(na_ofi_addr);
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_read(na_context_t *context, size_t max_count,
    struct fi_cq_tagged_entry cq_events[], fi_addr_t src_addrs[],
    void **src_err_addr, size_t *src_err_addrlen, size_t *actual_count)
{
    struct fid_cq *cq_hdl = NA_OFI_CONTEXT(context)->fi_cq;
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
    NA_CHECK_ERROR(rc != -FI_EAVAIL, out, ret, NA_PROTOCOL_ERROR,
        "fi_cq_readfrom() failed, rc: %zd (%s)", rc, fi_strerror((int) -rc));

    memset(&cq_err, 0, sizeof(cq_err));

    /* Prevent provider from internally allocating resources */
    cq_err.err_data = *src_err_addr;
    cq_err.err_data_size = *src_err_addrlen;

    /* Read error entry */
    rc = fi_cq_readerr(cq_hdl, &cq_err, 0 /* flags */);
    NA_CHECK_ERROR(rc != 1, out, ret, NA_PROTOCOL_ERROR,
        "fi_cq_readerr() failed, rc: %zd (%s)", rc, fi_strerror((int) -rc));

    switch (cq_err.err) {
        case FI_ECANCELED: {
            struct na_ofi_op_id *na_ofi_op_id = NULL;

            NA_CHECK_ERROR(cq_err.op_context == NULL, out, ret, NA_INVALID_ARG,
                "Invalid operation context");
            na_ofi_op_id =
                container_of(cq_err.op_context, struct na_ofi_op_id, fi_ctx);
            NA_CHECK_ERROR(na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG,
                "Invalid operation ID");

            NA_CHECK_ERROR(
                hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED,
                out, ret, NA_FAULT, "Operation ID was completed");
            NA_LOG_DEBUG("FI_ECANCELED event on operation ID %p", na_ofi_op_id);

            /* When tearing down connections, it is possible that operations
            will be canceled by libfabric itself.

            NA_CHECK_WARNING(
                !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELED),
                "Operation ID was not canceled by user");
            */

            /* Complete operation in canceled state */
            ret = na_ofi_complete(na_ofi_op_id);
            NA_CHECK_NA_ERROR(out, ret, "Unable to complete operation");
        } break;

        case FI_EADDRNOTAVAIL:
            /* Only one error event processed in that case */
            memcpy(&cq_events[0], &cq_err, sizeof(cq_events[0]));
            *src_err_addr = cq_err.err_data;
            *src_err_addrlen = cq_err.err_data_size;
            *actual_count = 1;
            break;

        default:
            NA_LOG_WARNING("fi_cq_readerr() got err: %d (%s), "
                           "prov_errno: %d (%s)",
                cq_err.err, fi_strerror(cq_err.err), cq_err.prov_errno,
                fi_cq_strerror(
                    cq_hdl, cq_err.prov_errno, cq_err.err_data, NULL, 0));

            if (cq_err.op_context == NULL)
                break;
            else {
                struct na_ofi_op_id *na_ofi_op_id = container_of(
                    cq_err.op_context, struct na_ofi_op_id, fi_ctx);

                NA_CHECK_ERROR(na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG,
                    "Invalid operation ID");
                NA_LOG_DEBUG("error event on operation ID %p", na_ofi_op_id);

                NA_CHECK_ERROR(hg_atomic_get32(&na_ofi_op_id->status) &
                                   NA_OFI_OP_COMPLETED,
                    out, ret, NA_FAULT, "Operation ID was completed");

                if (hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_ERRORED) &
                    NA_OFI_OP_CANCELED)
                    break;

                /* Complete operation in error state */
                ret = na_ofi_complete(na_ofi_op_id);
                NA_CHECK_NA_ERROR(out, ret, "Unable to complete operation");
            }
            break;
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_event(na_class_t *na_class,
    const struct fi_cq_tagged_entry *cq_event, fi_addr_t src_addr,
    void *src_err_addr, size_t src_err_addrlen)
{
    struct na_ofi_op_id *na_ofi_op_id =
        container_of(cq_event->op_context, struct na_ofi_op_id, fi_ctx);
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    /* Cannot have an already completed operation ID, sanity check */
    NA_CHECK_ERROR(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED,
        out, ret, NA_FAULT, "Operation ID was completed");

    if (cq_event->flags & FI_SEND) {
        ret = na_ofi_cq_process_send_event(na_ofi_op_id);
        NA_CHECK_NA_ERROR(out, ret, "Could not process send event");
    } else if (cq_event->flags & FI_RECV) {
        if (cq_event->tag & NA_OFI_UNEXPECTED_TAG) {
            ret = na_ofi_cq_process_recv_unexpected_event(na_class,
                na_ofi_op_id, src_addr, src_err_addr, src_err_addrlen,
                cq_event->tag, cq_event->len);
            NA_CHECK_NA_ERROR(
                out, ret, "Could not process unexpected recv event");
        } else {
            ret = na_ofi_cq_process_recv_expected_event(
                na_ofi_op_id, cq_event->tag, cq_event->len);
            NA_CHECK_NA_ERROR(
                out, ret, "Could not process expected recv event");
        }
    } else if (cq_event->flags & FI_RMA) {
        ret = na_ofi_cq_process_rma_event(na_ofi_op_id);
        NA_CHECK_NA_ERROR(out, ret, "Could not process rma event");
    } else
        NA_GOTO_ERROR(out, ret, NA_PROTONOSUPPORT,
            "Unsupported CQ event flags: 0x%" PRIx64 ".", cq_event->flags);

    /* Complete operation */
    ret = na_ofi_complete(na_ofi_op_id);
    NA_CHECK_NA_ERROR(out, ret, "Unable to complete operation");

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_cq_process_send_event(struct na_ofi_op_id *na_ofi_op_id)
{
    na_cb_type_t cb_type = na_ofi_op_id->completion_data.callback_info.type;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(
        cb_type != NA_CB_SEND_EXPECTED && cb_type != NA_CB_SEND_UNEXPECTED, out,
        ret, NA_PROTOCOL_ERROR,
        "Invalid cb_type %d, expected NA_CB_SEND_EXPECTED/UNEXPECTED", cb_type);

    NA_LOG_DEBUG("send msg completion event (op id=%p)", na_ofi_op_id);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_recv_unexpected_event(na_class_t *na_class,
    struct na_ofi_op_id *na_ofi_op_id, fi_addr_t src_addr, void *src_err_addr,
    size_t src_err_addrlen, uint64_t tag, size_t len)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    na_cb_type_t cb_type = na_ofi_op_id->completion_data.callback_info.type;
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(cb_type != NA_CB_RECV_UNEXPECTED, out, ret, NA_INVALID_ARG,
        "Invalid cb_type %d, expected NA_CB_RECV_UNEXPECTED", cb_type);
    NA_CHECK_ERROR((tag & ~NA_OFI_UNEXPECTED_TAG) > NA_OFI_MAX_TAG, out, ret,
        NA_OVERFLOW, "Invalid tag value %" PRIu64, tag);

    /* Allocate new address */
    na_ofi_addr = na_ofi_addr_alloc(domain);
    NA_CHECK_ERROR(
        na_ofi_addr == NULL, out, ret, NA_NOMEM, "na_ofi_addr_alloc() failed");
    /* Unexpected addresses do not need to set addr/addrlen info, fi_av_lookup()
     * can be used when needed. */

    /* Use src_addr when available */
    if ((na_ofi_prov_extra_caps[domain->prov_type] & FI_SOURCE) &&
        src_addr != FI_ADDR_UNSPEC)
        na_ofi_addr->fi_addr = src_addr;
    else if (src_err_addr && src_err_addrlen) { /* addr from error info */
        /* We do not need to keep a copy of src_err_addr */
        ret = na_ofi_addr_ht_lookup(domain,
            na_ofi_prov_addr_format[domain->prov_type], src_err_addr,
            src_err_addrlen, &na_ofi_addr->fi_addr, &na_ofi_addr->ht_key);
        NA_CHECK_NA_ERROR(error, ret, "na_ofi_addr_ht_lookup() failed");
    } else if (na_ofi_with_msg_hdr(na_class)) { /* addr from msg header */
        /* We do not need to keep a copy of msg header */
        ret = na_ofi_addr_ht_lookup(domain,
            na_ofi_prov_addr_format[domain->prov_type],
            na_ofi_op_id->info.msg.buf.ptr,
            na_ofi_prov_addr_size(na_ofi_prov_addr_format[domain->prov_type]),
            &na_ofi_addr->fi_addr, &na_ofi_addr->ht_key);
        NA_CHECK_NA_ERROR(error, ret, "na_ofi_addr_ht_lookup() failed");
    } else
        NA_GOTO_ERROR(
            error, ret, NA_PROTONOSUPPORT, "Insufficient address information");

    na_ofi_op_id->addr = na_ofi_addr;
    na_ofi_op_id->info.msg.tag = tag & NA_OFI_TAG_MASK;
    na_ofi_op_id->info.msg.actual_buf_size = len;

    NA_LOG_DEBUG("unexpected recv msg completion event with tag=%llu, len=%zu ",
        "(op id=%p)", tag, len, na_ofi_op_id);

out:
    return ret;

error:
    na_ofi_addr_decref(na_ofi_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_cq_process_recv_expected_event(
    struct na_ofi_op_id *na_ofi_op_id, uint64_t tag, size_t len)
{
    na_cb_type_t cb_type = na_ofi_op_id->completion_data.callback_info.type;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(cb_type != NA_CB_RECV_EXPECTED, out, ret, NA_INVALID_ARG,
        "Invalid cb_type %d, expected NA_CB_RECV_EXPECTED", cb_type);
    NA_CHECK_ERROR(
        tag > NA_OFI_MAX_TAG, out, ret, NA_OVERFLOW, "Invalid tag value");

    na_ofi_op_id->info.msg.actual_buf_size = len;

    NA_LOG_DEBUG("expected recv msg completion event with tag=%llu, len=%zu "
                 "(op id=%p)",
        tag, len, na_ofi_op_id);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_cq_process_rma_event(struct na_ofi_op_id *na_ofi_op_id)
{
    na_cb_type_t cb_type = na_ofi_op_id->completion_data.callback_info.type;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(cb_type != NA_CB_PUT && cb_type != NA_CB_GET, out, ret,
        NA_INVALID_ARG, "Invalid cb_type %d, expected NA_CB_PUT/GET", cb_type);

    NA_LOG_DEBUG("RMA completion event (op id=%p)", na_ofi_op_id);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cq_process_retries(na_context_t *context)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS, complete_ret;

    do {
        ssize_t rc = 0;

        hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);

        na_ofi_op_id = HG_QUEUE_FIRST(&ctx->retry_op_queue->queue);
        if (!na_ofi_op_id)
            break;

        NA_LOG_DEBUG("Attempting to retry %p", na_ofi_op_id);
        NA_CHECK_ERROR(
            hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_CANCELED, error,
            ret, NA_FAULT, "Operation ID was canceled");

        /* Dequeue OP ID */
        HG_QUEUE_POP_HEAD(&ctx->retry_op_queue->queue, entry);
        hg_atomic_and32(&na_ofi_op_id->status, ~NA_OFI_OP_QUEUED);

        /* Retry operation */
        switch (na_ofi_op_id->completion_data.callback_info.type) {
            case NA_CB_SEND_UNEXPECTED:
                rc = fi_tsend(ctx->fi_tx, na_ofi_op_id->info.msg.buf.const_ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr,
                    na_ofi_op_id->info.msg.tag | NA_OFI_UNEXPECTED_TAG,
                    &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_RECV_UNEXPECTED:
                rc = fi_trecv(ctx->fi_rx, na_ofi_op_id->info.msg.buf.ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr, NA_OFI_UNEXPECTED_TAG,
                    NA_OFI_TAG_MASK, &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_SEND_EXPECTED:
                rc = fi_tsend(ctx->fi_tx, na_ofi_op_id->info.msg.buf.const_ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr, na_ofi_op_id->info.msg.tag,
                    &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_RECV_EXPECTED:
                rc = fi_trecv(ctx->fi_rx, na_ofi_op_id->info.msg.buf.ptr,
                    na_ofi_op_id->info.msg.buf_size,
                    na_ofi_op_id->info.msg.fi_mr,
                    na_ofi_op_id->info.msg.fi_addr, na_ofi_op_id->info.msg.tag,
                    0, &na_ofi_op_id->fi_ctx);
                break;
            case NA_CB_PUT: {
                struct iovec *msg_iov = NA_OFI_MSG_IOV(na_ofi_op_id);
                struct fi_rma_iov *rma_iov = NA_OFI_RMA_IOV(na_ofi_op_id);
                struct fi_msg_rma fi_msg_rma;

                /* Set RMA msg */
                NA_OFI_MSG_RMA_SET(fi_msg_rma, msg_iov, rma_iov, na_ofi_op_id);
                rc =
                    fi_writemsg(ctx->fi_tx, &fi_msg_rma, NA_OFI_PUT_COMPLETION);
                break;
            }
            case NA_CB_GET: {
                struct iovec *msg_iov = NA_OFI_MSG_IOV(na_ofi_op_id);
                struct fi_rma_iov *rma_iov = NA_OFI_RMA_IOV(na_ofi_op_id);
                struct fi_msg_rma fi_msg_rma;

                /* Set RMA msg */
                NA_OFI_MSG_RMA_SET(fi_msg_rma, msg_iov, rma_iov, na_ofi_op_id);

                rc = fi_readmsg(ctx->fi_tx, &fi_msg_rma, NA_OFI_GET_COMPLETION);
                break;
            }
            default:
                NA_GOTO_ERROR(error, ret, NA_INVALID_ARG,
                    "Operation type %d not supported",
                    na_ofi_op_id->completion_data.callback_info.type);
        }

        if (unlikely(rc == -FI_EAGAIN)) {
            NA_LOG_DEBUG("Re-pushing %p for retry", na_ofi_op_id);

            /* Re-push op ID to retry queue */
            HG_QUEUE_PUSH_TAIL(&NA_OFI_CONTEXT(context)->retry_op_queue->queue,
                na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);

            /* Do not attempt to retry again and continue making progress */
            break;
        } else
            NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
                "retry operation of %d failed, rc: %zd (%s)",
                na_ofi_op_id->completion_data.callback_info.type, rc,
                fi_strerror((int) -rc));

        hg_thread_mutex_unlock(&NA_OFI_CONTEXT(context)->retry_op_queue->mutex);

    } while (1);

    hg_thread_mutex_unlock(&NA_OFI_CONTEXT(context)->retry_op_queue->mutex);

    return ret;

error:
    /* Force internal cancelation */
    hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED);
    complete_ret = na_ofi_complete(na_ofi_op_id);
    NA_CHECK_ERROR_DONE(
        complete_ret != NA_SUCCESS, "Could not complete operation");

    hg_thread_mutex_unlock(&NA_OFI_CONTEXT(context)->retry_op_queue->mutex);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_complete(struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret = NA_SUCCESS;
    hg_util_int32_t status;

    /* Mark op id as completed before checking for cancelation */
    status = hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    /* Init callback info */
    callback_info = &na_ofi_op_id->completion_data.callback_info;

    /* Check for current status before completing */
    if (status & NA_OFI_OP_CANCELED) {
        /* If it was canceled while being processed, set callback ret
         * accordingly */
        NA_LOG_DEBUG("Operation ID %p is canceled", na_ofi_op_id);
        callback_info->ret = NA_CANCELED;
    } else if (status & NA_OFI_OP_ERRORED) {
        /* If it was errored, set callback ret accordingly */
        NA_LOG_DEBUG("Operation ID %p is errored", na_ofi_op_id);
        callback_info->ret = NA_PROTOCOL_ERROR;
    } else
        callback_info->ret = NA_SUCCESS;

    switch (callback_info->type) {
        case NA_CB_RECV_UNEXPECTED:
            if (callback_info->ret != NA_SUCCESS) {
                /* In case of cancellation where no recv'd data */
                callback_info->info.recv_unexpected.actual_buf_size = 0;
                callback_info->info.recv_unexpected.source = NA_ADDR_NULL;
                callback_info->info.recv_unexpected.tag = 0;
            } else {
                /* Increment addr ref count */
                na_ofi_addr_addref(na_ofi_op_id->addr);

                /* Fill callback info */
                callback_info->info.recv_unexpected.actual_buf_size =
                    na_ofi_op_id->info.msg.actual_buf_size;
                callback_info->info.recv_unexpected.source =
                    (na_addr_t) na_ofi_op_id->addr;
                callback_info->info.recv_unexpected.tag =
                    na_ofi_op_id->info.msg.tag;
            }
            break;
        case NA_CB_RECV_EXPECTED:
            /* Check buf_size and msg_size */
            NA_CHECK_ERROR(na_ofi_op_id->info.msg.actual_buf_size >
                               na_ofi_op_id->info.msg.buf_size,
                out, ret, NA_MSGSIZE,
                "Expected recv msg size too large for buffer");
            break;
        case NA_CB_SEND_UNEXPECTED:
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_PUT:
        case NA_CB_GET:
            /* Can free extra IOVs here */
            if (na_ofi_op_id->info.rma.local_iovcnt > NA_OFI_IOV_STATIC_MAX) {
                free(na_ofi_op_id->info.rma.local_iov.d);
                na_ofi_op_id->info.rma.local_iov.d = NULL;
            }
            if (na_ofi_op_id->info.rma.remote_iovcnt > NA_OFI_IOV_STATIC_MAX) {
                free(na_ofi_op_id->info.rma.remote_iov.d);
                na_ofi_op_id->info.rma.remote_iov.d = NULL;
            }
            break;
        default:
            NA_GOTO_ERROR(out, ret, NA_INVALID_ARG,
                "Operation type %d not supported", callback_info->type);
            break;
    }

    /* Add OP to NA completion queue */
    na_cb_completion_add(na_ofi_op_id->context, &na_ofi_op_id->completion_data);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ofi_release(void *arg)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) arg;

    NA_CHECK_WARNING(na_ofi_op_id && (!(hg_atomic_get32(&na_ofi_op_id->status) &
                                         NA_OFI_OP_COMPLETED)),
        "Releasing resources from an uncompleted operation");

    if (na_ofi_op_id->addr) {
        na_ofi_addr_decref(na_ofi_op_id->addr);
        na_ofi_op_id->addr = NULL;
    }
}

/********************/
/* Plugin callbacks */
/********************/

static na_bool_t
na_ofi_check_protocol(const char *protocol_name)
{
    struct fi_info *providers = NULL, *prov;
    na_bool_t accept = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    enum na_ofi_prov_type type;

    type = na_ofi_prov_name_to_type(protocol_name);
    NA_CHECK_ERROR(type == NA_OFI_PROV_NULL, out, ret, NA_PROTONOSUPPORT,
        "Protocol %s not supported", protocol_name);

    /* Get info from provider */
    ret = na_ofi_getinfo(type, &providers, protocol_name);
    NA_CHECK_NA_ERROR(out, ret, "na_ofi_getinfo() failed");

    prov = providers;
    while (prov != NULL) {
        NA_LOG_DEBUG(
            "fabric_attr - prov_name %s, name - %s, "
            "domain_attr - name %s, mode: 0x%llx, domain_attr->mode 0x%llx, "
            "caps: 0x%llx",
            prov->fabric_attr->prov_name, prov->fabric_attr->name,
            prov->domain_attr->name, prov->mode, prov->domain_attr->mode,
            prov->caps);
        if (!strcmp(na_ofi_prov_name[type], prov->fabric_attr->prov_name)) {
            accept = NA_TRUE;
            break;
        }
        prov = prov->next;
    }

    fi_freeinfo(providers);

out:
    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_initialize(na_class_t *na_class, const struct na_info *na_info,
    na_bool_t NA_UNUSED listen)
{
    struct na_ofi_class *priv;
    void *src_addr = NULL;
    na_size_t src_addrlen = 0;
    char *resolve_name = NULL;
    char *host_name = NULL;
    unsigned int port = 0;
    const char *node_ptr = NULL;
    char node[NA_OFI_MAX_URI_LEN] = {'\0'};
    char *domain_name_ptr = NULL;
    char domain_name[NA_OFI_MAX_URI_LEN] = {'\0'};
    na_bool_t no_wait = NA_FALSE, no_retry = NA_FALSE;
    na_uint8_t context_max = 1; /* Default */
    const char *auth_key = NULL;
    na_return_t ret = NA_SUCCESS;
    enum na_ofi_prov_type prov_type;

    NA_LOG_DEBUG("Entering na_ofi_initialize() class_name %s, protocol_name %s,"
                 " host_name %s",
        na_info->class_name, na_info->protocol_name, na_info->host_name);

    prov_type = na_ofi_prov_name_to_type(na_info->protocol_name);
    NA_CHECK_ERROR(prov_type == NA_OFI_PROV_NULL, out, ret, NA_INVALID_ARG,
        "Protocol %s not supported", na_info->protocol_name);

#if defined(NA_OFI_HAS_EXT_GNI_H) && defined(NA_OFI_GNI_HAS_UDREG)
    /* In case of GNI using udreg, we check to see whether
     * MPICH_GNI_NDREG_ENTRIES environment variable is set or not.  If not, this
     * code is not likely to work if Cray MPI is also used. Print error msg
     * suggesting workaround.
     */
    NA_CHECK_ERROR(
        prov_type == NA_OFI_PROV_GNI && !getenv("MPICH_GNI_NDREG_ENTRIES"), out,
        ret, NA_INVALID_ARG,
        "ofi+gni provider requested, but the MPICH_GNI_NDREG_ENTRIES "
        "environment variable is not set.\n"
        "Please run this executable with "
        "\"export MPICH_GNI_NDREG_ENTRIES=1024\" to ensure compatibility.");
#endif

    /* Use default interface name if no hostname was passed */
    if (na_info->host_name) {
        host_name = strdup(na_info->host_name);
        NA_CHECK_ERROR(host_name == NULL, out, ret, NA_NOMEM,
            "strdup() of host_name failed");

        /* Extract hostname */
        if (strstr(host_name, ":")) {
            char *port_str = NULL;
            strtok_r(host_name, ":", &port_str);
            port = (unsigned int) strtoul(port_str, NULL, 10);
        }

        /* Extract domain (if specified) */
        if (strstr(host_name, "/")) {
            strtok_r(host_name, "/", &resolve_name);
            domain_name_ptr = host_name;
        } else
            resolve_name = host_name;
    } else if (na_ofi_prov_addr_format[prov_type] == FI_ADDR_GNI)
        resolve_name = NA_OFI_GNI_IFACE_DEFAULT;

    /* Get hostname/port info if available */
    if (resolve_name) {
        if (na_ofi_prov_addr_format[prov_type] == FI_SOCKADDR_IN) {
            char *ifa_name;
            struct na_ofi_sin_addr *na_ofi_sin_addr = NULL;

            /* Try to get matching IP/device */
            ret = na_ofi_check_interface(
                resolve_name, port, &ifa_name, &na_ofi_sin_addr);
            NA_CHECK_NA_ERROR(out, ret, "Could not check interfaces");

            /* Set SIN addr if found */
            if (na_ofi_sin_addr && ifa_name) {
                src_addr = na_ofi_sin_addr;
                src_addrlen = sizeof(*na_ofi_sin_addr);
                if (!domain_name_ptr) {
                    /* Attempt to pass domain name as ifa_name if not set */
                    strncpy(domain_name, ifa_name, NA_OFI_MAX_URI_LEN - 1);
                    domain_name_ptr = domain_name;
                }
                free(ifa_name);
            } else if (!domain_name_ptr) {
                /* Pass domain name as hostname if not set */
                strncpy(domain_name, resolve_name, NA_OFI_MAX_URI_LEN - 1);
                domain_name_ptr = domain_name;
            }
        } else if (na_ofi_prov_addr_format[prov_type] == FI_ADDR_GNI) {
            struct na_ofi_sin_addr *na_ofi_sin_addr = NULL;
            const char *ptr;

            /* Try to get matching IP/device (do not use port) */
            ret =
                na_ofi_check_interface(resolve_name, 0, NULL, &na_ofi_sin_addr);
            NA_CHECK_ERROR(ret != NA_SUCCESS || !na_ofi_sin_addr, out, ret,
                NA_ADDRNOTAVAIL, "Could not check interfaces");

            /* Node must match IP resolution */
            ptr = inet_ntop(na_ofi_sin_addr->sin.sin_family,
                &na_ofi_sin_addr->sin.sin_addr, node, sizeof(node));
            free(na_ofi_sin_addr);
            NA_CHECK_ERROR(ptr == NULL, out, ret, NA_ADDRNOTAVAIL,
                "Could not convert IP to string");
            node_ptr = node;
        } else if (na_ofi_prov_addr_format[prov_type] == FI_ADDR_PSMX) {
            /* Nothing to do */
        } else if (na_ofi_prov_addr_format[prov_type] == FI_ADDR_PSMX2) {
            /* Nothing to do */
        }
    }

    /* Get init info */
    if (na_info->na_init_info) {
        /* Progress mode */
        if (na_info->na_init_info->progress_mode & NA_NO_BLOCK)
            no_wait = NA_TRUE;
        if (na_info->na_init_info->progress_mode & NA_NO_RETRY)
            no_retry = NA_TRUE;
        /* Max contexts */
        context_max = na_info->na_init_info->max_contexts;
        /* Auth key */
        auth_key = na_info->na_init_info->auth_key;
    }

    /* Create private data */
    na_class->plugin_class =
        (struct na_ofi_class *) malloc(sizeof(struct na_ofi_class));
    NA_CHECK_ERROR(na_class->plugin_class == NULL, out, ret, NA_NOMEM,
        "Could not allocate NA private data class");
    memset(na_class->plugin_class, 0, sizeof(struct na_ofi_class));
    priv = NA_OFI_CLASS(na_class);
    priv->no_wait = no_wait;
    priv->no_retry = no_retry;
    priv->context_max = context_max;
    priv->contexts = 0;

    /* Initialize queue / mutex */
    hg_thread_mutex_init(&priv->mutex);

    /* Initialize buf pool */
    hg_thread_spin_init(&priv->buf_pool_lock);
    HG_QUEUE_INIT(&priv->buf_pool);

    /* Create domain */
    ret = na_ofi_domain_open(
        na_class, prov_type, domain_name_ptr, auth_key, &priv->domain);
    NA_CHECK_NA_ERROR(out, ret, "Could not open domain for %s, %s",
        na_ofi_prov_name[prov_type], domain_name_ptr);

    /* Cache IOV max */
    priv->iov_max = priv->domain->fi_prov->domain_attr->mr_iov_limit;

    /* Create endpoint */
    ret = na_ofi_endpoint_open(priv->domain, node_ptr, src_addr, src_addrlen,
        priv->no_wait, priv->context_max, &priv->endpoint);
    NA_CHECK_NA_ERROR(
        out, ret, "Could not create endpoint for %s", resolve_name);

    /* Get address from endpoint */
    ret = na_ofi_get_ep_addr(na_class, &priv->endpoint->src_addr);
    NA_CHECK_NA_ERROR(out, ret, "Could not get address from endpoint");

out:
    if (ret != NA_SUCCESS) {
        if (na_class->plugin_class) {
            na_ofi_finalize(na_class);
            na_class->plugin_class = NULL;
        }
    }
    free(src_addr);
    free(host_name);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_finalize(na_class_t *na_class)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    na_return_t ret = NA_SUCCESS;

    if (priv == NULL)
        goto out;

    /* Close endpoint */
    if (priv->endpoint) {
        ret = na_ofi_endpoint_close(priv->endpoint);
        NA_CHECK_NA_ERROR(out, ret, "Could not close endpoint");
        priv->endpoint = NULL;
    }

    /* Free memory pool (must be done before trying to close the domain as
     * the pool is holding memory handles) */
    while (!HG_QUEUE_IS_EMPTY(&priv->buf_pool)) {
        struct na_ofi_mem_pool *na_ofi_mem_pool =
            HG_QUEUE_FIRST(&priv->buf_pool);
        HG_QUEUE_POP_HEAD(&priv->buf_pool, entry);

        na_ofi_mem_pool_destroy(na_class, na_ofi_mem_pool);
    }
    hg_thread_spin_destroy(&NA_OFI_CLASS(na_class)->buf_pool_lock);

    /* Close domain */
    if (priv->domain) {
        ret = na_ofi_domain_close(priv->domain);
        NA_CHECK_NA_ERROR(out, ret, "Could not close domain");
        priv->domain = NULL;
    }

    /* Close mutex / free private data */
    hg_thread_mutex_destroy(&priv->mutex);
    free(priv);
    na_class->plugin_class = NULL;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_context_create(na_class_t *na_class, void **context, na_uint8_t id)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_domain *domain = priv->domain;
    struct na_ofi_endpoint *ep = priv->endpoint;
    struct na_ofi_context *ctx = NULL;
    struct fi_cq_attr cq_attr = {0};
    na_return_t ret = NA_SUCCESS;
    int rc = 0;

    ctx = (struct na_ofi_context *) calloc(1, sizeof(struct na_ofi_context));
    NA_CHECK_ERROR(
        ctx == NULL, out, ret, NA_NOMEM, "Could not allocate na_ofi_context");
    ctx->idx = id;

    /* If not using SEP, just point to endpoint objects */
    hg_thread_mutex_lock(&priv->mutex);

    if (!na_ofi_with_sep(na_class)) {
        ctx->fi_tx = ep->fi_ep;
        ctx->fi_rx = ep->fi_ep;
        ctx->fi_cq = ep->fi_cq;
        ctx->fi_wait = ep->fi_wait;
        ctx->retry_op_queue = ep->retry_op_queue;
    } else {
        ctx->retry_op_queue = malloc(sizeof(struct na_ofi_queue));
        NA_CHECK_ERROR(ctx->retry_op_queue == NULL, error, ret, NA_NOMEM,
            "Could not allocate retry_op_queue/_lock");

        /* Initialize queue / mutex */
        HG_QUEUE_INIT(&ctx->retry_op_queue->queue);
        hg_thread_mutex_init(&ctx->retry_op_queue->mutex);

        NA_CHECK_ERROR(
            priv->contexts >= priv->context_max || id >= priv->context_max,
            error, ret, NA_OPNOTSUPPORTED,
            "contexts %d, context id %d, max_contexts %d", priv->contexts, id,
            priv->context_max);

        if (!priv->no_wait) {
            if (na_ofi_prov_flags[domain->prov_type] & NA_OFI_WAIT_FD)
                cq_attr.wait_obj = FI_WAIT_FD; /* Wait on fd */
            else {
                struct fi_wait_attr wait_attr = {0};

                /* Open wait set for other providers. */
                wait_attr.wait_obj = FI_WAIT_UNSPEC;
                rc = fi_wait_open(domain->fi_fabric, &wait_attr, &ctx->fi_wait);
                NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
                    "fi_wait_open() failed, rc: %d (%s)", rc, fi_strerror(-rc));
                cq_attr.wait_obj = FI_WAIT_SET; /* Wait on wait set */
                cq_attr.wait_set = ctx->fi_wait;
            }
        }
        cq_attr.wait_cond = FI_CQ_COND_NONE;
        cq_attr.format = FI_CQ_FORMAT_TAGGED;
        cq_attr.size = NA_OFI_CQ_DEPTH;
        rc = fi_cq_open(domain->fi_domain, &cq_attr, &ctx->fi_cq, NULL);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_cq_open() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_tx_context(ep->fi_ep, id, NULL, &ctx->fi_tx, NULL);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_tx_context() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_rx_context(ep->fi_ep, id, NULL, &ctx->fi_rx, NULL);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_rx_context() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_ep_bind(ctx->fi_tx, &ctx->fi_cq->fid, FI_TRANSMIT);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_ep_bind() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_ep_bind(ctx->fi_rx, &ctx->fi_cq->fid, FI_RECV);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_ep_bind() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_enable(ctx->fi_tx);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_enable() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = fi_enable(ctx->fi_rx);
        NA_CHECK_ERROR(rc < 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_enable() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));
    }

    priv->contexts++;
    hg_thread_mutex_unlock(&priv->mutex);

    *context = ctx;

out:
    return ret;

error:
    hg_thread_mutex_unlock(&priv->mutex);
    if (na_ofi_with_sep(na_class) && ctx->retry_op_queue) {
        hg_thread_mutex_destroy(&ctx->retry_op_queue->mutex);
        free(ctx->retry_op_queue);
    }
    free(ctx);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_context_destroy(na_class_t *na_class, void *context)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_context *ctx = (struct na_ofi_context *) context;
    na_return_t ret = NA_SUCCESS;
    int rc;

    if (na_ofi_with_sep(na_class)) {
        na_bool_t empty;

        /* Check that retry op queue is empty */
        empty = HG_QUEUE_IS_EMPTY(&ctx->retry_op_queue->queue);
        NA_CHECK_ERROR(empty == NA_FALSE, out, ret, NA_BUSY,
            "Retry op queue should be empty");

        if (ctx->fi_tx) {
            rc = fi_close(&ctx->fi_tx->fid);
            NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
                "fi_close() noc_tx failed, rc: %d (%s)", rc, fi_strerror(-rc));
            ctx->fi_tx = NULL;
        }

        if (ctx->fi_rx) {
            rc = fi_close(&ctx->fi_rx->fid);
            NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
                "fi_close() noc_rx failed, rc: %d (%s)", rc, fi_strerror(-rc));
            ctx->fi_rx = NULL;
        }

        /* Close wait set */
        if (ctx->fi_wait) {
            rc = fi_close(&ctx->fi_wait->fid);
            NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
                "fi_close() wait failed, rc: %d (%s)", rc, fi_strerror(-rc));
            ctx->fi_wait = NULL;
        }

        /* Close completion queue */
        if (ctx->fi_cq) {
            rc = fi_close(&ctx->fi_cq->fid);
            NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
                "fi_close() CQ failed, rc: %d (%s)", rc, fi_strerror(-rc));
            ctx->fi_cq = NULL;
        }

        hg_thread_mutex_destroy(&ctx->retry_op_queue->mutex);
        free(ctx->retry_op_queue);
    }

    hg_thread_mutex_lock(&priv->mutex);
    priv->contexts--;
    hg_thread_mutex_unlock(&priv->mutex);

    free(ctx);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_ofi_op_create(na_class_t NA_UNUSED *na_class)
{
    struct na_ofi_op_id *na_ofi_op_id = NULL;

    na_ofi_op_id =
        (struct na_ofi_op_id *) calloc(1, sizeof(struct na_ofi_op_id));
    NA_CHECK_ERROR_NORET(
        na_ofi_op_id == NULL, out, "Could not allocate NA OFI operation ID");

    /* Completed by default */
    hg_atomic_init32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    /* Set op ID release callbacks */
    na_ofi_op_id->completion_data.plugin_callback = na_ofi_release;
    na_ofi_op_id->completion_data.plugin_callback_args = na_ofi_op_id;

out:
    return (na_op_id_t *) na_ofi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to free OP ID that was not completed");

    free(na_ofi_op_id);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Check provider from name */
    NA_CHECK_ERROR(na_ofi_addr_prov(name) != domain->prov_type, out, ret,
        NA_INVALID_ARG, "Unrecognized provider type found from: %s", name);

    /* Allocate addr */
    na_ofi_addr = na_ofi_addr_alloc(domain);
    NA_CHECK_ERROR(na_ofi_addr == NULL, error, ret, NA_NOMEM,
        "na_ofi_addr_alloc() failed");
    na_ofi_addr->uri = strdup(name);
    NA_CHECK_ERROR(na_ofi_addr->uri == NULL, error, ret, NA_NOMEM,
        "strdup() of URI failed");

    /* Convert name to address */
    ret = na_ofi_str_to_addr(name, na_ofi_prov_addr_format[domain->prov_type],
        &na_ofi_addr->addr, &na_ofi_addr->addrlen);
    NA_CHECK_NA_ERROR(error, ret, "Could not convert string to address");

    /* Lookup address */
    ret = na_ofi_addr_ht_lookup(domain,
        na_ofi_prov_addr_format[domain->prov_type], na_ofi_addr->addr,
        na_ofi_addr->addrlen, &na_ofi_addr->fi_addr, &na_ofi_addr->ht_key);
    NA_CHECK_NA_ERROR(error, ret, "na_ofi_addr_ht_lookup(%s) failed", name);

    *addr = (na_addr_t) na_ofi_addr;

out:
    return ret;

error:
    if (na_ofi_addr) {
        free(na_ofi_addr->addr);
        free(na_ofi_addr->uri);
        free(na_ofi_addr);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ofi_addr_decref((struct na_ofi_addr *) addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_set_remove(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    ((struct na_ofi_addr *) addr)->remove = NA_TRUE;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr)
{
    struct na_ofi_endpoint *ep = NA_OFI_CLASS(na_class)->endpoint;

    na_ofi_addr_addref(ep->src_addr); /* decref in na_ofi_addr_free() */
    *addr = (na_addr_t) ep->src_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ofi_addr_dup(
    na_class_t NA_UNUSED *na_class, na_addr_t addr, na_addr_t *new_addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_addr_free() */
    *new_addr = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_addr_cmp(
    na_class_t NA_UNUSED *na_class, na_addr_t addr1, na_addr_t addr2)
{
    struct na_ofi_addr *na_ofi_addr1 = (struct na_ofi_addr *) addr1;
    struct na_ofi_addr *na_ofi_addr2 = (struct na_ofi_addr *) addr2;

    if ((na_ofi_addr1 == na_ofi_addr2) ||
        (na_ofi_addr1->fi_addr == na_ofi_addr2->fi_addr))
        return NA_TRUE;

    /* If we don't have the addr, look it up from AV */
    if (!na_ofi_addr1->addr) {
        na_return_t na_ret = na_ofi_av_lookup(na_ofi_addr1->domain,
            na_ofi_addr1->fi_addr, &na_ofi_addr1->addr, &na_ofi_addr1->addrlen);
        NA_CHECK_NA_ERROR(out, na_ret, "Could not get addr from AV");
    }
    if (!na_ofi_addr2->addr) {
        na_return_t na_ret = na_ofi_av_lookup(na_ofi_addr2->domain,
            na_ofi_addr2->fi_addr, &na_ofi_addr2->addr, &na_ofi_addr2->addrlen);
        NA_CHECK_NA_ERROR(out, na_ret, "Could not get addr from AV");
    }

    if ((na_ofi_addr1->addrlen == na_ofi_addr2->addrlen) &&
        (memcmp(na_ofi_addr1->addr, na_ofi_addr2->addr,
             na_ofi_addr1->addrlen) == 0))
        return NA_TRUE;

out:
    return NA_FALSE;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_addr_is_self(na_class_t *na_class, na_addr_t addr)
{
    struct na_ofi_endpoint *ep = NA_OFI_CLASS(na_class)->endpoint;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;

    if (ep->src_addr == na_ofi_addr)
        goto done;

    if (ep->src_addr->addrlen != na_ofi_addr->addrlen)
        return NA_FALSE;

    if (memcmp(ep->src_addr->addr, na_ofi_addr->addr, na_ofi_addr->addrlen))
        return NA_FALSE;

done:
    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    na_size_t *buf_size, na_addr_t addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;
    na_size_t str_len;
    na_return_t ret = NA_SUCCESS;

    /* If there is no URI for address, attempt to reconstruct one */
    if (!na_ofi_addr->uri) {
        NA_CHECK_ERROR(na_ofi_addr->fi_addr == FI_ADDR_UNSPEC, out, ret,
            NA_ADDRNOTAVAIL, "Addr is not initialized");

        /* If we don't have the addr either, look it up from AV */
        if (!na_ofi_addr->addr) {
            ret = na_ofi_av_lookup(na_ofi_addr->domain, na_ofi_addr->fi_addr,
                &na_ofi_addr->addr, &na_ofi_addr->addrlen);
            NA_CHECK_NA_ERROR(out, ret, "Could not get addr from AV");
        }

        ret = na_ofi_get_uri(na_class, na_ofi_addr->addr, &na_ofi_addr->uri);
        NA_CHECK_NA_ERROR(out, ret, "Could not get URI for address");
    }

    str_len = strlen(na_ofi_addr->uri);
    if (buf) {
        NA_CHECK_ERROR(str_len >= *buf_size, out, ret, NA_OVERFLOW,
            "Buffer size too small to copy addr");
        strcpy(buf, na_ofi_addr->uri);
    }
    *buf_size = str_len + 1;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ofi_addr_get_serialize_size(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;
    na_size_t size = 0;

    if (!na_ofi_addr->addr) {
        na_return_t ret;

        NA_CHECK_ERROR_NORET(na_ofi_addr->fi_addr == FI_ADDR_UNSPEC, out,
            "Addr is not initialized");

        /* If we don't have the addr, look it up from AV */
        ret = na_ofi_av_lookup(na_ofi_addr->domain, na_ofi_addr->fi_addr,
            &na_ofi_addr->addr, &na_ofi_addr->addrlen);
        NA_CHECK_ERROR_NORET(
            ret != NA_SUCCESS, out, "Could not get addr from AV");
    }

    size = na_ofi_addr->addrlen + sizeof(na_ofi_addr->addrlen);

out:
    return size;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, na_addr_t addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;
    na_uint8_t *p = buf;
    na_size_t len;
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_addr->addr) {
        NA_CHECK_ERROR(na_ofi_addr->fi_addr == FI_ADDR_UNSPEC, out, ret,
            NA_ADDRNOTAVAIL, "Addr is not initialized");

        /* If we don't have the addr, look it up from AV */
        ret = na_ofi_av_lookup(na_ofi_addr->domain, na_ofi_addr->fi_addr,
            &na_ofi_addr->addr, &na_ofi_addr->addrlen);
        NA_CHECK_NA_ERROR(out, ret, "Could not get addr from AV");
    }

    len = na_ofi_addr->addrlen + sizeof(na_ofi_addr->addrlen);
    NA_CHECK_ERROR(buf_size < len, out, ret, NA_OVERFLOW,
        "Buffer size too small for serializing address");

    /* TODO could skip the addrlen but include it for sanity check */
    memcpy(p, &na_ofi_addr->addrlen, sizeof(na_ofi_addr->addrlen));
    p += sizeof(na_ofi_addr->addrlen);
    memcpy(p, na_ofi_addr->addr, na_ofi_addr->addrlen);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_deserialize(na_class_t *na_class, na_addr_t *addr, const void *buf,
    na_size_t NA_UNUSED buf_size)
{
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    struct na_ofi_addr *na_ofi_addr = NULL;
    const na_uint8_t *p = buf;
    na_return_t ret = NA_SUCCESS;

    /* Allocate addr */
    na_ofi_addr = na_ofi_addr_alloc(domain);
    NA_CHECK_ERROR(
        na_ofi_addr == NULL, out, ret, NA_NOMEM, "na_ofi_addr_alloc() failed");
    memcpy(&na_ofi_addr->addrlen, p, sizeof(na_ofi_addr->addrlen));
    p += sizeof(na_ofi_addr->addrlen);

    na_ofi_addr->addr = malloc(na_ofi_addr->addrlen);
    NA_CHECK_ERROR(na_ofi_addr->addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate %zu bytes for address", na_ofi_addr->addrlen);
    memcpy(na_ofi_addr->addr, p, na_ofi_addr->addrlen);

    /* Skip URI generation, URI will only be generated when needed */

    /* Lookup address */
    ret = na_ofi_addr_ht_lookup(domain,
        na_ofi_prov_addr_format[domain->prov_type], na_ofi_addr->addr,
        na_ofi_addr->addrlen, &na_ofi_addr->fi_addr, &na_ofi_addr->ht_key);
    NA_CHECK_NA_ERROR(error, ret, "na_ofi_addr_ht_lookup() failed");

    *addr = (na_addr_t) na_ofi_addr;

out:
    return ret;

error:
    free(na_ofi_addr->addr);
    free(na_ofi_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ofi_msg_get_max_unexpected_size(const na_class_t NA_UNUSED *na_class)
{
    na_size_t max_unexpected_size = NA_OFI_UNEXPECTED_SIZE;
#ifdef NA_OFI_HAS_EXT_GNI_H
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;

    if (domain->prov_type == NA_OFI_PROV_GNI) {
        struct fi_gni_ops_domain *gni_domain_ops;
        int rc;

        rc = fi_open_ops(&domain->fi_domain->fid, FI_GNI_DOMAIN_OPS_1, 0,
            (void **) &gni_domain_ops, NULL);
        NA_CHECK_ERROR(rc != 0, out, max_unexpected_size, 0,
            "fi_open_ops() failed, rc: %d (%s)", rc, fi_strerror(-rc));

        rc = gni_domain_ops->get_val(&domain->fi_domain->fid,
            GNI_MBOX_MSG_MAX_SIZE, &max_unexpected_size);
        NA_CHECK_ERROR(rc != 0, out, max_unexpected_size, 0,
            "gni_domain_ops->get_val() failed, rc: %d (%s)", rc,
            fi_strerror(-rc));
    }

out:
#endif
    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ofi_msg_get_max_expected_size(const na_class_t NA_UNUSED *na_class)
{
    return na_ofi_msg_get_max_unexpected_size(na_class);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class)
{
    if (na_ofi_with_msg_hdr(na_class)) {
        return na_ofi_prov_addr_size(
            na_ofi_prov_addr_format[NA_OFI_CLASS(na_class)->domain->prov_type]);
    } else
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
na_ofi_msg_buf_alloc(na_class_t *na_class, na_size_t size, void **plugin_data)
{
    struct fid_mr *mr_hdl = NULL;
    void *mem_ptr = NULL;

#ifdef NA_OFI_HAS_MEM_POOL
    mem_ptr = na_ofi_mem_pool_alloc(na_class, size, &mr_hdl);
    NA_CHECK_ERROR_NORET(
        mem_ptr == NULL, out, "Could not allocate buffer from pool");
#else
    mem_ptr = na_ofi_mem_alloc(na_class, size, &mr_hdl);
    NA_CHECK_ERROR_NORET(
        mem_ptr == NULL, out, "Could not allocate %d bytes", (int) size);
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
    na_ofi_mem_pool_free(na_class, buf, mr_hdl);
#else
    na_ofi_mem_free(na_class, buf, mr_hdl);
#endif

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_init_unexpected(na_class_t *na_class, void *buf, na_size_t buf_size)
{
    na_return_t ret = NA_SUCCESS;

    /*
     * For those providers that don't support FI_SOURCE/FI_SOURCE_ERR, insert
     * the msg header to piggyback the source address for unexpected message.
     */
    if (na_ofi_with_msg_hdr(na_class)) {
        struct na_ofi_class *priv = NA_OFI_CLASS(na_class);

        NA_CHECK_ERROR(buf_size < priv->endpoint->src_addr->addrlen, out, ret,
            NA_OVERFLOW, "Buffer size too small to copy addr");
        memcpy(buf, priv->endpoint->src_addr->addr,
            priv->endpoint->src_addr->addrlen);
    }

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) dest_addr;
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    na_ofi_op_id->context = context;
    na_ofi_op_id->completion_data.callback_info.type = NA_CB_SEND_UNEXPECTED;
    na_ofi_op_id->completion_data.callback = callback;
    na_ofi_op_id->completion_data.callback_info.arg = arg;
    na_ofi_addr_addref(na_ofi_addr);
    na_ofi_op_id->addr = na_ofi_addr;
    hg_atomic_set32(&na_ofi_op_id->status, 0);
    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ofi_op_id->info.msg.buf.const_ptr = buf;
    na_ofi_op_id->info.msg.buf_size = buf_size;
    na_ofi_op_id->info.msg.actual_buf_size = buf_size;
    /* Specify target receive context */
    na_ofi_op_id->info.msg.fi_addr =
        fi_rx_addr(na_ofi_addr->fi_addr, dest_id, NA_OFI_SEP_RX_CTX_BITS);
    na_ofi_op_id->info.msg.fi_mr = plugin_data;
    na_ofi_op_id->info.msg.tag = tag;

    NA_LOG_DEBUG("Posting unexpected msg send with tag=%llu (op id=%p)",
        tag | NA_OFI_UNEXPECTED_TAG, na_ofi_op_id);

    /* Post the FI unexpected send request */
    rc = fi_tsend(ctx->fi_tx, buf, buf_size, na_ofi_op_id->info.msg.fi_mr,
        na_ofi_op_id->info.msg.fi_addr, tag | NA_OFI_UNEXPECTED_TAG,
        &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN)) {
        if (NA_OFI_CLASS(na_class)->no_retry)
            /* Do not attempt to retry */
            NA_GOTO_DONE(error, ret, NA_AGAIN);
        else {
            NA_LOG_DEBUG("Pushing %p for retry", na_ofi_op_id);

            /* Push op ID to retry queue */
            hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
            HG_QUEUE_PUSH_TAIL(
                &ctx->retry_op_queue->queue, na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        }
    } else
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_tsend() unexpected failed, rc: %zd (%s)", rc,
            fi_strerror((int) -rc));

out:
    return ret;

error:
    na_ofi_addr_decref(na_ofi_addr);
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_op_id_t *op_id)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    na_ofi_op_id->context = context;
    na_ofi_op_id->completion_data.callback_info.type = NA_CB_RECV_UNEXPECTED;
    na_ofi_op_id->completion_data.callback = callback;
    na_ofi_op_id->completion_data.callback_info.arg = arg;
    na_ofi_op_id->addr = NULL;
    hg_atomic_set32(&na_ofi_op_id->status, 0);
    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ofi_op_id->info.msg.buf.ptr = buf;
    na_ofi_op_id->info.msg.buf_size = buf_size;
    na_ofi_op_id->info.msg.actual_buf_size = 0;
    na_ofi_op_id->info.msg.fi_addr = FI_ADDR_UNSPEC;
    na_ofi_op_id->info.msg.fi_mr = plugin_data;
    na_ofi_op_id->info.msg.tag = 0;

    NA_LOG_DEBUG("Posting unexpected msg recv (op id=%p)", na_ofi_op_id);

    /* Post the FI unexpected recv request */
    rc = fi_trecv(ctx->fi_rx, buf, buf_size, na_ofi_op_id->info.msg.fi_mr,
        na_ofi_op_id->info.msg.fi_addr, NA_OFI_UNEXPECTED_TAG, NA_OFI_TAG_MASK,
        &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN)) {
        if (NA_OFI_CLASS(na_class)->no_retry)
            /* Do not attempt to retry */
            NA_GOTO_DONE(error, ret, NA_AGAIN);
        else {
            NA_LOG_DEBUG("Pushing %p for retry", na_ofi_op_id);

            /* Push op ID to retry queue */
            hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
            HG_QUEUE_PUSH_TAIL(
                &ctx->retry_op_queue->queue, na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        }
    } else
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_trecv() unexpected failed, rc: %zd (%s)", rc,
            fi_strerror((int) -rc));

out:
    return ret;

error:
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) dest_addr;
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    na_ofi_op_id->context = context;
    na_ofi_op_id->completion_data.callback_info.type = NA_CB_SEND_EXPECTED;
    na_ofi_op_id->completion_data.callback = callback;
    na_ofi_op_id->completion_data.callback_info.arg = arg;
    na_ofi_addr_addref(na_ofi_addr);
    na_ofi_op_id->addr = na_ofi_addr;
    hg_atomic_set32(&na_ofi_op_id->status, 0);
    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ofi_op_id->info.msg.buf.const_ptr = buf;
    na_ofi_op_id->info.msg.buf_size = buf_size;
    na_ofi_op_id->info.msg.actual_buf_size = buf_size;
    /* Specify target receive context */
    na_ofi_op_id->info.msg.fi_addr =
        fi_rx_addr(na_ofi_addr->fi_addr, dest_id, NA_OFI_SEP_RX_CTX_BITS);
    na_ofi_op_id->info.msg.fi_mr = plugin_data;
    na_ofi_op_id->info.msg.tag = tag;

    NA_LOG_DEBUG("Posting expected msg send with tag=%llu (op id=%p)", tag,
        na_ofi_op_id);

    /* Post the FI expected send request */
    rc = fi_tsend(ctx->fi_tx, buf, buf_size, na_ofi_op_id->info.msg.fi_mr,
        na_ofi_op_id->info.msg.fi_addr, tag, &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN)) {
        if (NA_OFI_CLASS(na_class)->no_retry)
            /* Do not attempt to retry */
            NA_GOTO_DONE(error, ret, NA_AGAIN);
        else {
            NA_LOG_DEBUG("Pushing %p for retry", na_ofi_op_id);

            /* Push op ID to retry queue */
            hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
            HG_QUEUE_PUSH_TAIL(
                &ctx->retry_op_queue->queue, na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        }
    } else
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_tsend() expected failed, rc: %zd (%s)", rc,
            fi_strerror((int) -rc));

out:
    return ret;

error:
    na_ofi_addr_decref(na_ofi_addr);
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source_addr, na_uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) source_addr;
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Check op_id */
    NA_CHECK_ERROR(
        na_ofi_op_id == NULL, out, ret, NA_INVALID_ARG, "Invalid operation ID");
    NA_CHECK_ERROR(
        !(hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_COMPLETED), out,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    na_ofi_op_id->context = context;
    na_ofi_op_id->completion_data.callback_info.type = NA_CB_RECV_EXPECTED;
    na_ofi_op_id->completion_data.callback = callback;
    na_ofi_op_id->completion_data.callback_info.arg = arg;
    na_ofi_addr_addref(na_ofi_addr);
    na_ofi_op_id->addr = na_ofi_addr;
    hg_atomic_set32(&na_ofi_op_id->status, 0);
    na_ofi_op_id->info.msg.buf.ptr = buf;
    na_ofi_op_id->info.msg.buf_size = buf_size;
    na_ofi_op_id->info.msg.actual_buf_size = 0;
    /* Specify target source context */
    na_ofi_op_id->info.msg.fi_addr =
        fi_rx_addr(na_ofi_addr->fi_addr, source_id, NA_OFI_SEP_RX_CTX_BITS);
    na_ofi_op_id->info.msg.fi_mr = plugin_data;
    na_ofi_op_id->info.msg.tag = tag;

    NA_LOG_DEBUG("Posting expected msg recv with tag=%llu (op id=%p)", tag,
        na_ofi_op_id);

    /* Post the FI expected recv request */
    rc = fi_trecv(ctx->fi_rx, buf, buf_size, na_ofi_op_id->info.msg.fi_mr,
        na_ofi_op_id->info.msg.fi_addr, tag, 0, &na_ofi_op_id->fi_ctx);
    if (unlikely(rc == -FI_EAGAIN)) {
        if (NA_OFI_CLASS(na_class)->no_retry)
            /* Do not attempt to retry */
            NA_GOTO_DONE(error, ret, NA_AGAIN);
        else {
            NA_LOG_DEBUG("Pushing %p for retry", na_ofi_op_id);

            /* Push op ID to retry queue */
            hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
            HG_QUEUE_PUSH_TAIL(
                &ctx->retry_op_queue->queue, na_ofi_op_id, entry);
            hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_QUEUED);
            hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        }
    } else
        NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "fi_trecv() expected failed, rc: %zd (%s)", rc,
            fi_strerror((int) -rc));

out:
    return ret;

error:
    na_ofi_addr_decref(na_ofi_addr);
    hg_atomic_set32(&na_ofi_op_id->status, NA_OFI_OP_COMPLETED);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle */
    na_ofi_mem_handle = (struct na_ofi_mem_handle *) calloc(
        1, sizeof(struct na_ofi_mem_handle));
    NA_CHECK_ERROR(na_ofi_mem_handle == NULL, done, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");

    na_ofi_mem_handle->desc.iov.s[0].iov_base = buf;
    na_ofi_mem_handle->desc.iov.s[0].iov_len = buf_size;
    na_ofi_mem_handle->desc.info.iovcnt = 1;
    na_ofi_mem_handle->desc.info.flags = flags & 0xff;
    na_ofi_mem_handle->desc.info.len = buf_size;

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_create_segments(na_class_t *na_class,
    struct na_segment *segments, na_size_t segment_count, unsigned long flags,
    na_mem_handle_t *mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    struct iovec *iov = NULL;
    na_return_t ret = NA_SUCCESS;
    na_size_t i;

    NA_CHECK_WARNING(segment_count == 1, "Segment count is 1");

    /* Check that we do not exceed IOV limit */
    NA_CHECK_ERROR(segment_count > NA_OFI_CLASS(na_class)->iov_max, error, ret,
        NA_INVALID_ARG, "Segment count exceeds provider limit (%zu)",
        NA_OFI_CLASS(na_class)->iov_max);

    /* Allocate memory handle */
    na_ofi_mem_handle = (struct na_ofi_mem_handle *) calloc(
        1, sizeof(struct na_ofi_mem_handle));
    NA_CHECK_ERROR(na_ofi_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");

    if (segment_count > NA_OFI_IOV_STATIC_MAX) {
        /* Allocate IOVs */
        na_ofi_mem_handle->desc.iov.d =
            (struct iovec *) calloc(segment_count, sizeof(struct iovec));
        NA_CHECK_ERROR(na_ofi_mem_handle->desc.iov.d == NULL, error, ret,
            NA_NOMEM, "Could not allocate IOV array");

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
static NA_INLINE na_size_t
na_ofi_mem_handle_get_max_segments(const na_class_t *na_class)
{
#ifdef NA_OFI_USE_REGV
    return NA_OFI_CLASS(na_class)->iov_max;
#else
    (void) na_class;
    return 1;
#endif
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;
    struct na_ofi_domain *domain = NA_OFI_CLASS(na_class)->domain;
    const struct iovec *iov = NULL;
    const struct iovec null_iov = {0, 0};
    size_t count = 0;
    na_uint64_t access;
    int rc = 0;
    na_return_t ret = NA_SUCCESS;

    /* Nothing to do for providers that do not need physically backed
     * virtual addresses (FI_MR_SCALABLE) */
    if (!(domain->fi_prov->domain_attr->mr_mode & FI_MR_ALLOCATED)) {
        /* Use global handle and key */
        na_ofi_mem_handle->fi_mr = domain->fi_mr;
        na_ofi_mem_handle->desc.info.fi_mr_key = domain->fi_mr_key;
        goto out;
    }

    /* Set access mode */
    switch (na_ofi_mem_handle->desc.info.flags) {
        case NA_MEM_READ_ONLY:
            access = FI_REMOTE_READ | FI_WRITE;
            break;
        case NA_MEM_WRITE_ONLY:
            access = FI_REMOTE_WRITE | FI_READ;
            break;
        case NA_MEM_READWRITE:
            access = FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
            break;
        default:
            NA_GOTO_ERROR(
                out, ret, NA_INVALID_ARG, "Invalid memory access flag");
            break;
    }

    /* Use virtual addresses only when provider needs it */
    if (domain->fi_prov->domain_attr->mr_mode & FI_MR_VIRT_ADDR) {
        count = na_ofi_mem_handle->desc.info.iovcnt;
        iov = NA_OFI_IOV(na_ofi_mem_handle);
    } else {
        count = 1;
        iov = &null_iov;
    }

    /* Register region */
    rc = fi_mr_regv(domain->fi_domain, iov, count, access, 0 /* offset */,
        0 /* requested key */, 0 /* flags */, &na_ofi_mem_handle->fi_mr,
        NULL /* context */);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_mr_regv() failed, rc: %d (%s), mr_reg_count: %d", rc,
        fi_strerror(-rc), hg_atomic_get32(&domain->mr_reg_count));
    hg_atomic_incr32(&domain->mr_reg_count);

    /* Retrieve key */
    na_ofi_mem_handle->desc.info.fi_mr_key =
        fi_mr_key(na_ofi_mem_handle->fi_mr);

out:
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

    if (!(domain->fi_prov->domain_attr->mr_mode & FI_MR_ALLOCATED) ||
        !na_ofi_mem_handle->fi_mr)
        goto out;

    /* close MR handle */
    rc = fi_close(&na_ofi_mem_handle->fi_mr->fid);
    NA_CHECK_ERROR(rc != 0, out, ret, NA_PROTOCOL_ERROR,
        "fi_close() mr_hdl failed, rc: %d (%s)", rc, fi_strerror(-rc));
    hg_atomic_decr32(&domain->mr_reg_count);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
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
    na_size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) mem_handle;
    struct iovec *iov = NA_OFI_IOV(na_ofi_mem_handle);
    char *buf_ptr = (char *) buf;
    na_size_t buf_size_left = buf_size;
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
    na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    const char *buf_ptr = (const char *) buf;
    na_size_t buf_size_left = buf_size;
    struct iovec *iov = NULL;
    na_return_t ret = NA_SUCCESS;

    na_ofi_mem_handle =
        (struct na_ofi_mem_handle *) malloc(sizeof(struct na_ofi_mem_handle));
    NA_CHECK_ERROR(na_ofi_mem_handle == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA OFI memory handle");
    na_ofi_mem_handle->desc.iov.d = NULL;
    na_ofi_mem_handle->fi_mr = NULL;

    /* Descriptor info */
    NA_DECODE(error, ret, buf_ptr, buf_size_left, &na_ofi_mem_handle->desc.info,
        struct na_ofi_mem_desc_info);

    /* IOV */
    if (na_ofi_mem_handle->desc.info.iovcnt > NA_OFI_IOV_STATIC_MAX) {
        /* Allocate IOV */
        na_ofi_mem_handle->desc.iov.d = (struct iovec *) malloc(
            na_ofi_mem_handle->desc.info.iovcnt * sizeof(struct iovec));
        NA_CHECK_ERROR(na_ofi_mem_handle->desc.iov.d == NULL, error, ret,
            NA_NOMEM, "Could not allocate segment array");

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
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id)
{
    na_return_t ret = NA_SUCCESS;

    ret = na_ofi_rma(na_class, context, NA_CB_PUT, callback, arg, fi_writemsg,
        NA_OFI_PUT_COMPLETION, (struct na_ofi_mem_handle *) local_mem_handle,
        local_offset, (struct na_ofi_mem_handle *) remote_mem_handle,
        remote_offset, length, (struct na_ofi_addr *) remote_addr, remote_id,
        (struct na_ofi_op_id *) op_id);
    NA_CHECK_NA_ERROR(out, ret, "Could not post RMA put");

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id)
{
    na_return_t ret = NA_SUCCESS;

    ret = na_ofi_rma(na_class, context, NA_CB_GET, callback, arg, fi_readmsg,
        NA_OFI_GET_COMPLETION, (struct na_ofi_mem_handle *) local_mem_handle,
        local_offset, (struct na_ofi_mem_handle *) remote_mem_handle,
        remote_offset, length, (struct na_ofi_addr *) remote_addr, remote_id,
        (struct na_ofi_op_id *) op_id);
    NA_CHECK_NA_ERROR(out, ret, "Could not post RMA get");

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t *context)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    int fd = -1, rc;

    if (priv->no_wait ||
        (na_ofi_prov_flags[priv->domain->prov_type] & NA_OFI_WAIT_SET))
        goto out;

    rc = fi_control(&ctx->fi_cq->fid, FI_GETWAIT, &fd);
    NA_CHECK_ERROR_NORET(rc != 0 && rc != -FI_ENOSYS, out,
        "fi_control() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));
    NA_CHECK_ERROR_NORET(
        fd < 0, out, "Returned fd is not valid (%d), will not block", fd);

out:
    return fd;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_poll_try_wait(na_class_t *na_class, na_context_t *context)
{
    struct na_ofi_class *priv = NA_OFI_CLASS(na_class);
    struct na_ofi_context *ctx = NA_OFI_CONTEXT(context);
    struct fid *fids[1];
    int rc;

    if (priv->no_wait)
        return NA_FALSE;

    /* Keep making progress if retry queue is not empty */
    hg_thread_mutex_lock(&ctx->retry_op_queue->mutex);
    if (!HG_QUEUE_IS_EMPTY(&ctx->retry_op_queue->queue)) {
        hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);
        return NA_FALSE;
    }
    hg_thread_mutex_unlock(&ctx->retry_op_queue->mutex);

    /* Assume it is safe to block if provider is using wait set */
    if ((na_ofi_prov_flags[priv->domain->prov_type] & NA_OFI_WAIT_SET)
        /* PSM2 shows very slow performance with fi_trywait() */
        || priv->domain->prov_type == NA_OFI_PROV_PSM2)
        return NA_TRUE;

    fids[0] = &ctx->fi_cq->fid;
    /* Check whether it is safe to block on that fd */
    rc = fi_trywait(priv->domain->fi_fabric, fids, 1);
    if (rc == FI_SUCCESS)
        return NA_TRUE;
    else if (rc == -FI_EAGAIN)
        return NA_FALSE;
    else {
        NA_LOG_ERROR(
            "fi_trywait() failed, rc: %d (%s)", rc, fi_strerror((int) -rc));
        return NA_FALSE;
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout)
{
    /* Convert timeout in ms into seconds */
    double remaining = timeout / 1000.0;
    na_return_t ret;

    do {
        struct fi_cq_tagged_entry cq_events[NA_OFI_CQ_EVENT_NUM];
        fi_addr_t src_addrs[NA_OFI_CQ_EVENT_NUM] = {FI_ADDR_UNSPEC};
        char src_err_addr[NA_OFI_CQ_MAX_ERR_DATA_SIZE] = {0};
        void *src_err_addr_ptr = src_err_addr;
        size_t src_err_addrlen = NA_OFI_CQ_MAX_ERR_DATA_SIZE;
        size_t i, actual_count = 0;
        hg_time_t t1, t2;

        if (timeout) {
            struct fid_wait *wait_hdl = NA_OFI_CONTEXT(context)->fi_wait;

            hg_time_get_current_ms(&t1);

            if (wait_hdl) {
                /* Wait in wait set if provider does not support wait on FDs */
                int rc = fi_wait(wait_hdl, (int) (remaining * 1000.0));

                if (rc == -FI_EINTR) {
                    hg_time_get_current_ms(&t2);
                    remaining -= hg_time_diff(t2, t1);
                    continue;
                }

                if (rc == -FI_ETIMEDOUT)
                    break;

                NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
                    "fi_wait() failed, rc: %d (%s)", rc,
                    fi_strerror((int) -rc));
            }
        }

        /* Read from CQ and process events */
        ret = na_ofi_cq_read(context, NA_OFI_CQ_EVENT_NUM, cq_events, src_addrs,
            &src_err_addr_ptr, &src_err_addrlen, &actual_count);
        NA_CHECK_NA_ERROR(error, ret, "Could not read events from context CQ");

        for (i = 0; i < actual_count; i++) {
            ret = na_ofi_cq_process_event(na_class, &cq_events[i], src_addrs[i],
                src_err_addr_ptr, src_err_addrlen);
            NA_CHECK_NA_ERROR(error, ret, "Could not process event");
        }

        /* Attempt to process retries */
        ret = na_ofi_cq_process_retries(context);
        NA_CHECK_NA_ERROR(error, ret, "Could not process retries");

        if (actual_count > 0)
            return NA_SUCCESS;

        if (timeout) {
            hg_time_get_current_ms(&t2);
            remaining -= hg_time_diff(t2, t1);
        }
    } while ((int) (remaining * 1000.0) > 0);

    return NA_TIMEOUT;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t *op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    struct fid_ep *fi_ep = NULL;
    na_return_t ret = NA_SUCCESS;
    na_bool_t canceled = NA_FALSE;
    hg_util_int32_t status;
    ssize_t rc;

    /* Exit if op has already completed */
    status = hg_atomic_or32(&na_ofi_op_id->status, NA_OFI_OP_CANCELED);
    if ((status & NA_OFI_OP_COMPLETED) || (status & NA_OFI_OP_ERRORED))
        goto out;

    NA_LOG_DEBUG("Canceling operation ID %p", na_ofi_op_id);

    switch (na_ofi_op_id->completion_data.callback_info.type) {
        case NA_CB_RECV_UNEXPECTED:
        case NA_CB_RECV_EXPECTED:
            fi_ep = NA_OFI_CONTEXT(context)->fi_rx;
            break;
        case NA_CB_SEND_UNEXPECTED:
        case NA_CB_SEND_EXPECTED:
        case NA_CB_PUT:
        case NA_CB_GET:
            fi_ep = NA_OFI_CONTEXT(context)->fi_tx;
            break;
        default:
            NA_GOTO_ERROR(out, ret, NA_INVALID_ARG,
                "Operation type %d not supported",
                na_ofi_op_id->completion_data.callback_info.type);
            break;
    }

    /* Check if op_id is in retry queue */
    hg_thread_mutex_lock(&NA_OFI_CONTEXT(context)->retry_op_queue->mutex);
    if (hg_atomic_get32(&na_ofi_op_id->status) & NA_OFI_OP_QUEUED) {
        HG_QUEUE_REMOVE(&NA_OFI_CONTEXT(context)->retry_op_queue->queue,
            na_ofi_op_id, na_ofi_op_id, entry);
        hg_atomic_and32(&na_ofi_op_id->status, ~NA_OFI_OP_QUEUED);
        canceled = NA_TRUE;
    }
    hg_thread_mutex_unlock(&NA_OFI_CONTEXT(context)->retry_op_queue->mutex);

    if (canceled) {
        ret = na_ofi_complete(na_ofi_op_id);
        NA_CHECK_NA_ERROR(out, ret, "Could not complete operation");
    } else {
        /* fi_cancel() is an asynchronous operation, either the operation
         * will be canceled and an FI_ECANCELED event will be generated
         * or it will show up in the regular completion queue.
         */
        rc = fi_cancel(&fi_ep->fid, &na_ofi_op_id->fi_ctx);
        NA_LOG_DEBUG(
            "fi_cancel() rc: %d (%s)", (int) rc, fi_strerror((int) -rc));
        (void) rc;
    }

    /* Work around segfault on fi_cq_signal() in some providers */
    if (na_ofi_prov_flags[NA_OFI_CLASS(na_class)->domain->prov_type] &
        NA_OFI_SIGNAL) {
        /* Signal CQ to wake up and no longer wait on FD */
        int rc_signal = fi_cq_signal(NA_OFI_CONTEXT(context)->fi_cq);
        NA_CHECK_ERROR(rc_signal != 0 && rc_signal != -ENOSYS, out, ret,
            NA_PROTOCOL_ERROR, "fi_cq_signal (op type %d) failed, rc: %d (%s)",
            na_ofi_op_id->completion_data.callback_info.type, rc_signal,
            fi_strerror((int) -rc_signal));
    }

out:
    return ret;
}
