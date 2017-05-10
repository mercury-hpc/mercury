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

#include "na_private.h"
#include "na_error.h"

#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_rwlock.h"
#include "mercury_hash_table.h"
#include "mercury_time.h"
#include "mercury_atomic.h"

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NDEBUG /* for assert */
#include <assert.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/uio.h> /* for struct iovec */

/********************/
/* Global Variables */
/********************/

enum na_ofi_prov_type {
    NA_OFI_PROV_SOCKETS,
    NA_OFI_PROV_PSM2,
    NA_OFI_PROV_VERBS,
    NA_OFI_PROV_GNI
};

enum na_ofi_mr_mode {
    NA_OFI_MR_SCALABLE,
    NA_OFI_MR_BASIC,
};

struct na_ofi_domain {
    enum na_ofi_prov_type nod_prov_type; /* OFI provider type */
    enum na_ofi_mr_mode nod_mr_mode; /* OFI memory region mode */
    char *nod_prov_name; /* OFI provider name */
    struct fi_info *nod_prov; /* OFI provider handle */
    struct fid_fabric *nod_fabric; /* Fabric domain handle */
    struct fid_domain *nod_domain; /* Access domain handle */
    /* Memory region handle, only valid for MR_SCALABLE */
    struct fid_mr *nod_mr;
    struct fid_av *nod_av; /* Address vector handle */
    /*
     * Address hash-table, to map the source-side address to fi_addr_t.
     * The key is 64bits value serialized from source-side IP+Port (see
     * na_ofi_reqhdr_2_key), the value is fi_addr_t.
     */
    hg_hash_table_t *nod_addr_ht;
    /* the rwlock to protect nod_addr_ht */
    hg_thread_rwlock_t nod_rwlock;
    uint32_t nod_refcount; /* Refcount of this domain */
    size_t nod_src_addrlen;
    size_t nod_dest_addrlen;
    HG_LIST_ENTRY(na_ofi_domain) nod_entry; /* Entry in nog_domain_list */
};

struct na_ofi_global_data {
    struct fi_info *nog_providers; /* All available providers */
    HG_LIST_HEAD(na_ofi_domain) nog_domain_list; /* OFI access domain list */
    uint32_t nog_refcount; /* Refcount to free nog_providers */
    hg_thread_mutex_t nog_mutex; /* Protects all fields above */
    hg_atomic_int32_t nog_init_flag; /* Initialization flag */
} nofi_gdata;

/****************/
/* Local Macros */
/****************/

/**
 * FI VERSION provides binary backward and forward compatibility support.
 * Specify the version of OFI is coded to, the provider will select struct
 * layouts that are compatible with this version.
 */
#if FI_MINOR_VERSION >= 5
#define NA_OFI_VERSION FI_VERSION(1, 5)
#else
#define NA_OFI_VERSION FI_VERSION(1, 4)
#endif

#define NA_OFI_MAX_URI_LEN (128)
#define NA_OFI_MAX_NODE_LEN (64)
#define NA_OFI_MAX_PORT_LEN (16)
#define NA_OFI_HDR_MAGIC (0x0f106688)

/* Max tag */
#define NA_OFI_MAX_TAG ((1 << 30) -1)

#define NA_OFI_UNEXPECTED_SIZE 4096
#define NA_OFI_EXPECTED_TAG_FLAG (0x100000000ULL)
#define NA_OFI_UNEXPECTED_TAG_IGNORE (0xFFFFFFFFULL)

/* the predefined RMA KEY for MR_SCALABLE */
#define NA_OFI_RMA_KEY (0x0F1B0F1BULL)

#if !defined(container_of)
/* given a pointer @ptr to the field @member embedded into type (usually
 *  * struct) @type, return pointer to the embedding instance of @type. */
# define container_of(ptr, type, member)		\
	        ((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

typedef struct na_ofi_op_id na_ofi_op_id_t;
typedef struct na_ofi_addr na_ofi_addr_t;
typedef struct na_ofi_mem_handle na_ofi_mem_handle_t;

/**
 * Inline header for NA_OFI (16 bytes).
 *
 * It is mainly to piggyback the source-side IP/port address for the unexpected
 * message. For those providers that does not support FI_SOURCE/FI_SOURCE_ERR.
 */
typedef struct {
    na_uint32_t fih_feats; /* feature bits */
    na_uint32_t fih_magic; /* magic number for byte-order checking */
    na_uint32_t fih_ip; /* IP addr in integer */
    na_uint32_t fih_port; /* Port number */
} na_ofi_reqhdr_t;

struct na_ofi_private_data {
    struct na_ofi_domain *nop_domain; /* Point back to access domain */
    struct fi_info *nop_fi_info; /* fi info for the endpoint */
    struct fid_cq *nop_cq; /* Completion queue handle */
    struct fid_ep *nop_ep; /* Endpoint to communicate on */
    /* Unexpected op queue */
    HG_QUEUE_HEAD(na_ofi_op_id) nop_unexpected_op_queue;
    hg_thread_mutex_t nop_unexpected_op_mutex;
    char *nop_uri; /* URI address string */
    na_ofi_reqhdr_t nop_req_hdr; /* request header */
};

#define NA_OFI_PRIVATE_DATA(na_class) \
    ((struct na_ofi_private_data *)(na_class->private_data))

struct na_ofi_addr {
    fi_addr_t noa_addr; /* FI fabric address */
    char *noa_uri; /* Peer's URI */
    hg_atomic_int32_t noa_refcount; /* Reference counter (dup/free)  */
    na_bool_t noa_unexpected; /* Address generated from unexpected recv */
    na_bool_t noa_self; /* Boolean for self */
};

struct na_ofi_mem_handle {
    struct fid_mr *nom_mr_hdl; /* FI MR handle */
    na_uint64_t nom_mr_key; /* FI MR key */
    na_ptr_t nom_base; /* Initial address of memory */
    na_size_t nom_size; /* Size of memory */
    na_uint8_t nom_attr; /* Flag of operation access */
    na_uint8_t nom_remote; /* Flag of remote handle */
};

struct na_ofi_info_lookup {
    na_addr_t noi_addr;
};

struct na_ofi_info_send_unexpected {
    /* no extra info */
};

struct na_ofi_info_recv_unexpected {
    void *noi_buf;
    na_size_t noi_buf_size;
    na_size_t noi_msg_size;
    na_tag_t noi_tag;
};

struct na_ofi_info_send_expected {
    /* no extra info */
};

struct na_ofi_info_recv_expected {
    void *noi_buf;
    na_size_t noi_buf_size;
    na_size_t noi_msg_size;
    na_tag_t noi_tag;
};

struct na_ofi_info_put {
    /* no extra info */
};

struct na_ofi_info_get {
    /* no extra info */
};

struct na_ofi_op_id {
    HG_QUEUE_ENTRY(na_ofi_op_id) noo_entry;
    na_context_t *noo_context;
    struct fi_context noo_fi_ctx;
    na_cb_type_t noo_type;
    na_cb_t noo_callback;
    void *noo_arg;
    na_addr_t noo_addr;
    hg_atomic_int32_t noo_refcount;
    hg_atomic_int32_t noo_completed; /* Operation completed */
    hg_atomic_int32_t noo_canceled; /* Operation canceled  */
    union {
        struct na_ofi_info_lookup noo_lookup;
        struct na_ofi_info_send_unexpected noo_send_unexpected;
        struct na_ofi_info_recv_unexpected noo_recv_unexpected;
        struct na_ofi_info_send_expected noo_send_expected;
        struct na_ofi_info_recv_expected noo_recv_expected;
        struct na_ofi_info_put noo_put;
        struct na_ofi_info_get noo_get;
    } noo_info;
    struct na_cb_completion_data noo_completion_data;
};

/********************/
/* Local Helpers */
/********************/

#define na_ofi_bswap16(x) ((x) >> 8 | ((x) & 0xFFU) << 8)
#define na_ofi_bswap32(x) ((na_ofi_bswap16((x) >> 16) & 0xFFFFU) |\
                           (na_ofi_bswap16((x) & 0xFFFFU) << 16))
#define na_ofi_bswap32s(x) do { *(x) = na_ofi_bswap32(*(x)); } while (0)

static inline na_bool_t
na_ofi_with_reqhdr(na_class_t *na_class)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;

    return domain->nod_prov_type != NA_OFI_PROV_PSM2;
}

/**
 * Converts the inline header to a 64 bits key to search corresponding FI addr.
 */
static inline na_uint64_t
na_ofi_reqhdr_2_key(na_ofi_reqhdr_t *hdr)
{
    return (((na_uint64_t)hdr->fih_ip) << 32 | hdr->fih_port);
}

static int
av_addr_ht_key_equal(hg_hash_table_key_t vlocation1,
                     hg_hash_table_key_t vlocation2)
{
    return *((na_uint64_t *) vlocation1) == *((na_uint64_t *) vlocation2);
}

static unsigned int
av_addr_ht_key_hash(hg_hash_table_key_t vlocation)
{
    na_uint64_t key = *((na_uint64_t *) vlocation);
    na_uint32_t hi, lo;

    hi = (na_uint32_t) (key >> 32);
    lo = (key & 0xFFFFFFFFU);

    return ((hi & 0xFFFF0000U) | (lo & 0xFFFFU));
}

static void
av_addr_ht_key_free(hg_hash_table_key_t key)
{
    free((na_uint64_t *) key);
}

static void
av_addr_ht_value_free(hg_hash_table_value_t value)
{
    free((fi_addr_t *) value);
}

static na_return_t
na_ofi_av_insert(na_class_t *na_class, char *node_str, char *service_str,
                 fi_addr_t *fi_addr)
{
    struct na_ofi_domain *domain;
    struct fi_info *tmp_info = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* address resolution by fi AV */
    domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    assert(domain != NULL);

    rc = fi_getinfo(NA_OFI_VERSION, node_str, service_str, 0 /* flags */,
                    NULL /* hints */, &tmp_info);
    if (rc != 0) {
        NA_LOG_ERROR("fi_getinfo (%s:%s) failed, rc: %d(%s).",
                     node_str, service_str, rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }
    rc = fi_av_insert(domain->nod_av, tmp_info->dest_addr, 1, fi_addr,
                      0 /* flags */, NULL /* context */);
    /* fi_av_insertsvc not supported by PSM2 provider */
    //rc = fi_av_insertsvc(domain->nod_av, node_str, service_str,
    //                     fi_addr, 0 /* flags */, NULL /* context */)
    fi_freeinfo(tmp_info);
    if (rc < 0) {
        NA_LOG_ERROR("fi_av_insertsvc failed(node %s, service %s), rc: %d(%s).",
                     node_str, service_str, rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    } else if (rc != 1) {
        NA_LOG_ERROR("fi_av_insert failed(node %s, service %s), rc: %d.",
                     node_str, service_str, rc);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* The below just to verify the AV address resolution */
    /*
    void *peer_addr;
    size_t addrlen;
    char peer_addr_str[NA_OFI_MAX_URI_LEN] = {'\0'};

    addrlen = domain->nod_src_addrlen;
    peer_addr = malloc(addrlen);
    if (peer_addr == NULL) {
        NA_LOG_ERROR("Could not allocate peer_addr.");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    rc = fi_av_lookup(domain->nod_av, *fi_addr, peer_addr, &addrlen);
    if (rc != 0) {
        NA_LOG_ERROR("fi_av_lookup failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }
    addrlen = NA_OFI_MAX_URI_LEN;
    fi_av_straddr(domain->nod_av, peer_addr, peer_addr_str, &addrlen);
    NA_LOG_DEBUG("node %s, service %s, peer address %s.",
                 node_str, service_str, peer_addr_str);
    free(peer_addr);
    */

out:
    return ret;
}

/* lookup the address hash-table */
static na_return_t
na_ofi_addr_ht_lookup(na_class_t *na_class, na_ofi_reqhdr_t *reqhdr,
                      fi_addr_t *src_addr)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    na_uint64_t addr_key, *new_key;
    fi_addr_t *fi_addr, tmp_addr, *new_value;
    char *node, service[16];
    struct in_addr in;
    na_return_t ret = NA_SUCCESS;

    addr_key = na_ofi_reqhdr_2_key(reqhdr);
    hg_thread_rwlock_rdlock(&domain->nod_rwlock);
    fi_addr = hg_hash_table_lookup(domain->nod_addr_ht, &addr_key);
    if (fi_addr != HG_HASH_TABLE_NULL) {
        /*
        in.s_addr = reqhdr->fih_ip;
        node = inet_ntoa(in);
        NA_LOG_DEBUG("hg_hash_table_lookup(%s:%d) succeed, fi_addr: %d.\n",
                     node, reqhdr->fih_port, *fi_addr);
        */
        *src_addr = *fi_addr;
        hg_thread_rwlock_release_rdlock(&domain->nod_rwlock);
        return ret;
    }
    hg_thread_rwlock_release_rdlock(&domain->nod_rwlock);

    in.s_addr = reqhdr->fih_ip;
    node = inet_ntoa(in);
    memset(service, 0, 16);
    sprintf(service, "%d", reqhdr->fih_port);

    ret = na_ofi_av_insert(na_class, node, service, &tmp_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_av_insert(%s:%s) failed, ret: %d.",
                     node, service, ret);
        goto out;
    }
    *src_addr = tmp_addr;

    hg_thread_rwlock_wrlock(&domain->nod_rwlock);
    fi_addr = hg_hash_table_lookup(domain->nod_addr_ht, &addr_key);
    if (fi_addr != HG_HASH_TABLE_NULL) {
        /* in race condition, use addr in HT and remove the new addr from AV */
        *src_addr = *fi_addr;
        hg_thread_rwlock_release_wrlock(&domain->nod_rwlock);
        fi_av_remove(domain->nod_av, &tmp_addr, 1 /* count */, 0 /* flag */);
        return ret;
    }
    new_key = (na_uint64_t *)malloc(sizeof(*new_key));
    new_value = (fi_addr_t *)malloc(sizeof(*new_value));
    if (new_key == NULL || new_value == NULL) {
        NA_LOG_ERROR("cannot allocate memory for new_key/new_value.");
        ret = NA_NOMEM_ERROR;
        goto unlock;
    }
    *new_key = addr_key;
    *new_value = tmp_addr;
    if (hg_hash_table_insert(domain->nod_addr_ht, new_key, new_value) == 0) {
        NA_LOG_ERROR("hg_hash_table_insert(%s:%s) failed.", node, service);
        ret = NA_NOMEM_ERROR;
    } else {
        /*
        NA_LOG_DEBUG("hg_hash_table_insert(%s:%s) succeed, fi_addr: %d.",
                     node, service, tmp_addr);
        */
    }
unlock:
    hg_thread_rwlock_release_wrlock(&domain->nod_rwlock);
out:
    return ret;
}

/********************/
/* Local Prototypes */
/********************/

/* check_protocol */
static na_bool_t
na_ofi_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_ofi_initialize(na_class_t *na_class, const struct na_info *na_info,
    na_bool_t listen);

/* finalize */
static na_return_t
na_ofi_finalize(na_class_t *na_class);

/* op_create */
static na_op_id_t
na_ofi_op_create(na_class_t *na_class);

/* op_destroy */
static na_return_t
na_ofi_op_destroy(na_class_t *na_class, na_op_id_t op_id);

/* addr_lookup */
static na_return_t
na_ofi_addr_lookup(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const char *name, na_op_id_t *op_id);

/* addr_self */
static na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr);

/* addr_dup */
static na_return_t
na_ofi_addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr);

/* addr_free */
static na_return_t
na_ofi_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_is_self */
static na_bool_t
na_ofi_addr_is_self(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t
na_ofi_addr_to_string(na_class_t *na_class, char *buf, na_size_t *buf_size,
    na_addr_t addr);

/* msg_get_max */
static na_size_t
na_ofi_msg_get_max_expected_size(na_class_t *na_class);

static na_size_t
na_ofi_msg_get_max_unexpected_size(na_class_t *na_class);

static na_size_t
na_ofi_msg_get_reserved_unexpected_size(na_class_t *na_class);

static na_tag_t
na_ofi_msg_get_max_tag(na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    na_tag_t mask, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    na_addr_t source, na_tag_t tag, na_op_id_t *op_id);

/* mem_handle */
static na_return_t
na_ofi_mem_handle_create(na_class_t *na_class, void *buf, na_size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle);

static na_return_t
na_ofi_mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle);

/* mem_handle serialization */
static na_size_t
na_ofi_mem_handle_get_serialize_size(na_class_t *na_class,
    na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_serialize(na_class_t *na_class, void *buf,
    na_size_t buf_size, na_mem_handle_t mem_handle);

static na_return_t
na_ofi_mem_handle_deserialize(na_class_t *na_class,
    na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);

/* put */
static na_return_t
na_ofi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);

/* get */
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);

/* progress */
static na_return_t
na_ofi_progress(na_class_t *na_class, na_context_t *context,
    unsigned int timeout);

static na_return_t
na_ofi_complete(na_ofi_addr_t *na_ofi_addr, na_ofi_op_id_t *na_ofi_op_id,
    na_return_t ret);

static void
na_ofi_release(void *arg);

/* cancel */
static na_return_t
na_ofi_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t op_id);

/*******************/
/* Local Variables */
/*******************/

const na_class_t na_ofi_class_g = {
    NULL,                                   /* private_data */
    "ofi",                                  /* name */
    na_ofi_check_protocol,                  /* check_protocol */
    na_ofi_initialize,                      /* initialize */
    na_ofi_finalize,                        /* finalize */
    NULL,                                   /* check_feature */
    NULL,                                   /* context_create */
    NULL,                                   /* context_destroy */
    na_ofi_op_create,                       /* op_create */
    na_ofi_op_destroy,                      /* op_destroy */
    na_ofi_addr_lookup,                     /* addr_lookup */
    na_ofi_addr_free,                       /* addr_free */
    na_ofi_addr_self,                       /* addr_self */
    na_ofi_addr_dup,                        /* addr_dup */
    na_ofi_addr_is_self,                    /* addr_is_self */
    na_ofi_addr_to_string,                  /* addr_to_string */
    na_ofi_msg_get_max_expected_size,       /* msg_get_max_expected_size */
    na_ofi_msg_get_max_unexpected_size,     /* msg_get_max_unexpected_size */
    na_ofi_msg_get_reserved_unexpected_size,/* msg_get_reserved_unexpected_size */
    NULL,                                   /* msg_buf_alloc */
    NULL,                                   /* msg_buf_free */
    na_ofi_msg_get_max_tag,                 /* msg_get_max_tag */
    na_ofi_msg_send_unexpected,             /* msg_send_unexpected */
    na_ofi_msg_recv_unexpected,             /* msg_recv_unexpected */
    na_ofi_msg_send_expected,               /* msg_send_expected */
    na_ofi_msg_recv_expected,               /* msg_recv_expected */
    na_ofi_mem_handle_create,               /* mem_handle_create */
    NULL,                                   /* mem_handle_create_segment */
    na_ofi_mem_handle_free,                 /* mem_handle_free */
    na_ofi_mem_register,                    /* mem_register */
    na_ofi_mem_deregister,                  /* mem_deregister */
    NULL,                                   /* mem_publish */
    NULL,                                   /* mem_unpublish */
    na_ofi_mem_handle_get_serialize_size,   /* mem_handle_get_serialize_size */
    na_ofi_mem_handle_serialize,            /* mem_handle_serialize */
    na_ofi_mem_handle_deserialize,          /* mem_handle_deserialize */
    na_ofi_put,                             /* put */
    na_ofi_get,                             /* get */
    NULL,                                   /* get_poll_fd */
    na_ofi_progress,                        /* progress */
    na_ofi_cancel                           /* cancel */
};

/*****************/
/* Local Helpers */
/*****************/

static int
na_ofi_getinfo()
{
    struct fi_info *hints;
    struct fi_info *providers = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Only the first initiator queries OFI providers */
    if (HG_UTIL_TRUE != hg_atomic_cas32(&nofi_gdata.nog_init_flag, 0, 1)) {
        while(nofi_gdata.nog_providers == NULL)
            usleep(1);
        goto out;
    }

    /**
     * Hints to query && filter providers.
     *
     * mode: operational mode, NA_OFI passes in context for communication calls.
     * ep_type: reliable datagram (connection-less).
     * caps: capabilities required.
     * msg_order: guarantee that messages with same tag are ordered.
     * (FI_ORDER_SAS - Send after send. If set, message send operations,
     *  including tagged sends, are transmitted in the order submitted relative
     *  to other message send. If not set, message sends may be transmitted out
     *  of order from their submission).
     */
    hints = fi_allocinfo();
    if (!hints) {
        NA_LOG_ERROR("fi_allocinfo failed.\n");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    hints->mode               = FI_CONTEXT;
    hints->ep_attr->type      = FI_EP_RDM;
    hints->caps               = FI_TAGGED | FI_RMA;
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->rx_attr->msg_order = FI_ORDER_SAS;

    hints->domain_attr->threading        = FI_THREAD_UNSPEC;
    hints->domain_attr->control_progress = FI_PROGRESS_MANUAL;
    hints->domain_attr->data_progress    = FI_PROGRESS_MANUAL;
    hints->domain_attr->av_type          = FI_AV_MAP;
    hints->domain_attr->resource_mgmt    = FI_RM_ENABLED;

    /**
     * fi_getinfo:  returns information about fabric services.
     * Pass NULL for name/service to list all providers supported with above
     * requirement hints.
     */
    rc = fi_getinfo(NA_OFI_VERSION, /* OFI version requested */
                    NULL,  /* Optional name or fabric to resolve */
                    NULL,  /* Optional service name or port to request */
                    0ULL,  /* Optional flag */
                    hints, /* In: Hints to filter providers */
                    &providers); /* Out: List of matching providers */
    if (rc != 0) {
        NA_LOG_ERROR("fi_getinfo failed, rc: %d(%s).", rc, fi_strerror(-rc));
        fi_freeinfo(hints);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    assert(providers != NULL);
    nofi_gdata.nog_refcount = 0;
    hg_thread_mutex_init(&nofi_gdata.nog_mutex);
    nofi_gdata.nog_providers = providers;
    HG_LIST_INIT(&nofi_gdata.nog_domain_list);

    fi_freeinfo(hints);

out:
    return ret;
}

static inline void
nofi_gdata_addref_locked()
{
    assert(hg_atomic_get32(&nofi_gdata.nog_init_flag));
    nofi_gdata.nog_refcount++;
    //NA_LOG_DEBUG("nog_refcount increased to %d.", nofi_gdata.nog_refcount);
}

static inline void
nofi_gdata_addref()
{
    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);
    nofi_gdata_addref_locked();
    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
}

static void
nofi_gdata_decref_locked()
{
    assert(hg_atomic_get32(&nofi_gdata.nog_init_flag));
    assert(nofi_gdata.nog_refcount >= 1);

    nofi_gdata.nog_refcount--;
    //NA_LOG_DEBUG("nog_refcount decreased to %d.", nofi_gdata.nog_refcount);

    if (nofi_gdata.nog_refcount == 0) {
        assert(HG_LIST_IS_EMPTY(&nofi_gdata.nog_domain_list));
        fi_freeinfo(nofi_gdata.nog_providers);
        nofi_gdata.nog_providers = NULL;
        HG_LIST_INIT(&nofi_gdata.nog_domain_list);
        hg_atomic_set32(&nofi_gdata.nog_init_flag, 0);
    }
}

void
nofi_gdata_decref()
{
    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);
    nofi_gdata_decref_locked();
    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
}

static inline void
na_ofi_domain_addref_locked(struct na_ofi_domain *domain)
{
    domain->nod_refcount++;
    /*
    NA_LOG_DEBUG("ofi domain (provider %s), nod_refcount increased to %d.",
                 domain->nod_prov_name, domain->nod_refcount);
    */
}

static inline void
na_ofi_domain_addref(struct na_ofi_domain *domain)
{
    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);
    na_ofi_domain_addref_locked(domain);
    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
}

static inline void
na_ofi_domain_decref_locked(struct na_ofi_domain *domain)
{
    assert(domain->nod_refcount >= 1);
    domain->nod_refcount--;
    /*
    NA_LOG_DEBUG("ofi domain (provider %s), nod_refcount decreased to %d.",
                 domain->nod_prov_name, domain->nod_refcount);
    */
    if (domain->nod_refcount == 0) {
        hg_hash_table_free(domain->nod_addr_ht);
        domain->nod_addr_ht = NULL;
        hg_thread_rwlock_destroy(&domain->nod_rwlock);
        if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE && domain->nod_mr != NULL)
            fi_close(&domain->nod_mr->fid);
        fi_close(&domain->nod_av->fid);
        fi_close(&domain->nod_domain->fid);
        fi_close(&domain->nod_fabric->fid);
        free(domain->nod_prov_name);
        domain->nod_prov = NULL;
        HG_LIST_REMOVE(domain, nod_entry);
        free(domain);
        nofi_gdata_decref_locked();
    }
}

static inline void
na_ofi_domain_decref(struct na_ofi_domain *domain)
{
    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);
    na_ofi_domain_decref_locked(domain);
    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
}

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_check_protocol(const char *protocol_name)
{
    struct fi_info *prov;
    na_bool_t accept = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    ret = na_ofi_getinfo();
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_getinfo failed, ret: %d.", ret);
        goto out;
    }

    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);

    prov = nofi_gdata.nog_providers;
    while (prov != NULL) {
        /*
        NA_LOG_DEBUG("fabric_attr - prov_name %s, name - %s, "
                     "domain_attr - name %s.", prov->fabric_attr->prov_name,
                     prov->fabric_attr->name, prov->domain_attr->name);
        */
        if (!strcmp(protocol_name, prov->fabric_attr->prov_name)) {
            accept = NA_TRUE;
            break;
        }
        prov = prov->next;
    };

    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);

out:
    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_check_interface(const char *hostname, char *node, size_t node_len,
    char *domain, size_t domain_len)
{
    struct ifaddrs *ifaddrs = NULL, *ifaddr;
    na_return_t ret = NA_SUCCESS;
    na_bool_t found = NA_FALSE;

    if (getifaddrs(&ifaddrs) == -1) {
        NA_LOG_ERROR("getifaddrs() failed");
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Check and compare interfaces */
    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        char host[NI_MAXHOST];
        char ip[INET_ADDRSTRLEN]; /* This restricts to ipv4 addresses */

        if (ifaddr->ifa_addr == NULL)
            continue;

        if (ifaddr->ifa_addr->sa_family != AF_INET)
            continue;

        /* Get hostname */
        if (getnameinfo(ifaddr->ifa_addr, sizeof(struct sockaddr_in), host,
            NI_MAXHOST, NULL, 0, 0) != 0) {
            NA_LOG_ERROR("Name could not be resolved for: %s", ifaddr->ifa_name);
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }

        /* Get IP */
        if (!inet_ntop(ifaddr->ifa_addr->sa_family,
            &((struct sockaddr_in *) ifaddr->ifa_addr)->sin_addr, ip,
            INET_ADDRSTRLEN)) {
            NA_LOG_ERROR("IP could not be resolved for: %s", ifaddr->ifa_name);
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }

        /* Compare hostnames / device names */
        if (!strcmp(host, hostname) || !strcmp(ip, hostname) ||
            !strcmp(ifaddr->ifa_name, hostname)) {
            if (node_len)
               strncpy(node, ip, node_len);
            if (domain_len)
               strncpy(domain, ifaddr->ifa_name, domain_len);
            found = NA_TRUE;
            break;
        }
    }

    /* Allow for passing hostname/device name directly if no match */
    if (!found) {
        strncpy(node, hostname, node_len);
        strncpy(domain, hostname, domain_len);
    }

out:
    freeifaddrs(ifaddrs);
    return ret;
}

/*---------------------------------------------------------------------------*/
/**
 * Generate the request header for NA class. Can be called after nop_uri being
 * initialized (for example "sockets://192.168.42.170:7779").
 */
static inline na_return_t
na_ofi_gen_req_hdr(struct na_ofi_private_data *priv)
{
    char *uri = NULL, *locator, *ip_str;
    na_uint32_t port;
    struct in_addr in;
    int rc;
    na_return_t ret = NA_SUCCESS;

    uri = strdup(priv->nop_uri);
    if (uri == NULL) {
        NA_LOG_ERROR("strdup nop_uri failed.");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    locator = strrchr(uri, ':');
    if (locator == NULL) {
        ret = NA_INVALID_PARAM;
        goto out;
    }
    *locator++ = '\0';
    port = (na_uint32_t) atoi(locator);
    locator = strrchr(uri, '/');
    if (locator == NULL) {
        ret = NA_INVALID_PARAM;
        goto out;
    }
    ip_str = locator + 1;

    rc = inet_aton(ip_str, &in);
    if (rc == 0) {
        NA_LOG_ERROR("Bad IP addr: %s.", ip_str);
        ret = NA_INVALID_PARAM;
        goto out;
    }
    priv->nop_req_hdr.fih_feats = 0;
    priv->nop_req_hdr.fih_magic = NA_OFI_HDR_MAGIC;
    priv->nop_req_hdr.fih_ip = in.s_addr;
    priv->nop_req_hdr.fih_port = port;

out:
    if (uri != NULL)
        free(uri);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_initialize(na_class_t *na_class, const struct na_info *na_info,
    na_bool_t NA_UNUSED listen)
{
    struct na_ofi_private_data *priv;
    struct na_ofi_domain *domain;
    struct fid_fabric *fabric_hdl;
    struct fid_domain *domain_hdl;
    struct fid_mr *mr_hdl = NULL;
    struct fid_av *av_hdl;
    struct fid_cq *cq_hdl;
    struct fid_ep *ep_hdl;
    struct fi_av_attr av_attr = {0};
    struct fi_cq_attr cq_attr = {0};
    struct fi_info *prov;
    void *ep_addr;
    char ep_addr_str[NA_OFI_MAX_URI_LEN] = {'\0'};
    char node[NA_OFI_MAX_URI_LEN] = {'\0'};
    char domain_name[NA_OFI_MAX_URI_LEN] = {'\0'};
    char *service = NULL;
    size_t addrlen;
    na_bool_t found = NA_FALSE;
    na_bool_t retried = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    int rc;

    ret = na_ofi_getinfo();
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_getinfo failed, ret: %d.", ret);
        goto out;
    }
    /*
    NA_LOG_DEBUG("Entering na_ofi_initialize class_name %s, protocol_name %s, "
                 "host_name %s.\n", na_info->class_name, na_info->protocol_name,
                 na_info->host_name);
    */
    /* Get hostname/port info if available */
    if (na_info->host_name) {
        /* Extract hostname */
        if (strstr(na_info->host_name, ":"))
            strtok_r(na_info->host_name, ":", &service);

        /* Try to get matching IP/device */
        ret = na_ofi_check_interface(na_info->host_name, node,
            NA_OFI_MAX_URI_LEN, domain_name, NA_OFI_MAX_URI_LEN);
        if (ret != NA_SUCCESS) {
            NA_LOG_ERROR("Could not check interfaces");
            goto out;
        }
    }

    hg_thread_mutex_lock(&nofi_gdata.nog_mutex);

    /**
     * Search nog_domain_list. It allows to create endpoints with different
     * providers. The endpoints with same provider name can reuse the same
     * na_ofi_domain.
     */
    HG_LIST_FOREACH(domain, &nofi_gdata.nog_domain_list, nod_entry) {
        if (strcmp(domain->nod_prov_name, na_info->protocol_name) != 0)
            continue;

        if (domain->nod_prov_type == NA_OFI_PROV_PSM2 ||
            domain->nod_prov_type == NA_OFI_PROV_GNI ||
            !strcmp(domain_name, domain->nod_prov->domain_attr->name)) {
            na_ofi_domain_addref_locked(domain);
            hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
            goto create_ep;
        }
    }

    /**
     * No fi domain reusable, search the provider and open fi fabric/domain/av
     * object.
     */
    domain = (struct na_ofi_domain *)malloc(sizeof(struct na_ofi_domain));
    if (domain == NULL) {
        ret = NA_NOMEM_ERROR;
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        goto out;
    }

    prov = nofi_gdata.nog_providers;
    while (prov != NULL) {
        if (!strcmp(na_info->protocol_name, prov->fabric_attr->prov_name) &&
            (!strcmp(na_info->protocol_name, "psm2") ||
             !strcmp(na_info->protocol_name, "gni") || !na_info->host_name ||
            !strcmp(domain_name, prov->domain_attr->name))) {
            /*
            NA_LOG_DEBUG("mode 0x%llx, fabric_attr - prov_name %s, name - %s, "
                         "domain_attr - name %s.", prov->mode,
                         prov->fabric_attr->prov_name, prov->fabric_attr->name,
                         prov->domain_attr->name);
            */

            found = NA_TRUE;
            nofi_gdata_addref_locked();
            break;
        }
        prov = prov->next;
    }

    if (found == NA_FALSE) {
        NA_LOG_ERROR("No provider found for \"%s\" protocol on domain \"%s\"",
                     na_info->protocol_name, domain_name);
        free(domain);
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    domain->nod_prov = prov;
    /* create addr hash-table */
    domain->nod_addr_ht = hg_hash_table_new(av_addr_ht_key_hash,
                                            av_addr_ht_key_equal);
    if (domain->nod_addr_ht == NULL) {
        NA_LOG_ERROR("hg_hash_table_new failed.");
        free(domain);
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    hg_hash_table_register_free_functions(domain->nod_addr_ht,
                                          av_addr_ht_key_free,
                                          av_addr_ht_value_free);
    rc = hg_thread_rwlock_init(&domain->nod_rwlock);
    if (rc != HG_UTIL_SUCCESS) {
        NA_LOG_ERROR("hg_hash_table_new failed.");
        free(domain);
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Open fi fabric */
    rc = fi_fabric(prov->fabric_attr, /* In:  Fabric attributes */
                   &fabric_hdl,       /* Out: Fabric handle */
                   NULL);             /* Optional context for fabric events */
    if (rc != 0) {
        NA_LOG_ERROR("fi_fabric failed, rc: %d(%s).", rc, fi_strerror(-rc));
        hg_hash_table_free(domain->nod_addr_ht);
        hg_thread_rwlock_destroy(&domain->nod_rwlock);
        free(domain);
        ret = NA_PROTOCOL_ERROR;
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        goto out;
    }

    domain->nod_prov_name = strdup(na_info->protocol_name);
    if (!strcmp(domain->nod_prov_name, "sockets")) {
        domain->nod_prov_type = NA_OFI_PROV_SOCKETS;
        /* sockets provider without MR_BASIC supporting */
        domain->nod_prov->domain_attr->mr_mode = FI_MR_SCALABLE;
        domain->nod_mr_mode = NA_OFI_MR_SCALABLE;
#if defined(FI_SOURCE_ERR)
    } else if (!strcmp(domain->nod_prov_name, "psm2")) {
        domain->nod_prov_type = NA_OFI_PROV_PSM2;
        domain->nod_prov->caps |= (FI_SOURCE | FI_SOURCE_ERR);
        domain->nod_prov->domain_attr->mr_mode = FI_MR_BASIC;
        domain->nod_mr_mode = NA_OFI_MR_BASIC;
#endif
    } else if (!strcmp(domain->nod_prov_name, "verbs")) {
        domain->nod_prov_type = NA_OFI_PROV_VERBS;
        domain->nod_prov->domain_attr->mr_mode = FI_MR_BASIC;
        domain->nod_mr_mode = NA_OFI_MR_BASIC;
    } else if (!strcmp(domain->nod_prov_name, "gni")) {
        domain->nod_prov_type = NA_OFI_PROV_GNI;
        domain->nod_prov->domain_attr->mr_mode = FI_MR_BASIC;
        domain->nod_mr_mode = NA_OFI_MR_BASIC;
    } else {
        NA_LOG_ERROR("bad domain->nod_prov_name %s.", domain->nod_prov_name);
        hg_hash_table_free(domain->nod_addr_ht);
        hg_thread_rwlock_destroy(&domain->nod_rwlock);
        fi_close(&fabric_hdl->fid);
        free(domain);
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Create the fi access domain */
    rc = fi_domain(fabric_hdl,   /* In:  Fabric object */
                   prov,         /* In:  Provider */
                   &domain_hdl,  /* Out: Domain oject */
                   NULL);        /* Optional context for domain events */
    if (rc != 0) {
        NA_LOG_ERROR("fi_domain failed, rc: %d(%s).", rc, fi_strerror(-rc));
        hg_hash_table_free(domain->nod_addr_ht);
        hg_thread_rwlock_destroy(&domain->nod_rwlock);
        fi_close(&fabric_hdl->fid);
        free(domain);
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* For MR_SCALABLE, create MR, now exports all memory range for RMA */
    if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) {
        rc = fi_mr_reg(domain_hdl, (void *)0, UINT64_MAX,
                       FI_REMOTE_READ | FI_REMOTE_WRITE, 0ULL /* offset */,
                       NA_OFI_RMA_KEY, 0 /* flags */, &mr_hdl,
                       NULL /* context */);
        if (rc != 0) {
            hg_hash_table_free(domain->nod_addr_ht);
            hg_thread_rwlock_destroy(&domain->nod_rwlock);
            NA_LOG_ERROR("fi_mr_reg failed, rc: %d(%s).", rc, fi_strerror(-rc));
            fi_close(&domain_hdl->fid);
            fi_close(&fabric_hdl->fid);
            free(domain);
            nofi_gdata_decref_locked(); /* rollback refcount taken above */
            hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
    }

    /* Open fi address vector */
    av_attr.type = FI_AV_MAP;
    rc = fi_av_open(domain_hdl, &av_attr, &av_hdl, NULL);
    if (rc != 0) {
        NA_LOG_ERROR("fi_av_open failed, rc: %d(%s).", rc, fi_strerror(-rc));
        hg_hash_table_free(domain->nod_addr_ht);
        hg_thread_rwlock_destroy(&domain->nod_rwlock);
        if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE)
            fi_close(&mr_hdl->fid);
        fi_close(&domain_hdl->fid);
        fi_close(&fabric_hdl->fid);
        free(domain);
        nofi_gdata_decref_locked(); /* rollback refcount taken above */
        hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    domain->nod_fabric = fabric_hdl;
    domain->nod_domain = domain_hdl;
    if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE)
        domain->nod_mr = mr_hdl;
    domain->nod_av = av_hdl;
    domain->nod_refcount = 0;
    domain->nod_src_addrlen = prov->src_addrlen;
    domain->nod_dest_addrlen = prov->dest_addrlen;
    na_ofi_domain_addref_locked(domain);

    /* insert to domain list */
    HG_LIST_INSERT_HEAD(&nofi_gdata.nog_domain_list, domain, nod_entry);
    hg_thread_mutex_unlock(&nofi_gdata.nog_mutex);

create_ep:
    assert(domain != NULL);

    priv = (struct na_ofi_private_data *)calloc(1,
                sizeof(struct na_ofi_private_data));
    if (priv == NULL) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        na_ofi_domain_decref(domain);
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    rc = fi_getinfo(NA_OFI_VERSION, node, service, FI_SOURCE | FI_NUMERICHOST,
                    domain->nod_prov, &priv->nop_fi_info);
    if (rc != 0) {
        NA_LOG_ERROR("fi_getinfo(%s, %s) failed, rc: %d(%s).", node, service,
            rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto getinfo_err;
    }
    assert(priv->nop_fi_info != NULL);

    priv->nop_fi_info->addr_format = FI_SOCKADDR_IN;
    /* Create a transport level communication endpoint */
    rc = fi_endpoint(domain->nod_domain,   /* In:  Domain object */
                     priv->nop_fi_info,    /* In:  Provider */
                     &ep_hdl,              /* Out: Endpoint object */
                     NULL);                /* Optional context */
    if (rc != 0) {
        NA_LOG_ERROR("fi_endpoint failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto ep_create_err;
    }

    /* Create fi completion queue for events */
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    rc = fi_cq_open(domain->nod_domain, &cq_attr, &cq_hdl, NULL);
    if (rc != 0) {
        NA_LOG_ERROR("fi_cq_open failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto cq_open_err;
    }

    /* Bind the CQ and AV to the endpoint */
    rc = fi_ep_bind(ep_hdl, &cq_hdl->fid, FI_TRANSMIT | FI_RECV);
    if (rc != 0) {
        NA_LOG_ERROR("fi_ep_bind failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto ep_bind_err;
    }

    rc = fi_ep_bind(ep_hdl, &domain->nod_av->fid, 0);
    if (rc != 0) {
        NA_LOG_ERROR("fi_ep_bind failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto ep_bind_err;
    }

    /* Enable the endpoint for communication, and commits the bind operations */
    ret = fi_enable(ep_hdl);
    if (rc != 0) {
        NA_LOG_ERROR("fi_enable failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto ep_bind_err;
    }

    priv->nop_domain = domain;
    priv->nop_cq = cq_hdl;
    priv->nop_ep = ep_hdl;
    HG_QUEUE_INIT(&priv->nop_unexpected_op_queue);
    hg_thread_mutex_init(&priv->nop_unexpected_op_mutex);
    na_class->private_data = priv;

    addrlen = domain->nod_src_addrlen;
retry_getname:
    ep_addr = malloc(addrlen);
    if (ep_addr == NULL) {
        NA_LOG_ERROR("Could not allocate ep_addr.");
        ret = NA_NOMEM_ERROR;
        goto ep_bind_err;
    }
    rc = fi_getname(&ep_hdl->fid, ep_addr, &addrlen);
    if (rc != 0) {
        if (rc == -FI_ETOOSMALL && retried == NA_FALSE) {
            retried = NA_TRUE;
            free(ep_addr);
            goto retry_getname;
        }
        NA_LOG_ERROR("fi_getname failed, rc: %d(%s), addrlen: %zu.",
                     rc, fi_strerror(-rc), addrlen);
        free(ep_addr);
        goto ep_bind_err;
    }

    addrlen = NA_OFI_MAX_URI_LEN;
    rc = snprintf(ep_addr_str, addrlen, "%s://", na_info->protocol_name);
    if (rc < 0) {
        NA_LOG_ERROR("snprintf failed, rc: %d.", rc);
        free(ep_addr);
        goto ep_bind_err;
    }
    addrlen -= (size_t) rc;
    if (domain->nod_prov_type == NA_OFI_PROV_PSM2 || domain->nod_prov_type == NA_OFI_PROV_GNI)
        snprintf(ep_addr_str + rc, addrlen, "%s:%s", node, service);
    else
        fi_av_straddr(domain->nod_av, ep_addr, ep_addr_str + rc, &addrlen);
    priv->nop_uri = strdup(ep_addr_str);
    free(ep_addr);
    if (priv->nop_uri == NULL) {
        NA_LOG_ERROR("Could not strdup nop_uri.");
        ret = NA_NOMEM_ERROR;
        goto ep_bind_err;
    }
    ret = na_ofi_gen_req_hdr(priv);
    if (ret != NA_SUCCESS) {
        free(priv->nop_uri);
        NA_LOG_ERROR("na_ofi_gen_req_hdr failed, ret: %d.", ret);
        goto ep_bind_err;
    }
    NA_LOG_DEBUG("created endpoint addr %s.\n", priv->nop_uri);

out:
    return ret;

ep_bind_err:
    fi_close(&cq_hdl->fid);
cq_open_err:
    fi_close(&ep_hdl->fid);
ep_create_err:
    fi_freeinfo(priv->nop_fi_info);
getinfo_err:
    free(priv);
    na_ofi_domain_decref(domain);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_finalize(na_class_t *na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* Check that unexpected op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&priv->nop_unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    rc = fi_close(&priv->nop_ep->fid);
    if (rc != 0) {
        NA_LOG_ERROR("fi_close endpoint failed, rc: %d(%s).",
                     rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    rc = fi_close(&priv->nop_cq->fid);
    if (rc != 0) {
        NA_LOG_ERROR("fi_close CQ failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    na_ofi_domain_decref(priv->nop_domain);

    hg_thread_mutex_destroy(&priv->nop_unexpected_op_mutex);
    fi_freeinfo(priv->nop_fi_info);
    free(priv->nop_uri);
    free(priv);
    na_class->private_data = NULL;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_id_addref(na_ofi_op_id_t *na_ofi_op_id)
{
    /* init as 1 when op_create */
    assert(hg_atomic_get32(&na_ofi_op_id->noo_refcount));
    hg_atomic_incr32(&na_ofi_op_id->noo_refcount);

    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_id_decref(na_ofi_op_id_t *na_ofi_op_id)
{
    assert(hg_atomic_get32(&na_ofi_op_id->noo_refcount) > 0);

    /* If there are more references, return */
    if (hg_atomic_decr32(&na_ofi_op_id->noo_refcount))
        return;

    /* No more references, cleanup */
    free(na_ofi_op_id);

    return;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t
na_ofi_op_create(na_class_t NA_UNUSED *na_class)
{
    na_ofi_op_id_t *na_ofi_op_id = NULL;

    na_ofi_op_id = (na_ofi_op_id_t *)calloc(1, sizeof(na_ofi_op_id_t));
    if (!na_ofi_op_id) {
        NA_LOG_ERROR("Could not allocate NA OFI operation ID");
        goto done;
    }
    hg_atomic_set32(&na_ofi_op_id->noo_refcount, 1);
    /* Completed by default */
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 1);

done:
    return (na_op_id_t) na_ofi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t op_id)
{
    na_ofi_op_id_t *na_ofi_op_id = (na_ofi_op_id_t *) op_id;

    na_ofi_op_id_decref(na_ofi_op_id);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
/*
 * Gets node and service string for the remote peer uri.
 * Example input name: "sockets://192.168.42.170:4567", will get result node
 * "192.168.42.170" and service "4567".
 * Caller should provide the needed buffer for all parameters.
 */
static na_return_t
na_ofi_get_port_info(const char *name, char *node, char *service)
{
    char *dup_name;
    char *node_str = NULL, *port_str = NULL;
    na_return_t ret = NA_SUCCESS;

    dup_name = strdup(name);
    if (!dup_name) {
        NA_LOG_ERROR("Cannot dup name");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    port_str = strrchr(dup_name, ':');
    if (port_str == NULL) {
        NA_LOG_ERROR("invalid name %s.", name);
        ret = NA_INVALID_PARAM;
        goto out;
    }
    *port_str++ = '\0';
    node_str = strrchr(dup_name, '/');
    if (node_str == NULL) {
        NA_LOG_ERROR("invalid name %s.", name);
        ret = NA_INVALID_PARAM;
        goto out;
    }
    *node_str++ = '\0';

    strcpy(node, node_str);
    strcpy(service, port_str);
    /*
    NA_LOG_DEBUG("name %s, node_string %s, port_str %s.\n",
                 name, node_str, port_str);
    */

out:
    free(dup_name);
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_addr *
na_ofi_addr_alloc(const char *name)
{
    struct na_ofi_addr *na_ofi_addr;

    na_ofi_addr = (struct na_ofi_addr *)calloc(1, sizeof(*na_ofi_addr));
    if (!na_ofi_addr) {
        NA_LOG_ERROR("Could not allocate addr");
        return NULL;
    }

    if (name != NULL) {
        na_ofi_addr->noa_uri = strdup(name);
        if (na_ofi_addr->noa_uri == NULL) {
            NA_LOG_ERROR("Could not strdup name");
            free(na_ofi_addr);
            return NULL;
        }
    }

    na_ofi_addr->noa_addr = 0;
    na_ofi_addr->noa_unexpected = NA_FALSE;
    na_ofi_addr->noa_self = NA_FALSE;
    /* One refcount for the caller to hold until addr_free */
    hg_atomic_set32(&na_ofi_addr->noa_refcount, 1);

    return na_ofi_addr;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_addref(na_ofi_addr_t *na_ofi_addr)
{
    assert(hg_atomic_get32(&na_ofi_addr->noa_refcount));
    hg_atomic_incr32(&na_ofi_addr->noa_refcount);
    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_decref(na_ofi_addr_t *na_ofi_addr)
{
    assert(hg_atomic_get32(&na_ofi_addr->noa_refcount) > 0);

    /* If there are more references, return */
    if (hg_atomic_decr32(&na_ofi_addr->noa_refcount))
        return;

    /* No more references, cleanup */
    na_ofi_addr->noa_addr = 0;
    /* TODO need to fi_av_remove? */
    free(na_ofi_addr->noa_uri);
    free(na_ofi_addr);

    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_lookup(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const char *name, na_op_id_t *op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    struct na_ofi_addr *na_ofi_addr = NULL;
    char node_str[NA_OFI_MAX_NODE_LEN] = {'\0'};
    char service_str[NA_OFI_MAX_PORT_LEN] = {'\0'};
    na_return_t ret = NA_SUCCESS;

    /* Allocate op_id */
    na_ofi_op_id = (struct na_ofi_op_id *)calloc(1, sizeof(*na_ofi_op_id));
    if (!na_ofi_op_id) {
        NA_LOG_ERROR("Could not allocate NA MPI operation ID");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_LOOKUP;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);
    /* take one refcount to be released in na_ofi_complete->na_ofi_release */
    hg_atomic_set32(&na_ofi_op_id->noo_refcount, 1);

    /* Allocate addr */
    na_ofi_addr = na_ofi_addr_alloc(name);
    if (!na_ofi_addr) {
        NA_LOG_ERROR("na_ofi_addr_alloc failed");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    /* One extra refcount to be decref in na_ofi_complete(). */
    na_ofi_addr_addref(na_ofi_addr);

    na_ofi_op_id->noo_info.noo_lookup.noi_addr = (na_addr_t) na_ofi_addr;

    ret = na_ofi_get_port_info(name, node_str, service_str);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_get_port_info(%s) failed, ret: %d.\n", name, ret);
        goto out;
    }

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE) *op_id = (na_op_id_t) na_ofi_op_id;

    /* address resolution by fi AV */
    ret = na_ofi_av_insert(na_class, node_str, service_str,
                           &na_ofi_addr->noa_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_av_insert(%s:%s) failed, ret: %d.",
                     node_str, service_str, ret);
        goto out;
    }

    /* As the fi_av_insert is blocking, always complete here */
    ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_SUCCESS);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not complete operation");
        goto out;
    }

out:
    if (ret != NA_SUCCESS) {
        free(na_ofi_addr);
        free(na_ofi_op_id);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_self(na_class_t *na_class, na_addr_t *addr)
{
    na_ofi_addr_t *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate addr */
    na_ofi_addr = (na_ofi_addr_t *)calloc(1, sizeof(*na_ofi_addr));
    if (!na_ofi_addr) {
        NA_LOG_ERROR("Could not allocate OFI addr");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    na_ofi_addr->noa_addr = 0;
    na_ofi_addr->noa_uri = strdup(NA_OFI_PRIVATE_DATA(na_class)->nop_uri);
    na_ofi_addr->noa_unexpected = NA_FALSE;
    na_ofi_addr->noa_self = NA_TRUE;
    hg_atomic_set32(&na_ofi_addr->noa_refcount, 1);

    *addr = (na_addr_t) na_ofi_addr;

out:
    if (ret != NA_SUCCESS) {
        free(na_ofi_addr);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_dup(na_class_t NA_UNUSED *na_class, na_addr_t addr,
    na_addr_t *new_addr)
{
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *)addr;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_addr_free() */
    *new_addr = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *)addr;
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_addr) {
        NA_LOG_ERROR("NULL NA addr");
        ret = NA_INVALID_PARAM;
        return ret;
    }

    na_ofi_addr_decref(na_ofi_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_addr_is_self(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *) addr;

    return na_ofi_addr->noa_self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    na_size_t *buf_size, na_addr_t addr)
{
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *) addr;
    na_size_t str_len;
    na_return_t ret = NA_SUCCESS;

    str_len = strlen(na_ofi_addr->noa_uri);
    if (buf) {
        if (str_len >= *buf_size) {
            NA_LOG_ERROR("Buffer size too small to copy addr");
            ret = NA_SIZE_ERROR;
        } else {
            strcpy(buf, na_ofi_addr->noa_uri);
        }
    }
    *buf_size = str_len + 1;

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_msg_get_max_expected_size(na_class_t NA_UNUSED *na_class)
{
    /*
     * Use same size as NA_OFI_UNEXPECTED_SIZE to save memory footprint.
     * The (ep_attr->max_msg_size - ep_attr->msg_prefix_size) will get 8MB as
     * the size of hg_handle->out_buf_size.
     */
    /*
    struct fi_ep_attr *ep_attr;
    na_size_t max_expected_size;

    ep_attr = NA_OFI_PRIVATE_DATA(na_class)->nop_domain->nod_prov->ep_attr;
    max_expected_size = ep_attr->max_msg_size - ep_attr->msg_prefix_size;

    return max_expected_size;
    */
    return NA_OFI_UNEXPECTED_SIZE;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_msg_get_max_unexpected_size(na_class_t NA_UNUSED *na_class)
{
    return NA_OFI_UNEXPECTED_SIZE;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_msg_get_reserved_unexpected_size(na_class_t *na_class)
{
    if (na_ofi_with_reqhdr(na_class) == NA_TRUE)
        return sizeof(na_ofi_reqhdr_t);
    else
        return 0;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_ofi_msg_get_max_tag(na_class_t NA_UNUSED *na_class)
{
    return NA_OFI_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_unexpected_op_push(na_class_t *na_class,
    na_ofi_op_id_t *na_ofi_op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_op_id) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto out;
    }

    hg_thread_mutex_lock(&priv->nop_unexpected_op_mutex);
    HG_QUEUE_PUSH_TAIL(&priv->nop_unexpected_op_queue, na_ofi_op_id, noo_entry);
    hg_thread_mutex_unlock(&priv->nop_unexpected_op_mutex);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_unexpected_op_remove(na_class_t *na_class,
    na_ofi_op_id_t *na_ofi_op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_op_id) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto out;
    }

    hg_thread_mutex_lock(&priv->nop_unexpected_op_mutex);
    HG_QUEUE_REMOVE(&priv->nop_unexpected_op_queue, na_ofi_op_id, na_ofi_op_id,
                    noo_entry);
    hg_thread_mutex_unlock(&priv->nop_unexpected_op_mutex);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_ofi_op_id_t *
na_ofi_msg_unexpected_op_pop(na_class_t * na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_ofi_op_id_t *na_ofi_op_id;

    hg_thread_mutex_lock(&priv->nop_unexpected_op_mutex);
    na_ofi_op_id = HG_QUEUE_FIRST(&priv->nop_unexpected_op_queue);
    HG_QUEUE_POP_HEAD(&priv->nop_unexpected_op_queue, noo_entry);
    hg_thread_mutex_unlock(&priv->nop_unexpected_op_mutex);

    return na_ofi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_ep *ep_hdl = priv->nop_ep;
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *)dest;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    void *reqhdr = (void *) buf; /* TODO would be nice to keep the const */
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *)na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_SEND_UNEXPECTED;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    na_ofi_op_id->noo_addr = dest;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    /*
     * For those providers that don't support FI_SOURCE/FI_SOURCE_ERR, insert
     * the request header to piggyback the source address of request for
     * unexpected message.
     */
    if (na_ofi_with_reqhdr(na_class) == NA_TRUE)
        memcpy(reqhdr, &priv->nop_req_hdr, sizeof(priv->nop_req_hdr));

    /* Post the FI unexpected send request */
    do {
        rc = fi_tsend(ep_hdl, buf, buf_size, NULL /* desc */,
                       na_ofi_addr->noa_addr, tag, &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_tsend(unexpected) to %s failed, rc: %d(%s)",
                     na_ofi_addr->noa_uri, rc, fi_strerror((int) -rc));
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS) {
        na_ofi_addr_decref(na_ofi_addr);
        if (na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    na_tag_t NA_UNUSED mask, na_op_id_t *op_id)
{
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *)na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_RECV_UNEXPECTED;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);
    na_ofi_op_id->noo_info.noo_recv_unexpected.noi_buf = buf;
    na_ofi_op_id->noo_info.noo_recv_unexpected.noi_buf_size = buf_size;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    na_ofi_msg_unexpected_op_push(na_class, na_ofi_op_id);

    /* Post the FI unexpected recv request */
    do {
        rc = fi_trecv(ep_hdl, buf, buf_size, NULL /* desc */,
                       FI_ADDR_UNSPEC, 1 /* tag */,
                       NA_OFI_UNEXPECTED_TAG_IGNORE, &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_trecv(unexpected) failed, rc: %d(%s)",
                     rc, fi_strerror((int) -rc));
        na_ofi_msg_unexpected_op_remove(na_class, na_ofi_op_id);
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS && na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *)dest;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *)na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_SEND_EXPECTED;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    na_ofi_op_id->noo_addr = dest;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    /* Post the FI expected send request */
    do {
        rc = fi_tsend(ep_hdl, buf, buf_size, NULL /* desc */,
                       na_ofi_addr->noa_addr, NA_OFI_EXPECTED_TAG_FLAG | tag,
                       &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_tsend(expected) to %s failed, rc: %d(%s)",
                     na_ofi_addr->noa_uri, rc, fi_strerror((int) -rc));
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS) {
        na_ofi_addr_decref(na_ofi_addr);
        if (na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    na_addr_t source, na_tag_t tag, na_op_id_t *op_id)
{
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *)source;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *)na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_RECV_EXPECTED;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);
    na_ofi_op_id->noo_addr = na_ofi_addr;
    na_ofi_op_id->noo_info.noo_recv_expected.noi_buf = buf;
    na_ofi_op_id->noo_info.noo_recv_expected.noi_buf_size = buf_size;
    na_ofi_op_id->noo_info.noo_recv_expected.noi_tag = tag;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    /* Post the FI expected recv request */
    do {
        rc = fi_trecv(ep_hdl, buf, buf_size, NULL /* desc */,
                       na_ofi_addr->noa_addr, NA_OFI_EXPECTED_TAG_FLAG | tag,
                       0 /* ignore */, &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_trecv(expected) failed, rc: %d(%s)",
                     rc, fi_strerror((int) -rc));
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS) {
        na_ofi_addr_decref(na_ofi_addr);
        if (na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_create(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, unsigned long flags, na_mem_handle_t *mem_handle)
{
    na_ofi_mem_handle_t *na_ofi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle */
    na_ofi_mem_handle = (na_ofi_mem_handle_t *) calloc(1,
        sizeof(na_ofi_mem_handle_t));
    if (!na_ofi_mem_handle) {
        NA_LOG_ERROR("Could not allocate NA OFI memory handle");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    na_ofi_mem_handle->nom_base = (na_ptr_t)buf;
    na_ofi_mem_handle->nom_size = buf_size;
    na_ofi_mem_handle->nom_attr = (na_uint8_t)flags;
    na_ofi_mem_handle->nom_remote = 0;

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_free(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t mem_handle)
{
    na_ofi_mem_handle_t *ofi_mem_handle = (na_ofi_mem_handle_t *) mem_handle;

    free(ofi_mem_handle);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_register(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t NA_UNUSED mem_handle)
{
    na_ofi_mem_handle_t *na_ofi_mem_handle = mem_handle;
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    na_uint64_t access;
    int rc = 0;
    na_return_t ret = NA_SUCCESS;

    /* nothing to do for scalable memory registration mode */
    if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE)
        return NA_SUCCESS;

    switch (na_ofi_mem_handle->nom_attr) {
        case NA_MEM_READ_ONLY:
            access = FI_REMOTE_READ;
            break;
        case NA_MEM_WRITE_ONLY:
            access = FI_REMOTE_WRITE;
            break;
        case NA_MEM_READWRITE:
            access = FI_REMOTE_READ | FI_REMOTE_WRITE;
            break;
        default:
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto out;
    }

    //access = FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;
    //access = FI_REMOTE_READ | FI_REMOTE_WRITE;
    rc = fi_mr_reg(domain->nod_domain, (void *)na_ofi_mem_handle->nom_base,
                   na_ofi_mem_handle->nom_size, access, 0ULL /* offset */,
                   na_ofi_mem_handle->nom_base, 0 /* flags */,
                   &na_ofi_mem_handle->nom_mr_hdl, NULL /* context */);
    if (rc != 0) {
        NA_LOG_ERROR("fi_mr_reg failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    na_ofi_mem_handle->nom_mr_key = fi_mr_key(na_ofi_mem_handle->nom_mr_hdl);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    na_ofi_mem_handle_t *na_ofi_mem_handle = mem_handle;
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    int rc;

    /* nothing to do for scalable memory registration mode */
    if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE)
        return NA_SUCCESS;

    if (na_ofi_mem_handle->nom_mr_hdl == NULL) {
        NA_LOG_ERROR("invalid parameter - NULL na_ofi_mem_handle->nom_mr_hdl.");
        return NA_PROTOCOL_ERROR;
    }

    if (na_ofi_mem_handle->nom_remote != 0)
        return NA_SUCCESS;

    rc = fi_close(&na_ofi_mem_handle->nom_mr_hdl->fid);
    if (rc != 0) {
        NA_LOG_ERROR("fi_mr_reg failed, rc: %d(%s).", rc, fi_strerror(-rc));
        return NA_PROTOCOL_ERROR;
    }

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_mem_handle_get_serialize_size(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t NA_UNUSED mem_handle)
{
    return sizeof(struct na_ofi_mem_handle);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_serialize(na_class_t NA_UNUSED *na_class, void *buf,
    na_size_t buf_size, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle =
            (struct na_ofi_mem_handle*) mem_handle;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_ofi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for serializing handle");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    /* Copy struct */
    memcpy(buf, na_ofi_mem_handle, sizeof(struct na_ofi_mem_handle));

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_handle_deserialize(na_class_t NA_UNUSED *na_class,
    na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    if (buf_size < sizeof(struct na_ofi_mem_handle)) {
        NA_LOG_ERROR("Buffer size too small for deserializing handle");
        ret = NA_SIZE_ERROR;
        goto done;
    }

    na_ofi_mem_handle = (struct na_ofi_mem_handle *)
            malloc(sizeof(struct na_ofi_mem_handle));
    if (!na_ofi_mem_handle) {
          NA_LOG_ERROR("Could not allocate NA MPI memory handle");
          ret = NA_NOMEM_ERROR;
          goto done;
    }

    /* Copy struct */
    memcpy(na_ofi_mem_handle, buf, sizeof(struct na_ofi_mem_handle));
    na_ofi_mem_handle->nom_remote = 1;

    *mem_handle = (na_mem_handle_t) na_ofi_mem_handle;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    na_ofi_mem_handle_t *ofi_local_mem_handle =
        (na_ofi_mem_handle_t *) local_mem_handle;
    na_ofi_mem_handle_t *ofi_remote_mem_handle =
        (na_ofi_mem_handle_t *) remote_mem_handle;
    struct iovec iov;
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *) remote_addr;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    na_uint64_t rma_key;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* for na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *) na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_PUT;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);
    na_ofi_op_id->noo_addr = na_ofi_addr;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    /* Post the OFI RMA write */
    iov.iov_base = (char *)ofi_local_mem_handle->nom_base + local_offset;
    iov.iov_len = length;
    rma_key = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NA_OFI_RMA_KEY :
              ofi_remote_mem_handle->nom_mr_key;
    do {
        rc = fi_writev(ep_hdl, &iov, NULL /* desc */, 1 /* count */,
                       na_ofi_addr->noa_addr,
                       (na_uint64_t)ofi_remote_mem_handle->nom_base +
                       remote_offset, rma_key, &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_writev() to %s failed, rc: %d(%s)",
                     na_ofi_addr->noa_uri, rc, fi_strerror((int) -rc));
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS) {
        na_ofi_addr_decref(na_ofi_addr);
        if (na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    na_ofi_mem_handle_t *ofi_local_mem_handle =
        (na_ofi_mem_handle_t *) local_mem_handle;
    na_ofi_mem_handle_t *ofi_remote_mem_handle =
        (na_ofi_mem_handle_t *) remote_mem_handle;
    struct iovec iov;
    na_ofi_addr_t *na_ofi_addr = (na_ofi_addr_t *) remote_addr;
    na_ofi_op_id_t *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    na_uint64_t rma_key;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* for na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (na_ofi_op_id_t *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (na_ofi_op_id_t *) na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
    }

    na_ofi_op_id->noo_context = context;
    na_ofi_op_id->noo_type = NA_CB_PUT;
    na_ofi_op_id->noo_callback = callback;
    na_ofi_op_id->noo_arg = arg;
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 0);
    hg_atomic_set32(&na_ofi_op_id->noo_canceled, 0);
    na_ofi_op_id->noo_addr = na_ofi_addr;

    /* Assign op_id */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id == NA_OP_ID_NULL)
        *op_id = (na_op_id_t) na_ofi_op_id;

    /* Post the OFI RMA read */
    iov.iov_base = (char *)ofi_local_mem_handle->nom_base + local_offset;
    iov.iov_len = length;
    rma_key = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NA_OFI_RMA_KEY :
              ofi_remote_mem_handle->nom_mr_key;
    do {
        rc = fi_readv(ep_hdl, &iov, NULL /* desc */, 1 /* count */,
                      na_ofi_addr->noa_addr,
                      (na_uint64_t)ofi_remote_mem_handle->nom_base + remote_offset,
                      rma_key, &na_ofi_op_id->noo_fi_ctx);
        /* for EAGAIN, progress and do it again */
        if (rc == -FI_EAGAIN)
            na_ofi_progress(na_class, context, 0);
        else
            break;
    } while (1);
    if (rc) {
        NA_LOG_ERROR("fi_readv() from %s failed, rc: %d(%s)",
                     na_ofi_addr->noa_uri, rc, fi_strerror((int) -rc));
        ret = NA_PROTOCOL_ERROR;
    }

out:
    if (ret != NA_SUCCESS) {
        na_ofi_addr_decref(na_ofi_addr);
        if (na_ofi_op_id != NULL)
            na_ofi_op_id_decref(na_ofi_op_id);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_handle_send_event(na_class_t NA_UNUSED *class,
    na_context_t NA_UNUSED *context, struct fi_cq_tagged_entry *cq_event)
{
    na_ofi_op_id_t *na_ofi_op_id;
    na_ofi_addr_t *na_ofi_addr;
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    na_ofi_addr = (na_ofi_addr_t *)na_ofi_op_id->noo_addr;

    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;

    ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, ret);
    if (ret != NA_SUCCESS)
        NA_LOG_ERROR("Unable to complete send");

    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_handle_recv_event(na_class_t *na_class,
    na_context_t NA_UNUSED *context, fi_addr_t src_addr,
    struct fi_cq_tagged_entry *cq_event)
{
    struct na_ofi_addr *peer_addr = NULL;
    na_ofi_reqhdr_t *reqhdr;
    na_ofi_op_id_t *na_ofi_op_id;
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;

    if (cq_event->tag & ~NA_OFI_UNEXPECTED_TAG_IGNORE) {
        assert(na_ofi_op_id->noo_type == NA_CB_RECV_EXPECTED);
        peer_addr = na_ofi_op_id->noo_addr;
        assert(peer_addr != NULL);
        assert(na_ofi_op_id->noo_info.noo_recv_expected.noi_tag ==
               (cq_event->tag & ~NA_OFI_EXPECTED_TAG_FLAG));
        na_ofi_op_id->noo_info.noo_recv_expected.noi_msg_size = cq_event->len;
    } else {
        assert(na_ofi_op_id->noo_type == NA_CB_RECV_UNEXPECTED);

        peer_addr = na_ofi_addr_alloc(NULL);
        if (peer_addr == NULL) {
            NA_LOG_ERROR("na_ofi_addr_alloc failed");
            return;
        }

        if (na_ofi_with_reqhdr(na_class) == NA_TRUE) {
            reqhdr = na_ofi_op_id->noo_info.noo_recv_unexpected.noi_buf;
            /* check magic number and swap byte order when needed */
            if (reqhdr->fih_magic == na_ofi_bswap32(NA_OFI_HDR_MAGIC)) {
                na_ofi_bswap32s(&reqhdr->fih_feats);
                na_ofi_bswap32s(&reqhdr->fih_ip);
                na_ofi_bswap32s(&reqhdr->fih_port);
            } else if (reqhdr->fih_magic != NA_OFI_HDR_MAGIC) {
                NA_LOG_ERROR("illegal magic number, 0x%x.", reqhdr->fih_magic);
                ret = NA_PROTOCOL_ERROR;
                goto out;
            }
            ret = na_ofi_addr_ht_lookup(na_class, reqhdr, &src_addr);
            if (ret != NA_SUCCESS) {
                NA_LOG_ERROR("na_ofi_addr_ht_lookup failed, ret: %d.", ret);
                goto out;
            }
        }

        peer_addr->noa_addr = src_addr;
        /* For unexpected msg, take one extra ref to be released by
         * NA_Addr_free() (see hg_handle->addr_mine). */
        na_ofi_addr_addref(peer_addr);

        na_ofi_op_id->noo_addr = peer_addr;
        /* TODO check max tag */
        na_ofi_op_id->noo_info.noo_recv_unexpected.noi_tag = (na_tag_t) cq_event->tag;
        na_ofi_op_id->noo_info.noo_recv_unexpected.noi_msg_size = cq_event->len;
        na_ofi_msg_unexpected_op_remove(na_class, na_ofi_op_id);
    }

out:
    ret = na_ofi_complete(peer_addr, na_ofi_op_id, ret);
    if (ret != NA_SUCCESS)
        NA_LOG_ERROR("Unable to complete send");

    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_handle_rma_event(na_class_t NA_UNUSED *class,
    na_context_t NA_UNUSED *context, struct fi_cq_tagged_entry *cq_event)
{
    na_ofi_op_id_t *na_ofi_op_id;
    na_ofi_addr_t *na_ofi_addr;
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    na_ofi_addr = (na_ofi_addr_t *)na_ofi_op_id->noo_addr;

    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;

    ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, ret);
    if (ret != NA_SUCCESS)
        NA_LOG_ERROR("Unable to complete send");

    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_progress(na_class_t *na_class, na_context_t *context,
    unsigned int timeout)
{
    /* Convert timeout in ms into seconds */
    double remaining = timeout / 1000.0;
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_cq *cq_hdl = priv->nop_cq;
    struct fid_av *av_hdl = priv->nop_domain->nod_av;
    na_return_t ret = NA_TIMEOUT;

    do {
        ssize_t rc;
        hg_time_t t1, t2;
        fi_addr_t src_addr;
        struct fi_cq_tagged_entry cq_event;
        struct fi_cq_err_entry cq_err;
        fi_addr_t tmp_addr;

        hg_time_get_current(&t1);

        if (na_ofi_with_reqhdr(na_class) == NA_FALSE)
            rc = fi_cq_readfrom(cq_hdl, &cq_event, 1, &src_addr);
        else
            rc = fi_cq_read(cq_hdl, &cq_event, 1);
        if (rc == -FI_EAGAIN) {
            hg_time_get_current(&t2);
            remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
            if (remaining < 0)
                break; /* Return NA_TIMEOUT */
            continue;
        } else if (rc == -FI_EAVAIL) {
            /* error available */
            memset(&cq_err, 0, sizeof(cq_err));
            rc = fi_cq_readerr(cq_hdl, &cq_err, 0 /* flags */);
            if (rc != 1) {
                NA_LOG_ERROR("fi_cq_readerr() failed, rc: %d(%s).",
                             rc, fi_strerror((int) -rc));
                rc = NA_PROTOCOL_ERROR;
                break;
            }
            if (cq_err.err == FI_ECANCELED) {
                cq_event.op_context = cq_err.op_context;
                cq_event.flags = cq_err.flags;
                cq_event.buf = NULL;
                cq_event.len = 0;
//                NA_LOG_DEBUG("got a FI_ECANCELED event, cq_event.flags 0x%x.",
//                             cq_err.flags);
                continue;
            } else if (cq_err.err == FI_EADDRNOTAVAIL) {
                rc = fi_av_insert(av_hdl, cq_err.err_data, 1, &tmp_addr,
                                  0 /* flags */, NULL /* context */);
                if (rc < 0) {
                    NA_LOG_ERROR("fi_av_insertsvc failed, rc: %d(%s).",
                                 rc, fi_strerror((int) -rc));
                    ret = NA_PROTOCOL_ERROR;
                    break;
                } else if (rc != 1) {
                    NA_LOG_ERROR("fi_av_insert failed, rc: %d.", rc);
                    ret = NA_PROTOCOL_ERROR;
                    break;
                }
                cq_event.op_context = cq_err.op_context;
                cq_event.flags = cq_err.flags;
                cq_event.buf = cq_err.buf;
                cq_event.len = cq_err.len;
                cq_event.tag = cq_err.tag;
                src_addr = tmp_addr;
            } else {
                NA_LOG_ERROR("fi_cq_readerr got err: %d(%s), "
                             "prov_errno: %d(%s).",
                             cq_err.err, fi_strerror(cq_err.err),
                             cq_err.prov_errno,
                             fi_strerror(-cq_err.prov_errno));
                rc = NA_PROTOCOL_ERROR;
                break;
            }
        } else if (rc <= 0) {
            NA_LOG_ERROR("fi_cq_read(/_readfrom() failed, rc: %d(%s).",
                         rc, fi_strerror((int) -rc));
            rc = NA_PROTOCOL_ERROR;
            break;
        }

        /* got one completion event */
        assert(rc == 1);
        ret = NA_SUCCESS;
        /*
        NA_LOG_DEBUG("got completion event flags: 0x%x, rc: %d, src_addr %d.\n",
                     cq_event.flags, rc, src_addr);
        */
        switch (cq_event.flags) {
        case FI_SEND | FI_TAGGED:
        case FI_SEND | FI_MSG:
        case FI_SEND | FI_TAGGED | FI_MSG:
            na_ofi_handle_send_event(na_class, context, &cq_event);
            break;
        case FI_RECV | FI_TAGGED:
        case FI_RECV | FI_MSG:
        case FI_RECV | FI_TAGGED | FI_MSG:
            na_ofi_handle_recv_event(na_class, context, src_addr, &cq_event);
            break;
        case FI_READ | FI_RMA:
        case FI_WRITE | FI_RMA:
            na_ofi_handle_rma_event(na_class, context, &cq_event);
            break;
        };

    } while (remaining > 0 && ret != NA_SUCCESS);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_complete(na_ofi_addr_t *na_ofi_addr, na_ofi_op_id_t *na_ofi_op_id,
    na_return_t op_ret)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret;

    /* Mark op id as completed */
    hg_atomic_incr32(&na_ofi_op_id->noo_completed);

    /* Init callback info */
    callback_info = &na_ofi_op_id->noo_completion_data.callback_info;
    callback_info->arg = na_ofi_op_id->noo_arg;
    callback_info->ret = op_ret;
    callback_info->type = na_ofi_op_id->noo_type;

    switch (na_ofi_op_id->noo_type) {
    case NA_CB_LOOKUP:
        callback_info->info.lookup.addr =
            na_ofi_op_id->noo_info.noo_lookup.noi_addr;
        break;
    case NA_CB_SEND_UNEXPECTED:
    case NA_CB_SEND_EXPECTED:
        break;
    case NA_CB_RECV_UNEXPECTED:
        /* Fill callback info */
        callback_info->info.recv_unexpected.actual_buf_size =
            (na_size_t) na_ofi_op_id->noo_info.noo_recv_unexpected.noi_msg_size;
        callback_info->info.recv_unexpected.source =
            (na_addr_t) na_ofi_op_id->noo_addr;
        callback_info->info.recv_unexpected.tag =
            (na_tag_t) na_ofi_op_id->noo_info.noo_recv_unexpected.noi_tag;
        break;
    case NA_CB_RECV_EXPECTED:
        /* Check buf_size and msg_size */
        if (na_ofi_op_id->noo_info.noo_recv_expected.noi_msg_size >
            na_ofi_op_id->noo_info.noo_recv_expected.noi_buf_size) {
            NA_LOG_ERROR("Expected recv too large for buffer");
            ret = NA_SIZE_ERROR;
            goto out;
        }
        break;
    case NA_CB_PUT:
    case NA_CB_GET:
        break;
    default:
        NA_LOG_ERROR("Operation type 0x%x not supported.",
                     na_ofi_op_id->noo_type);
        ret = NA_INVALID_PARAM;
        break;
    }

    na_ofi_op_id->noo_completion_data.callback = na_ofi_op_id->noo_callback;
    na_ofi_op_id->noo_completion_data.plugin_callback = na_ofi_release;
    na_ofi_op_id->noo_completion_data.plugin_callback_args = na_ofi_op_id;

    ret = na_cb_completion_add(na_ofi_op_id->noo_context,
       &na_ofi_op_id->noo_completion_data);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not add callback to completion queue");
    }

out:
    if (na_ofi_addr)
        na_ofi_addr_decref(na_ofi_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_release(void *arg)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) arg;

    if (na_ofi_op_id && !hg_atomic_get32(&na_ofi_op_id->noo_completed))
        NA_LOG_WARNING("Releasing resources from an uncompleted operation");

    na_ofi_op_id_decref(na_ofi_op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_cancel(na_class_t *na_class, na_context_t NA_UNUSED *context,
    na_op_id_t op_id)
{
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_ep;
    na_ofi_op_id_t *na_ofi_op_id = (na_ofi_op_id_t *) op_id;
    na_ofi_op_id_t *tmp = NULL, *first = NULL;
    na_ofi_addr_t *na_ofi_addr = NULL;
    ssize_t rc;
    na_return_t ret = NA_SUCCESS;

    if (hg_atomic_get32(&na_ofi_op_id->noo_completed))
        goto out;

    hg_atomic_incr32(&na_ofi_op_id->noo_canceled);

    switch (na_ofi_op_id->noo_type) {
    case NA_CB_LOOKUP:
        break;
    case NA_CB_RECV_UNEXPECTED:
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        if (rc != 0)
            NA_LOG_DEBUG("fi_cancel unexpected recv failed, rc: %d(%s).",
                         rc, fi_strerror((int) -rc));

        tmp = first = na_ofi_msg_unexpected_op_pop(na_class);
        do {
            if (!tmp) {
                NA_LOG_ERROR("got NULL head of unexpected op queue.");
                ret = NA_PROTOCOL_ERROR;
                goto out;
            }
            if (tmp == na_ofi_op_id) {
                break;
            }
            na_ofi_msg_unexpected_op_push(na_class, tmp);

            tmp = na_ofi_msg_unexpected_op_pop(na_class);
            if (tmp == first) {
                NA_LOG_ERROR("tmp == first");
                ret = NA_PROTOCOL_ERROR;
                goto out;
            }
        } while (tmp != na_ofi_op_id);

        ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_CANCELED);
        break;
    case NA_CB_RECV_EXPECTED:
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        if (rc != 0)
            NA_LOG_DEBUG("fi_cancel expected recv failed, rc: %d(%s).",
                         rc, fi_strerror((int) -rc));

        na_ofi_addr = (na_ofi_addr_t *)na_ofi_op_id->noo_addr;
        ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_CANCELED);
        break;
    case NA_CB_SEND_UNEXPECTED:
    case NA_CB_SEND_EXPECTED:
    case NA_CB_PUT:
    case NA_CB_GET:
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        if (rc != 0)
            NA_LOG_DEBUG("fi_cancel (op type %d) failed, rc: %d(%s).",
                         na_ofi_op_id->noo_type, rc, fi_strerror((int) -rc));

        na_ofi_addr = (na_ofi_addr_t *)na_ofi_op_id->noo_addr;
        ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_CANCELED);
        break;
    default:
        break;
    }

out:
    return ret;
}
