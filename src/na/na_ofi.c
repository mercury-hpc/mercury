/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
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

#include "na_private.h"
#include "na_error.h"

#include "mercury_list.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_spin.h"
#include "mercury_thread_rwlock.h"
#include "mercury_hash_table.h"
#include "mercury_time.h"
#include "mercury_atomic.h"
#include "mercury_mem.h"

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>
#ifdef NA_OFI_HAS_EXT_GNI_H
#include <rdma/fi_ext_gni.h>
#endif

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

/****************/
/* Local Macros */
/****************/

/**
 * FI VERSION provides binary backward and forward compatibility support.
 * Specify the version of OFI is coded to, the provider will select struct
 * layouts that are compatible with this version.
 */
#define NA_OFI_VERSION FI_VERSION(1, 5)

/* Name of providers */
#define NA_OFI_PROV_SOCKETS_NAME    "sockets"
#define NA_OFI_PROV_PSM2_NAME       "psm2"
#define NA_OFI_PROV_GNI_NAME        "gni"
#define NA_OFI_PROV_VERBS_NAME      "verbs"

#define NA_OFI_MAX_URI_LEN (128)
#define NA_OFI_MAX_NODE_LEN (64)
#define NA_OFI_MAX_PORT_LEN (16)
#define NA_OFI_HDR_MAGIC (0x0f106688)

/* Max tag */
#define NA_OFI_MAX_TAG ((1 << 30) -1)

#define NA_OFI_UNEXPECTED_SIZE 4096
#define NA_OFI_EXPECTED_TAG_FLAG (0x100000000ULL)
#define NA_OFI_UNEXPECTED_TAG_IGNORE (0xFFFFFFFFULL)

/* number of CQ event provided for fi_cq_read() */
#define NA_OFI_CQ_EVENT_NUM (16)
/* CQ depth (the socket provider's default value is 256 */
#define NA_OFI_CQ_DEPTH (8192)

/* The magic number for na_ofi_op_id verification */
#define NA_OFI_OP_ID_MAGIC_1 (0x1928374655627384ULL)
#define NA_OFI_OP_ID_MAGIC_2 (0x8171615141312111ULL)

/* Default basic bits */
#define NA_OFI_MR_BASIC_REQ \
    (FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY)

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
    enum na_ofi_prov_type nod_prov_type;    /* OFI provider type */
    enum na_ofi_mr_mode nod_mr_mode;        /* OFI memory region mode */
    char *nod_prov_name;                    /* OFI provider name */
    struct fi_info *nod_prov;               /* OFI provider info */
    struct fid_fabric *nod_fabric;          /* Fabric domain handle */
    struct fid_domain *nod_domain;          /* Access domain handle */
    /* Memory region handle, only valid for MR_SCALABLE */
    struct fid_mr *nod_mr;
    struct fid_av *nod_av;                  /* Address vector handle */
    /*
     * Address hash-table, to map the source-side address to fi_addr_t.
     * The key is 64bits value serialized from source-side IP+Port (see
     * na_ofi_reqhdr_2_key), the value is fi_addr_t.
     */
    hg_hash_table_t *nod_addr_ht;
    hg_thread_rwlock_t nod_rwlock;          /* RW lock to protect nod_addr_ht */
    hg_atomic_int32_t nod_refcount;         /* Refcount of this domain */
    HG_LIST_ENTRY(na_ofi_domain) nod_entry; /* Entry in nog_domain_list */
};

struct na_ofi_endpoint {
    char *noe_node;             /* Fabric address */
    char *noe_service;          /* Service name */
    void *noe_auth_key;         /* Auth key */
    na_size_t noe_auth_key_size;/* Auth key size */
    struct fi_info *noe_prov;   /* OFI provider info */
    struct fid_ep *noe_ep;      /* Endpoint to communicate on */
    struct fid_cq *noe_cq;      /* Completion queue handle */
    struct fid_wait *noe_wait;  /* Wait set handle */
};

/**
 * Inline header for NA_OFI (16 bytes).
 *
 * It is mainly to piggyback the source-side IP/port address for the unexpected
 * message. For those providers that does not support FI_SOURCE/FI_SOURCE_ERR.
 */
struct na_ofi_reqhdr {
    na_uint32_t fih_feats; /* feature bits */
    na_uint32_t fih_magic; /* magic number for byte-order checking */
    na_uint32_t fih_ip; /* IP addr in integer */
    na_uint32_t fih_port; /* Port number */
};

struct na_ofi_private_data {
    struct na_ofi_domain *nop_domain; /* Point back to access domain */
    struct na_ofi_endpoint *nop_endpoint;
    /* Unexpected op queue */
    HG_QUEUE_HEAD(na_ofi_op_id) nop_unexpected_op_queue;
    hg_thread_spin_t nop_unexpected_op_lock;
    char *nop_uri; /* URI address string */
    struct na_ofi_reqhdr nop_req_hdr; /* request header */
    /* nop_mutex only used for verbs provider as it is not thread safe now */
    hg_thread_mutex_t nop_mutex;
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

struct na_ofi_info_recv_unexpected {
    void *noi_buf;
    na_size_t noi_buf_size;
    na_size_t noi_msg_size;
    na_tag_t noi_tag;
};

struct na_ofi_info_recv_expected {
    void *noi_buf;
    na_size_t noi_buf_size;
    na_size_t noi_msg_size;
    na_tag_t noi_tag;
};

struct na_ofi_op_id {
    /* noo_magic_1 and noo_magic_2 are for data verification */
    na_uint64_t noo_magic_1;
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
        struct na_ofi_info_recv_unexpected noo_recv_unexpected;
        struct na_ofi_info_recv_expected noo_recv_expected;
    } noo_info;
    struct na_cb_completion_data noo_completion_data;
    na_uint64_t noo_magic_2;
};

/*****************/
/* Local Helpers */
/*****************/

#define na_ofi_bswap16(x) ((x) >> 8 | ((x) & 0xFFU) << 8)
#define na_ofi_bswap32(x) ((na_ofi_bswap16((x) >> 16) & 0xFFFFU) |\
                           (na_ofi_bswap16((x) & 0xFFFFU) << 16))
#define na_ofi_bswap32s(x) do { *(x) = na_ofi_bswap32(*(x)); } while (0)

static NA_INLINE void
na_ofi_class_lock(na_class_t *na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct na_ofi_domain *domain = priv->nop_domain;

    if (domain->nod_prov_type == NA_OFI_PROV_VERBS)
        hg_thread_mutex_lock(&priv->nop_mutex);
}

static NA_INLINE void
na_ofi_class_unlock(na_class_t *na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct na_ofi_domain *domain = priv->nop_domain;

    if (domain->nod_prov_type == NA_OFI_PROV_VERBS)
        hg_thread_mutex_unlock(&priv->nop_mutex);
}

static NA_INLINE na_bool_t
na_ofi_with_reqhdr(const na_class_t *na_class)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;

    return domain->nod_prov_type != NA_OFI_PROV_PSM2;
}

/**
 * Converts the inline header to a 64 bits key to search corresponding FI addr.
 */
static NA_INLINE na_uint64_t
na_ofi_reqhdr_2_key(struct na_ofi_reqhdr *hdr)
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
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    na_return_t ret = NA_SUCCESS;
    int rc;

    /* address resolution by fi AV */
    assert(domain != NULL);

    /* Use fi_av_insertsvc if possible */
    na_ofi_class_lock(na_class);
    rc = fi_av_insertsvc(domain->nod_av, node_str, service_str,
                         fi_addr, 0 /* flags */, NULL /* context */);
    na_ofi_class_unlock(na_class);
    if (rc == -FI_ENOSYS) { /* Not supported by PSM2/GNI providers */
        struct fi_info *tmp_info = NULL;

        /* Resolve node / service (always pass a numeric host) */
        rc = fi_getinfo(NA_OFI_VERSION, node_str, service_str, 0,
                        NULL /* hints */, &tmp_info);
        if (rc != 0) {
            NA_LOG_ERROR("fi_getinfo (%s:%s) failed, rc: %d(%s).",
                         node_str, service_str, rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_class_lock(na_class);
        rc = fi_av_insert(domain->nod_av, tmp_info->dest_addr, 1, fi_addr,
                          0 /* flags */, NULL /* context */);
        na_ofi_class_unlock(na_class);

        fi_freeinfo(tmp_info);
    }

    if (rc < 0) {
        NA_LOG_ERROR("fi_av_insert/svc failed(node %s, service %s), rc: %d(%s).",
                     node_str, service_str, rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    if (rc != 1) {
        NA_LOG_ERROR("fi_av_insert/svc failed(node %s, service %s), rc: %d.",
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
na_ofi_addr_ht_lookup(na_class_t *na_class, struct na_ofi_reqhdr *reqhdr,
                      fi_addr_t *src_addr)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    na_uint64_t addr_key, *new_key = NULL;
    fi_addr_t *fi_addr, tmp_addr, *new_value = NULL;
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

    hg_thread_rwlock_wrlock(&domain->nod_rwlock);

    fi_addr = hg_hash_table_lookup(domain->nod_addr_ht, &addr_key);
    if (fi_addr != HG_HASH_TABLE_NULL) {
        *src_addr = *fi_addr;
        hg_thread_rwlock_release_wrlock(&domain->nod_rwlock);
        return ret;
    }

    in.s_addr = reqhdr->fih_ip;
    node = inet_ntoa(in);
    memset(service, 0, 16);
    sprintf(service, "%d", reqhdr->fih_port);

    ret = na_ofi_av_insert(na_class, node, service, &tmp_addr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_av_insert(%s:%s) failed, ret: %d.",
                     node, service, ret);
        goto unlock;
    }
    *src_addr = tmp_addr;

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
        free(new_key);
        free(new_value);
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
    return ret;
}

/********************/
/* Local Prototypes */
/********************/

static int
na_ofi_getinfo(const char *prov_name, struct fi_info **providers);

static na_return_t
na_ofi_check_interface(const char *hostname, char *node, size_t node_len,
    char *domain, size_t domain_len);

static NA_INLINE na_bool_t
na_ofi_verify_provider(const char *prov_name, const char *domain_name,
    const struct fi_info *fi_info);

static na_return_t
na_ofi_domain_open(const char *prov_name, const char *domain_name,
    struct na_ofi_domain **na_ofi_domain_p);

static na_return_t
na_ofi_domain_close(struct na_ofi_domain *na_ofi_domain);

static na_return_t
na_ofi_endpoint_open(const struct na_ofi_domain *na_ofi_domain,
    const char *node, const char *service, const char *auth_key,
    struct na_ofi_endpoint **na_ofi_endpoint_p);

static na_return_t
na_ofi_endpoint_close(struct na_ofi_endpoint *na_ofi_endpoint);

static na_return_t
na_ofi_get_ep_addr(const struct na_ofi_domain *na_ofi_domain,
    const struct na_ofi_endpoint *na_ofi_endpoint, char **uri_p);

static na_return_t
na_ofi_gen_req_hdr(const char *uri, struct na_ofi_reqhdr *na_ofi_reqhdr);

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

/* msg_get_max_unexpected_size */
static na_size_t
na_ofi_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static na_size_t
na_ofi_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_unexpected_header_size */
static na_size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class);

/* msg_get_max_tag */
static na_tag_t
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
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ofi_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_tag_t mask, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ofi_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ofi_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source, na_tag_t tag, na_op_id_t *op_id);

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

/* poll_get_fd */
static int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static na_bool_t
na_ofi_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* progress */
static na_return_t
na_ofi_progress(na_class_t *na_class, na_context_t *context,
    unsigned int timeout);

static na_return_t
na_ofi_complete(struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id,
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
    NULL,                                   /* cleanup */
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
    na_ofi_msg_get_max_unexpected_size,     /* msg_get_max_unexpected_size */
    na_ofi_msg_get_max_expected_size,       /* msg_get_max_expected_size */
    na_ofi_msg_get_unexpected_header_size,  /* msg_get_unexpected_header_size */
    NULL,                                   /* msg_get_expected_header_size */
    na_ofi_msg_get_max_tag,                 /* msg_get_max_tag */
    na_ofi_msg_buf_alloc,                   /* msg_buf_alloc */
    na_ofi_msg_buf_free,                    /* msg_buf_free */
    na_ofi_msg_init_unexpected,             /* msg_init_unexpected */
    na_ofi_msg_send_unexpected,             /* msg_send_unexpected */
    na_ofi_msg_recv_unexpected,             /* msg_recv_unexpected */
    NULL,                                   /* msg_init_expected */
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
    na_ofi_poll_get_fd,                     /* poll_get_fd */
    na_ofi_poll_try_wait,                   /* poll_try_wait */
    na_ofi_progress,                        /* progress */
    na_ofi_cancel                           /* cancel */
};

/* OFI access domain list */
static HG_LIST_HEAD(na_ofi_domain)
na_ofi_domain_list_g = HG_LIST_HEAD_INITIALIZER(na_ofi_domain);

/* Protects domain list */
static hg_thread_mutex_t na_ofi_domain_list_mutex_g =
    HG_THREAD_MUTEX_INITIALIZER;

/*****************/
/* Local Helpers */
/*****************/

static int
na_ofi_getinfo(const char *prov_name, struct fi_info **providers)
{
    struct fi_info *hints = NULL;
    na_return_t ret = NA_SUCCESS;
    int rc;

     /**
      * Hints to query && filter providers.
      */
    hints = fi_allocinfo();
    if (!hints) {
        NA_LOG_ERROR("fi_allocinfo failed.\n");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Protocol name is provider name, filter out providers within libfabric */
    hints->fabric_attr->prov_name = strdup(prov_name);
    if (!hints->fabric_attr->prov_name) {
        NA_LOG_ERROR("Could not duplicate name");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* mode: operational mode, NA_OFI passes in context for communication calls. */
    /* FI_ASYNC_IOV mode indicates  that  the  application  must  provide  the
       buffering needed for the IO vectors. When set, an application must not
       modify an IO vector  of  length  >  1, including  any  related  memory
       descriptor array, until the associated operation has completed. */
    hints->mode          = FI_CONTEXT | FI_ASYNC_IOV;

    /* ep_type: reliable datagram (connection-less). */
    hints->ep_attr->type = FI_EP_RDM;

    /* caps: capabilities required. */
    hints->caps          = FI_TAGGED | FI_RMA | FI_DIRECTED_RECV;

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

    hints->domain_attr->threading       = FI_THREAD_UNSPEC;
    hints->domain_attr->av_type         = FI_AV_MAP;
    hints->domain_attr->resource_mgmt   = FI_RM_ENABLED;

    /* Provider specific configuration (MR mode / caps) */
    if (!strcmp(prov_name, NA_OFI_PROV_SOCKETS_NAME)) {
        /* Limit ourselves to TCP for now */
        hints->ep_attr->protocol    = FI_PROTO_SOCK_TCP;

        /* For versions 1.5 and later, scalable is implied by the lack of any
         * mr_mode bits being set. */
        hints->domain_attr->mr_mode = FI_MR_UNSPEC;

        /* As "sockets" provider does not support manual progress and wait
         * objects, set progress to auto for now. Note that the provider
         * effectively creates a thread for internal progress in that case.
         */
        hints->domain_attr->control_progress = FI_PROGRESS_AUTO;
        hints->domain_attr->data_progress    = FI_PROGRESS_AUTO;
    } else {
        /* FI_MR_BASIC */
        hints->domain_attr->mr_mode = NA_OFI_MR_BASIC_REQ | FI_MR_LOCAL;

        /* Manual progress (no internal progress thread) */
        hints->domain_attr->control_progress = FI_PROGRESS_MANUAL;
        hints->domain_attr->data_progress    = FI_PROGRESS_MANUAL;

        if (!strcmp(prov_name, NA_OFI_PROV_PSM2_NAME)) {
            /* Can retrieve source address from processes not inserted in AV */
            hints->caps |= (FI_SOURCE | FI_SOURCE_ERR);

            /* PSM2 provider requires FI_MR_BASIC bit to be set for now */
            hints->domain_attr->mr_mode |= FI_MR_BASIC;
        }
        else if (!strcmp(prov_name, NA_OFI_PROV_VERBS_NAME)) {
            hints->rx_attr->mode |= FI_CONTEXT;
        }
    }

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
                    providers); /* Out: List of matching providers */
    if (rc != 0) {
        NA_LOG_ERROR("fi_getinfo failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

out:
    if (hints) {
        free(hints->fabric_attr->prov_name);
        hints->fabric_attr->prov_name = NULL;
        fi_freeinfo(hints);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_check_interface(const char *hostname, char *node, size_t node_len,
    char *domain, size_t domain_len)
{
    struct ifaddrs *ifaddrs = NULL, *ifaddr;
    struct addrinfo hints, *hostname_res = NULL;
    char ip_res[INET_ADDRSTRLEN] = {'\0'}; /* This restricts to ipv4 addresses */
    na_return_t ret = NA_SUCCESS;
    na_bool_t found = NA_FALSE;
    int s;

    /* Try to resolve hostname first so that we can later compare the IP */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    s = getaddrinfo(hostname, NULL, &hints, &hostname_res);
    if (s == 0) {
        struct addrinfo *rp;

        for (rp = hostname_res; rp != NULL; rp = rp->ai_next) {
            /* Get IP */
            if (!inet_ntop(rp->ai_addr->sa_family,
                &((struct sockaddr_in *) rp->ai_addr)->sin_addr, ip_res,
                INET_ADDRSTRLEN)) {
                NA_LOG_ERROR("IP could not be resolved");
                ret = NA_PROTOCOL_ERROR;
                goto out;
            }
            break;
        }
    }

    /* Check and compare interfaces */
    if (getifaddrs(&ifaddrs) == -1) {
        NA_LOG_ERROR("getifaddrs() failed");
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }
    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        char ip[INET_ADDRSTRLEN] = {'\0'}; /* This restricts to ipv4 addresses */

        if (ifaddr->ifa_addr == NULL)
            continue;

        if (ifaddr->ifa_addr->sa_family != AF_INET)
            continue;

        /* Get IP */
        if (!inet_ntop(ifaddr->ifa_addr->sa_family,
            &((struct sockaddr_in *) ifaddr->ifa_addr)->sin_addr, ip,
            INET_ADDRSTRLEN)) {
            NA_LOG_ERROR("IP could not be resolved for: %s", ifaddr->ifa_name);
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }

        /* Compare hostnames / device names */
        if (!strcmp(ip, ip_res) || !strcmp(ifaddr->ifa_name, hostname)) {
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
    if (hostname_res)
        freeaddrinfo(hostname_res);
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ofi_verify_provider(const char *prov_name, const char *domain_name,
    const struct fi_info *fi_info)
{
    na_bool_t ret = NA_FALSE;

    /* Does not match provider name */
    if (strcmp(prov_name, fi_info->fabric_attr->prov_name))
        goto out;

    /* Only for sockets providers is the provider name ambiguous and requires
     * checking the domain name as well */
    if (!strcmp(prov_name, NA_OFI_PROV_SOCKETS_NAME)) {
        /* Does not match domain name */
        if (domain_name && strcmp("\0", domain_name)
            && strcmp(domain_name, fi_info->domain_attr->name))
            goto out;
    }

    ret = NA_TRUE;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_domain_open(const char *prov_name, const char *domain_name,
    struct na_ofi_domain **na_ofi_domain_p)
{
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
    HG_LIST_FOREACH(na_ofi_domain, &na_ofi_domain_list_g, nod_entry) {
        if (na_ofi_verify_provider(prov_name, domain_name,
            na_ofi_domain->nod_prov)) {
            hg_atomic_incr32(&na_ofi_domain->nod_refcount);
            domain_found = NA_TRUE;
            break;
        }
    }
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);
    if (domain_found) {
        /*
        NA_LOG_DEBUG("Found existing domain (%s)",
            na_ofi_domain->nod_prov_name);
        */
        *na_ofi_domain_p = na_ofi_domain;
        goto out;
    }

    /* If no pre-existing domain, get OFI providers info */
    ret = na_ofi_getinfo(prov_name, &providers);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_getinfo failed, ret: %d.", ret);
        goto out;
    }

    /* Try to find provider that matches protocol and domain/host name */
    prov = providers;
    while (prov != NULL) {
        if (na_ofi_verify_provider(prov_name, domain_name, prov)) {
            /*
            NA_LOG_DEBUG("mode 0x%llx, fabric_attr - prov_name %s, name - %s, "
                         "domain_attr - name %s, domain_attr->threading: %d.",
                         prov->mode, prov->fabric_attr->prov_name,
                         prov->fabric_attr->name, prov->domain_attr->name,
                         prov->domain_attr->threading);
            */
            prov_found = NA_TRUE;
            break;
        }
        prov = prov->next;
    }
    if (!prov_found) {
        NA_LOG_ERROR("No provider found for \"%s\" provider on domain \"%s\"",
                     prov_name, domain_name);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    na_ofi_domain = (struct na_ofi_domain *) malloc(
        sizeof(struct na_ofi_domain));
    if (na_ofi_domain == NULL) {
        NA_LOG_ERROR("Could not allocate na_ofi_domain");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    memset(na_ofi_domain, 0, sizeof(struct na_ofi_domain));
    hg_atomic_set32(&na_ofi_domain->nod_refcount, 1);

    /* Create rw lock */
    rc = hg_thread_rwlock_init(&na_ofi_domain->nod_rwlock);
    if (rc != HG_UTIL_SUCCESS) {
        NA_LOG_ERROR("hg_thread_rwlock_init failed");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Keep fi_info */
    na_ofi_domain->nod_prov = fi_dupinfo(prov);
    if (!na_ofi_domain->nod_prov) {
        NA_LOG_ERROR("Could not duplicate fi_info");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Dup provider name */
    na_ofi_domain->nod_prov_name = strdup(prov->fabric_attr->prov_name);
    if (!na_ofi_domain->nod_prov_name) {
        NA_LOG_ERROR("Could not duplicate name");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Set domain configuration (MR mode / caps) */
    if (!strcmp(na_ofi_domain->nod_prov_name, NA_OFI_PROV_SOCKETS_NAME)) {
        na_ofi_domain->nod_prov_type = NA_OFI_PROV_SOCKETS;
    } else if (!strcmp(na_ofi_domain->nod_prov_name, NA_OFI_PROV_PSM2_NAME)) {
        na_ofi_domain->nod_prov_type = NA_OFI_PROV_PSM2;
    } else if (!strcmp(na_ofi_domain->nod_prov_name, NA_OFI_PROV_VERBS_NAME)) {
        na_ofi_domain->nod_prov_type = NA_OFI_PROV_VERBS;
    } else if (!strcmp(na_ofi_domain->nod_prov_name, NA_OFI_PROV_GNI_NAME)) {
        na_ofi_domain->nod_prov_type = NA_OFI_PROV_GNI;
    } else {
        NA_LOG_ERROR("bad domain->nod_prov_name %s.",
            na_ofi_domain->nod_prov_name);
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }
    na_ofi_domain->nod_mr_mode =
        (na_ofi_domain->nod_prov_type == NA_OFI_PROV_SOCKETS) ?
            NA_OFI_MR_SCALABLE : NA_OFI_MR_BASIC;

    /* Open fi fabric */
    rc = fi_fabric(na_ofi_domain->nod_prov->fabric_attr,/* In:  Fabric attributes */
                   &na_ofi_domain->nod_fabric,          /* Out: Fabric handle */
                   NULL);                               /* Optional context for fabric events */
    if (rc != 0) {
        NA_LOG_ERROR("fi_fabric failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Create the fi access domain */
    rc = fi_domain(na_ofi_domain->nod_fabric,   /* In:  Fabric object */
                   na_ofi_domain->nod_prov,     /* In:  Provider */
                   &na_ofi_domain->nod_domain,  /* Out: Domain oject */
                   NULL);                       /* Optional context for domain events */
    if (rc != 0) {
        NA_LOG_ERROR("fi_domain failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* For MR_SCALABLE, create MR, now exports all memory range for RMA */
    if (na_ofi_domain->nod_mr_mode == NA_OFI_MR_SCALABLE) {
        rc = fi_mr_reg(na_ofi_domain->nod_domain, (void *)0, UINT64_MAX,
                       FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE,
                       0ULL /* offset */, NA_OFI_RMA_KEY, 0 /* flags */,
                       &na_ofi_domain->nod_mr, NULL /* context */);
        if (rc != 0) {
            NA_LOG_ERROR("fi_mr_reg failed, rc: %d(%s).", rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
    }

    /* Open fi address vector */
    av_attr.type = FI_AV_MAP;
    rc = fi_av_open(na_ofi_domain->nod_domain, &av_attr, &na_ofi_domain->nod_av,
        NULL);
    if (rc != 0) {
        NA_LOG_ERROR("fi_av_open failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Create addr hash-table */
    na_ofi_domain->nod_addr_ht = hg_hash_table_new(av_addr_ht_key_hash,
        av_addr_ht_key_equal);
    if (na_ofi_domain->nod_addr_ht == NULL) {
        NA_LOG_ERROR("hg_hash_table_new failed");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    hg_hash_table_register_free_functions(na_ofi_domain->nod_addr_ht,
                                          av_addr_ht_key_free,
                                          av_addr_ht_value_free);

    /* Insert to global domain list */
    hg_thread_mutex_lock(&na_ofi_domain_list_mutex_g);
    HG_LIST_INSERT_HEAD(&na_ofi_domain_list_g, na_ofi_domain, nod_entry);
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);

    *na_ofi_domain_p = na_ofi_domain;

out:
    if (ret != NA_SUCCESS)
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

    if (!na_ofi_domain) goto out;

    /* Remove from global domain list if not used anymore */
    hg_thread_mutex_lock(&na_ofi_domain_list_mutex_g);
    if (hg_atomic_decr32(&na_ofi_domain->nod_refcount)) {
        /* Cannot free yet */
        hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);
        goto out;
    }
    /* inserted to na_ofi_domain_list_g after nod_addr_ht created */
    if (na_ofi_domain->nod_addr_ht != NULL)
        HG_LIST_REMOVE(na_ofi_domain, nod_entry);
    hg_thread_mutex_unlock(&na_ofi_domain_list_mutex_g);

    /* Close MR */
    if (na_ofi_domain->nod_mr) {
        rc = fi_close(&na_ofi_domain->nod_mr->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close MR failed, rc: %d(%s).",
                rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_domain->nod_mr = NULL;
    }

    /* Close AV */
    if (na_ofi_domain->nod_av) {
        rc = fi_close(&na_ofi_domain->nod_av->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close AV failed, rc: %d(%s).",
                rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_domain->nod_av = NULL;
    }

    /* Close domain */
    if (na_ofi_domain->nod_domain) {
        rc = fi_close(&na_ofi_domain->nod_domain->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close domain failed, rc: %d(%s).",
                rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_domain->nod_domain = NULL;
    }

    /* Close fabric */
    if (na_ofi_domain->nod_fabric) {
        rc = fi_close(&na_ofi_domain->nod_fabric->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close fabric failed, rc: %d(%s).",
                rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_domain->nod_fabric = NULL;
    }

    /* Free OFI info */
    if (na_ofi_domain->nod_prov)
        fi_freeinfo(na_ofi_domain->nod_prov);

    if (na_ofi_domain->nod_addr_ht)
        hg_hash_table_free(na_ofi_domain->nod_addr_ht);

    hg_thread_rwlock_destroy(&na_ofi_domain->nod_rwlock);

    free(na_ofi_domain->nod_prov_name);
    free(na_ofi_domain);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_open(const struct na_ofi_domain *na_ofi_domain,
    const char *node, const char *service, const char NA_UNUSED *auth_key,
    struct na_ofi_endpoint **na_ofi_endpoint_p)
{
    struct na_ofi_endpoint *na_ofi_endpoint;
    struct fi_cq_attr cq_attr = {0};
    struct fi_wait_attr wait_attr = {0};
    na_return_t ret = NA_SUCCESS;
    int rc;

    na_ofi_endpoint = (struct na_ofi_endpoint *) malloc(
        sizeof(struct na_ofi_endpoint));
    if (na_ofi_endpoint == NULL) {
        NA_LOG_ERROR("Could not allocate na_ofi_endpoint");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    memset(na_ofi_endpoint, 0, sizeof(struct na_ofi_endpoint));

    /* Dup node */
    if (node && strcmp("\0", node)
        && !(na_ofi_endpoint->noe_node = strdup(node))) {
        NA_LOG_ERROR("Could not duplicate node name");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    /* Dup service */
    if (service && strcmp("\0", service)
        && !(na_ofi_endpoint->noe_service = strdup(service))) {
        NA_LOG_ERROR("Could not duplicate service name");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

#if defined(NA_OFI_HAS_EXT_GNI_H)
    if (auth_key) {
        if (na_ofi_domain->nod_prov_type == NA_OFI_PROV_GNI) {
            struct fi_gni_auth_key fi_gni_auth_key;

            fi_gni_auth_key.type = GNIX_AKT_RAW;
            fi_gni_auth_key.raw.protection_key = (uint32_t) strtoul(auth_key,
                NULL, 10);

            na_ofi_endpoint->noe_auth_key = malloc(
                sizeof(struct fi_gni_auth_key));
            if (!na_ofi_endpoint->noe_auth_key) {
                NA_LOG_ERROR("Could not allocate na_ofi_endpoint auth key");
                ret = NA_NOMEM_ERROR;
                goto out;
            }
            memcpy(na_ofi_endpoint->noe_auth_key, &fi_gni_auth_key,
                sizeof(struct fi_gni_auth_key));
            na_ofi_endpoint->noe_auth_key_size = sizeof(struct fi_gni_auth_key);
        }
    }
#endif

    /* Resolve node / service (always pass a numeric host) */
    rc = fi_getinfo(NA_OFI_VERSION, na_ofi_endpoint->noe_node,
        na_ofi_endpoint->noe_service, FI_SOURCE | FI_NUMERICHOST,
        na_ofi_domain->nod_prov, &na_ofi_endpoint->noe_prov);
    if (rc != 0) {
        NA_LOG_ERROR("fi_getinfo(%s, %s) failed, rc: %d(%s).", node, service,
            rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    //priv->nop_fi_info->addr_format = FI_SOCKADDR_IN;

    /* Create a transport level communication endpoint */
    rc = fi_endpoint(na_ofi_domain->nod_domain, /* In:  Domain object */
                     na_ofi_endpoint->noe_prov, /* In:  Provider */
                     &na_ofi_endpoint->noe_ep,  /* Out: Endpoint object */
                     NULL);                     /* Optional context */
    if (rc != 0) {
        NA_LOG_ERROR("fi_endpoint failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* verbs provider does not support FI_WAIT_FD/FI_WAIT_SET now */
    if (na_ofi_domain->nod_prov_type == NA_OFI_PROV_VERBS ||
        na_ofi_domain->nod_prov_type == NA_OFI_PROV_GNI ||
        na_ofi_domain->nod_prov_type == NA_OFI_PROV_PSM2)
        goto no_wait_obj;

    /**
     * TODO: for now only sockets provider supports wait on fd.
     * Open wait set for other providers.
     */
    if (na_ofi_domain->nod_prov_type != NA_OFI_PROV_SOCKETS) {
        wait_attr.wait_obj = FI_WAIT_UNSPEC;
        rc = fi_wait_open(na_ofi_domain->nod_fabric, &wait_attr,
            &na_ofi_endpoint->noe_wait);
        if (rc != 0) {
            NA_LOG_ERROR("fi_wait_open failed, rc: %d(%s).", rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
    }

    /* Create fi completion queue for events */
    if (na_ofi_endpoint->noe_wait) {
        cq_attr.wait_obj = FI_WAIT_SET; /* Wait on wait set */
        cq_attr.wait_set = na_ofi_endpoint->noe_wait;
    } else {
        cq_attr.wait_obj = FI_WAIT_FD; /* Wait on fd */
    }
    cq_attr.wait_cond = FI_CQ_COND_NONE;

no_wait_obj:
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    cq_attr.size = NA_OFI_CQ_DEPTH;
    rc = fi_cq_open(na_ofi_domain->nod_domain, &cq_attr,
        &na_ofi_endpoint->noe_cq, NULL);
    if (rc != 0) {
        NA_LOG_ERROR("fi_cq_open failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Bind the CQ and AV to the endpoint */
    rc = fi_ep_bind(na_ofi_endpoint->noe_ep, &na_ofi_endpoint->noe_cq->fid,
        FI_TRANSMIT | FI_RECV);
    if (rc != 0) {
        NA_LOG_ERROR("fi_ep_bind failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    rc = fi_ep_bind(na_ofi_endpoint->noe_ep, &na_ofi_domain->nod_av->fid, 0);
    if (rc != 0) {
        NA_LOG_ERROR("fi_ep_bind failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Enable the endpoint for communication, and commits the bind operations */
    ret = fi_enable(na_ofi_endpoint->noe_ep);
    if (rc != 0) {
        NA_LOG_ERROR("fi_enable failed, rc: %d(%s).", rc, fi_strerror(-rc));
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    *na_ofi_endpoint_p = na_ofi_endpoint;

out:
    if (ret != NA_SUCCESS)
        na_ofi_endpoint_close(na_ofi_endpoint);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_endpoint_close(struct na_ofi_endpoint *na_ofi_endpoint)
{
    na_return_t ret = NA_SUCCESS;
    int rc;

    if (!na_ofi_endpoint) goto out;

    /* Close endpoint */
    if (na_ofi_endpoint->noe_ep) {
        rc = fi_close(&na_ofi_endpoint->noe_ep->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close endpoint failed, rc: %d(%s).",
                rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_endpoint->noe_ep = NULL;
    }

    /* Close wait set */
    if (na_ofi_endpoint->noe_wait) {
        rc = fi_close(&na_ofi_endpoint->noe_wait->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close wait failed, rc: %d(%s).", rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_endpoint->noe_wait = NULL;
    }

    /* Close completion queue */
    if (na_ofi_endpoint->noe_cq) {
        rc = fi_close(&na_ofi_endpoint->noe_cq->fid);
        if (rc != 0) {
            NA_LOG_ERROR("fi_close CQ failed, rc: %d(%s).", rc, fi_strerror(-rc));
            ret = NA_PROTOCOL_ERROR;
            goto out;
        }
        na_ofi_endpoint->noe_cq = NULL;
    }

    /* Free OFI info */
    if (na_ofi_endpoint->noe_prov)
        fi_freeinfo(na_ofi_endpoint->noe_prov);

    free(na_ofi_endpoint->noe_auth_key);
    free(na_ofi_endpoint->noe_node);
    free(na_ofi_endpoint->noe_service);
    free(na_ofi_endpoint);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_get_ep_addr(const struct na_ofi_domain *na_ofi_domain,
    const struct na_ofi_endpoint *na_ofi_endpoint, char **uri_p)
{
    void *ep_addr = NULL;
    char ep_addr_str[NA_OFI_MAX_URI_LEN] = {'\0'};
    size_t addrlen = na_ofi_domain->nod_prov->src_addrlen;
    na_bool_t retried = NA_FALSE;
    na_return_t ret = NA_SUCCESS;
    char *uri;
    int rc;

retry_getname:
    ep_addr = malloc(addrlen);
    if (ep_addr == NULL) {
        NA_LOG_ERROR("Could not allocate ep_addr.");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    rc = fi_getname(&na_ofi_endpoint->noe_ep->fid, ep_addr, &addrlen);
    if (rc != 0) {
        if (rc == -FI_ETOOSMALL && retried == NA_FALSE) {
            retried = NA_TRUE;
            free(ep_addr);
            goto retry_getname;
        }
        NA_LOG_ERROR("fi_getname failed, rc: %d(%s), addrlen: %zu.",
                     rc, fi_strerror(-rc), addrlen);
        goto out;
    }

    addrlen = NA_OFI_MAX_URI_LEN;
    rc = snprintf(ep_addr_str, addrlen, "%s://",
        na_ofi_domain->nod_prov->fabric_attr->prov_name);
    if (rc < 0) {
        NA_LOG_ERROR("snprintf failed, rc: %d.", rc);
        goto out;
    }
    addrlen -= (size_t) rc;

    if (na_ofi_domain->nod_prov_type == NA_OFI_PROV_PSM2 ||
        na_ofi_domain->nod_prov_type == NA_OFI_PROV_GNI) {
        snprintf(ep_addr_str + rc, addrlen, "%s:%s", na_ofi_endpoint->noe_node,
            na_ofi_endpoint->noe_service);
    } else {
        fi_av_straddr(na_ofi_domain->nod_av, ep_addr, ep_addr_str + rc,
            &addrlen);
        /* verbs provider returns "verbs://inet://192.168.1.64:22222" style */
        if (na_ofi_domain->nod_prov_type == NA_OFI_PROV_VERBS &&
            !strncmp(ep_addr_str, "verbs://inet", 12)) {
            char *tmp_dst, *tmp_src;

            tmp_dst = ep_addr_str + 8;
            tmp_src = ep_addr_str + 15;
            while (*tmp_src != 0) {
                *tmp_dst = *tmp_src;
                tmp_dst++;
                tmp_src++;
            }
            *tmp_dst = 0;
        }
    }

    uri = strdup(ep_addr_str);
    if (uri == NULL) {
        NA_LOG_ERROR("Could not strdup nop_uri.");
        ret = NA_NOMEM_ERROR;
        goto out;
    }

    *uri_p = uri;

out:
    free(ep_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
/**
 * Generate the request header for NA class. Can be called after nop_uri being
 * initialized (for example "sockets://192.168.42.170:7779").
 */
static na_return_t
na_ofi_gen_req_hdr(const char *uri, struct na_ofi_reqhdr *na_ofi_reqhdr)
{
    char *dup_uri = NULL, *locator, *ip_str;
    na_uint32_t port;
    struct in_addr in;
    int rc;
    na_return_t ret = NA_SUCCESS;

    dup_uri = strdup(uri);
    if (dup_uri == NULL) {
        NA_LOG_ERROR("strdup uri failed.");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    locator = strrchr(dup_uri, ':');
    if (locator == NULL) {
        ret = NA_INVALID_PARAM;
        goto out;
    }
    *locator++ = '\0';
    port = (na_uint32_t) strtoul(locator, NULL, 10);
    locator = strrchr(dup_uri, '/');
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
    na_ofi_reqhdr->fih_feats = 0;
    na_ofi_reqhdr->fih_magic = NA_OFI_HDR_MAGIC;
    na_ofi_reqhdr->fih_ip = in.s_addr;
    na_ofi_reqhdr->fih_port = port;

out:
    free(dup_uri);
    return ret;
}

/********************/
/* Plugin callbacks */
/********************/

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_check_protocol(const char *protocol_name)
{
    struct fi_info *providers = NULL, *prov;
    const char *prov_name;
    na_bool_t accept = NA_FALSE;
    na_return_t ret = NA_SUCCESS;

    /* In case of sockets, protocol used is TCP but allow for passing provider
     * name directly, will use TCP by default */
    if (!strcmp(protocol_name, "tcp"))
        prov_name = NA_OFI_PROV_SOCKETS_NAME;
    else
        prov_name = protocol_name;

    /* Get info from provider */
    ret = na_ofi_getinfo(prov_name, &providers);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_getinfo failed, ret: %d.", ret);
        goto out;
    }

    prov = providers;
    while (prov != NULL) {
        /*
        NA_LOG_DEBUG("fabric_attr - prov_name %s, name - %s, "
                     "domain_attr - name %s, mode: 0x%llx, domain_attr->mode 0x%llx, caps: 0x%llx.", prov->fabric_attr->prov_name,
                     prov->fabric_attr->name, prov->domain_attr->name, prov->mode, prov->domain_attr->mode, prov->caps);
        */
        if (!strcmp(prov_name, prov->fabric_attr->prov_name)) {
            accept = NA_TRUE;
            break;
        }
        prov = prov->next;
    }

out:
    if (providers)
        fi_freeinfo(providers);
    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_initialize(na_class_t *na_class, const struct na_info *na_info,
    na_bool_t NA_UNUSED listen)
{
    char node[NA_OFI_MAX_URI_LEN] = {'\0'};
    char domain_name[NA_OFI_MAX_URI_LEN] = {'\0'};
    const char *prov_name;
    char *service = NULL;
    char *auth_key = NULL;
    na_return_t ret = NA_SUCCESS;

    /*
    NA_LOG_DEBUG("Entering na_ofi_initialize class_name %s, protocol_name %s, "
                 "host_name %s.\n", na_info->class_name, na_info->protocol_name,
                 na_info->host_name);
    */

    /* In case of sockets, protocol used is TCP but allow for passing provider
     * name directly, will use TCP by default */
    if (!strcmp(na_info->protocol_name, "tcp"))
        prov_name = NA_OFI_PROV_SOCKETS_NAME;
    else
        prov_name = na_info->protocol_name;

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

    /* Create private data */
    na_class->private_data = (struct na_ofi_private_data *) malloc(
        sizeof(struct na_ofi_private_data));
    if (!na_class->private_data) {
        NA_LOG_ERROR("Could not allocate NA private data class");
        ret = NA_NOMEM_ERROR;
        goto out;
    }
    memset(na_class->private_data, 0, sizeof(struct na_ofi_private_data));

    /* Initialize queue / mutex */
    HG_QUEUE_INIT(&NA_OFI_PRIVATE_DATA(na_class)->nop_unexpected_op_queue);
    hg_thread_spin_init(&NA_OFI_PRIVATE_DATA(na_class)->nop_unexpected_op_lock);
    hg_thread_mutex_init(&NA_OFI_PRIVATE_DATA(na_class)->nop_mutex);

    /* Create domain */
    ret = na_ofi_domain_open(prov_name, domain_name,
        &NA_OFI_PRIVATE_DATA(na_class)->nop_domain);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not open domain for %s, %s", prov_name,
            domain_name);
        goto out;
    }

    /* Create endpoint */
    ret = na_ofi_endpoint_open(NA_OFI_PRIVATE_DATA(na_class)->nop_domain,
        node, service, auth_key, &NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not create endpoint for %s, %s", node, service);
        goto out;
    }

    /* Get address from endpoint */
    ret = na_ofi_get_ep_addr(NA_OFI_PRIVATE_DATA(na_class)->nop_domain,
        NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint,
        &NA_OFI_PRIVATE_DATA(na_class)->nop_uri);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not get address from endpoint");
        goto out;
    }

    /* Generate request header from endpoint address */
    ret = na_ofi_gen_req_hdr(NA_OFI_PRIVATE_DATA(na_class)->nop_uri,
        &NA_OFI_PRIVATE_DATA(na_class)->nop_req_hdr);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("na_ofi_gen_req_hdr failed, ret: %d.", ret);
        goto out;
    }

    /*
    NA_LOG_DEBUG("created endpoint addr %s.\n",
        NA_OFI_PRIVATE_DATA(na_class)->nop_uri);
    */

out:
    if (ret != NA_SUCCESS && na_class->private_data) {
        na_ofi_finalize(na_class);
        na_class->private_data = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_finalize(na_class_t *na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    /* Check that unexpected op queue is empty */
    if (!HG_QUEUE_IS_EMPTY(&priv->nop_unexpected_op_queue)) {
        NA_LOG_ERROR("Unexpected op queue should be empty");
        ret = NA_PROTOCOL_ERROR;
        goto out;
    }

    /* Close endpoint */
    ret = na_ofi_endpoint_close(priv->nop_endpoint);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close endpoint");
        goto out;
    }

    /* Close domain */
    ret = na_ofi_domain_close(priv->nop_domain);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not close domain");
        goto out;
    }

    /* Close mutex / free private data */
    hg_thread_spin_destroy(&priv->nop_unexpected_op_lock);
    hg_thread_mutex_destroy(&priv->nop_mutex);
    free(priv->nop_uri);
    free(priv);
    na_class->private_data = NULL;

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_id_addref(struct na_ofi_op_id *na_ofi_op_id)
{
    /* init as 1 when op_create */
    assert(hg_atomic_get32(&na_ofi_op_id->noo_refcount));
    hg_atomic_incr32(&na_ofi_op_id->noo_refcount);

    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_op_id_decref(struct na_ofi_op_id *na_ofi_op_id)
{
    if (na_ofi_op_id == NULL)
        return;

    assert(hg_atomic_get32(&na_ofi_op_id->noo_refcount) > 0);

    /* If there are more references, return */
    if (hg_atomic_decr32(&na_ofi_op_id->noo_refcount))
        return;

    /* No more references, cleanup */
    na_ofi_op_id->noo_magic_1 = 0;
    na_ofi_op_id->noo_magic_2 = 0;
    free(na_ofi_op_id);

    return;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_op_id_valid(struct na_ofi_op_id *na_ofi_op_id)
{
    if (na_ofi_op_id == NULL)
        return NA_FALSE;

    if (na_ofi_op_id->noo_magic_1 != NA_OFI_OP_ID_MAGIC_1 ||
        na_ofi_op_id->noo_magic_2 != NA_OFI_OP_ID_MAGIC_2) {
        NA_LOG_ERROR("invalid magic number for na_ofi_op_id.");
        return NA_FALSE;
    }

    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t
na_ofi_op_create(na_class_t NA_UNUSED *na_class)
{
    struct na_ofi_op_id *na_ofi_op_id = NULL;

    na_ofi_op_id = (struct na_ofi_op_id *)calloc(1, sizeof(struct na_ofi_op_id));
    if (!na_ofi_op_id) {
        NA_LOG_ERROR("Could not allocate NA OFI operation ID");
        goto done;
    }
    hg_atomic_set32(&na_ofi_op_id->noo_refcount, 1);
    /* Completed by default */
    hg_atomic_set32(&na_ofi_op_id->noo_completed, 1);

    na_ofi_op_id->noo_magic_1 = NA_OFI_OP_ID_MAGIC_1;
    na_ofi_op_id->noo_magic_2 = NA_OFI_OP_ID_MAGIC_2;

done:
    return (na_op_id_t) na_ofi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t op_id)
{
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;

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
na_ofi_addr_addref(struct na_ofi_addr *na_ofi_addr)
{
    assert(hg_atomic_get32(&na_ofi_addr->noa_refcount));
    hg_atomic_incr32(&na_ofi_addr->noa_refcount);
    return;
}

/*---------------------------------------------------------------------------*/
static void
na_ofi_addr_decref(struct na_ofi_addr *na_ofi_addr)
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
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    struct na_ofi_addr *na_ofi_addr = NULL;
    char node_str[NA_OFI_MAX_NODE_LEN] = {'\0'};
    char service_str[NA_OFI_MAX_PORT_LEN] = {'\0'};
    na_return_t ret = NA_SUCCESS;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *)na_ofi_op_create(na_class);
        if (!na_ofi_op_id) {
            NA_LOG_ERROR("Could not create NA OFI operation ID");
            ret = NA_NOMEM_ERROR;
            goto out;
        }
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
    /*
     * TODO: later if concurrent calling of fi_av_insert does not cause probelm
     * then can remove this lock. Now libfabric internal memory corruption found
     */
    hg_thread_rwlock_wrlock(&domain->nod_rwlock);
    ret = na_ofi_av_insert(na_class, node_str, service_str,
                           &na_ofi_addr->noa_addr);
    hg_thread_rwlock_release_wrlock(&domain->nod_rwlock);
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
    struct na_ofi_addr *na_ofi_addr = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate addr */
    na_ofi_addr = (struct na_ofi_addr *)calloc(1, sizeof(*na_ofi_addr));
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
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *)addr;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_addr_free() */
    *new_addr = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *)addr;
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
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;

    return na_ofi_addr->noa_self;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_addr_to_string(na_class_t NA_UNUSED *na_class, char *buf,
    na_size_t *buf_size, na_addr_t addr)
{
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) addr;
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
na_ofi_msg_get_max_unexpected_size(const na_class_t NA_UNUSED *na_class)
{
    na_size_t max_unexpected_size = NA_OFI_UNEXPECTED_SIZE;
#ifdef NA_OFI_HAS_EXT_GNI_H
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;

    if (domain->nod_prov_type == NA_OFI_PROV_GNI) {
        struct fi_gni_ops_domain *gni_domain_ops;
        int rc;

        rc = fi_open_ops(&domain->nod_domain->fid, FI_GNI_DOMAIN_OPS_1,
            0, (void **) &gni_domain_ops, NULL);
        if (rc != 0) {
            NA_LOG_ERROR("fi_open_ops failed, rc: %d(%s).", rc, fi_strerror(-rc));
            goto out;
        }

        rc = gni_domain_ops->get_val(&domain->nod_domain->fid,
            GNI_MBOX_MSG_MAX_SIZE, &max_unexpected_size);
        if (rc != 0) {
            NA_LOG_ERROR("get_val failed, rc: %d(%s).", rc, fi_strerror(-rc));
            goto out;
        }
    }

out:
#endif
    return max_unexpected_size;
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_msg_get_max_expected_size(const na_class_t NA_UNUSED *na_class)
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
    return na_ofi_msg_get_max_unexpected_size(na_class);
}

/*---------------------------------------------------------------------------*/
static na_size_t
na_ofi_msg_get_unexpected_header_size(const na_class_t *na_class)
{
    if (na_ofi_with_reqhdr(na_class) == NA_TRUE)
        return sizeof(struct na_ofi_reqhdr);
    else
        return 0;
}

/*---------------------------------------------------------------------------*/
static na_tag_t
na_ofi_msg_get_max_tag(const na_class_t NA_UNUSED *na_class)
{
    return NA_OFI_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static void *
na_ofi_msg_buf_alloc(na_class_t *na_class, na_size_t size, void **plugin_data)
{
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct na_ofi_endpoint *endpoint =
        NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint;
    na_size_t page_size = (na_size_t) hg_mem_get_page_size();
    void *mem_ptr = NULL;
    struct fid_mr *mr_hdl = NULL;
    struct iovec mr_iov = {0};
    struct fi_mr_attr attr = {
        .mr_iov = &mr_iov,
        .iov_count = 1,
        .access = (FI_REMOTE_READ | FI_REMOTE_WRITE | FI_SEND |
            FI_RECV | FI_READ | FI_WRITE),
        .offset = 0,
        .requested_key = 0,
        .context = NULL,
        .auth_key = NULL,
        .auth_key_size = 0
       };
    int rc;

    mem_ptr = hg_mem_aligned_alloc(page_size, size);
    if (!mem_ptr) {
        NA_LOG_ERROR("Could not allocate %d bytes", (int) size);
        goto out;
    }
    memset(mem_ptr, 0, size);

    /* Set IOV */
    mr_iov.iov_base = mem_ptr;
    mr_iov.iov_len = (size_t) size;
    /* GNI provider does not support user requested key */
    if (domain->nod_prov_type != NA_OFI_PROV_GNI)
        attr.requested_key = (uint64_t) mem_ptr;

    /* If auth key, register memory with new authorization key */
    if (endpoint->noe_auth_key) {
        attr.auth_key = (uint8_t *) endpoint->noe_auth_key;
        attr.auth_key_size = endpoint->noe_auth_key_size;
    }

    rc = fi_mr_regattr(domain->nod_domain, &attr, 0, &mr_hdl);
    if (rc != 0) {
        NA_LOG_ERROR("fi_mr_reg failed, rc: %d (%s).", rc, fi_strerror(-rc));
        hg_mem_aligned_free(mem_ptr);
        goto out;
    }

    *plugin_data = mr_hdl;

out:
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_buf_free(na_class_t NA_UNUSED *na_class, void *buf,
    void *plugin_data)
{
    struct fid_mr *mr_hdl = plugin_data;
    int rc;

    rc = fi_close(&mr_hdl->fid);
    if (rc != 0) {
        NA_LOG_ERROR("fi_close mr_hdl failed, rc: %d(%s).",
            rc, fi_strerror(-rc));
        return NA_PROTOCOL_ERROR;
    }

    hg_mem_aligned_free(buf);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_unexpected_op_push(na_class_t *na_class,
    struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_op_id) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto out;
    }

    hg_thread_spin_lock(&priv->nop_unexpected_op_lock);
    HG_QUEUE_PUSH_TAIL(&priv->nop_unexpected_op_queue, na_ofi_op_id, noo_entry);
    hg_thread_spin_unlock(&priv->nop_unexpected_op_lock);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_unexpected_op_remove(na_class_t *na_class,
    struct na_ofi_op_id *na_ofi_op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_op_id) {
        NA_LOG_ERROR("NULL operation ID");
        ret = NA_INVALID_PARAM;
        goto out;
    }

    hg_thread_spin_lock(&priv->nop_unexpected_op_lock);
    HG_QUEUE_REMOVE(&priv->nop_unexpected_op_queue, na_ofi_op_id, na_ofi_op_id,
                    noo_entry);
    hg_thread_spin_unlock(&priv->nop_unexpected_op_lock);

out:
    return ret;
}

/*---------------------------------------------------------------------------*/
static struct na_ofi_op_id *
na_ofi_msg_unexpected_op_pop(na_class_t * na_class)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct na_ofi_op_id *na_ofi_op_id;

    hg_thread_spin_lock(&priv->nop_unexpected_op_lock);
    na_ofi_op_id = HG_QUEUE_FIRST(&priv->nop_unexpected_op_queue);
    HG_QUEUE_POP_HEAD(&priv->nop_unexpected_op_queue, noo_entry);
    hg_thread_spin_unlock(&priv->nop_unexpected_op_lock);

    return na_ofi_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_init_unexpected(na_class_t *na_class, void *buf, na_size_t buf_size)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    na_return_t ret = NA_SUCCESS;

    assert(buf_size > sizeof(priv->nop_req_hdr));

    /*
     * For those providers that don't support FI_SOURCE/FI_SOURCE_ERR, insert
     * the request header to piggyback the source address of request for
     * unexpected message.
     */
    if (na_ofi_with_reqhdr(na_class) == NA_TRUE)
        memcpy(buf, &priv->nop_req_hdr, sizeof(priv->nop_req_hdr));

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_ep *ep_hdl = priv->nop_endpoint->noe_ep;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *)dest;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    struct fid_mr *mr_hdl = plugin_data;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *)na_ofi_op_create(na_class);
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

    /* Post the FI unexpected send request */
    do {
        na_ofi_class_lock(na_class);
        rc = fi_tsend(ep_hdl, buf, buf_size, mr_hdl, na_ofi_addr->noa_addr, tag,
                      &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    void *plugin_data, na_tag_t NA_UNUSED mask, na_op_id_t *op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_ep *ep_hdl = priv->nop_endpoint->noe_ep;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    struct fid_mr *mr_hdl = plugin_data;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *)na_ofi_op_create(na_class);
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
        na_ofi_class_lock(na_class);
        rc = fi_trecv(ep_hdl, buf, buf_size, mr_hdl, FI_ADDR_UNSPEC,
                      1 /* tag */, NA_OFI_UNEXPECTED_TAG_IGNORE,
                      &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    void *plugin_data, na_addr_t dest, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_ep *ep_hdl = priv->nop_endpoint->noe_ep;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *)dest;
    struct fid_mr *mr_hdl = plugin_data;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *)na_ofi_op_create(na_class);
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
        na_ofi_class_lock(na_class);
        rc = fi_tsend(ep_hdl, buf, buf_size, mr_hdl, na_ofi_addr->noa_addr,
                      NA_OFI_EXPECTED_TAG_FLAG | tag,
                      &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    void *plugin_data, na_addr_t source, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_ep *ep_hdl = priv->nop_endpoint->noe_ep;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *)source;
    struct fid_mr *mr_hdl = plugin_data;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* decref in na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *)na_ofi_op_create(na_class);
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
        na_ofi_class_lock(na_class);
        rc = fi_trecv(ep_hdl, buf, buf_size, mr_hdl, na_ofi_addr->noa_addr,
                      NA_OFI_EXPECTED_TAG_FLAG | tag, 0 /* ignore */,
                      &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    struct na_ofi_mem_handle *na_ofi_mem_handle = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Allocate memory handle */
    na_ofi_mem_handle = (struct na_ofi_mem_handle *) calloc(1,
        sizeof(struct na_ofi_mem_handle));
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
    struct na_ofi_mem_handle *ofi_mem_handle = (struct na_ofi_mem_handle *) mem_handle;

    free(ofi_mem_handle);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle)
{
    struct na_ofi_mem_handle *na_ofi_mem_handle = mem_handle;
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct na_ofi_endpoint *endpoint =
        NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint;
    na_uint64_t access;
    struct iovec mr_iov = {0};
    struct fi_mr_attr attr = {
        .mr_iov = &mr_iov,
        .iov_count = 1,
        .access = 0,
        .offset = 0,
        .requested_key = 0,
        .context = NULL,
        .auth_key = NULL,
        .auth_key_size = 0
       };
    int rc = 0;
    na_return_t ret = NA_SUCCESS;

    /* nothing to do for scalable memory registration mode */
    if (domain->nod_mr_mode == NA_OFI_MR_SCALABLE)
        return NA_SUCCESS;

    /* Set access mode */
    switch (na_ofi_mem_handle->nom_attr) {
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
            NA_LOG_ERROR("Invalid memory access flag");
            ret = NA_INVALID_PARAM;
            goto out;
    }
    attr.access = access;

    /* Set IOV */
    mr_iov.iov_base = (void *)na_ofi_mem_handle->nom_base;
    mr_iov.iov_len = (size_t) na_ofi_mem_handle->nom_size;

    /* If auth key, register memory with new authorization key */
    if (endpoint->noe_auth_key) {
        attr.auth_key = (uint8_t *) endpoint->noe_auth_key;
        attr.auth_key_size = endpoint->noe_auth_key_size;
    }

    rc = fi_mr_regattr(domain->nod_domain, &attr, 0,
        &na_ofi_mem_handle->nom_mr_hdl);
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
    struct na_ofi_mem_handle *na_ofi_mem_handle = mem_handle;
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
        NA_LOG_ERROR("fi_close mr_hdr failed, rc: %d(%s).",
                     rc, fi_strerror(-rc));
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
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint->noe_ep;
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct na_ofi_mem_handle *ofi_local_mem_handle =
        (struct na_ofi_mem_handle *) local_mem_handle;
    struct na_ofi_mem_handle *ofi_remote_mem_handle =
        (struct na_ofi_mem_handle *) remote_mem_handle;
    struct iovec iov;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) remote_addr;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    void *local_desc;
    na_uint64_t rma_key;
    na_return_t ret = NA_SUCCESS;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* for na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *) na_ofi_op_create(na_class);
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
    local_desc = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NULL :
              fi_mr_desc(ofi_local_mem_handle->nom_mr_hdl);
    rma_key = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NA_OFI_RMA_KEY :
              ofi_remote_mem_handle->nom_mr_key;
    do {
        na_ofi_class_lock(na_class);
        rc = fi_writev(ep_hdl, &iov, &local_desc, 1 /* count */,
                       na_ofi_addr->noa_addr,
                       (na_uint64_t)ofi_remote_mem_handle->nom_base +
                       remote_offset, rma_key, &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint->noe_ep;
    struct na_ofi_mem_handle *ofi_local_mem_handle =
        (struct na_ofi_mem_handle *) local_mem_handle;
    struct na_ofi_mem_handle *ofi_remote_mem_handle =
        (struct na_ofi_mem_handle *) remote_mem_handle;
    struct iovec iov;
    struct na_ofi_addr *na_ofi_addr = (struct na_ofi_addr *) remote_addr;
    struct na_ofi_op_id *na_ofi_op_id = NULL;
    na_return_t ret = NA_SUCCESS;
    void *local_desc;
    na_uint64_t rma_key;
    ssize_t rc;

    na_ofi_addr_addref(na_ofi_addr); /* for na_ofi_complete() */

    /* Allocate op_id if not provided */
    if (op_id && op_id != NA_OP_ID_IGNORE && *op_id != NA_OP_ID_NULL) {
        na_ofi_op_id = (struct na_ofi_op_id *) *op_id;
        na_ofi_op_id_addref(na_ofi_op_id);
    } else {
        na_ofi_op_id = (struct na_ofi_op_id *) na_ofi_op_create(na_class);
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
    local_desc = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NULL :
              fi_mr_desc(ofi_local_mem_handle->nom_mr_hdl);
    rma_key = (domain->nod_mr_mode == NA_OFI_MR_SCALABLE) ? NA_OFI_RMA_KEY :
              ofi_remote_mem_handle->nom_mr_key;

    do {
        na_ofi_class_lock(na_class);
        rc = fi_readv(ep_hdl, &iov, &local_desc, 1 /* count */,
                      na_ofi_addr->noa_addr,
                      (na_uint64_t)ofi_remote_mem_handle->nom_base + remote_offset,
                      rma_key, &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
    struct na_ofi_op_id *na_ofi_op_id;
    struct na_ofi_addr *na_ofi_addr;
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    if (!na_ofi_op_id_valid(na_ofi_op_id)) {
        NA_LOG_ERROR("bad na_ofi_op_id, ignore the send event.");
        return;
    }
    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;
    if (hg_atomic_get32(&na_ofi_op_id->noo_completed)) {
        NA_LOG_ERROR("ignore the send_event as the op is completed.");
        return;
    }
    if (na_ofi_op_id->noo_type != NA_CB_SEND_EXPECTED &&
        na_ofi_op_id->noo_type != NA_CB_SEND_UNEXPECTED) {
        NA_LOG_ERROR("ignore the send_event as na_ofi_op_id->noo_type %d "
                     "mismatch with NA_CB_SEND_EXPECTED/_UNEXPECTED.",
                     na_ofi_op_id->noo_type);
        return;
    }

    na_ofi_addr = (struct na_ofi_addr *)na_ofi_op_id->noo_addr;

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
    struct na_ofi_domain *domain = NA_OFI_PRIVATE_DATA(na_class)->nop_domain;
    struct na_ofi_addr *peer_addr = NULL;
    struct na_ofi_reqhdr *reqhdr;
    struct na_ofi_op_id *na_ofi_op_id;
    char peer_uri[NA_OFI_MAX_URI_LEN] = {'\0'};
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    if (!na_ofi_op_id_valid(na_ofi_op_id)) {
        NA_LOG_ERROR("bad na_ofi_op_id, ignore the recv event.");
        return;
    }
    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;
    if (hg_atomic_get32(&na_ofi_op_id->noo_completed)) {
        NA_LOG_ERROR("ignore the recv_event as the op is completed.");
        return;
    }

    if (cq_event->tag & ~NA_OFI_UNEXPECTED_TAG_IGNORE) {
        if (na_ofi_op_id->noo_type != NA_CB_RECV_EXPECTED) {
            NA_LOG_ERROR("ignore the recv_event as na_ofi_op_id->noo_type %d "
                         "mismatch with NA_CB_RECV_EXPECTED.",
                         na_ofi_op_id->noo_type);
            return;
        }
        if (na_ofi_op_id->noo_info.noo_recv_expected.noi_tag !=
               (cq_event->tag & ~NA_OFI_EXPECTED_TAG_FLAG)) {
            NA_LOG_ERROR("ignore the recv_event as noi_tag 0x%x mismatch with "
                         "cq_event->tag: 0x%x.",
                         na_ofi_op_id->noo_info.noo_recv_expected.noi_tag,
                         cq_event->tag & ~NA_OFI_EXPECTED_TAG_FLAG);
            return;
        }
        peer_addr = na_ofi_op_id->noo_addr;
        assert(peer_addr != NULL);
        na_ofi_op_id->noo_info.noo_recv_expected.noi_msg_size = cq_event->len;
    } else {
        if (na_ofi_op_id->noo_type != NA_CB_RECV_UNEXPECTED) {
            NA_LOG_ERROR("ignore the recv_event as na_ofi_op_id->noo_type %d "
                         "mismatch with NA_CB_RECV_UNEXPECTED.",
                         na_ofi_op_id->noo_type);
            return;
        }

        peer_addr = na_ofi_addr_alloc(NULL);
        if (peer_addr == NULL) {
            NA_LOG_ERROR("na_ofi_addr_alloc failed");
            return;
        }

        if (na_ofi_with_reqhdr(na_class) == NA_TRUE) {
            struct in_addr in;

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

            in.s_addr = reqhdr->fih_ip;
            snprintf(peer_uri, NA_OFI_MAX_URI_LEN, "%s://%s:%d",
                     domain->nod_prov->fabric_attr->prov_name,
                     inet_ntoa(in), reqhdr->fih_port);
            peer_addr->noa_uri = strdup(peer_uri);
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
    struct na_ofi_op_id *na_ofi_op_id;
    struct na_ofi_addr *na_ofi_addr;
    na_return_t ret = NA_SUCCESS;

    na_ofi_op_id = container_of(cq_event->op_context, struct na_ofi_op_id,
                                noo_fi_ctx);
    if (!na_ofi_op_id_valid(na_ofi_op_id)) {
        NA_LOG_ERROR("bad na_ofi_op_id, ignore the RMA event.");
        return;
    }
    if (na_ofi_op_id->noo_type != NA_CB_PUT &&
        na_ofi_op_id->noo_type != NA_CB_GET) {
        NA_LOG_ERROR("ignore the send_event as na_ofi_op_id->noo_type %d "
                     "mismatch with NA_CB_PUT/_GET.",
                     na_ofi_op_id->noo_type);
        return;
    }
    if (hg_atomic_get32(&na_ofi_op_id->noo_canceled))
        return;
    if (hg_atomic_get32(&na_ofi_op_id->noo_completed)) {
        NA_LOG_ERROR("ignore the rma_event as the op is completed.");
        return;
    }

    na_ofi_addr = (struct na_ofi_addr *)na_ofi_op_id->noo_addr;

    ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, ret);
    if (ret != NA_SUCCESS)
        NA_LOG_ERROR("Unable to complete send");

    return;
}

/*---------------------------------------------------------------------------*/
static int
na_ofi_poll_get_fd(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    int fd = 0, rc;

    /* Only sockets provider supports wait on fd for now */
    if (priv->nop_domain->nod_prov_type != NA_OFI_PROV_SOCKETS)
        goto out;

    rc = fi_control(&priv->nop_endpoint->noe_cq->fid, FI_GETWAIT, &fd);
    if (rc == -FI_ENOSYS) {
        NA_LOG_WARNING("%s provider does not support wait objects",
            priv->nop_domain->nod_prov_name);
    } else if (rc < 0)
        NA_LOG_ERROR("fi_control() failed, rc: %d(%s).",
            rc, fi_strerror((int) -rc));

out:
    return fd;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ofi_poll_try_wait(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid *fids[1];

    /* Only sockets provider supports wait on fd for now */
    if (priv->nop_domain->nod_prov_type != NA_OFI_PROV_SOCKETS)
        return NA_TRUE;

    fids[0] = &priv->nop_endpoint->noe_cq->fid;
    return (fi_trywait(priv->nop_domain->nod_fabric, fids, 1) == FI_SUCCESS);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_progress(na_class_t *na_class, na_context_t *context,
    unsigned int timeout)
{
    struct na_ofi_private_data *priv = NA_OFI_PRIVATE_DATA(na_class);
    struct fid_cq *cq_hdl = priv->nop_endpoint->noe_cq;
    /* Convert timeout in ms into seconds */
    double remaining = timeout / 1000.0;
    na_return_t ret = NA_TIMEOUT;

    do {
        struct fi_cq_tagged_entry cq_event[NA_OFI_CQ_EVENT_NUM];
        fi_addr_t src_addr[NA_OFI_CQ_EVENT_NUM] = {FI_ADDR_UNSPEC};
        ssize_t rc, i, event_num = 0;
        hg_time_t t1, t2;

        if (timeout) {
            struct fid_wait *wait_hdl = priv->nop_endpoint->noe_wait;

            hg_time_get_current(&t1);

            if (wait_hdl) {
                int rc_wait = fi_wait(wait_hdl, (int) (remaining * 1000.0));
                if (rc_wait == -FI_ETIMEDOUT)
                    break;
                else if (rc_wait != FI_SUCCESS) {
                    NA_LOG_ERROR("fi_wait() failed, rc: %d(%s).",
                        rc_wait, fi_strerror((int) -rc_wait));
                    ret = NA_PROTOCOL_ERROR;
                    break;
                }
            }
        }

        na_ofi_class_lock(na_class);
        if (na_ofi_with_reqhdr(na_class) == NA_FALSE) {
            rc = fi_cq_readfrom(cq_hdl, cq_event, NA_OFI_CQ_EVENT_NUM,
                                src_addr);
        } else
            rc = fi_cq_read(cq_hdl, cq_event, NA_OFI_CQ_EVENT_NUM);
        na_ofi_class_unlock(na_class);
        if (rc == -FI_EAGAIN) {
            if (timeout) {
                hg_time_get_current(&t2);
                remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
            }
            if (remaining <= 0)
                break; /* Return NA_TIMEOUT */
            continue;
        } else if (rc == -FI_EAVAIL) {
            struct fi_cq_err_entry cq_err;

            memset(&cq_err, 0, sizeof(cq_err));

            na_ofi_class_lock(na_class);
            /* error available */
            rc = fi_cq_readerr(cq_hdl, &cq_err, 0 /* flags */);
            na_ofi_class_unlock(na_class);
            if (rc != 1) {
                NA_LOG_ERROR("fi_cq_readerr() failed, rc: %d(%s).",
                             rc, fi_strerror((int) -rc));
                ret = NA_PROTOCOL_ERROR;
                break;
            }
            if (cq_err.err == FI_ECANCELED) {
                /*
                cq_event[0].op_context = cq_err.op_context;
                cq_event[0].flags = cq_err.flags;
                cq_event[0].buf = NULL;
                cq_event[0].len = 0;
                NA_LOG_DEBUG("got a FI_ECANCELED event, cq_event.flags 0x%x.",
                             cq_err.flags);
                */
                continue;
            } else if (cq_err.err == FI_EADDRNOTAVAIL) {
                struct fid_av *av_hdl = priv->nop_domain->nod_av;
                fi_addr_t tmp_addr;

                na_ofi_class_lock(na_class);
                rc = fi_av_insert(av_hdl, cq_err.err_data, 1, &tmp_addr,
                                  0 /* flags */, NULL /* context */);
                na_ofi_class_unlock(na_class);
                if (rc < 0) {
                    NA_LOG_ERROR("fi_av_insert failed, rc: %d(%s).",
                                 rc, fi_strerror((int) -rc));
                    ret = NA_PROTOCOL_ERROR;
                    break;
                } else if (rc != 1) {
                    NA_LOG_ERROR("fi_av_insert failed, rc: %d.", rc);
                    ret = NA_PROTOCOL_ERROR;
                    break;
                }
                cq_event[0].op_context = cq_err.op_context;
                cq_event[0].flags = cq_err.flags;
                cq_event[0].buf = cq_err.buf;
                cq_event[0].len = cq_err.len;
                cq_event[0].tag = cq_err.tag;
                src_addr[0] = tmp_addr;
                event_num = 1;
            } else {
                NA_LOG_ERROR("fi_cq_readerr got err: %d(%s), "
                             "prov_errno: %d(%s).",
                             cq_err.err, fi_strerror(cq_err.err),
                             cq_err.prov_errno,
                             fi_strerror(-cq_err.prov_errno));
                ret = NA_PROTOCOL_ERROR;
                break;
            }
        } else if (rc <= 0) {
            NA_LOG_ERROR("fi_cq_read(/_readfrom() failed, rc: %d(%s).",
                         rc, fi_strerror((int) -rc));
            ret = NA_PROTOCOL_ERROR;
            break;
        } else {
            assert(rc > 0);
            event_num = rc;
        }

        /* got at least one completion event */
        assert(event_num >= 1);
        ret = NA_SUCCESS;
        for (i = 0; i < event_num; i++) {
            /*
            NA_LOG_DEBUG("got cq event[%d/%d] flags: 0x%x, src_addr %d.",
                         i + 1, event_num, cq_event[i].flags, src_addr[i]);
            */
            switch (cq_event[i].flags) {
            case FI_SEND | FI_TAGGED:
            case FI_SEND | FI_MSG:
            case FI_SEND | FI_TAGGED | FI_MSG:
                na_ofi_handle_send_event(na_class, context, &cq_event[i]);
                break;
            case FI_RECV | FI_TAGGED:
            case FI_RECV | FI_MSG:
            case FI_RECV | FI_TAGGED | FI_MSG:
                na_ofi_handle_recv_event(na_class, context, src_addr[i],
                                         &cq_event[i]);
                break;
            case FI_READ | FI_RMA:
            case FI_WRITE | FI_RMA:
                na_ofi_handle_rma_event(na_class, context, &cq_event[i]);
                break;
            default:
                NA_LOG_DEBUG("bad cq event[%d/%d] flags: 0x%x, src_addr %d.",
                         i + 1, event_num, cq_event[i].flags, src_addr[i]);
                break;
            };
        }

    } while (remaining > 0 && ret != NA_SUCCESS);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ofi_complete(struct na_ofi_addr *na_ofi_addr, struct na_ofi_op_id *na_ofi_op_id,
    na_return_t op_ret)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret = NA_SUCCESS;

    /* Mark op id as completed */
    if (!hg_atomic_cas32(&na_ofi_op_id->noo_completed, 0, 1)) {
        NA_LOG_ERROR("ignore completing for a completed op.");
        return ret;
    }

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
    struct fid_ep *ep_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint->noe_ep;
    struct fid_cq *cq_hdl = NA_OFI_PRIVATE_DATA(na_class)->nop_endpoint->noe_cq;
    struct na_ofi_op_id *na_ofi_op_id = (struct na_ofi_op_id *) op_id;
    struct na_ofi_op_id *tmp = NULL, *first = NULL;
    struct na_ofi_addr *na_ofi_addr = NULL;
    ssize_t rc;
    na_return_t ret = NA_SUCCESS;

    if (!na_ofi_op_id_valid(na_ofi_op_id)) {
        NA_LOG_ERROR("bad na_ofi_op_id, ignore the cancel request.");
        goto out;
    }
    if (hg_atomic_get32(&na_ofi_op_id->noo_completed))
        goto out;
    if (!hg_atomic_cas32(&na_ofi_op_id->noo_canceled, 0, 1)) {
        NA_LOG_WARNING("ignore canceling for a canceled op.");
        goto out;
    }

    hg_atomic_incr32(&na_ofi_op_id->noo_canceled);

    switch (na_ofi_op_id->noo_type) {
    case NA_CB_LOOKUP:
        break;
    case NA_CB_RECV_UNEXPECTED:
        na_ofi_class_lock(na_class);
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
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
        na_ofi_class_lock(na_class);
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
        if (rc != 0)
            NA_LOG_DEBUG("fi_cancel expected recv failed, rc: %d(%s).",
                         rc, fi_strerror((int) -rc));

        na_ofi_addr = (struct na_ofi_addr *)na_ofi_op_id->noo_addr;
        ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_CANCELED);
        break;
    case NA_CB_SEND_UNEXPECTED:
    case NA_CB_SEND_EXPECTED:
    case NA_CB_PUT:
    case NA_CB_GET:
        na_ofi_class_lock(na_class);
        rc = fi_cancel(&ep_hdl->fid, &na_ofi_op_id->noo_fi_ctx);
        na_ofi_class_unlock(na_class);
        if (rc != 0)
            NA_LOG_DEBUG("fi_cancel (op type %d) failed, rc: %d(%s).",
                         na_ofi_op_id->noo_type, rc, fi_strerror((int) -rc));

        na_ofi_addr = (struct na_ofi_addr *)na_ofi_op_id->noo_addr;
        ret = na_ofi_complete(na_ofi_addr, na_ofi_op_id, NA_CANCELED);
        break;
    default:
        break;
    }

    /* signal the cq to make the wait FD can work */
    rc = fi_cq_signal(cq_hdl);
    if (rc != 0 && rc != -ENOSYS)
        NA_LOG_DEBUG("fi_cq_signal (op type %d) failed, rc: %d(%s).",
            na_ofi_op_id->noo_type, rc, fi_strerror((int) -rc));
out:
    return ret;
}
