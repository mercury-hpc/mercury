/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MERCURY_PRIVATE_H
#define MERCURY_PRIVATE_H

#include "mercury_core.h"

#include "mercury_queue.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* Private callback type after completion of operations */
typedef void (*hg_core_completion_cb_t)(void *arg);

/* Completion type */
typedef enum {
    HG_ADDR, /*!< Addr completion */
    HG_RPC,  /*!< RPC completion */
    HG_BULK  /*!< Bulk completion */
} hg_op_type_t;

/* Completion queue entry */
struct hg_completion_entry {
    union {
        struct hg_core_op_id *hg_core_op_id;
        hg_core_handle_t hg_core_handle;
        struct hg_bulk_op_id *hg_bulk_op_id;
    } op_id;
    HG_QUEUE_ENTRY(hg_completion_entry) entry;
    hg_op_type_t op_type;
};

struct hg_bulk_op_pool;

/*****************/
/* Public Macros */
/*****************/

#ifdef HG_HAS_DEBUG
#    define HG_DEBUG_LOG_USED
#else
#    define HG_DEBUG_LOG_USED HG_UNUSED
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * \ptr:        the pointer to the member.
 * \type:       the type of the container struct this is embedded in.
 * \member:     the name of the member within the struct.
 *
 */
#if !defined(container_of)
#    define container_of(ptr, type, member)                                    \
        ((type *) ((char *) ptr - offsetof(type, member)))
#endif

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Increment bulk handle counter.
 */
HG_PRIVATE void
hg_core_bulk_incr(hg_core_class_t *hg_core_class);

/**
 * Decrement bulk handle counter.
 */
HG_PRIVATE void
hg_core_bulk_decr(hg_core_class_t *hg_core_class);

/**
 * Get bulk op pool.
 */
HG_PRIVATE struct hg_bulk_op_pool *
hg_core_context_get_bulk_op_pool(struct hg_core_context *core_context);

/**
 * Add entry to completion queue.
 */
HG_PRIVATE void
hg_core_completion_add(struct hg_core_context *core_context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t loopback_notify);

/**
 * Trigger callback from bulk op ID.
 */
HG_PRIVATE hg_return_t
hg_bulk_trigger_entry(struct hg_bulk_op_id *hg_bulk_op_id);

/**
 * Create pool of bulk op IDs.
 */
HG_PRIVATE hg_return_t
hg_bulk_op_pool_create(hg_core_context_t *core_context, unsigned int init_count,
    struct hg_bulk_op_pool **hg_bulk_op_pool_p);

/**
 * Destroy pool of bulk op IDs.
 */
HG_PRIVATE void
hg_bulk_op_pool_destroy(struct hg_bulk_op_pool *hg_bulk_op_pool);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_PRIVATE_H */
