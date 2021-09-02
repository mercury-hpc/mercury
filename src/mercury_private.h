/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
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

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get bulk op pool.
 */
HG_PRIVATE struct hg_bulk_op_pool *
hg_core_context_get_bulk_op_pool(struct hg_core_context *core_context);

/**
 * Add entry to completion queue.
 */
HG_PRIVATE hg_return_t
hg_core_completion_add(struct hg_core_context *core_context,
    struct hg_completion_entry *hg_completion_entry, hg_bool_t self_notify);

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
    struct hg_bulk_op_pool **hg_bulk_op_pool_ptr);

/**
 * Destroy pool of bulk op IDs.
 */
HG_PRIVATE hg_return_t
hg_bulk_op_pool_destroy(struct hg_bulk_op_pool *hg_bulk_op_pool);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_PRIVATE_H */
