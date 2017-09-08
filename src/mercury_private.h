/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PRIVATE_H
#define MERCURY_PRIVATE_H

#include "mercury_types.h"

#include "mercury_queue.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* Completion type */
typedef enum {
    HG_ADDR,            /*!< Addr completion */
    HG_RPC,             /*!< RPC completion */
    HG_BULK             /*!< Bulk completion */
} hg_op_type_t;

/* Completion queue entry */
struct hg_completion_entry {
    hg_op_type_t op_type;
    union {
        struct hg_op_id *hg_op_id;
        struct hg_handle *hg_handle;
        struct hg_bulk_op_id *hg_bulk_op_id;
    } op_id;
    HG_QUEUE_ENTRY(hg_completion_entry) entry;
};

#endif /* MERCURY_PRIVATE_H */
