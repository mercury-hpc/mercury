/*
 * Copyright (C) 2013-2015 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PRIVATE_H
#define MERCURY_PRIVATE_H

#include "mercury_types.h"

#include "mercury_hash_table.h"
#include "mercury_atomic.h"

/* HG class */
struct hg_class {
    na_class_t *na_class;           /* NA class */
    na_context_t *na_context;       /* NA context */
    hg_hash_table_t *func_map;      /* Function map */
    hg_atomic_int32_t request_tag;  /* Atomic used for tag generation */
    na_tag_t request_max_tag;       /* Max value for tag */
};

/* Completion type */
typedef enum {
    HG_RPC,             /*!< RPC completion */
    HG_BULK             /*!< Bulk completion */
} hg_completion_type_t;

/* Completion queue entry */
struct hg_completion_entry {
    hg_completion_type_t completion_type;
    union {
        struct hg_handle *hg_handle;
        struct hg_bulk_op_id *hg_bulk_op_id;
    };
};

#endif /* MERCURY_PRIVATE_H */
