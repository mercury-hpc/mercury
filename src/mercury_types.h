/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TYPES_H
#define MERCURY_TYPES_H

#include "na.h"
#include "mercury_config.h"

typedef hg_uint32_t hg_id_t;          /* Operation ID of the operation */
typedef hg_bool_t   hg_status_t;      /* Status of the operation */
typedef void *      hg_request_t;     /* Abstract request */
typedef void *      hg_context_t;     /* Abstract request context */
typedef void *      hg_proc_t;        /* Abstract serialization processor */
typedef void *      hg_handle_t;      /* Abstract RPC handle */
typedef void *      hg_bulk_t;        /* Abstract bulk data handle */
typedef void *      hg_bulk_block_t;  /* Abstract block handle for bulk data */
typedef void *      hg_bulk_request_t;/* Bulk request object */

typedef struct hg_bulk_segment {
    void *    address; /* address of the segment */
    size_t    size;    /* size of the segment in bytes */
} hg_bulk_segment_t;

#define HG_BULK_READWRITE    NA_MEM_READWRITE
#define HG_BULK_READ_ONLY    NA_MEM_READ_ONLY

#define HG_STATUS_IGNORE     ((hg_status_t *)1)

#define HG_MAX_IDLE_TIME     NA_MAX_IDLE_TIME

#define HG_REQUEST_NULL      ((hg_request_t)0)
#define HG_PROC_NULL         ((hg_proc_t)0)
#define HG_HANDLE_NULL       ((hg_handle_t)0)
#define HG_BULK_NULL         ((hg_bulk_t)0)
#define HG_BULK_BLOCK_NULL   ((hg_bulk_block_t)0)
#define HG_BULK_REQUEST_NULL ((hg_bulk_request_t)0)

/**
 * Proc operations.  HG_ENCODE causes the type to be encoded into the
 * stream.  HG_DECODE causes the type to be extracted from the stream.
 * HG_FREE can be used to release the space allocated by an HG_DECODE
 * request.
 */
typedef enum {
    HG_ENCODE,
    HG_DECODE,
    HG_FREE
} hg_proc_op_t;

/* Error return codes */
#define HG_SUCCESS  1
#define HG_FAIL    -1
#define HG_TRUE     1
#define HG_FALSE    0

#endif /* MERCURY_TYPES_H */
