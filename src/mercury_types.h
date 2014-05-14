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

typedef struct hg_class hg_class_t;           /* Opaque HG class */
typedef struct hg_bulk_class hg_bulk_class_t; /* Opaque HG bulk class */

typedef hg_uint32_t hg_id_t; /* Operation ID of the operation */
typedef void *hg_handle_t;   /* Abstract RPC handle */
typedef void *hg_bulk_t;     /* Abstract bulk data handle */
typedef void *hg_proc_t;     /* Abstract serialization processor */
typedef void *hg_op_id_t;    /* Abstract operation id */

/**
 * Bulk transfer operator:
 *   - HG_BULK_PUSH: push data to origin
 *   - HG_BULK_PULL: pull data from origin
 */
typedef enum {
    HG_BULK_PUSH,
    HG_BULK_PULL
} hg_bulk_op_t;

/**
 * Proc operations.  HG_ENCODE causes the type to be encoded into the
 * stream.  HG_DECODE causes the type to be extracted from the stream.
 * HG_FREE can be used to release the space allocated by an HG_DECODE request.
 */
typedef enum {
    HG_ENCODE,
    HG_DECODE,
    HG_FREE
} hg_proc_op_t;

/**
 * Hash methods available for proc.
 */
typedef enum {
    HG_CRC16,
    HG_CRC64,
    HG_NOHASH
} hg_proc_hash_t;

/* Error return codes:
 * Functions return 0 for success or -HG_XXX_ERROR for failure */
typedef enum hg_return {
    HG_FAIL = -1,      /* default (TODO keep until switch to new error format) */
    HG_SUCCESS = 0,
    HG_NA_ERROR,       /* error in NA layer */
    HG_TIMEOUT,        /* reached timeout */
    HG_INVALID_PARAM,  /* invalid parameter */
    HG_SIZE_ERROR,     /* size error */
    HG_NOMEM_ERROR,    /* no memory error */
    HG_PROTOCOL_ERROR, /* protocol does not match */
    HG_NO_MATCH,       /* no function match */
    HG_CHECKSUM_ERROR  /* checksum error */
} hg_return_t;

/* Callback info structs */
struct hg_cb_info {
    hg_class_t *hg_class; /* HG class */
    void *arg;            /* User data */
    hg_return_t ret;      /* Return value */
};

struct hg_bulk_cb_info {
    hg_bulk_class_t *bulk_class; /* HG bulk class */
    void *arg;                   /* User data */
    hg_return_t ret;             /* Return value */
    hg_bulk_op_t op;             /* Operation type */
};

/* Callback for executing RPC */
typedef hg_return_t
(*hg_rpc_cb_t)(hg_handle_t handle);

/* HG callback */
typedef hg_return_t
(*hg_cb_t)(const struct hg_cb_info *callback_info);

/* HG Bulk callback */
typedef hg_return_t
(*hg_bulk_cb_t)(const struct hg_bulk_cb_info *callback_info);

/* Proc callback for serializing/deserializing parameters */
typedef hg_return_t
(*hg_proc_cb_t)(hg_proc_t proc, void *data);

/* Constant values */
#define HG_BULK_READWRITE    NA_MEM_READWRITE
#define HG_BULK_READ_ONLY    NA_MEM_READ_ONLY
#define HG_BULK_WRITE_ONLY   NA_MEM_READWRITE

#define HG_MAX_IDLE_TIME     NA_MAX_IDLE_TIME

#define HG_OP_ID_NULL        ((hg_op_id_t)0)
#define HG_OP_ID_IGNORE      ((hg_op_id_t *)1)
#define HG_PROC_NULL         ((hg_proc_t)0)
#define HG_HANDLE_NULL       ((hg_handle_t)0)
#define HG_BULK_NULL         ((hg_bulk_t)0)

/* Context used for request emulation */
//struct hg_context {
//    na_class_t *na_class;
//    na_context_t *na_context;
//};

#endif /* MERCURY_TYPES_H */
