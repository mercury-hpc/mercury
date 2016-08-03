/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TYPES_H
#define MERCURY_TYPES_H

#include "mercury_config.h"
#include "mercury_util_config.h"

#ifdef HG_UTIL_HAS_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "mercury_sys_queue.h"
#endif

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

typedef struct hg_class hg_class_t;     /* Opaque HG class */
typedef struct hg_context hg_context_t; /* Opaque HG context */

typedef hg_uint64_t hg_size_t;          /* Size */
typedef hg_uint32_t hg_id_t;            /* RPC ID */
typedef struct hg_addr *hg_addr_t;      /* Abstract HG address */
typedef struct hg_handle *hg_handle_t;  /* Abstract RPC handle */
typedef struct hg_bulk *hg_bulk_t;      /* Abstract bulk data handle */
typedef struct hg_proc *hg_proc_t;      /* Abstract serialization processor */
typedef struct hg_op_id *hg_op_id_t;    /* Abstract operation id */

/* HG info struct */
struct hg_info {
    hg_class_t *hg_class;       /* HG class */
    hg_context_t *context;      /* HG context */
    hg_addr_t addr;             /* HG address */
    hg_id_t id;                 /* RPC ID */
};

/**
 * Bulk transfer operators.
 */
typedef enum {
    HG_BULK_PUSH,   /*!< push data to origin */
    HG_BULK_PULL    /*!< pull data from origin */
} hg_bulk_op_t;

/**
 * Proc operations.
 */
typedef enum {
    HG_ENCODE,  /*!< causes the type to be encoded into the stream */
    HG_DECODE,  /*!< causes the type to be extracted from the stream */
    HG_FREE     /*!< can be used to release the space allocated by an HG_DECODE request */
} hg_proc_op_t;

/**
 * Hash methods available for proc.
 */
typedef enum {
    HG_CRC16,
    HG_CRC32,
    HG_CRC64,
    HG_NOHASH
} hg_proc_hash_t;

/* Error return codes:
 * Functions return 0 for success or HG_XXX_ERROR for failure */
typedef enum hg_return {
    HG_SUCCESS = 0,     /*!< operation succeeded */
    HG_NA_ERROR,        /*!< error in NA layer */
    HG_TIMEOUT,         /*!< reached timeout */
    HG_INVALID_PARAM,   /*!< invalid parameter */
    HG_SIZE_ERROR,      /*!< size error */
    HG_NOMEM_ERROR,     /*!< no memory error */
    HG_PROTOCOL_ERROR,  /*!< protocol does not match */
    HG_NO_MATCH,        /*!< no function match */
    HG_CHECKSUM_ERROR,  /*!< checksum error */
    HG_CANCELED,        /*!< operation was canceled */
    HG_OTHER_ERROR      /*!< error from mercury_util or external to mercury */
} hg_return_t;

/* Callback operation type */
typedef enum hg_cb_type {
    HG_CB_LOOKUP,       /*!< lookup callback */
    HG_CB_FORWARD,      /*!< forward callback */
    HG_CB_RESPOND,      /*!< respond callback */
    HG_CB_BULK,         /*!< bulk transfer callback */
    HG_CB_INTFORWARD    /*!< internal forward callback */
} hg_cb_type_t;

/* HG callback */
struct hg_cb_info;      /* defined below */
typedef hg_return_t (*hg_cb_t)(const struct hg_cb_info *callback_info);

/* Callback info structs */
struct hg_cb_info_lookup {
    hg_addr_t addr;     /* HG address */
};

struct hg_cb_info_forward {
    hg_handle_t handle; /* HG handle */
};

struct hg_cb_info_intforward {
    hg_handle_t handle;        /* HG handle */
    hg_cb_t usercb;            /* user-level callback */
    void *userarg;             /* user arg */
    hg_bulk_t extra_in_handle; /* extra buf handle if handle isn't big enough */
    void *extra_in_buf;        /* extra buf itself */
};

struct hg_cb_info_respond {
    hg_handle_t handle; /* HG handle */
};

struct hg_cb_info_bulk {
    hg_bulk_op_t op;            /* Operation type */
    hg_bulk_t origin_handle;    /* HG Bulk origin handle */
    hg_bulk_t local_handle;     /* HG Bulk local handle */
};

struct hg_cb_info {
    void *arg;                  /* User data */
    hg_return_t ret;            /* Return value */
    hg_cb_type_t type;          /* Callback type */
    union {                     /* Union of callback info structures */
        struct hg_cb_info_lookup lookup;
        struct hg_cb_info_forward forward;
        struct hg_cb_info_respond respond;
        struct hg_cb_info_bulk bulk;
        struct hg_cb_info_intforward intforward;
    } info;
};

/* RPC callback */
typedef hg_return_t (*hg_rpc_cb_t)(hg_handle_t handle);

/* Proc callback for serializing/deserializing parameters */
typedef hg_return_t (*hg_proc_cb_t)(hg_proc_t proc, void *data);

/*****************/
/* Public Macros */
/*****************/

/* Constant values */
#define HG_BULK_READ_ONLY   0x01
#define HG_BULK_WRITE_ONLY  0x02
#define HG_BULK_READWRITE   0x04

#define HG_MAX_IDLE_TIME     (3600*1000)

#define HG_ADDR_NULL         ((hg_addr_t)0)
#define HG_HANDLE_NULL       ((hg_handle_t)0)
#define HG_BULK_NULL         ((hg_bulk_t)0)
#define HG_PROC_NULL         ((hg_proc_t)0)
#define HG_OP_ID_NULL        ((hg_op_id_t)0)
#define HG_OP_ID_IGNORE      ((hg_op_id_t *)1)

#endif /* MERCURY_TYPES_H */
