/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_TYPES_H
#define NA_TYPES_H

#include "na_config.h"

#include <limits.h>

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

typedef struct na_class na_class_t;     /* Opaque NA class */
typedef struct na_context na_context_t; /* Opaque NA execution context */
typedef void *na_addr_t;                /* Abstract NA address */
typedef na_uint64_t na_size_t;          /* Size */
typedef na_uint32_t na_tag_t;           /* Tag */
typedef void *na_op_id_t;               /* Abstract operation id */

typedef void *na_mem_handle_t;          /* Abstract memory handle */
typedef na_uint64_t na_offset_t;        /* Offset */

/* Progress mode */
typedef enum na_progress_mode {
    NA_DEFAULT,     /*!< blocking progress, depending on timeout value */
    NA_NO_BLOCK     /*!< no blocking progress, independent of timeout value */
} na_progress_mode_t;

/* Init info */
struct na_init_info {
    na_progress_mode_t progress_mode;   /* Progress mode */
    na_uint8_t max_contexts;            /* Max contexts */
    const char *auth_key;               /* Authorization key */
};

/* Segment */
struct na_segment {
    na_ptr_t address;   /* Address of the segment */
    na_size_t size;     /* Size of the segment in bytes */
};

/* Error return codes:
 * Functions return 0 for success or NA_XXX_ERROR for failure */
typedef enum na_return {
    NA_SUCCESS,             /*!< operation succeeded */
    NA_TIMEOUT,             /*!< reached timeout */
    NA_INVALID_PARAM,       /*!< invalid parameter */
    NA_SIZE_ERROR,          /*!< message size error */
    NA_ALIGNMENT_ERROR,     /*!< alignment error */
    NA_PERMISSION_ERROR,    /*!< read/write permission error */
    NA_NOMEM_ERROR,         /*!< no memory error */
    NA_PROTOCOL_ERROR,      /*!< unknown error reported from the protocol layer */
    NA_CANCELED,            /*!< operation was canceled */
    NA_CANCEL_ERROR,        /*!< operation could not be canceled */
    NA_ADDRINUSE_ERROR      /*!< address already in use */
} na_return_t;

/* Callback operation type */
typedef enum na_cb_type {
    NA_CB_LOOKUP,           /*!< lookup callback */
    NA_CB_SEND_UNEXPECTED,  /*!< unexpected send callback */
    NA_CB_RECV_UNEXPECTED,  /*!< unexpected recv callback */
    NA_CB_SEND_EXPECTED,    /*!< expected send callback */
    NA_CB_RECV_EXPECTED,    /*!< expected recv callback */
    NA_CB_PUT,              /*!< put callback */
    NA_CB_GET               /*!< get callback */
} na_cb_type_t;

/* Callback info structs */
struct na_cb_info_lookup {
    na_addr_t addr;
};

struct na_cb_info_recv_unexpected {
    na_size_t actual_buf_size;
    na_addr_t source;
    na_tag_t  tag;
};

/* Callback info struct */
struct na_cb_info {
    void *arg;          /* User data */
    na_return_t ret;    /* Return value */
    na_cb_type_t type;  /* Callback type */
    union {             /* Union of callback info structures */
        struct na_cb_info_lookup lookup;
        struct na_cb_info_recv_unexpected recv_unexpected;
    } info;
};

/* Callback type */
typedef int (*na_cb_t)(const struct na_cb_info *callback_info);

/*****************/
/* Public Macros */
/*****************/

/* Constant values */
#define NA_ADDR_NULL        ((na_addr_t)0)
#define NA_OP_ID_NULL       ((na_op_id_t)0)
#define NA_OP_ID_IGNORE     ((na_op_id_t *)1)
#define NA_MEM_HANDLE_NULL  ((na_mem_handle_t)0)

/* Max timeout */
#define NA_MAX_IDLE_TIME    (3600*1000)

/* Tag upper bound
 * \remark This is not the user tag limit but only the limit imposed by the type */
#define NA_TAG_UB           UINT_MAX

/* The memory attributes associated with the memory handle
 * can be defined as read only, write only or read/write */
#define NA_MEM_READ_ONLY    0x01
#define NA_MEM_WRITE_ONLY   0x02
#define NA_MEM_READWRITE    0x03

#endif /* NA_TYPES_H */
