/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
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
typedef struct na_addr *na_addr_t;      /* Abstract NA address */
typedef na_uint64_t na_size_t;          /* Size */
typedef na_uint32_t na_tag_t;           /* Tag */
typedef struct na_op_id na_op_id_t;     /* Opaque operation id */

typedef struct na_mem_handle *na_mem_handle_t; /* Abstract memory handle */
typedef na_uint64_t na_offset_t;               /* Offset */

/* Init info */
struct na_init_info {
    const char *ip_subnet;     /* Preferred IP subnet */
    const char *auth_key;      /* Authorization key */
    na_uint32_t progress_mode; /* Progress mode */
    na_uint8_t max_contexts;   /* Max contexts */
};

/* Segment */
struct na_segment {
    na_ptr_t base; /* Address of the segment */
    na_size_t len; /* Size of the segment in bytes */
};

/* Return codes:
 * Functions return 0 for success or corresponding return code */
#define NA_RETURN_VALUES                                                       \
    X(NA_SUCCESS)        /*!< operation succeeded */                           \
    X(NA_PERMISSION)     /*!< operation not permitted */                       \
    X(NA_NOENTRY)        /*!< no such file or directory */                     \
    X(NA_INTERRUPT)      /*!< operation interrupted */                         \
    X(NA_AGAIN)          /*!< operation must be retried */                     \
    X(NA_NOMEM)          /*!< out of memory */                                 \
    X(NA_ACCESS)         /*!< permission denied */                             \
    X(NA_FAULT)          /*!< bad address */                                   \
    X(NA_BUSY)           /*!< device or resource busy */                       \
    X(NA_EXIST)          /*!< entry already exists */                          \
    X(NA_NODEV)          /*!< no such device */                                \
    X(NA_INVALID_ARG)    /*!< invalid argument */                              \
    X(NA_PROTOCOL_ERROR) /*!< protocol error */                                \
    X(NA_OVERFLOW)       /*!< value too large */                               \
    X(NA_MSGSIZE)        /*!< message size too long */                         \
    X(NA_PROTONOSUPPORT) /*!< protocol not supported */                        \
    X(NA_OPNOTSUPPORTED) /*!< operation not supported on endpoint */           \
    X(NA_ADDRINUSE)      /*!< address already in use */                        \
    X(NA_ADDRNOTAVAIL)   /*!< cannot assign requested address */               \
    X(NA_TIMEOUT)        /*!< operation reached timeout */                     \
    X(NA_CANCELED)       /*!< operation canceled */                            \
    X(NA_RETURN_MAX)

#define X(a) a,
typedef enum na_return { NA_RETURN_VALUES } na_return_t;
#undef X

/* Callback operation type */
typedef enum na_cb_type {
    NA_CB_SEND_UNEXPECTED, /*!< unexpected send callback */
    NA_CB_RECV_UNEXPECTED, /*!< unexpected recv callback */
    NA_CB_SEND_EXPECTED,   /*!< expected send callback */
    NA_CB_RECV_EXPECTED,   /*!< expected recv callback */
    NA_CB_PUT,             /*!< put callback */
    NA_CB_GET              /*!< get callback */
} na_cb_type_t;

/* Callback info structs */
struct na_cb_info_recv_unexpected {
    na_size_t actual_buf_size;
    na_addr_t source;
    na_tag_t tag;
};

/* Callback info struct */
struct na_cb_info {
    union { /* Union of callback info structures */
        struct na_cb_info_recv_unexpected recv_unexpected;
    } info;
    void *arg;         /* User data */
    na_cb_type_t type; /* Callback type */
    na_return_t ret;   /* Return value */
};

/* Callback type */
typedef int (*na_cb_t)(const struct na_cb_info *callback_info);

/*****************/
/* Public Macros */
/*****************/

/* Constant values */
#define NA_ADDR_NULL       ((na_addr_t) 0)
#define NA_MEM_HANDLE_NULL ((na_mem_handle_t) 0)

/* Max timeout */
#define NA_MAX_IDLE_TIME (3600 * 1000)

/* Context ID max value
 * \remark This is not the user limit but only the limit imposed by the type */
#define NA_CONTEXT_ID_MAX UINT8_MAX

/* Tag max value
 * \remark This is not the user limit but only the limit imposed by the type */
#define NA_TAG_MAX UINT_MAX

/* The memory attributes associated with the memory handle
 * can be defined as read only, write only or read/write */
#define NA_MEM_READ_ONLY  0x01
#define NA_MEM_WRITE_ONLY 0x02
#define NA_MEM_READWRITE  0x03

/* Progress modes */
#define NA_NO_BLOCK 0x01 /*!< no blocking progress */
#define NA_NO_RETRY 0x02 /*!< no retry of operations in progress */

/* NA init info initializer */
#define NA_INIT_INFO_INITIALIZER                                               \
    {                                                                          \
        NULL, NULL, 0, 1                                                       \
    }

#endif /* NA_TYPES_H */
