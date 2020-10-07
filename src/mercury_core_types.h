/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CORE_TYPES_H
#define MERCURY_CORE_TYPES_H

#include "mercury_config.h"
#include "na_types.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

typedef hg_uint64_t hg_size_t; /* Size */
typedef hg_uint64_t hg_id_t;   /* RPC ID */

/* HG init info struct */
struct hg_init_info {
    struct na_init_info na_init_info; /* NA Init Info */
    na_class_t *na_class;             /* NA class */
    hg_bool_t auto_sm;                /* Use NA SM plugin with local addrs */
    hg_bool_t stats;                  /* (Debug) Print stats at exit */
};

/* Error return codes:
 * Functions return 0 for success or corresponding return code */
#define HG_RETURN_VALUES                                                       \
    X(HG_SUCCESS)        /*!< operation succeeded */                           \
    X(HG_PERMISSION)     /*!< operation not permitted */                       \
    X(HG_NOENTRY)        /*!< no such file or directory */                     \
    X(HG_INTERRUPT)      /*!< operation interrupted */                         \
    X(HG_AGAIN)          /*!< operation must be retried */                     \
    X(HG_NOMEM)          /*!< out of memory */                                 \
    X(HG_ACCESS)         /*!< permission denied */                             \
    X(HG_FAULT)          /*!< bad address */                                   \
    X(HG_BUSY)           /*!< device or resource busy */                       \
    X(HG_EXIST)          /*!< entry already exists */                          \
    X(HG_NODEV)          /*!< no such device */                                \
    X(HG_INVALID_ARG)    /*!< invalid argument */                              \
    X(HG_PROTOCOL_ERROR) /*!< protocol error */                                \
    X(HG_OVERFLOW)       /*!< value too large */                               \
    X(HG_MSGSIZE)        /*!< message size too long */                         \
    X(HG_PROTONOSUPPORT) /*!< protocol not supported */                        \
    X(HG_OPNOTSUPPORTED) /*!< operation not supported on endpoint */           \
    X(HG_ADDRINUSE)      /*!< address already in use */                        \
    X(HG_ADDRNOTAVAIL)   /*!< cannot assign requested address */               \
    X(HG_TIMEOUT)        /*!< operation reached timeout */                     \
    X(HG_CANCELED)       /*!< operation canceled */                            \
    X(HG_CHECKSUM_ERROR) /*!< checksum error */                                \
    X(HG_NA_ERROR)       /*!< generic NA error */                              \
    X(HG_OTHER_ERROR)    /*!< generic HG error */                              \
    X(HG_RETURN_MAX)

#define X(a) a,
typedef enum hg_return { HG_RETURN_VALUES } hg_return_t;
#undef X

/* Compat return codes */
#define HG_INVALID_PARAM HG_INVALID_ARG
#define HG_SIZE_ERROR    HG_MSGSIZE
#define HG_NOMEM_ERROR   HG_NOMEM
#define HG_NO_MATCH      HG_NOENTRY

/* Callback operation type */
typedef enum hg_cb_type {
    HG_CB_LOOKUP,  /*!< lookup callback */
    HG_CB_FORWARD, /*!< forward callback */
    HG_CB_RESPOND, /*!< respond callback */
    HG_CB_BULK     /*!< bulk transfer callback */
} hg_cb_type_t;

/* Input / output operation type */
typedef enum { HG_UNDEF, HG_INPUT, HG_OUTPUT } hg_op_t;

/**
 * Encode/decode operations.
 */
typedef enum {
    HG_ENCODE, /*!< causes the type to be encoded into the stream */
    HG_DECODE, /*!< causes the type to be extracted from the stream */
    HG_FREE    /*!< can be used to release the space allocated by an HG_DECODE
                  request */
} hg_proc_op_t;

/**
 * Encode/decode operation flags.
 */
#define HG_CORE_SM (1 << 0)

/*****************/
/* Public Macros */
/*****************/

/* Max timeout */
#define HG_MAX_IDLE_TIME (3600 * 1000)

/* HG size max */
#define HG_SIZE_MAX UINT64_MAX

/* HG init info initializer */
#define HG_INIT_INFO_INITIALIZER                                               \
    {                                                                          \
        NA_INIT_INFO_INITIALIZER, NULL, HG_FALSE, HG_FALSE                     \
    }

#endif /* MERCURY_CORE_TYPES_H */
