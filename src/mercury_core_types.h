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

typedef hg_uint64_t hg_size_t;          /* Size */
typedef hg_uint64_t hg_id_t;            /* RPC ID */

/* HG init info struct */
struct hg_init_info {
    struct na_init_info na_init_info;   /* NA Init Info */
    na_class_t *na_class;               /* NA class */
    hg_bool_t auto_sm;                  /* Use NA SM plugin with local addrs */
    hg_bool_t stats;                    /* (Debug) Print stats at exit */
};

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
    HG_CANCEL_ERROR,    /*!< operation could not be canceled */
    HG_OTHER_ERROR      /*!< error from mercury_util or external to mercury */
} hg_return_t;

/* Callback operation type */
typedef enum hg_cb_type {
    HG_CB_LOOKUP,       /*!< lookup callback */
    HG_CB_FORWARD,      /*!< forward callback */
    HG_CB_RESPOND,      /*!< respond callback */
    HG_CB_BULK          /*!< bulk transfer callback */
} hg_cb_type_t;

/* Input / output operation type */
typedef enum {
    HG_UNDEF,
    HG_INPUT,
    HG_OUTPUT
} hg_op_t;

/**
 * Encode/decode operations.
 */
typedef enum {
    HG_ENCODE,  /*!< causes the type to be encoded into the stream */
    HG_DECODE,  /*!< causes the type to be extracted from the stream */
    HG_FREE     /*!< can be used to release the space allocated by an HG_DECODE request */
} hg_proc_op_t;

/*****************/
/* Public Macros */
/*****************/

/* Max timeout */
#define HG_MAX_IDLE_TIME    (3600*1000)

/* HG size max */
#define HG_SIZE_MAX         UINT64_MAX

#endif /* MERCURY_CORE_TYPES_H */
