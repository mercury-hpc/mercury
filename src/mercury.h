/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_H
#define MERCURY_H

#include "na.h"
#include "mercury_config.h"
#include "mercury_error.h"
#include "mercury_proc.h"

#include <stdbool.h>

typedef uint32_t     hg_id_t;          /* Op id of the operation */
typedef bool         hg_status_t;      /* Status of the operation */
typedef void *       hg_request_t;     /* Request object */

#define HG_STATUS_IGNORE ((hg_status_t *)1)

#define HG_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define HG_REQUEST_NULL ((hg_request_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper and select a network protocol */
int HG_Init(na_class_t *network_class);

/* Finalize the function shipper */
int HG_Finalize(void);

/* Register a function name and provide a unique ID */
hg_id_t HG_Register(const char *func_name,
        int (*enc_routine)(hg_proc_t proc, void *in_struct),
        int (*dec_routine)(hg_proc_t proc, void *out_struct));

/* Forward a call to a remote server */
int HG_Forward(na_addr_t addr, hg_id_t id,
        const void *in_struct, void *out_struct, hg_request_t *request);

/* Wait for an operation request to complete */
int HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status);

/* Wait for all operations to complete */
int HG_Wait_all(int count, hg_request_t array_of_requests[],
        unsigned int timeout, hg_status_t array_of_statuses[]);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_H */
