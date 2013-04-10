/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HANDLER_H
#define MERCURY_HANDLER_H

#include "mercury.h"

typedef void * hg_handle_t;

#define HG_HANDLER_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define HG_HANDLE_NULL ((hg_handle_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper handler and select a network protocol */
int HG_Handler_init(na_class_t *network_class);

/* Finalize the function shipper handler */
int HG_Handler_finalize(void);

/* Register a function name and provide a unique ID */
void HG_Handler_register(const char *func_name,
        int (*hg_routine) (hg_handle_t handle));

/* Get remote addr from handle */
const na_addr_t HG_Handler_get_addr(hg_handle_t handle);

/* Get input from handle */
int HG_Handler_get_input(hg_handle_t handle, void **in_buf, size_t *in_buf_size);

/* Get output from handle */
int HG_Handler_get_output(hg_handle_t handle, void **out_buf, size_t *out_buf_size);

/* Receive a call from a remote client and process request */
int HG_Handler_process(unsigned int timeout);

/* Send the response back to the remote client and free handle */
int HG_Handler_start_response(hg_handle_t handle, const void *extra_out_buf, size_t extra_out_buf_size);

/* Wait for a response to complete */
int HG_Handler_wait_response(hg_handle_t handle, unsigned int timeout, hg_status_t *status);

/* Free the handle (N.B. called in hg_handler_respond) */
int HG_Handler_free(hg_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HANDLER_H */
