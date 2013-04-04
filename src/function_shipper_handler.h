/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef FUNCTION_SHIPPER_HANDLER_H
#define FUNCTION_SHIPPER_HANDLER_H

#include "function_shipper.h"

typedef void * fs_handle_t;

#define FS_HANDLER_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#define FS_HANDLE_NULL ((fs_handle_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper handler and select a network protocol */
int fs_handler_init(na_network_class_t *network_class);

/* Finalize the function shipper handler */
int fs_handler_finalize(void);

/* Register a function name and provide a unique ID */
void fs_handler_register(const char *func_name,
        int (*fs_routine) (fs_handle_t handle));

/* Get remote addr from handle */
const na_addr_t fs_handler_get_addr(fs_handle_t handle);

/* Get input from handle */
int fs_handler_get_input(fs_handle_t handle, void **in_buf, size_t *in_buf_size);

/* Get output from handle */
int fs_handler_get_output(fs_handle_t handle, void **out_buf, size_t *out_buf_size);

/* Receive a call from a remote client and process request */
int fs_handler_process(unsigned int timeout);

/* Send the response back to the remote client and free handle */
int fs_handler_start_response(fs_handle_t handle, const void *extra_out_buf, size_t extra_out_buf_size);

/* Wait for a response to complete */
int fs_handler_wait_response(fs_handle_t handle, unsigned int timeout, fs_status_t *status);

/* Free the handle (N.B. called in fs_handler_respond) */
int fs_handler_free(fs_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_HANDLER_H */
