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

#include "network_abstraction.h"
#include "generic_proc.h"

typedef void * fs_handle_t;

#define FS_HANDLER_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper handler and select a network protocol */
int fs_handler_init(na_network_class_t *network_class);

/* Finalize the function shipper handler */
int fs_handler_finalize(void);

/* Register a function name and provide a unique ID */
void fs_handler_register(const char *func_name,
        int (*fs_routine) (fs_handle_t handle),
        int (*dec_routine)(fs_proc_t proc, void *in_struct),
        int (*enc_routine)(fs_proc_t proc, void *out_struct));

/* Get input from handle */
int fs_handler_get_input (fs_handle_t handle, void *in_struct);

/* Get remote addr from handle */
const na_addr_t fs_handler_get_addr (fs_handle_t handle);

/* Receive a call from a remote client */
int fs_handler_process(unsigned int timeout);

/* Forward the response back to the remote client and free handle */
int fs_handler_complete(fs_handle_t handle, const void *out_struct);

/* Debug Temporary for using user-defined manual proc routines and avoid call to
 * automatic free */
int fs_handler_use_manual_proc();

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_HANDLER_H */
