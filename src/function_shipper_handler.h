/*
 * function_shipper_handler.h
 */

#ifndef FUNCTION_SHIPPER_HANDLER_H
#define FUNCTION_SHIPPER_HANDLER_H

#include "network_abstraction.h"
#include "generic_proc.h"

typedef void * fs_handle_t;

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
int fs_handler_receive(void);

/* Forward the response back to the remote client and free handle */
int fs_handler_complete(fs_handle_t handle, const void *out_struct);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_HANDLER_H */
