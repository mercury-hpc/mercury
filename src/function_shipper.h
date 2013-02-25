/*
 * function_shipper.h
 */

#ifndef FUNCTION_SHIPPER_H
#define FUNCTION_SHIPPER_H

#include "network_abstraction.h"
#include "generic_proc.h"

#include <stdbool.h>

typedef uint32_t     fs_id_t;          /* Op id of the operation */
typedef bool         fs_status_t;      /* Status of the operation */
typedef void *       fs_request_t;     /* Request object */

#define FS_STATUS_IGNORE (fs_status_t *)1
#define FS_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper and select a network protocol */
int fs_init(na_network_class_t *network_class);

/* Finalize the function shipper */
int fs_finalize(void);

/* Register a function name and provide a unique ID */
fs_id_t fs_register(const char *func_name,
        int (*enc_routine)(fs_proc_t proc, void *in_struct),
        int (*dec_routine)(fs_proc_t proc, void *out_struct));

/* Forward a call to a remote server */
int fs_forward(na_addr_t addr, fs_id_t id,
        const void *in_struct, void *out_struct, fs_request_t *request);

/* Wait for an operation request to complete */
int fs_wait(fs_request_t request, unsigned int timeout, fs_status_t *status);

/* Wait for all operations to complete */
int fs_wait_all(int count, fs_request_t array_of_requests[],
        unsigned int timeout, fs_status_t array_of_statuses[]);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_H */
