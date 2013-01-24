/*
 * function_shipper.h
 */

#ifndef FUNCTION_SHIPPER_H
#define FUNCTION_SHIPPER_H

#include <stdbool.h>

typedef unsigned int fs_id_t;              /* Op id of the operation */
typedef bool         fs_status_t;          /* Status of the operation */
typedef void *       fs_request_t;         /* Request object */
typedef void *       fs_addr_t;            /* Addr of remote server */

#define FS_STATUS_IGNORE (fs_status_t *)1

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper and select a network protocol */
int fs_init();

/* Finalize the function shipper */
int fs_finalize(void);

/* Register a function name and provide a unique ID */
fs_id_t fs_register(const char *name,
        int (*enc_routine)(void *buf, int buf_len, void *struct_in),
        int (*dec_routine)(void *struct_out, void *buf, int buf_len));

/* Forward a call to a remote server */
int fs_forward(fs_addr_t addr, fs_id_t id, void *struct_in, void *struct_out,
        fs_request_t *request);

/* Wait for an operation request to complete */
int fs_wait(fs_request_t request, unsigned int timeout, fs_status_t *status);

/* Wait for all operations to complete */
int fs_wait_all(int count, fs_request_t array_of_requests[],
        unsigned int timeout, fs_status_t array_of_statuses[]);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_H */
