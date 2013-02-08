/*
 * function_shipper.h
 */

#ifndef FUNCTION_SHIPPER_H
#define FUNCTION_SHIPPER_H

#include "network_abstraction.h"

#include <stdbool.h>

typedef unsigned int fs_id_t;          /* Op id of the operation */
typedef bool         fs_status_t;      /* Status of the operation */
typedef void *       fs_peer_t;        /* Remote peer id */
typedef void *       fs_request_t;     /* Request object */
typedef void *       fs_info_t;        /* Info internally used */

#define FS_STATUS_IGNORE (fs_status_t *)1
#define FS_MAX_IDLE_TIME NA_MAX_IDLE_TIME

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the function shipper and select a network protocol */
int fs_init(na_network_class_t *network_class);

/* Finalize the function shipper */
int fs_finalize(void);

/* Lookup a peer */
int fs_peer_lookup(const char *name, fs_peer_t *peer);

/* Free the peer */
int fs_peer_free(fs_peer_t peer);

/* Register a function name and provide a unique ID */
fs_id_t fs_register(const char *func_name,
        int (*enc_routine)(void *buf, int buf_len, const void *in_struct),
        int (*dec_routine)(void *out_struct, const void *buf, int buf_len));

/* Forward a call to a remote server */
int fs_forward(fs_peer_t addr, fs_id_t id, const void *in_struct, void *out_struct, fs_request_t *request);

/* Wait for an operation request to complete */
int fs_wait(fs_request_t request, unsigned int timeout, fs_status_t *status);

/* Wait for all operations to complete */
int fs_wait_all(int count, fs_request_t array_of_requests[],
        unsigned int timeout, fs_status_t array_of_statuses[]);

/*
 * Server calls
 */

/* Register a function name and provide a unique ID */
fs_id_t fs_server_register(const char *func_name,
        size_t size_in_struct, size_t size_out_struct,
        int (*dec_routine)(void *in_struct, const void *buf, int buf_len),
        int (*exe_routine)(const void *in_struct, void *out_struct, fs_info_t info),
        int (*enc_routine)(void *buf, int buf_len, const void *out_struct));

/* Receive a call from a remote client */
int fs_server_receive(fs_id_t *id, fs_info_t *info, void **in_struct);

/* Execute the call */
int fs_server_execute(fs_id_t id, fs_info_t info, const void *in_struct, void **out_struct);

/* Forward a response back to a remote client */
int fs_server_respond(fs_id_t id, fs_info_t info, const void *out_struct);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_SHIPPER_H */
