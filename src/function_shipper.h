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
typedef void *       fs_addr_t;        /* Addr of remote server */

#define FS_STATUS_IGNORE (fs_status_t *)1

/* Error return codes */
#define FS_SUCCESS  1
#define FS_FAIL    -1
#define FS_TRUE     1
#define FS_FALSE    0

/* Default error macro */
#define FS_ERROR_DEFAULT(x) {             \
  fprintf(stderr, "Error "                \
        "in %s:%d (%s): "                 \
        "%s.\n",                          \
        __FILE__, __LINE__, __func__, x); \
}

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
        int (*enc_routine)(void *buf, int buf_len, void *in_struct),
        int (*dec_routine)(void *out_struct, void *buf, int buf_len));

/* Forward a call to a remote server */
int fs_forward(fs_peer_t addr, fs_id_t id, void *in_struct, void *out_struct,
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
