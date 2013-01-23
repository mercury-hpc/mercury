/*
 * network_abstraction.h
 *
 *  Created on: Nov 5, 2012
 *      Author: soumagne
 */

#ifndef NETWORK_ABSTRACTION_H
#define NETWORK_ABSTRACTION_H

#include <stddef.h>

typedef size_t na_size_t;
typedef void * na_addr_t;
typedef int    na_tag_t;
typedef void * na_request_t;
typedef void * na_mem_handle_t;
typedef ptrdiff_t na_offset_t;
typedef struct na_status_t {
    na_size_t count;
/*  bool cancelled;
 *  na_target_t NA_SOURCE;
 *  na_tag_t NA_TAG;
 *  int NA_ERROR;
 */
} na_status_t;

#define NA_STATUS_IGNORE (na_status_t *)1

#define NA_SUCCESS  1
#define NA_FAIL    -1
#define NA_TRUE     1
#define NA_FALSE    0

#define NA_ERROR_DEFAULT(x) {             \
  fprintf(stderr, "Error "                \
        "in %s:%d (%s): "                 \
        "%s.\n",                          \
        __FILE__, __LINE__, __func__, x); \
}

typedef struct network_class_t {
    void (*finalize)(void);                                /* finalize interface */
    na_size_t (*get_unexpected_size)(void);                /* get_unexpected_size */

    /* Peer lookup */
    int (*lookup)(const char *name, na_addr_t *target);  /* lookup peer target */
    int (*free)(na_addr_t target);                       /* free peer target */

    /* Metadata */
    int (*send_unexpected)(const void *buf, na_size_t buf_len, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);  /* send_unexpected */
    int (*recv_unexpected)(void *buf, na_size_t *buf_len, na_addr_t *source,
            na_tag_t *tag, na_request_t *request, void *op_arg); /* recv_unexpected */

    int (*send)(const void *buf, na_size_t buf_len, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);  /* send */
    int (*recv)(void *buf, na_size_t buf_len, na_addr_t source,
            na_tag_t tag, na_request_t *request, void *op_arg);  /* recv */

    /* Bulk data */
    int (*mem_register)(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle); /* mem_register */
    int (*mem_deregister)(na_mem_handle_t mem_handle); /* mem_deregister */

    int (*mem_handle_serialize)(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);   /* mem_handle_serialize */
    int (*mem_handle_deserialize)(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len); /* mem_handle_deserialize */

    int (*put)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request); /* put */
    int (*get)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request); /* get */

    /* Progress */
    int (*wait)(na_request_t request, int *flag, int timeout, na_status_t *status); /* wait */
} network_class_t;

/* Register a driver to the NA layer */
void na_register(network_class_t *network_class);

/* Finalize the network abstraction layer */
void na_finalize(void);

/* Get the maximum size of an unexpected message */
na_size_t na_get_unexpected_size(void);

/* Lookup a target from a peer address/name */
int na_lookup(const char *name, na_addr_t *target);

/* Free the target from the list of peers */
int na_free(na_addr_t target);

/* Send a message to dest (unexpected asynchronous) */
int na_send_unexpected(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive a message from source (unexpected asynchronous) */
int na_recv_unexpected(void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg);

/* Send a message to dest (asynchronous) */
int na_send(const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive a message from source (asynchronous) */
int na_recv(void *buf, na_size_t buf_len, na_addr_t source, na_tag_t tag,
        na_request_t *request, void *op_arg);

/* Register/Deregister memory for RMA operations */
int na_mem_register(void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle);
int na_mem_deregister(na_mem_handle_t mem_handle);

/* Serialize/Deserialize memory handle for exchange over the network */
int na_mem_handle_serialize(void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);
int na_mem_handle_deserialize(na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len);

/* Put/Get data to/from remote target */
int na_put(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);
int na_get(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);

/* Wait for a request to complete or until timeout (ms) is reached */
int na_wait(na_request_t request, int *flag, int timeout, na_status_t *status);

#endif /* NETWORK_ABSTRACTION_H */
