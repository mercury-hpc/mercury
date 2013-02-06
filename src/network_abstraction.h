/*
 * network_abstraction.h
 */

#ifndef NETWORK_ABSTRACTION_H
#define NETWORK_ABSTRACTION_H

#include <stddef.h>
#include <stdbool.h>

typedef void * na_addr_t;
typedef size_t na_size_t;
typedef int    na_tag_t;
typedef void * na_request_t;
typedef struct na_status {
    bool      completed;   /* true if operation has completed */
    na_size_t count;       /* if completed is true, number of bytes transmitted */
    //na_addr_t source;    /* if completed is true, source of operation */
    //na_tag_t  tag;       /* if completed is true, tag of operation */
    //int       error;     /* TODO may also want error handling here */
} na_status_t;

#define NA_MAX_IDLE_TIME (3600*1000)
#define NA_STATUS_IGNORE (na_status_t *)1

typedef void * na_mem_handle_t;
typedef ptrdiff_t na_offset_t;

/* The memory attributes associated with the region */
#define NA_MEM_READWRITE  0x00
#define NA_MEM_READ_ONLY  0x01

typedef struct na_network_class {
    /*  Lookup callbacks */
    void (*finalize)(void);
    na_size_t (*get_unexpected_size)(void);
    int (*addr_lookup)(const char *name, na_addr_t *addr);
    int (*addr_free)(na_addr_t addr);

    /* Metadata callbacks */
    int (*send_unexpected)(const void *buf, na_size_t buf_len, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*recv_unexpected)(void *buf, na_size_t *buf_len, na_addr_t *source,
            na_tag_t *tag, na_request_t *request, void *op_arg);
    int (*send)(const void *buf, na_size_t buf_len, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*recv)(void *buf, na_size_t buf_len, na_addr_t source,
            na_tag_t tag, na_request_t *request, void *op_arg);

    /* Bulk data callbacks */
    int (*mem_register)(void *buf, na_size_t buf_len, unsigned long flags,
            na_mem_handle_t *mem_handle);
    int (*mem_deregister)(na_mem_handle_t mem_handle);
    int (*mem_handle_serialize)(void *buf, na_size_t buf_len,
            na_mem_handle_t mem_handle);
    int (*mem_handle_deserialize)(na_mem_handle_t *mem_handle,
            const void *buf, na_size_t buf_len);
    int (*mem_handle_free)(na_mem_handle_t mem_handle);
    int (*put)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);
    int (*get)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);

    /* Progress callbacks */
    int (*wait)(na_request_t request, unsigned int timeout, na_status_t *status);
} na_network_class_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Finalize the network abstraction layer */
void na_finalize(na_network_class_t *network_class);

/* Get the maximum size of an unexpected message */
na_size_t na_get_unexpected_size(na_network_class_t *network_class);

/* Lookup an addr from a peer address/name */
int na_addr_lookup(na_network_class_t *network_class,
        const char *name, na_addr_t *addr);

/* Free the addr from the list of peers */
int na_addr_free(na_network_class_t *network_class,
        na_addr_t addr);

/* Send a message to dest (unexpected asynchronous) */
int na_send_unexpected(na_network_class_t *network_class,
        const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive a message from source (unexpected asynchronous) */
int na_recv_unexpected(na_network_class_t *network_class,
        void *buf, na_size_t *buf_len, na_addr_t *source,
        na_tag_t *tag, na_request_t *request, void *op_arg);

/* Send a message to dest (asynchronous) */
int na_send(na_network_class_t *network_class,
        const void *buf, na_size_t buf_len, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive a message from source (asynchronous) */
int na_recv(na_network_class_t *network_class,
        void *buf, na_size_t buf_len, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Register memory for RMA operations */
int na_mem_register(na_network_class_t *network_class,
        void *buf, na_size_t buf_len, unsigned long flags, na_mem_handle_t *mem_handle);

/* Deregister memory */
int na_mem_deregister(na_network_class_t *network_class,
        na_mem_handle_t mem_handle);

/* Serialize memory handle for exchange over the network */
int na_mem_handle_serialize(na_network_class_t *network_class,
        void *buf, na_size_t buf_len, na_mem_handle_t mem_handle);

/* Deserialize memory handle */
int na_mem_handle_deserialize(na_network_class_t *network_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_len);

/* Free memory handle */
int na_mem_handle_free(na_network_class_t *network_class,
        na_mem_handle_t mem_handle);

/* Put data to remote target */
int na_put(na_network_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);

/* Get data from remote target */
int na_get(na_network_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);

/* Wait for a request to complete or until timeout (ms) is reached */
int na_wait(na_network_class_t *network_class,
        na_request_t request, unsigned int timeout, na_status_t *status);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_ABSTRACTION_H */
