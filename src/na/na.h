/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_H
#define NA_H

#include "na_config.h"
#include "na_error.h"

#include <stddef.h>
#include <stdbool.h>

typedef void * na_addr_t;    /* Abstract network address */
typedef size_t na_size_t;    /* Size */
typedef int    na_tag_t;     /* Tag */
typedef void * na_request_t; /* Abstract request */
typedef struct na_status {   /* Operation status */
    bool      completed;     /* - true if operation has completed */
    na_size_t count;         /* - number of bytes transmitted */
} na_status_t;

typedef void * na_mem_handle_t; /* Absract memory handle */
typedef ptrdiff_t na_offset_t;  /* Offset */
typedef struct na_segment {     /* Segment */
    void      *address;         /* - address of the segment */
    na_size_t  size;            /* - size of the segment in bytes */
} na_segment_t;

#define NA_ADDR_NULL    ((na_addr_t)0)
#define NA_REQUEST_NULL ((na_request_t)0)
#define NA_STATUS_IGNORE ((na_status_t *)1)
#define NA_MEM_HANDLE_NULL ((na_mem_handle_t)0)

/* Max timeout */
#define NA_MAX_IDLE_TIME (3600*1000)

/* The memory attributes associated with the memory handle
 * can be defined as read/write or read only */
#define NA_MEM_READWRITE  0x00
#define NA_MEM_READ_ONLY  0x01

typedef struct na_class {
    /* Finalize callback */
    int (*finalize)(void);

    /* Network address callbacks
     * *************************
     * Look up a remote peer address and establish a connection.
     * NB. only clients need to call lookup */
    int (*addr_lookup)(const char *name, na_addr_t *addr);
    int (*addr_free)(na_addr_t addr);

    /* Message callbacks (used for metadata transfer)
     * **********************************************
     * Unexpected and expected callbacks can be used to
     * transfer small messages of "maximum size" bytes between peers.
     * Unexpected sends do not require a matching receive to complete.
     * Unexpected receives may wait on ANY_TAG and ANY_SOURCE depending on the
     * implementation.
     * NB. An expected send should not be considered as a ready send in the
     * sense that a matching recv may or may not have been posted already */
    na_size_t (*msg_get_maximum_size)(void);
    int (*msg_send_unexpected)(const void *buf, na_size_t buf_size, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*msg_recv_unexpected)(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
            na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
    int (*msg_send)(const void *buf, na_size_t buf_size, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*msg_recv)(void *buf, na_size_t buf_size, na_addr_t source,
            na_tag_t tag, na_request_t *request, void *op_arg);

    /* Memory registration callbacks
     * *****************************
     * Memory pieces must be registered before one-sided transfers can be
     * initiated.
     * Register can be used to register a contiguous piece of memory.
     * Register_segments can be used to register fragmented pieces and get
     * a single memory handle, this should be implemented only if the network
     * transport supports it. */
    int (*mem_register)(void *buf, na_size_t buf_size, unsigned long flags,
            na_mem_handle_t *mem_handle);
    int (*mem_register_segments)(na_segment_t *segments, na_size_t segment_count,
            unsigned long flags, na_mem_handle_t *mem_handle);
    int (*mem_deregister)(na_mem_handle_t mem_handle);

    /* Memory handle serialization callbacks
     * *************************************
     * One-sided transfers require prior exchange of memory handles between
     * peers, serialization callbacks can be used to "pack" a memory handle and
     * send it across the network.
     * NB. Memory handles can be variable size, therefore the space required
     * to serialize a handle into a buffer can be obtained using
     * mem_handle_get_serialize_size */
    na_size_t (*mem_handle_get_serialize_size)(na_mem_handle_t mem_handle);
    int (*mem_handle_serialize)(void *buf, na_size_t buf_size,
            na_mem_handle_t mem_handle);
    int (*mem_handle_deserialize)(na_mem_handle_t *mem_handle,
            const void *buf, na_size_t buf_size);
    int (*mem_handle_free)(na_mem_handle_t mem_handle);

    /* One-sided transfer callbacks (used for for bulk data operations)
     * ****************************************************************
     * Initiate a put or get to/from the registered memory regions with the
     * given offset/size.
     * NB. Memory must be registered and handles exchanged between peers. */
    int (*put)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);
    int (*get)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);

    /* Progress callbacks
     * ******************
     * Wait for the completion of a request issued by a non-blocking operation.
     * NB. Progress may be used to get a notification event that ensures
     * the completion of a one-sided operation or may be used to make progress
     * for plugins that need to emulate one-sided over two-sided operations. */
    int (*wait)(na_request_t request, unsigned int timeout, na_status_t *status);
    int (*progress)(unsigned int timeout, na_status_t *status);
} na_class_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Finalize the network abstraction layer */
int NA_Finalize(na_class_t *network_class);

/* Lookup an addr from a peer address/name */
int NA_Addr_lookup(na_class_t *network_class,
        const char *name, na_addr_t *addr);

/* Free the addr from the list of peers */
int NA_Addr_free(na_class_t *network_class,
        na_addr_t addr);

/* Get the maximum size of a message */
na_size_t NA_Msg_get_maximum_size(na_class_t *network_class);

/* Send an unexpected message to dest */
int NA_Msg_send_unexpected(na_class_t *network_class,
        const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive an unexpected message */
int NA_Msg_recv_unexpected(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
        na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);

/* Send an expected message to dest */
int NA_Msg_send(na_class_t *network_class,
        const void *buf, na_size_t buf_size, na_addr_t dest,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Receive an expected message from source */
int NA_Msg_recv(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_addr_t source,
        na_tag_t tag, na_request_t *request, void *op_arg);

/* Register memory for RMA operations */
int NA_Mem_register(na_class_t *network_class,
        void *buf, na_size_t buf_size, unsigned long flags,
        na_mem_handle_t *mem_handle);

/* Register segmented memory for RMA operations */
int NA_Mem_register_segments(na_class_t *network_class,
        na_segment_t *segments, na_size_t segment_count, unsigned long flags,
        na_mem_handle_t *mem_handle);

/* Deregister memory */
int NA_Mem_deregister(na_class_t *network_class,
        na_mem_handle_t mem_handle);

/* Get size required to serialize handle */
na_size_t NA_Mem_handle_get_serialize_size(na_class_t *network_class,
        na_mem_handle_t mem_handle);

/* Serialize memory handle into a buffer */
int NA_Mem_handle_serialize(na_class_t *network_class,
        void *buf, na_size_t buf_size, na_mem_handle_t mem_handle);

/* Deserialize memory handle from buffer */
int NA_Mem_handle_deserialize(na_class_t *network_class,
        na_mem_handle_t *mem_handle, const void *buf, na_size_t buf_size);

/* Free memory handle */
int NA_Mem_handle_free(na_class_t *network_class,
        na_mem_handle_t mem_handle);

/* Put data to remote target */
int NA_Put(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);

/* Get data from remote target */
int NA_Get(na_class_t *network_class,
        na_mem_handle_t local_mem_handle, na_offset_t local_offset,
        na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
        na_size_t length, na_addr_t remote_addr, na_request_t *request);

/* Wait for a request to complete or until timeout (ms) is reached */
int NA_Wait(na_class_t *network_class,
        na_request_t request, unsigned int timeout, na_status_t *status);

/* Track completion of RMA operations and make progress */
int NA_Progress(na_class_t *network_class,
        unsigned int timeout, na_status_t *status);

#ifdef __cplusplus
}
#endif

#endif /* NA_H */
