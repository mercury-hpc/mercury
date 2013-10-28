/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_PRIVATE_H
#define NA_PRIVATE_H

#include "na.h"

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
    #define NA_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #define NA_UNUSED __attribute__((unused))
#else
    #define NA_UNUSED
#endif

/* NA class definition */
struct na_class {
    /* Finalize callback */
    int (*finalize)(void);

    /* Network address callbacks */
    int (*addr_lookup)(const char *name, na_addr_t *addr);
    int (*addr_free)(na_addr_t addr);
    int (*addr_to_string)(char *buf, na_size_t buf_size, na_addr_t addr);

    /* Message callbacks (used for metadata transfer) */
    na_size_t (*msg_get_max_expected_size)(void);
    na_size_t (*msg_get_max_unexpected_size)(void);
    na_tag_t (*msg_get_max_tag)(void);
    int (*msg_send_unexpected)(const void *buf, na_size_t buf_size, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*msg_recv_unexpected)(void *buf, na_size_t buf_size, na_size_t *actual_buf_size,
            na_addr_t *source, na_tag_t *tag, na_request_t *request, void *op_arg);
    int (*msg_send)(const void *buf, na_size_t buf_size, na_addr_t dest,
            na_tag_t tag, na_request_t *request, void *op_arg);
    int (*msg_recv)(void *buf, na_size_t buf_size, na_addr_t source,
            na_tag_t tag, na_request_t *request, void *op_arg);

    /* Memory registration callbacks */
    int (*mem_register)(void *buf, na_size_t buf_size, unsigned long flags,
            na_mem_handle_t *mem_handle);
    int (*mem_register_segments)(na_segment_t *segments, na_size_t segment_count,
            unsigned long flags, na_mem_handle_t *mem_handle);
    int (*mem_deregister)(na_mem_handle_t mem_handle);

    /* Memory handle serialization callbacks */
    na_size_t (*mem_handle_get_serialize_size)(na_mem_handle_t mem_handle);
    int (*mem_handle_serialize)(void *buf, na_size_t buf_size,
            na_mem_handle_t mem_handle);
    int (*mem_handle_deserialize)(na_mem_handle_t *mem_handle,
            const void *buf, na_size_t buf_size);
    int (*mem_handle_free)(na_mem_handle_t mem_handle);

    /* One-sided transfer callbacks (used for for bulk data operations) */
    int (*put)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);
    int (*get)(na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_request_t *request);

    /* Progress callbacks */
    int (*wait)(na_request_t request, unsigned int timeout, na_status_t *status);
    int (*progress)(unsigned int timeout, na_status_t *status);
    int (*request_free)(na_request_t request);
};

/* Host string buffer */
struct na_host_buffer {
    char *na_class;          /* Class name (e.g., ssm, bmi, mpi) */
    char *na_protocol;       /* Protocol (e.g., tcp, ib) */
    char *na_host;           /* Host */
    int   na_port;           /* Port for communication */
    char *na_host_string;    /* Full request string sent by the user */
};

/* Class description */
struct na_class_describe {
    const char *class_name;
    na_bool_t (*verify) (const char *protocol);
    na_class_t *(*initialize) (const struct na_host_buffer *na_buffer,
            na_bool_t listen);
};

typedef enum na_class_priority {
  NA_CLASS_PRIORITY_INVALID  = 0,
  NA_CLASS_PRIORITY_LOW      = 1,
  NA_CLASS_PRIORITY_HIGH     = 2,
  NA_CLASS_PRIORITY_MAX      = 10
} na_class_priority_t;

#endif /* NA_PRIVATE_H */
