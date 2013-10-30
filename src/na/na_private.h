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
    na_return_t (*finalize)(void);

    /* Network address callbacks */
    na_return_t (*addr_lookup)(na_cb_t callback, void *arg, const char *name,
            na_op_id_t *op_id);
    na_return_t (*addr_free)(na_addr_t addr);
    na_return_t (*addr_to_string)(char *buf, na_size_t buf_size,
            na_addr_t addr);

    /* Message callbacks (used for metadata transfer) */
    na_size_t (*msg_get_max_expected_size)(void);
    na_size_t (*msg_get_max_unexpected_size)(void);
    na_tag_t (*msg_get_max_tag)(void);
    na_return_t (*msg_send_unexpected)(na_cb_t callback, void *arg,
            const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
            na_op_id_t *op_id);
    na_return_t (*msg_recv_unexpected)(na_cb_t callback, void *arg,
            void *buf, na_size_t buf_size, na_op_id_t *op_id);
    na_return_t (*msg_send_expected)(na_cb_t callback, void *arg,
            const void *buf, na_size_t buf_size, na_addr_t dest, na_tag_t tag,
            na_op_id_t *op_id);
    na_return_t (*msg_recv_expected)(na_cb_t callback, void *arg,
            void *buf, na_size_t buf_size, na_addr_t source, na_tag_t tag,
            na_op_id_t *op_id);

    /* Memory registration callbacks */
    na_return_t (*mem_handle_create)(void *buf, na_size_t buf_size,
        unsigned long flags, na_mem_handle_t *mem_handle);
    na_return_t (*mem_handle_create_segments)(struct na_segment *segments,
            na_size_t segment_count, unsigned long flags,
            na_mem_handle_t *mem_handle);
    na_return_t (*mem_handle_free)(na_mem_handle_t mem_handle);
    na_return_t (*mem_register)(na_mem_handle_t mem_handle);
    na_return_t (*mem_deregister)(na_mem_handle_t mem_handle);

    /* Memory handle serialization callbacks */
    na_size_t (*mem_handle_get_serialize_size)(na_mem_handle_t mem_handle);
    na_return_t (*mem_handle_serialize)(void *buf, na_size_t buf_size,
            na_mem_handle_t mem_handle);
    na_return_t (*mem_handle_deserialize)(na_mem_handle_t *mem_handle,
            const void *buf, na_size_t buf_size);

    /* One-sided transfer callbacks (used for for bulk data operations) */
    na_return_t (*put)(na_cb_t callback, void *arg,
            na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);
    na_return_t (*get)(na_cb_t callback, void *arg,
            na_mem_handle_t local_mem_handle, na_offset_t local_offset,
            na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
            na_size_t length, na_addr_t remote_addr, na_op_id_t *op_id);

    /* Progress callbacks */
    na_return_t (*progress)(unsigned int timeout, na_status_t *status);
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

/* NA status */
struct na_status {
    na_bool_t completed; /* true if operation has completed */
    na_size_t count;     /* number of bytes transmitted */
};

typedef enum na_class_priority {
  NA_CLASS_PRIORITY_INVALID  = 0,
  NA_CLASS_PRIORITY_LOW      = 1,
  NA_CLASS_PRIORITY_HIGH     = 2,
  NA_CLASS_PRIORITY_MAX      = 10
} na_class_priority_t;

#endif /* NA_PRIVATE_H */
