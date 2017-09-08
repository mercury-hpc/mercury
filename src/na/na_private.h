/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_PRIVATE_H
#define NA_PRIVATE_H

#include "na.h"
#include "mercury_queue.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* NA info definition */
struct na_info {
    char *class_name;    /* Class name (e.g., bmi) */
    char *protocol_name; /* Protocol (e.g., tcp, ib) */
    char *host_name;     /* Host (may be NULL in anonymous mode) */
};

/* Private callback type for NA plugins */
typedef void (*na_plugin_cb_t)(void *arg);

/* NA execution context, plugins may use plugin context if protocol supports
 * progress on separate contexts/queues/etc */
struct na_context {
    void *plugin_context;
};

/* Completion data stored in completion queue */
struct na_cb_completion_data {
    na_cb_t callback;                   /* Pointer to function */
    struct na_cb_info callback_info;    /* Callback info struct */
    na_plugin_cb_t plugin_callback;     /* Callback which will be called after
                                         * the user callback returns. */
    void *plugin_callback_args;         /* Argument to plugin_callback */
    HG_QUEUE_ENTRY(na_cb_completion_data) entry; /* Completion queue entry */
};

/* NA class definition */
struct na_class {
    void *private_data;     /* Plugin private data */
    const char *class_name; /* Class name */

    /* plugin callbacks */
    na_bool_t
    (*check_protocol)(
            const char *protocol_name
            );
    na_return_t
    (*initialize)(
            na_class_t *na_class,
            const struct na_info *na_info,
            na_bool_t listen
            );
    na_return_t
    (*finalize)(
            na_class_t *na_class
            );
    void
    (*cleanup)(
            void
            );
    na_bool_t
    (*check_feature)(
            na_class_t *na_class,
            na_uint8_t feature
            );
    na_return_t
    (*context_create)(
            na_class_t *na_class,
            void **plugin_context
            );
    na_return_t
    (*context_destroy)(
            na_class_t *na_class,
            void *plugin_context
            );
    na_op_id_t
    (*op_create)(
            na_class_t *na_class
            );
    na_return_t
    (*op_destroy)(
            na_class_t *na_class,
            na_op_id_t op_id
            );
    na_return_t
    (*addr_lookup)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            const char   *name,
            na_op_id_t   *op_id
            );
    na_return_t
    (*addr_free)(
            na_class_t *na_class,
            na_addr_t   addr
            );
    na_return_t
    (*addr_self)(
            na_class_t *na_class,
            na_addr_t  *addr
            );
    na_return_t
    (*addr_dup)(
            na_class_t *na_class,
            na_addr_t   addr,
            na_addr_t  *new_addr
            );
    na_bool_t
    (*addr_is_self)(
            na_class_t *na_class,
            na_addr_t   addr
            );
    na_return_t
    (*addr_to_string)(
            na_class_t *na_class,
            char       *buf,
            na_size_t  *buf_size,
            na_addr_t   addr
            );
    na_size_t
    (*msg_get_max_unexpected_size)(
            const na_class_t *na_class
            );
    na_size_t
    (*msg_get_max_expected_size)(
            const na_class_t *na_class
            );
    na_size_t
    (*msg_get_unexpected_header_size)(
            const na_class_t *na_class
            );
    na_size_t
    (*msg_get_expected_header_size)(
            const na_class_t *na_class
            );
    na_tag_t
    (*msg_get_max_tag)(
            const na_class_t *na_class
            );
    void *
    (*msg_buf_alloc)(
            na_class_t *na_class,
            na_size_t buf_size,
            void **plugin_data
            );
    na_return_t
    (*msg_buf_free)(
            na_class_t *na_class,
            void *buf,
            void *plugin_data
            );
    na_return_t
    (*msg_init_unexpected)(
            na_class_t *na_class,
            void *buf,
            na_size_t buf_size
            );
    na_return_t
    (*msg_send_unexpected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            const void   *buf,
            na_size_t     buf_size,
            void         *plugin_data,
            na_addr_t     dest,
            na_tag_t      tag,
            na_op_id_t   *op_id
            );
    na_return_t
    (*msg_recv_unexpected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            void         *buf,
            na_size_t     buf_size,
            void         *plugin_data,
            na_tag_t      mask,
            na_op_id_t   *op_id
            );
    na_return_t
    (*msg_init_expected)(
            na_class_t *na_class,
            void *buf,
            na_size_t buf_size
            );
    na_return_t
    (*msg_send_expected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            const void   *buf,
            na_size_t     buf_size,
            void         *plugin_data,
            na_addr_t     dest,
            na_tag_t      tag,
            na_op_id_t   *op_id
            );
    na_return_t
    (*msg_recv_expected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            void         *buf,
            na_size_t     buf_size,
            void         *plugin_data,
            na_addr_t     source,
            na_tag_t      tag,
            na_op_id_t   *op_id
            );
    na_return_t
    (*mem_handle_create)(
            na_class_t      *na_class,
            void            *buf,
            na_size_t        buf_size,
            unsigned long    flags,
            na_mem_handle_t *mem_handle
            );
    na_return_t
    (*mem_handle_create_segments)(
            na_class_t        *na_class,
            struct na_segment *segments,
            na_size_t          segment_count,
            unsigned long      flags,
            na_mem_handle_t   *mem_handle
            );
    na_return_t
    (*mem_handle_free)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_register)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_deregister)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_publish)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_unpublish)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_size_t
    (*mem_handle_get_serialize_size)(
            na_class_t      *na_class,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_handle_serialize)(
            na_class_t      *na_class,
            void            *buf,
            na_size_t        buf_size,
            na_mem_handle_t  mem_handle
            );
    na_return_t
    (*mem_handle_deserialize)(
            na_class_t      *na_class,
            na_mem_handle_t *mem_handle,
            const void      *buf,
            na_size_t        buf_size
            );
    na_return_t
    (*put)(
            na_class_t      *na_class,
            na_context_t    *context,
            na_cb_t          callback,
            void            *arg,
            na_mem_handle_t  local_mem_handle,
            na_offset_t      local_offset,
            na_mem_handle_t  remote_mem_handle,
            na_offset_t      remote_offset,
            na_size_t        length,
            na_addr_t        remote_addr,
            na_op_id_t      *op_id
            );
    na_return_t
    (*get)(
            na_class_t      *na_class,
            na_context_t    *context,
            na_cb_t          callback,
            void            *arg,
            na_mem_handle_t  local_mem_handle,
            na_offset_t      local_offset,
            na_mem_handle_t  remote_mem_handle,
            na_offset_t      remote_offset,
            na_size_t        length,
            na_addr_t        remote_addr,
            na_op_id_t      *op_id
            );
    int
    (*na_poll_get_fd)(
            na_class_t      *na_class,
            na_context_t    *context
            );
    na_bool_t
    (*na_poll_try_wait)(
            na_class_t      *na_class,
            na_context_t    *context
            );
    na_return_t
    (*progress)(
            na_class_t   *na_class,
            na_context_t *context,
            unsigned int  timeout
            );
    na_return_t
    (*cancel)(
            na_class_t   *na_class,
            na_context_t *context,
            na_op_id_t    op_id
            );
};

/*****************/
/* Public Macros */
/*****************/

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
    #define NA_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #define NA_UNUSED __attribute__((unused))
#else
    #define NA_UNUSED
#endif

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/* Private routines for use inside NA plugins */

/**
 * Add callback to context completion queue.
 *
 * \param context [IN/OUT]              pointer to context of execution
 * \param na_cb_completion_data [IN]    pointer to completion data
 *
 * \return NA_SUCCESS or corresponding NA error code (failure is not an option)
 */
NA_EXPORT na_return_t
na_cb_completion_add(
        na_context_t                 *context,
        struct na_cb_completion_data *na_cb_completion_data
        );

#ifdef __cplusplus
}
#endif

#endif /* NA_PRIVATE_H */
