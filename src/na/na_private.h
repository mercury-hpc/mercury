/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

/* NA info definition */
struct na_info {
    char *class_name;    /* Class name (e.g., bmi) */
    char *protocol_name; /* Protocol (e.g., tcp, ib) */
    char *host_name;     /* Host */
    int   port;          /* Port for communication */
    char *port_name;     /* Identifies the server and can be used by a client */
};

/* Private callback type for NA plugins */
typedef void (*na_plugin_cb_t)(struct na_cb_info *callback_info, void *arg);

/* NA execution context, plugins may use plugin context if protocol supports
 * progress on separate contexts/queues/etc */
typedef void *na_plugin_context_t;
struct na_context {
    na_plugin_context_t plugin_context;
};

/* NA class definition */
struct na_class {
    void *private_data; /* Plugin private data */
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
    na_return_t
    (*context_create)(
            na_class_t *na_class,
            na_plugin_context_t *plugin_context
            );
    na_return_t
    (*context_destroy)(
            na_class_t *na_class,
            na_plugin_context_t plugin_context
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
            na_size_t   buf_size,
            na_addr_t   addr
            );
    na_size_t
    (*msg_get_max_expected_size)(
            na_class_t *na_class
            );
    na_size_t
    (*msg_get_max_unexpected_size)(
            na_class_t *na_class
            );
    na_tag_t
    (*msg_get_max_tag)(
            na_class_t *na_class
            );
    na_return_t
    (*msg_send_unexpected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            const void   *buf,
            na_size_t     buf_size,
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
            na_op_id_t   *op_id
            );
    na_return_t
    (*msg_send_expected)(
            na_class_t   *na_class,
            na_context_t *context,
            na_cb_t       callback,
            void         *arg,
            const void   *buf,
            na_size_t     buf_size,
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

/* Private routines for use inside NA plugins */

/**
 * Add callback to context completion queue.
 *
 * \param context [IN]              pointer to context of execution
 * \param callback [IN]             pointer to function
 * \param callback_info [IN]        callback info struct
 * \param plugin_callback [IN]      Callback which will be called after the user
 *                                  callback returns.
 * \param plugin_callback_args [IN] Argument to pass to the plugin_callback
 *
 * \return NA_SUCCESS or corresponding NA error code (failure is not an option)
 */
NA_EXPORT na_return_t
na_cb_completion_add(
        na_context_t      *context,
        na_cb_t            callback,
        struct na_cb_info *callback_info,
        na_plugin_cb_t     plugin_callback,
        void              *plugin_callback_args
        );

#endif /* NA_PRIVATE_H */
