/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

#include <limits.h>

typedef struct na_class na_class_t;     /* Opaque NA class */
typedef struct na_context na_context_t; /* Opaque NA execution context */
typedef void *na_addr_t;                /* Abstract NA address */
typedef na_uint64_t na_size_t;          /* Size */
typedef na_uint32_t na_tag_t;           /* Tag */
typedef void *na_op_id_t;               /* Abstract operation id */

typedef void *na_mem_handle_t;          /* Abstract memory handle */
typedef na_uint64_t na_offset_t;        /* Offset */

/* Segment */
struct na_segment {
    na_ptr_t address; /* Address of the segment */
    na_size_t size;   /* Size of the segment in bytes */
};

/* Constant values */
#define NA_ADDR_NULL       ((na_addr_t)0)
#define NA_OP_ID_NULL      ((na_op_id_t)0)
#define NA_OP_ID_IGNORE    ((na_op_id_t *)1)
#define NA_MEM_HANDLE_NULL ((na_mem_handle_t)0)

/* Max timeout */
#define NA_MAX_IDLE_TIME (3600*1000)

/* Tag upper bound
 * NB. This is not the user tag limit but only the limit imposed by the type */
#define NA_TAG_UB UINT_MAX

/* Max len used for strings that represent an addr */
#define NA_MAX_ADDR_LEN 256

/* The memory attributes associated with the memory handle
 * can be defined as read/write or read only */
#define NA_MEM_READWRITE  0x00
#define NA_MEM_READ_ONLY  0x01

/* Error return codes:
 * Functions return 0 for success or NA_XXX_ERROR for failure */
typedef enum na_return {
    NA_SUCCESS,          /* operation succeeded */
    NA_CANCELED,         /* operation was canceled */
    NA_TIMEOUT,          /* reached timeout */
    NA_INVALID_PARAM,    /* invalid parameter */
    NA_SIZE_ERROR,       /* message size error */
    NA_ALIGNMENT_ERROR,  /* alignment error */
    NA_PERMISSION_ERROR, /* read/write permission error */
    NA_NOMEM_ERROR,      /* no memory error */
    NA_PROTOCOL_ERROR    /* unknown error reported from the protocol layer */
} na_return_t;

/* Callback operation type */
typedef enum na_cb_type {
    NA_CB_LOOKUP,
    NA_CB_SEND_UNEXPECTED,
    NA_CB_RECV_UNEXPECTED,
    NA_CB_SEND_EXPECTED,
    NA_CB_RECV_EXPECTED,
    NA_CB_PUT,
    NA_CB_GET
} na_cb_type_t;

/* Callback info structs */
struct na_cb_info_lookup {
    na_addr_t addr;
};

struct na_cb_info_recv_unexpected {
    na_size_t actual_buf_size;
    na_addr_t source;
    na_tag_t  tag;
};

/* Callback info struct */
struct na_cb_info {
    void *arg;         /* User data */
    na_return_t ret;   /* Return value */
    na_cb_type_t type; /* Callback type */
    union {            /* Union of callback info structures */
        struct na_cb_info_lookup lookup;
        struct na_cb_info_recv_unexpected recv_unexpected;
    } info;
};

/* Callback type */
typedef na_return_t (*na_cb_t)(const struct na_cb_info *callback_info);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the network abstraction layer.
 *
 * \param info_string [IN]      host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param listen [IN]           listen for incoming connections
 *
 * \return Pointer to NA class or NULL in case of failure
 */
NA_EXPORT na_class_t *
NA_Initialize(
        const char *info_string,
        na_bool_t   listen
        ) NA_WARN_UNUSED_RESULT;

/**
 * Finalize the network abstraction layer.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Finalize(
        na_class_t *na_class
        );

/**
 * Test whether class is listening or not.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return NA_TRUE if listening or NA_FALSE if not
 */
NA_EXPORT na_bool_t
NA_Is_listening(
        na_class_t *na_class
        );


/**
 * Create a new context.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Pointer to NA context or NULL in case of failure
 */
NA_EXPORT na_context_t *
NA_Context_create(
        na_class_t *na_class
        );

/**
 * Destroy a context created by using NA_Context_create().
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Context_destroy(
        na_class_t   *na_class,
        na_context_t *context
        );

/**
 * Lookup an addr from a peer address/name. Addresses need to be
 * freed by calling NA_Addr_free. Callback will be called with pointer to
 * na_addr_t that contains addr ::na_cb_info_lookup
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param name [IN]             lookup name
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_lookup(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        const char   *name,
        na_op_id_t   *op_id
        );

/**
 * For compatibility, temporarily provide this routine, which waits until
 * addr is returned.
 *
 * \param na_class [IN]         pointer to NA class
 * \param name [IN]             lookup name
 * \param addr [OUT]            pointer to abstract address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_lookup_wait(
        na_class_t *na_class,
        const char *name,
        na_addr_t  *addr
        );

/**
 * Free the addr from the list of peers.
 *
 * \param na_class [IN]         pointer to NA class
 * \param addr [IN]             abstract address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_free(
        na_class_t *na_class,
        na_addr_t   addr
        );

/**
 * Access self address.
 *
 * \param na_class [IN]         pointer to NA class
 * \param addr [OUT]            pointer to abstract address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_self(
        na_class_t *na_class,
        na_addr_t  *addr
        );

/**
 * Duplicate an existing NA abstract address. The duplicated address can be
 * stored for later use and the origin address be freed safely. The duplicated
 * address must be freed with NA_Addr_free.
 *
 * \param na_class [IN]         pointer to NA class
 * \param addr [IN]             abstract address
 * \param new_addr [OUT]        pointer to abstract address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_dup(
        na_class_t *na_class,
        na_addr_t   addr,
        na_addr_t  *new_addr
        );

/**
 * Test whether address is self or not.
 *
 * \param na_class [IN]         pointer to NA class
 * \param addr [IN]             abstract address
 *
 * \return NA_TRUE if self or NA_FALSE if not
 */
NA_EXPORT na_bool_t
NA_Addr_is_self(
        na_class_t *na_class,
        na_addr_t   addr
        );

/**
 * Convert an addr to a string (returned string includes the terminating
 * null byte '\0').
 *
 * \param na_class [IN]         pointer to NA class
 * \param buf [IN/OUT]          pointer to destination buffer
 * \param buf_size [IN]         buffer size (max string length is defined
 *                              by NA_MAX_ADDR_LEN)
 * \param addr [IN]             abstract address
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Addr_to_string(
        na_class_t *na_class,
        char       *buf,
        na_size_t   buf_size,
        na_addr_t   addr
        );

/**
 * Get the maximum size of messages supported by expected send/recv.
 * Small message size that may differ from the unexpected message size.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Non-negative value
 */
NA_EXPORT na_size_t
NA_Msg_get_max_expected_size(
        na_class_t *na_class
        ) NA_WARN_UNUSED_RESULT;

/**
 * Get the maximum size of messages supported by unexpected send/recv.
 * Small message size.
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Non-negative value
 */
NA_EXPORT na_size_t
NA_Msg_get_max_unexpected_size(
        na_class_t *na_class
        ) NA_WARN_UNUSED_RESULT;

/**
 * Get the maximum tag value that can be used by send/recv.
 * (both expected and unexpected)
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Non-negative value
 */
NA_EXPORT na_tag_t
NA_Msg_get_max_tag(
        na_class_t *na_class
        ) NA_WARN_UNUSED_RESULT;

/**
 * Send an unexpected message to dest.
 * Unexpected sends do not require a matching receive to complete.
 * Note also that unexpected messages do not require an unexpected receive to
 * be posted at the destination before sending the message and the destination
 * is allowed to drop the message without notification.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param buf [IN]              pointer to send buffer
 * \param buf_size [IN]         buffer size
 * \param dest [IN]             abstract address of destination
 * \param tag [IN]              tag attached to message
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Msg_send_unexpected(
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

/**
 * Receive an unexpected message.
 * Unexpected receives may wait on ANY_TAG and ANY_SOURCE depending on the
 * implementation.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param buf [IN]              pointer to send buffer
 * \param buf_size [IN]         buffer size
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Msg_recv_unexpected(
        na_class_t   *na_class,
        na_context_t *context,
        na_cb_t       callback,
        void         *arg,
        void         *buf,
        na_size_t     buf_size,
        na_op_id_t   *op_id
        );

/**
 * Send an expected message to dest. Note that expected messages require
 * an expected receive to be posted at the destination before sending the
 * message, otherwise the destination is allowed to drop the message without
 * notification.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param buf [IN]              pointer to send buffer
 * \param buf_size [IN]         buffer size
 * \param dest [IN]             abstract address of destination
 * \param tag [IN]              tag attached to message
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Msg_send_expected(
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

/**
 * Receive an expected message from source.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param buf [IN]              pointer to receive buffer
 * \param buf_size [IN]         buffer size
 * \param source [IN]           abstract address of source
 * \param tag [IN]              matching tag used to receive message
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Msg_recv_expected(
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

/**
 * Create memory handle for RMA operations.
 * For non-contiguous memory, use NA_Mem_handle_create_segments instead.
 *
 * Note to plugin developers: NA_Mem_handle_create may be called multiple times
 * on the same memory region.
 *
 * \param na_class [IN]         pointer to NA class
 * \param buf [IN]              pointer to buffer that needs to be registered
 * \param buf_size [IN]         buffer size
 * \param flags [IN]            permission flag:
 *                                - NA_MEM_READWRITE
 *                                - NA_MEM_READ_ONLY
 * \param mem_handle [OUT]      pointer to returned abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_handle_create(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        unsigned long    flags,
        na_mem_handle_t *mem_handle
        );

/**
 * Create memory handle for RMA operations.
 * Create_segments can be used to register fragmented pieces and get
 * a single memory handle.
 * Implemented only if the network transport or hardware supports it.
 *
 * \param na_class [IN]         pointer to NA class
 * \param segments [IN]         pointer to array of segments composed of:
 *                                - address of the segment that needs to be
 *                                  registered
 *                                - size of the segment in bytes
 * \param segment_count [IN]    segment count
 * \param flags [IN]            permission flag:
 *                                - NA_MEM_READWRITE
 *                                - NA_MEM_READ_ONLY
 * \param mem_handle [OUT]      pointer to returned abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_handle_create_segments(
        na_class_t        *na_class,
        struct na_segment *segments,
        na_size_t          segment_count,
        unsigned long      flags,
        na_mem_handle_t   *mem_handle
        );

/**
 * Free memory handle.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_handle_free(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/**
 * Register memory for RMA operations.
 * Memory pieces must be registered before one-sided transfers can be
 * initiated.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       pointer to abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_register(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/**
 * Unregister memory.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_deregister(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/**
 * Expose memory for RMA operations.
 * Memory pieces must be registered before one-sided transfers can be
 * initiated.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       pointer to abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_publish(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );

/**
 * Unpublish memory.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_unpublish(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        );



/**
 * Get size required to serialize handle.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [IN]       abstract memory handle
 *
 * \return Non-negative value
 */
NA_EXPORT na_size_t
NA_Mem_handle_get_serialize_size(
        na_class_t      *na_class,
        na_mem_handle_t  mem_handle
        ) NA_WARN_UNUSED_RESULT;

/**
 * Serialize memory handle into a buffer.
 * One-sided transfers require prior exchange of memory handles between
 * peers, serialization callbacks can be used to "pack" a memory handle and
 * send it across the network.
 * NB. Memory handles can be variable size, therefore the space required
 * to serialize a handle into a buffer can be obtained using
 * NA_Mem_handle_get_serialize_size.
 *
 * \param na_class [IN]         pointer to NA class
 * \param buf [IN/OUT]          pointer to buffer used for serialization
 * \param buf_size [IN]         buffer size
 * \param mem_handle [IN]       abstract memory handle
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_handle_serialize(
        na_class_t      *na_class,
        void            *buf,
        na_size_t        buf_size,
        na_mem_handle_t  mem_handle
        );

/**
 * Deserialize memory handle from buffer.
 *
 * \param na_class [IN]         pointer to NA class
 * \param mem_handle [OUT]      pointer to abstract memory handle
 * \param buf [IN]              pointer to buffer used for deserialization
 * \param buf_size [IN]         buffer size
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Mem_handle_deserialize(
        na_class_t      *na_class,
        na_mem_handle_t *mem_handle,
        const void      *buf,
        na_size_t        buf_size
        );

/**
 * Put data to remote target.
 * Initiate a put or get to/from the registered memory regions with the
 * given offset/size.
 * NB. Memory must be registered and handles exchanged between peers.
 *
 * \param na_class [IN]          pointer to NA class
 * \param context [IN]           pointer to context of execution
 * \param callback [IN]          pointer to function callback
 * \param arg [IN]               pointer to data passed to callback
 * \param local_mem_handle [IN]  abstract local memory handle
 * \param local_offset [IN]      local offset
 * \param remote_mem_handle [IN] abstract remote memory handle
 * \param remote_offset [IN]     remote offset
 * \param data_size [IN]         size of data that needs to be transferred
 * \param remote_addr [IN]       abstract address of remote destination
 * \param op_id [OUT]            pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Put(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t  local_mem_handle,
        na_offset_t      local_offset,
        na_mem_handle_t  remote_mem_handle,
        na_offset_t      remote_offset,
        na_size_t        data_size,
        na_addr_t        remote_addr,
        na_op_id_t      *op_id
        );

/**
 * Get data from remote target.
 *
 * \param na_class [IN]          pointer to NA class
 * \param context [IN]           pointer to context of execution
 * \param callback [IN]          pointer to function callback
 * \param arg [IN]               pointer to data passed to callback
 * \param local_mem_handle [IN]  abstract local memory handle
 * \param local_offset [IN]      local offset
 * \param remote_mem_handle [IN] abstract remote memory handle
 * \param remote_offset [IN]     remote offset
 * \param data_size [IN]         size of data that needs to be transferred
 * \param remote_addr [IN]       abstract address of remote source
 * \param op_id [OUT]            pointer to returned operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Get(
        na_class_t      *na_class,
        na_context_t    *context,
        na_cb_t          callback,
        void            *arg,
        na_mem_handle_t  local_mem_handle,
        na_offset_t      local_offset,
        na_mem_handle_t  remote_mem_handle,
        na_offset_t      remote_offset,
        na_size_t        data_size,
        na_addr_t        remote_addr,
        na_op_id_t      *op_id
        );

/**
 * Try to progress communication for at most timeout until timeout reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return NA_SUCCESS if any completion has occurred / NA error code otherwise
 */
NA_EXPORT na_return_t
NA_Progress(
        na_class_t   *na_class,
        na_context_t *context,
        unsigned int  timeout
        );

/**
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 *
 * \param context [IN]          pointer to context of execution
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count [IN]     actual number of callbacks triggered
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Trigger(
        na_context_t *context,
        unsigned int  timeout,
        unsigned int  max_count,
        unsigned int *actual_count
        );

/**
 * Cancel an ongoing operation.
 *
 * \param na_class [IN]         pointer to NA class
 * \param context [IN]          pointer to context of execution
 * \param op_id [IN]            operation ID
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_Cancel(
        na_class_t   *na_class,
        na_context_t *context,
        na_op_id_t    op_id
        );

/**
 * Convert error return code to string (null terminated).
 *
 * \param errnum [IN]           error return code
 *
 * \return String
 */
NA_EXPORT const char *
NA_Error_to_string(
        na_return_t errnum
        ) NA_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* NA_H */
