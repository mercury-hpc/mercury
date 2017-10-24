/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CORE_H
#define MERCURY_CORE_H

#include "mercury_types.h"
#include "na.h"

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the core Mercury layer.
 * Must be finalized with HG_Core_finalize().
 *
 * \param na_info_string [IN]   host address with port number (e.g.,
 *                              "tcp://localhost:3344" or
 *                              "bmi+tcp://localhost:3344")
 * \param na_listen [IN]        listen for incoming connections
 *
 * \return Pointer to HG class or NULL in case of failure
 */
HG_EXPORT hg_class_t *
HG_Core_init(
        const char *na_info_string,
        hg_bool_t na_listen
        );

/**
 * Initialize the Mercury layer from an existing NA class/context.
 * Must be finalized with HG_Core_finalize().
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Pointer to HG class or NULL in case of failure
 */
HG_EXPORT hg_class_t *
HG_Core_init_na(
        na_class_t *na_class
        );

/**
 * Finalize the Mercury layer.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_finalize(
        hg_class_t *hg_class
        );

/**
 * Clean up all temporary files that were created in previous HG instances.
 * While temporary resources (e.g., tmp files) are cleaned up on a call
 * to HG_Finalize(), this routine gives a chance to programs that terminate
 * abnormally to easily clean up those resources.
 */
HG_EXPORT void
HG_Core_cleanup(
        void
        );

/**
 * Set callback that will be triggered on HG handle creation. This allows upper
 * layers to instantiate data that needs to be attached to a handle.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param create_callback [IN]  pointer to create function callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_set_create_callback(
        struct hg_class *hg_class,
        hg_return_t (*create_callback)(hg_class_t *hg_class, hg_handle_t handle)
        );

/**
 * Set callback that will be triggered when additional data needs to be
 * transferred and HG_Core_set_more_data() has been called, usually when the
 * eager message size is exceeded. This allows upper layers to manually transfer
 * data using bulk transfers for example. The done_callback argument allows the
 * upper layer to notify back once the data has been successfully acquired.
 * The release callback allows the upper layer to release resources that were
 * allocated when acquiring the data.
 *
 * \param hg_class [IN]                     pointer to HG class
 * \param more_data_acquire_callback [IN]   pointer to acquire function callback
 * \param more_data_release_callback [IN]   pointer to release function callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_set_more_data_callback(
        struct hg_class *hg_class,
        hg_return_t (*more_data_acquire_callback)(hg_handle_t,
            hg_return_t (*done_callback)(hg_handle_t)),
        void (*more_data_release_callback)(hg_handle_t)
        );

/**
 * Obtain the name of the given class.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return the name of the class, or NULL if not a valid class
 */
HG_EXPORT const char *
HG_Core_class_get_name(
        const hg_class_t *hg_class
        );

/**
 * Obtain the protocol of the given class.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return the protocol of the class, or NULL if not a valid class
 */
HG_EXPORT const char *
HG_Core_class_get_protocol(
        const hg_class_t *hg_class
        );

/**
 * Obtain the underlying NA class.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return Pointer to NA class or NULL if not a valid class
 */
HG_EXPORT na_class_t *
HG_Core_class_get_na(
        const hg_class_t *hg_class
        );

/**
 * Obtain the maximum eager size for sending RPC inputs.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return the maximum size, or 0 if hg_class is not a valid class or XDR is
 * being used
 */
HG_EXPORT hg_size_t
HG_Core_class_get_input_eager_size(
        const hg_class_t *hg_class
        );

/**
 * Obtain the maximum eager size for sending RPC outputs.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return the maximum size, or 0 if hg_class is not a valid class or XDR is
 * being used
 */
HG_EXPORT hg_size_t
HG_Core_class_get_output_eager_size(
        const hg_class_t *hg_class
        );

/**
 * Create a new context. Must be destroyed by calling HG_Core_context_destroy().
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return Pointer to HG context or NULL in case of failure
 */
HG_EXPORT hg_context_t *
HG_Core_context_create(
        hg_class_t *hg_class
        );

/**
 * Destroy a context created by HG_Core_context_create().
 *
 * \param context [IN]          pointer to HG context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_context_destroy(
        hg_context_t *context
        );

/**
 * Retrieve the class used to create the given context
 *
 * \param context [IN]          pointer to HG context
 *
 * \return the associated class
 */
HG_EXPORT hg_class_t *
HG_Core_context_get_class(
        const hg_context_t *context
        );

/**
 * Retrieve the underlying NA context.
 *
 * \param context [IN]          pointer to HG context
 *
 * \return the associated context
 */
HG_EXPORT na_context_t *
HG_Core_context_get_na(
        const hg_context_t *context
        );

/**
 * Set user-defined context ID, this can be used for multiplexing incoming
 * RPC requests and define an RPC tag identifier. Only RPC requests that match
 * the same context ID will be received (Tags are internally generated).
 *
 * \param context [IN]          pointer to HG context
 * \param id [IN]               user-defined context ID (max value of 255)
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_context_set_id(
        hg_context_t *context,
        hg_uint8_t id
        );

/**
 * Retrieve context ID from context.
 *
 * \param context [IN]          pointer to HG context
 *
 * \return Non-negative integer (max value of 255) or 0 if no ID has been set
 */
HG_EXPORT hg_uint8_t
HG_Core_context_get_id(
        const hg_context_t *context
        );

/**
 * Post requests associated to context in order to receive incoming RPCs.
 * Requests are automatically re-posted after completion depending on the
 * value of \repost.
 *
 * \param context [IN]          pointer to HG context
 * \param request_count [IN]    number of requests
 * \param repost [IN]           boolean, when HG_TRUE, requests are re-posted
 *
 * \return the associated class
 */
HG_EXPORT hg_return_t
HG_Core_context_post(
        hg_context_t *context,
        unsigned int request_count,
        hg_bool_t repost
        );

/**
 * Dynamically register an RPC ID as well as the RPC callback executed
 * when the RPC request ID is received.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               ID to use to register RPC
 * \param rpc_cb [IN]           RPC callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_register(
        hg_class_t *hg_class,
        hg_id_t id,
        hg_rpc_cb_t rpc_cb
        );

/**
 * Indicate whether HG_Core_register() has been called.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               function ID
 * \param flag [OUT]            pointer to boolean
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_registered(
        hg_class_t *hg_class,
        hg_id_t id,
        hg_bool_t *flag
        );

/**
 * Register and associate user data to registered function. When HG_Core_finalize()
 * is called, free_callback (if defined) is called to free the registered
 * data.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 * \param data [IN]             pointer to data
 * \param free_callback [IN]    pointer to function
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_register_data(
        hg_class_t *hg_class,
        hg_id_t id,
        void *data,
        void (*free_callback)(void *)
        );

/**
 * Indicate whether HG_Core_register_data() has been called and return
 * associated data.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 *
 * \return Pointer to data or NULL
 */
HG_EXPORT void *
HG_Core_registered_data(
        hg_class_t *hg_class,
        hg_id_t id
        );

/**
 * Disable response for a given RPC ID. This allows an origin process to send an
 * RPC to a target without waiting for a response. The RPC completes locally and
 * the callback on the origin is therefore pushed to the completion queue once
 * the RPC send is completed. By default, all RPCs expect a response to
 * be sent back.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 * \param disable [IN]          boolean (HG_TRUE to disable
 *                                       HG_FALSE to re-enable)
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_registered_disable_response(
        hg_class_t *hg_class,
        hg_id_t id,
        hg_bool_t disable
        );

/**
 * Lookup an addr from a peer address/name. Addresses need to be
 * freed by calling HG_Core_addr_free(). After completion, user callback is
 * placed into a completion queue and can be triggered using HG_Core_trigger().
 *
 * \param context [IN]          pointer to context of execution
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param name [IN]             lookup name
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_addr_lookup(
        hg_context_t *context,
        hg_cb_t       callback,
        void         *arg,
        const char   *name,
        hg_op_id_t   *op_id
        );

/**
 * Free the addr from the list of peers.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_addr_free(
        hg_class_t *hg_class,
        hg_addr_t   addr
        );

/**
 * Obtain the underlying NA address from an HG address.
 *
 * \param addr [IN]             abstract address
 *
 * \return abstract NA addr or NA_ADDR_NULL if not a valid HG address
 */
HG_EXPORT na_addr_t
HG_Core_addr_get_na(
        hg_addr_t addr
        );

/**
 * Access self address. Address must be freed with HG_Core_addr_free().
 *
 * \param hg_class [IN]         pointer to HG class
 * \param addr [OUT]            pointer to abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_addr_self(
        hg_class_t *hg_class,
        hg_addr_t  *addr
        );

/**
 * Duplicate an existing HG abstract address. The duplicated address can be
 * stored for later use and the origin address be freed safely. The duplicated
 * address must be freed with HG_Core_addr_free().
 *
 * \param hg_class [IN]         pointer to HG class
 * \param addr [IN]             abstract address
 * \param new_addr [OUT]        pointer to abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_addr_dup(
        hg_class_t *hg_class,
        hg_addr_t   addr,
        hg_addr_t  *new_addr
        );

/**
 * Convert an addr to a string (returned string includes the terminating
 * null byte '\0'). If buf is NULL, the address is not converted and only
 * the required size of the buffer is returned. If the input value passed
 * through buf_size is too small, HG_SIZE_ERROR is returned and the buf_size
 * output is set to the minimum size required.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param buf [IN/OUT]          pointer to destination buffer
 * \param buf_size [IN/OUT]     pointer to buffer size
 * \param addr [IN]             abstract address
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_addr_to_string(
        hg_class_t *hg_class,
        char       *buf,
        hg_size_t  *buf_size,
        hg_addr_t   addr
        );

/**
 * Initiate a new HG RPC using the specified function ID and the local/remote
 * target defined by addr. The HG handle created can be used to query input
 * and output buffers, as well as issuing the RPC by using HG_Core_forward().
 * After completion the handle must be freed using HG_Core_destroy().
 *
 * \param context [IN]          pointer to HG context
 * \param addr [IN]             target address
 * \param id [IN]               registered function ID
 * \param handle [OUT]          pointer to HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_create(
        hg_context_t *context,
        hg_addr_t addr,
        hg_id_t id,
        hg_handle_t *handle
        );

/**
 * Destroy HG handle. Decrement reference count, resources associated to the
 * handle are freed when the reference count is null.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_destroy(
        hg_handle_t handle
        );

/**
 * Reset an existing HG handle to make it reusable for RPC forwarding.
 * Both target address and RPC ID can be modified at this time.
 * Operations on that handle must be completed in order to reset that handle
 * safely.
 *
 * \param handle [IN]           HG handle
 * \param addr [IN]             abstract network address of destination
 * \param id [IN]               registered function ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_reset(
        hg_handle_t handle,
        hg_addr_t addr,
        hg_id_t id
        );

/**
 * Increment ref count on handle.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_ref_incr(
        hg_handle_t hg_handle
        );

/**
 * Allows upper layers to attach private data to an existing HG handle.
 * The free_callback argument allows allocated resources to be released when
 * the handle gets freed.
 *
 * \param handle [IN]           HG handle
 * \param data [IN]             pointer to user data
 * \param free_callback         pointer to free function callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
hg_return_t
HG_Core_set_private_data(
        hg_handle_t hg_handle,
        void *data,
        void (*free_callback)(void *)
        );

/**
 * Allows upper layers to retrieve data from an existing HG handle.
 * Only valid if HG_Core_set_private_data() has been previously called.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to data or NULL in case of error
 */
void *
HG_Core_get_private_data(
        hg_handle_t hg_handle
        );

/**
 * Get info from handle.
 *
 * \remark Users must call HG_Core_addr_dup() to safely re-use the addr field.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to info or NULL in case of failure
 */
HG_EXPORT const struct hg_info *
HG_Core_get_info(
        hg_handle_t handle
        );

/**
 * Set target ID that will receive and process RPC request
 * (target ID is defined on target context).
 *
 * \param handle [IN]           HG handle
 * \param target_id [IN]        user-defined target ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_set_target_id(
        hg_handle_t handle,
        hg_uint8_t target_id
        );

/**
 * Set more data flag to handle, indicating that more data will be transmitted
 * before the RPC can be successfully processed. The user is then responsible
 * for transmitting that data.
 *
 * \param handle [IN]           HG handle
 * \param more_data [IN]        boolean
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_set_more_data(
        hg_handle_t handle,
        hg_bool_t more_data
        );

/**
 * Get input buffer from handle that can be used for serializing/deserializing
 * parameters.
 *
 * \param handle [IN]           HG handle
 * \param in_buf [OUT]          pointer to input buffer
 * \param in_buf_size [OUT]     pointer to input buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_get_input(
        hg_handle_t handle,
        void **in_buf,
        hg_size_t *in_buf_size
        );

/**
 * Get output buffer from handle that can be used for serializing/deserializing
 * parameters.
 *
 * \param handle [IN]           HG handle
 * \param out_buf [OUT]         pointer to output buffer
 * \param out_buf_size [OUT]    pointer to output buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_get_output(
        hg_handle_t handle,
        void **out_buf,
        hg_size_t *out_buf_size
        );

/**
 * Forward a call using an existing HG handle. Input and output buffers can be
 * queried from the handle to serialize/deserialize parameters.
 * Additionally, a bulk handle can be passed if the size of the input is larger
 * than the queried input buffer size.
 * After completion, the handle must be freed using HG_Core_destroy(), the user
 * callback is placed into a completion queue and can be triggered using
 * HG_Core_trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param payload_size [IN]     size of payload to send
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_forward(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        hg_size_t payload_size
        );

/**
 * Respond back to the origin. The output buffer, which can be used to encode
 * the response, must first be queried using HG_Core_get_output().
 * After completion, the user callback is placed into a completion queue and
 * can be triggered using HG_Core_trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param payload_size [IN]     size of payload to send
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_respond(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        hg_size_t payload_size
        );

/**
 * Try to progress RPC execution for at most timeout until timeout is reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 *
 * \param context [IN]          pointer to HG context
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return HG_SUCCESS if any completion has occurred / HG error code otherwise
 */
HG_EXPORT hg_return_t
HG_Core_progress(
        hg_context_t *context,
        unsigned int timeout
        );

/**
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 *
 * \param context [IN]          pointer to HG context
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count [IN]     actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_trigger(
        hg_context_t *context,
        unsigned int timeout,
        unsigned int max_count,
        unsigned int *actual_count
        );

/**
 * Cancel an ongoing operation.
 *
 * \param handle [IN]           HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_cancel(
        hg_handle_t handle
        );

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_CORE_H */
