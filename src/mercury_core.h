/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
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
 * \param na_context [IN]       pointer to NA context
 *
 * \return Pointer to HG class or NULL in case of failure
 */
HG_EXPORT hg_class_t *
HG_Core_init_na(
        na_class_t *na_class,
        na_context_t *na_context
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
        hg_context_t *context
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
 * Destroy HG handle. Resources associated to the handle are freed when the
 * reference count is null.
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
 * Get info from handle.
 * \remark Users must call HG_Core_addr_dup() to safely re-use the addr field.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to info or NULL in case of failure
 */
HG_EXPORT struct hg_info *
HG_Core_get_info(
        hg_handle_t handle
        );

/**
 * Get input buffer from handle that can be used for serializing/deserializing
 * parameters.
 *
 * \param handle [IN]           HG handle
 * \param in_buf [OUT]          pointer to input buffer
 * \param in_buf_size [OUT]     pointer to input buffer size
 * \cond TODO Use bulk_t instead and add requested_size argument ? \endcond
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
 * After completion, the handle must be freed using HG_Core_destroy(), user callback
 * is placed into a completion queue and can be triggered using HG_Core_trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param usercb [IN]           user-level callback
 * \param userarg [IN]          arg for usercb
 * \param extra_in_buf [IN]     extra input buffer
 * \param extra_in_handle [IN]  bulk handle to extra input buffer
 * \param size_to_send [IN]     size of request to transmit
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_forward(
        hg_handle_t handle,
        hg_cb_t callback,
        hg_cb_t usercb,
        void *userarg,
        void *extra_in_buf,
        hg_bulk_t extra_in_handle,
        hg_size_t size_to_send
        );

/**
 * Respond back to the origin. The output buffer, which can be used to encode
 * the response, must first be queried using HG_Core_get_output().
 * After completion, user callback is placed into a completion queue and can be
 * triggered using HG_Core_trigger().
 * \cond TODO Might add extra_out_handle here as well \endcond
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param ret_code [IN]         return code included in response
 * \param size_to_send [IN]     amount of data to send in response
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Core_respond(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        hg_return_t ret_code,
        hg_size_t size_to_send
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
