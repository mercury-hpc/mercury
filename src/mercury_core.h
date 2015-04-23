/*
 * Copyright (C) 2013-2015 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CORE_H
#define MERCURY_CORE_H

#include "mercury_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get Mercury version number.
 *
 * \param major [OUT]           pointer to unsigned integer
 * \param minor [OUT]           pointer to unsigned integer
 * \param patch [OUT]           pointer to unsigned integer
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Version_get(
        unsigned int *major,
        unsigned int *minor,
        unsigned int *patch
        );

/**
 * Convert error return code to string (null terminated).
 *
 * \param errnum [IN]           error return code
 *
 * \return String
 */
HG_EXPORT const char *
HG_Error_to_string(
        hg_return_t errnum
        );

/**
 * Initialize the Mercury layer from an existing NA class/context.
 * Must be finalized with HG_Finalize().
 * \remark Calling HG_Init() internally calls HG_Bulk_init() with the same NA
 * class if the HG bulk class passed is NULL. The HG bulk interface can however
 * be initialized with a different NA class and, in this case, must be
 * initialized separately by calling HG_Bulk_init().
 *
 * \param na_class [IN]         pointer to NA class
 * \param na_context [IN]       pointer to NA context
 * \param hg_bulk_class [IN]    pointer to HG bulk class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_class_t *
HG_Init(
        na_class_t *na_class,
        na_context_t *na_context,
        hg_bulk_class_t *hg_bulk_class
        );

/**
 * Finalize the Mercury layer.
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Finalize(
        hg_class_t *hg_class
        );

/**
 * Create a new context. Must be destroyed by calling HG_Context_destroy().
 *
 * \param hg_class [IN]         pointer to HG class
 *
 * \return Pointer to HG context or NULL in case of failure
 */
HG_EXPORT hg_context_t *
HG_Context_create(
        hg_class_t *hg_class
        );

/**
 * Destroy a context created by HG_Context_create().
 *
 * \param context [IN]          pointer to HG context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Context_destroy(
        hg_context_t *context
        );

/**
 * Dynamically register a function func_name as an RPC as well as the
 * RPC callback executed when the RPC request ID associated to func_name is
 * received.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param func_name [IN]        unique name associated to function
 * \param rpc_cb [IN]           RPC callback
 *
 * \return unique ID associated to the registered function
 */
HG_EXPORT hg_id_t
HG_Register_rpc(
        hg_class_t *hg_class,
        const char *func_name,
        hg_rpc_cb_t rpc_cb
        );

/**
 * Indicate whether HG_Register_rpc has been called and return associated ID.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param func_name [IN]        name associated to function
 * \param flag [OUT]            pointer to boolean
 * \param id [OUT]              pointer to ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Registered_rpc(
        hg_class_t *hg_class,
        const char *func_name,
        hg_bool_t *flag,
        hg_id_t *id
        );

/**
 * Register and associate user data to registered function. When HG_Finalize()
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
HG_Register_data(
        hg_class_t *hg_class,
        hg_id_t id,
        void *data,
        void (*free_callback)(void *)
        );

/**
 * Indicate whether HG_Register_data() has been called and return associated
 * data.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 *
 * \return Pointer to data or NULL
 */
HG_EXPORT void *
HG_Registered_data(
        hg_class_t *hg_class,
        hg_id_t id
        );

/**
 * Initiate a new HG RPC using the specified function ID and the local/remote
 * target defined by addr. The HG handle created can be used to query input
 * and output buffers, as well as issuing the RPC by using HG_Forward_buf().
 * After completion the handle must be freed using HG_Destroy().
 *
 * \param hg_class [IN]         pointer to HG class
 * \param context [IN]          pointer to HG context
 * \param addr [IN]             abstract network address of destination
 * \param id [IN]               registered function ID
 * \param handle [OUT]          pointer to HG handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Create(
        hg_class_t *hg_class,
        hg_context_t *context,
        na_addr_t addr,
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
HG_Destroy(
        hg_handle_t handle
        );

/**
 * Get info from handle.
 * \remark Users must call NA_Addr_dup() to safely re-use the NA address.
 *
 * \param handle [IN]           HG handle
 *
 * \return Pointer to info or NULL in case of failure
 */
HG_EXPORT struct hg_info *
HG_Get_info(
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
HG_Get_input_buf(
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
HG_Get_output_buf(
        hg_handle_t handle,
        void **out_buf,
        hg_size_t *out_buf_size
        );

/**
 * Forward a call using an existing HG handle. Input and output buffers can be
 * queried from the handle to serialize/deserialize parameters.
 * Additionally, a bulk handle can be passed if the size of the input is larger
 * than the queried input buffer size.
 * After completion, the handle must be freed using HG_Destroy(), user callback
 * is placed into a completion queue and can be triggered using HG_Trigger().
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param extra_in_handle [IN]  bulk handle to extra input buffer
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Forward_buf(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        hg_bulk_t extra_in_handle
        );

/**
 * Respond back to the origin. The output buffer, which can be used to encode
 * the response, must first be queried using HG_Get_output_buf().
 * After completion, user callback is placed into a completion queue and can be
 * triggered using HG_Trigger().
 * \cond TODO Might add extra_out_handle here as well \endcond
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param ret_code [IN]         return code included in response
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Respond_buf(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        hg_return_t ret_code
        );

/**
 * Try to progress RPC execution for at most timeout until timeout is reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param context [IN]          pointer to HG context
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return HG_SUCCESS if any completion has occurred / HG error code otherwise
 */
HG_EXPORT hg_return_t
HG_Progress(
        hg_class_t *hg_class,
        hg_context_t *context,
        unsigned int timeout
        );

/**
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 *
 * \param hg_class [IN]         pointer to HG class
 * \param context [IN]          pointer to HG context
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count [IN]     actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Trigger(
        hg_class_t *hg_class,
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
HG_Cancel(
        hg_handle_t handle
        );

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_CORE_H */
