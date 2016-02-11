/*
 * Copyright (C) 2013-2015 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_H
#define MERCURY_H

#include "mercury_core.h"

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
 * Retrieve the Mercury bulk class instance from the given Mercury class.
 * Note that HG_Bulk_finalize should *not* be called on the returned
 * instance if the bulk class is internal to the input class (that is, NULL
 * was passed as the bulk class to HG_Init).
 *
 * \param hg_class [IN] HG class
 *
 * \return The corresponding bulk class
 */
HG_EXPORT hg_bulk_class_t *
HG_Get_bulk_class(
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
 * Retrieve the Mercury bulk context instance from the given Mercury context.
 * Note that HG_Bulk_context_destroy should *not* be called on the returned
 * context if the bulk context is internal to the input context (in the current
 * API, this is always the case, but may not be in future revisions).
 *
 * \param hg_context [IN] HG context
 *
 * \return The corresponding bulk context
 */
HG_EXPORT hg_bulk_context_t *
HG_Get_bulk_context(
        hg_context_t *hg_context
        );

/**
 * Dynamically register a function func_name as an RPC as well as the
 * RPC callback executed when the RPC request ID associated to func_name is
 * received. Associate input and output proc to function ID, so that they can
 * be used to serialize and deserialize function parameters.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param func_name [IN]        unique name associated to function
 * \param in_proc_cb [IN]       pointer to input proc callback
 * \param out_proc_cb [IN]      pointer to output proc callback
 * \param rpc_cb [IN]           RPC callback
 *
 * \return unique ID associated to the registered function
 */
HG_EXPORT hg_id_t
HG_Register_name(
        hg_class_t *hg_class,
        const char *func_name,
        hg_proc_cb_t in_proc_cb,
        hg_proc_cb_t out_proc_cb,
        hg_rpc_cb_t rpc_cb
        );

/**
 * Dynamically register an RPC ID as well as the RPC callback executed when the
 * RPC request ID is received. Associate input and output proc to id, so that
 * they can be used to serialize and deserialize function parameters.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               ID to use to register RPC
 * \param in_proc_cb [IN]       pointer to input proc callback
 * \param out_proc_cb [IN]      pointer to output proc callback
 * \param rpc_cb [IN]           RPC callback
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Register(
        hg_class_t *hg_class,
        hg_id_t id,
        hg_proc_cb_t in_proc_cb,
        hg_proc_cb_t out_proc_cb,
        hg_rpc_cb_t rpc_cb
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
 * and output, as well as issuing the RPC by using HG_Forward().
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
 * Get input from handle (requires registration of input proc to deserialize
 * parameters).
 * \remark This is equivalent to:
 *   - HG_Core_get_input()
 *   - Call hg_proc to deserialize parameters
 * Input must be freed using HG_Free_input().
 *
 * \param handle [IN]           HG handle
 * \param in_struct [IN/OUT]    pointer to input structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Get_input(
        hg_handle_t handle,
        void *in_struct
        );

/**
 * Free resources allocated when deserializing the input.
 * User may copy parameters contained in the input structure before calling
 * HG_Free_input().
 *
 * \param handle [IN]           HG handle
 * \param in_struct [IN/OUT]    pointer to input structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Free_input(
        hg_handle_t handle,
        void *in_struct
        );

/**
 * Get output from handle (requires registration of output proc to deserialize
 * parameters).
 * \remark This is equivalent to:
 *   - HG_Core_get_output()
 *   - Call hg_proc to deserialize parameters
 * Output must be freed using HG_Free_output().
 *
 * \param handle [IN]           HG handle
 * \param out_struct [IN/OUT]   pointer to output structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Get_output(
        hg_handle_t handle,
        void *out_struct
        );

/**
 * Free resources allocated when deserializing the output.
 * User may copy parameters contained in the output structure before calling
 * HG_Free_output().
 *
 * \param handle [IN]           HG handle
 * \param out_struct [IN/OUT]   pointer to input structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Free_output(
        hg_handle_t handle,
        void *out_struct
        );

/**
 * Forward a call to a local/remote target using an existing HG handle.
 * Input structure can be passed and parameters serialized using a previously
 * registered input proc. After completion, user callback is placed into a
 * completion queue and can be triggered using HG_Trigger(). RPC output can
 * be queried using HG_Get_output() and freed using HG_Free_output().
 * \remark This routine is internally equivalent to:
 *   - HG_Core_get_input()
 *   - Call hg_proc to serialize parameters
 *   - HG_Core_forward()
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param in_struct [IN]        pointer to input structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Forward(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        void *in_struct
        );

/**
 * Respond back to origin using an existing HG handle.
 * Output structure can be passed and parameters serialized using a previously
 * registered output proc. After completion, user callback is placed into a
 * completion queue and can be triggered using HG_Trigger().
 * \remark This routine is internally equivalent to:
 *   - HG_Core_get_output()
 *   - Call hg_proc to serialize parameters
 *   - HG_Core_respond()
 *
 * \param handle [IN]           HG handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param out_struct [IN]       pointer to output structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Respond(
        hg_handle_t handle,
        hg_cb_t callback,
        void *arg,
        void *out_struct
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

#endif /* MERCURY_H */
