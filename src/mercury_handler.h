/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HANDLER_H
#define MERCURY_HANDLER_H

#include "mercury_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get abstract network address of remote caller from RPC handle.
 * The address gets freed when HG_Handler_free is called. Users
 * must call NA_Addr_dup to be able to safely re-use the address.
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return Abstract network address
 */
HG_EXPORT na_addr_t
HG_Handler_get_addr(hg_handle_t handle);

/**
 * Get NA class associated with handle.
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return Abstract NA class
 */
HG_EXPORT na_class_t *
HG_Handler_get_na_class(hg_handle_t handle);

/**
 * Get input from handle (requires registration of input proc to deserialize
 * parameters).
 * This is equivalent to:
 *   - HG_Handler_get_input_buf
 *   - Call hg_proc to deserialize parameters
 *
 * \param handle [IN]           abstract RPC handle
 * \param in_struct [OUT]       pointer to input structure that will be
 *                              filled with deserialized input parameters of
 *                              RPC call.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_get_input(hg_handle_t handle, void *in_struct);

/**
 * Free input members allocated during deserialization operation.
 */
HG_EXPORT hg_return_t
HG_Handler_free_input(hg_handle_t handle, void *in_struct);

/**
 * Start sending output from handle (requires registration of output proc to
 * serialize parameters)
 * This is equivalent to:
 *   - HG_Handler_get_output_buf
 *   - Call hg_proc to serialize parameters
 *   - HG_Handler_start_response
 *
 * \param handle [IN]           abstract RPC handle
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param out_struct [IN]       pointer to output structure that has been
 *                              filled with output parameters and which will
 *                              be serialized into a buffer. This buffer is then
 *                              sent using a non-blocking expected send.
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_respond(hg_handle_t handle, hg_cb_t callback, void *arg,
        void *out_struct, hg_op_id_t *op_id);

/**
 * Release resources allocated for handling the RPC.
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_free(hg_handle_t handle);

/************ TO BE MOVED TO LOWER LAYER ***************/

/**
 * Get RPC input buffer from handle.
 *
 * \param handle [IN]           abstract RPC handle
 * \param in_buf [OUT]          pointer to input buffer
 * \param in_buf_size [OUT]     pointer to input buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_get_input_buf(hg_handle_t handle, void **in_buf,
        size_t *in_buf_size);

/**
 * Get RPC output buffer from handle.
 *
 * \param handle [IN]           abstract RPC handle
 * \param out_buf [OUT]         pointer to output buffer
 * \param out_buf_size [OUT]    pointer to output buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_get_output_buf(hg_handle_t handle, void **out_buf,
        size_t *out_buf_size);

/**
 * Send the response back to the caller and free handle when it completes.
 *
 * \param handle [IN]                 abstract RPC handle
 * \param extra_out_buf [OUT]         pointer to extra output buffer
 * \param extra_out_buf_size [OUT]    pointer to extra output buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_start_response(hg_handle_t handle, void *extra_out_buf,
        size_t extra_out_buf_size);


#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HANDLER_H */
