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
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return Abstract network address
 */
HG_EXPORT na_addr_t
HG_Handler_get_addr(hg_handle_t handle);

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
 * Try timeout ms to process RPC requests.
 *
 * \param timeout [IN]          timeout (in milliseconds)
 * \param status [OUT]          pointer to status object
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_process(unsigned int timeout, hg_status_t *status);

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

/**
 * Free an RPC handle.
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_free(hg_handle_t handle);

/**
 * NB. The following routines are added for convenience
 */

/**
 * Get input from handle (requires registration of decoding function).
 * This is equivalent to:
 *   - HG_Handler_get_input_buf
 *   - decode proc
 *
 * \param handle [IN]           abstract RPC handle
 * \param in_struct [OUT]       pointer to input structure that will be
 *                              filled with deserialized input parameters of
 *                              RPC call
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_get_input(hg_handle_t handle, void *in_struct);

/**
 * Start sending output from handle (requires registration of encoding function)
 * This is equivalent to:
 *   - HG_Handler_get_output_buf
 *   - encode
 *   - HG_Handler_start_response
 *
 * \param handle [IN]           abstract RPC handle
 * \param out_struct [IN]       pointer to output structure that has been
 *                              filled with output parameters and which will
 *                              be serialized into a buffer. This buffer is then
 *                              sent using a non-blocking send.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Handler_start_output(hg_handle_t handle, void *out_struct);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HANDLER_H */
