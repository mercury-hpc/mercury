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
 * Initialize the function shipper handler layer.
 *
 * \param network_class [IN]    pointer to network class
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_init(na_class_t *network_class);

/**
 * Finalize the function shipper handler layer.
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_finalize(void);

/**
 * Register a function name that can be received and handled by RPC layer.
 *
 * \param func_name [IN]        unique name associated to function
 * \param callback_routine [IN] pointer to RPC routine that is called when
 *                              a new RPC request that corresponds to func_name
 *                              arrives
 * \param dec_routine [IN]      pointer to deserializing routine
 * \param enc_routine [IN]      pointer to serializing routine
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_register(const char *func_name,
        int (*callback_routine) (hg_handle_t handle),
        int (*dec_routine)(hg_proc_t proc, void *in_struct),
        int (*enc_routine)(hg_proc_t proc, void *out_struct));

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
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_get_input_buf(hg_handle_t handle, void **in_buf,
        size_t *in_buf_size);

/**
 * Get RPC output buffer from handle.
 *
 * \param handle [IN]           abstract RPC handle
 * \param out_buf [OUT]         pointer to output buffer
 * \param out_buf_size [OUT]    pointer to output buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_get_output_buf(hg_handle_t handle, void **out_buf,
        size_t *out_buf_size);

/**
 * Try timeout ms to process RPC requests.
 *
 * \param timeout [IN]          timeout (in milliseconds)
 * \param status [OUT]          pointer to status object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_process(unsigned int timeout, hg_status_t *status);

/**
 * Send the response back to the caller and free handle.
 *
 * \param handle [IN]                 abstract RPC handle
 * \param extra_out_buf [OUT]         pointer to extra output buffer
 * \param extra_out_buf_size [OUT]    pointer to extra output buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_start_response(hg_handle_t handle, void *extra_out_buf,
        size_t extra_out_buf_size);

/**
 * Wait timeout ms for the response of an RPC request to complete and free
 * RPC handle if it has completed.
 *
 * \param handle [IN]           abstract RPC handle
 * \param timeout [IN]          timeout (in milliseconds)
 * \param status [OUT]          pointer to status object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_wait_response(hg_handle_t handle, unsigned int timeout,
        hg_status_t *status);

/**
 * Free an RPC handle.
 *
 * \param handle [IN]           abstract RPC handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
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
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
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
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Handler_start_output(hg_handle_t handle, void *out_struct);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HANDLER_H */
