/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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
 * Dynamically register a function func_name as an RPC as well as the
 * RPC callback executed when the RPC request ID associated to func_name is
 * received. Associate input and output proc to function ID, so that they can
 * be used to serialize and deserialize function parameters.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 * \param in_proc_cb [IN]       pointer to input proc callback
 * \param out_proc_cb [IN]      pointer to output proc callback
 *
 * \return unique ID associated to the registered function
 */
HG_EXPORT hg_id_t
HG_Register(
        hg_class_t *hg_class,
        const char *func_name,
        hg_proc_cb_t in_proc_cb,
        hg_proc_cb_t out_proc_cb,
        hg_rpc_cb_t rpc_cb
        );

/**
 * Get input from handle (requires registration of input proc to deserialize
 * parameters). This is equivalent to:
 *   - HG_Get_input_buf
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
 * parameters). This is equivalent to:
 *   - HG_Get_output_buf
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
 * Forward a call to the network address defined by addr. If addr is a local
 * address, the callback associated to id is executed locally.
 * After completion the returned op_id must be freed using HG_Complete().
 * Output can be queried using HG_Get_output() and freed using HG_Free_output().
 * This routine is internally equivalent to:
 *   - HG_Get_input_buf
 *   - Call hg_proc to serialize parameters
 *   - HG_Forward_buf
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
 * Respond back to caller using information stored in operation ID (requires
 * registration of output proc to serialize parameters)
 * This routine is internally equivalent to:
 *   - HG_Get_output_buf
 *   - Call hg_proc to serialize parameters
 *   - HG_Respond_buf
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

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_H */
