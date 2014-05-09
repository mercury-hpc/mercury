/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_H
#define MERCURY_H

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
HG_Version_get(unsigned int *major, unsigned int *minor, unsigned int *patch);

/**
 * Initialize the Mercury layer.
 * Calling HG_Init also calls HG_Bulk_init with the same NA class if
 * HG_Bulk_init has not been called before, this allows users to
 * eventually initialize the bulk interface with a different NA class.
 *
 * \param na_class [IN]    pointer to network class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_class_t *
HG_Init(na_class_t *na_class);

/**
 * Finalize the Mercury layer.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Finalize(hg_class_t *hg_class);

/**
 * Register a function name that can be sent using the RPC layer.
 *
 * \param func_name [IN]        unique name associated to function
 * \param in_proc_cb [IN]       pointer to input proc routine
 * \param out_proc_cb [IN]      pointer to output proc routine
 * \param rpc_cb [IN]           RPC callback (may only be defined in server code)
 *
 * \return unique ID associated to the registered function
 */
HG_EXPORT hg_id_t
HG_Register(hg_class_t *hg_class, const char *func_name,
        hg_proc_cb_t in_proc_cb, hg_proc_cb_t out_proc_cb, hg_rpc_cb_t rpc_cb);

/**
 * Indicate whether HG_Register has been called and return associated ID.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param func_name [IN]        name associated to function
 * \param flag [OUT]            pointer to boolean
 * \param id [OUT]              pointer to ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Registered(hg_class_t *hg_class, const char *func_name, hg_bool_t *flag,
        hg_id_t *id);

/**
 * Forward a call to a remote server.
 * Request must be freed using HG_Request_free.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param addr [IN]             abstract network address of destination
 * \param id [IN]               registered function ID
 * \param in_struct [IN]        pointer to input structure
 * \param out_struct [OUT]      pointer to output structure
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Forward(hg_class_t *hg_class, hg_cb_t callback, void *arg, na_addr_t addr,
        hg_id_t id, void *in_struct, void *out_struct, hg_op_id_t *op_id);

/**
 * Free request and resources allocated when decoding the output.
 * User must get output parameters contained in the output structure
 * before calling HG_Request_free.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param id [IN]               registered function ID
 * \param out_struct [OUT]      pointer to output structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Free_output(hg_class_t *hg_class, hg_id_t id, void *out_struct);

/**
 * Try to progress communication for at most timeout until timeout reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return HG_SUCCESS if any completion has occurred / HG error code otherwise
 */
HG_EXPORT hg_return_t
HG_Progress(hg_class_t *hg_class, unsigned int timeout);

/**
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 *
 * \param hg_class [IN]         pointer to HG class
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count [IN]     actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Trigger(hg_class_t *hg_class, unsigned int timeout, unsigned int max_count,
        unsigned int *actual_count);

/**
 * Convert error return code to string (null terminated).
 *
 * \param errnum [IN]           error return code
 *
 * \return String
 */
HG_EXPORT const char *
HG_Error_to_string(hg_return_t errnum);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_H */
