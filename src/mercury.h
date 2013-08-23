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
 * Initialize the function shipper layer.
 *
 * \param network_class [IN]    pointer to network class
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Init(na_class_t *network_class);

/**
 * Finalize the function shipper layer.
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Finalize(void);

/**
 * Indicate whether HG_Init has been called
 * and return associated network class.
 *
 * \param flag [OUT]            pointer to boolean
 * \param na_class_t [OUT]      pointer to returned network class pointer
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Initialized(hg_bool_t *flag, na_class_t **network_class);

/**
 * Register a function name that can be sent by RPC layer.
 *
 * \param func_name [IN]        unique name associated to function
 * \param enc_routine [IN]      pointer to serializing routine
 * \param dec_routine [IN]      pointer to deserializing routine
 *
 * \return unique ID associated to the registered function
 */
HG_EXPORT hg_id_t
HG_Register(const char *func_name,
        int (*enc_routine)(hg_proc_t proc, void *in_struct),
        int (*dec_routine)(hg_proc_t proc, void *out_struct));

/**
 * Indicate whether HG_Register has been called and return associated ID.
 *
 * \param func_name [IN]        name associated to function
 * \param flag [OUT]            pointer to boolean
 * \param id [OUT]              pointer to ID
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Registered(const char *func_name, hg_bool_t *flag, hg_id_t *id);

/**
 * Forward a call to a remote server.
 *
 * \param addr [IN]             abstract network address of destination
 * \param id [IN]               registered function ID
 * \param in_struct [IN]        pointer to input structure
 * \param out_struct [OUT]      pointer to output structure
 * \param request [OUT]         pointer to RPC request
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Forward(na_addr_t addr, hg_id_t id,
        void *in_struct, void *out_struct, hg_request_t *request);

/**
 * Wait for an operation request to complete.
 *
 * \param request [IN]          RPC request
 * \param timeout [IN]          timeout (in milliseconds)
 * \param status [OUT]          pointer to returned status
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Wait(hg_request_t request, unsigned int timeout, hg_status_t *status);

/**
 * Wait for all operations in array_of_requests to complete.
 *
 * \param count [IN]              number of RPC requests
 * \param array_of_requests [IN]  arrays of RPC requests
 * \param timeout [IN]            timeout (in milliseconds)
 * \param array_of_statuses [OUT] array of statuses
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Wait_all(int count, hg_request_t array_of_requests[],
        unsigned int timeout, hg_status_t array_of_statuses[]);

/**
 * Free eventual resources allocated when decoding the output.
 *
 * \param id [IN]               registered function ID
 * \param out_struct [OUT]      pointer to output structure
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Free_output(hg_id_t id, void *out_struct);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_H */
