/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_REQUEST_H
#define MERCURY_REQUEST_H

#include "mercury_util_config.h"

/**
 * Purpose: define a request emulation library on top of the callback model
 * that uses progress/trigger functions.
 */

typedef struct hg_request_class  hg_request_class_t;  /* Opaque request class */
typedef struct hg_request hg_request_t; /* Opaque request object */

/**
 * Progress callback, arg can be used to pass extra parameters required by
 * underlying API.
 *
 * \param timeout [IN]          timeout (in milliseconds)
 * \param arg [IN]              pointer to data passed to callback
 *
 * \return HG_UTIL_SUCCESS if any completion has occurred / error code otherwise
 */
typedef int (*hg_request_progress_func_t)(unsigned int timeout, void *arg);

/**
 * Trigger callback, arg can be used to pass extra parameters required by
 * underlying API.
 *
 * \param timeout [IN]          timeout (in milliseconds)
 * \param flag [OUT]            1 if callback has been triggered, 0 otherwise
 * \param arg [IN]              pointer to data passed to callback
 *
 * \return HG_UTIL_SUCCESS or corresponding error code
 */
typedef int (*hg_request_trigger_func_t)(unsigned int timeout,
        unsigned int *flag, void *arg);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the request class with the specific progress/trigger functions
 * that will be called on hg_request_wait().
 * arg can be used to pass extra parameters required by underlying API.
 *
 * \param progress [IN]         progress function
 * \param trigger [IN]          trigger function
 * \param arg [IN]              pointer to data passed to callback
 *
 * \return Pointer to request class or NULL in case of failure
 */
HG_UTIL_EXPORT hg_request_class_t *
hg_request_init(hg_request_progress_func_t progress,
        hg_request_trigger_func_t trigger, void *arg);

/**
 * Finalize the request class.
 *
 * \param request_class [IN]    pointer to request class
 */
HG_UTIL_EXPORT int
hg_request_finalize(hg_request_class_t *request_class);

/**
 * Create a new request from a specified request class. The progress function
 * explicitly makes progress and may insert the completed operation into a
 * completion queue. The operation gets triggered after a call to the trigger
 * function.
 *
 * \param request_class [IN]    pointer to request class
 *
 * \return Pointer to request or NULL in case of failure
 */
HG_UTIL_EXPORT hg_request_t *
hg_request_create(hg_request_class_t *request_class);

/**
 * Destroy the request, freeing the resources.
 *
 * \param request [IN/OUT]      pointer to request
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_request_destroy(hg_request_t *request);

/**
 * Mark the request as completed. (most likely called by a callback triggered
 * after a call to trigger)
 *
 * \param request [IN/OUT]      pointer to request
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_request_complete(hg_request_t *request);

/**
 * Wait timeout ms for the specified request to complete.
 *
 * \param request [IN/OUT]      pointer to request
 * \param timeout [IN]          timeout (in milliseconds)
 * \param flag [OUT]            1 if request has completed, 0 otherwise
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_request_wait(hg_request_t *request, unsigned int timeout,
        unsigned int *flag);

/**
 * Wait timeout ms for all the specified request to complete.
 *
 * \param count [IN]            number of requests
 * \param request [IN/OUT]      arrays of requests
 * \param timeout [IN]          timeout (in milliseconds)
 * \param flag [OUT]            1 if all requests have completed, 0 otherwise
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_request_waitall(int count, hg_request_t *request[],  unsigned int timeout,
        unsigned int *flag);

/**
 * Attach user data to a specified request.
 *
 * \param request [IN/OUT]      pointer to request
 * \param data [IN]             pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_request_set_data(hg_request_t *request, void *data);

/**
 * Get user data from a specified request.
 *
 * \param request [IN/OUT]      pointer to request
 *
 * \return Pointer to data or NULL if nothing was attached by user
 */
HG_UTIL_EXPORT void *
hg_request_get_data(hg_request_t *request);

/**
 * Cancel the request.
 *
 * \param request [IN]          request object
 *
 * \return Non-negative on success or negative on failure
 *
HG_UTIL_EXPORT int
hg_request_cancel(hg_request_t *request);
 */

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_REQUEST_H */
