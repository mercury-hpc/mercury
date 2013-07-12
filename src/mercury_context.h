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
 * Create a new context.
 *
 * \param context [OUT]         pointer to context object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_create(hg_context_t *context);

/**
 * Return number of requests in context.
 *
 * \param context [IN]          context object
 *
 * \return Non-negative value
 */
HG_EXPORT unsigned int
HG_Context_get_size(hg_context_t context);

/**
 * Get request handles from context. Returns an error if the output
 * array is not big enough.
 *
 * \param context [IN]            pointer to context object
 * \param max_count [IN]          maximum number of requests get can return
 * \param array_of_requests [IN]  array of requests
 * \param count [OUT]             pointer to returned number of requests
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_get(hg_context_t context, unsigned int max_count,
        hg_request_t array_of_requests[], unsigned int *count);

/**
 * Free a context. The context should be empty or an error will be returned.
 *
 * \param context [IN]          context object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_free(hg_context_t context);

/**
 * Add request handle to context. A request can be added to at most one
 * context. A request can be added to a context even if that context is
 * being used by HG_Context_wait.
 *
 * A request that is part of a context can only be completed by
 * calling HG_Context_wait (i.e. not using the other wait functions).
 *
 * \param context [IN]          context object
 * \param request [IN]          request object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_add(hg_context_t context, hg_request_t request);

/**
 * Remove a request from a context. The request can be removed
 * from a context even if HG_Context_wait is called on that context.
 *
 * \param context [IN]          context object
 * \param request [IN]          request object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_remove(hg_context_t context, hg_request_t request);

/**
 * Removes completed requests from context and puts the statuses
 * in an array. Returns number of completed operations in count.
 *
 * \param context [IN]            context object
 * \param timeout [IN]            timeout (in milliseconds)
 * \param max_count [IN]          maximum number of completed requests
 * \param array_of_statuses [IN]  array of statuses
 * \param count [OUT]             number of completed requests
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Context_wait(hg_context_t context, unsigned int timeout,
        int max_count, hg_status_t array_of_statuses[], int *count);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_H */
