/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_THREAD_POOL_H
#define MERCURY_THREAD_POOL_H

#include "mercury_util_config.h"
#include "mercury_thread.h"

typedef struct hg_thread_pool hg_thread_pool_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the thread pool.
 *
 * \param thread_count [IN]     number of threads that will be created at
 *                              initialization
 * \param pool [OUT]            pointer to pool object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_pool_init(unsigned int thread_count, hg_thread_pool_t **pool);

/**
 * Destroy the thread pool.
 *
 * \param pool [IN/OUT]         pointer to pool object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_pool_destroy(hg_thread_pool_t *pool);

/**
 * Post the work function f to the pool. Note that the operation may
 * be queued depending on the number of threads and number of tasks already
 * running.
 *
 * \param pool [IN/OUT]         pointer to pool object
 * \param f [IN]                pointer to function
 * \param args [IN]             pointer to data that can be passed to function f
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_pool_post(hg_thread_pool_t *pool, hg_thread_func_t f, void *args);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_POOL_H */
