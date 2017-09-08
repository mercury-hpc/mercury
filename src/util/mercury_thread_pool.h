/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_THREAD_POOL_H
#define MERCURY_THREAD_POOL_H

#include "mercury_thread.h"
#include "mercury_queue.h"

typedef struct hg_thread_pool hg_thread_pool_t;

struct hg_thread_work {
    hg_thread_func_t func;
    void *args;
    HG_QUEUE_ENTRY(hg_thread_work) entry; /* Internal */
};

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
 * Post work to the pool. Note that the operation may be queued depending on
 * the number of threads and number of tasks already running.
 *
 * \param pool [IN/OUT]         pointer to pool object
 * \param work [IN]             pointer to work struct
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_pool_post(hg_thread_pool_t *pool, struct hg_thread_work *work);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_POOL_H */
