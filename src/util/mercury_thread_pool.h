/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
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
#include "mercury_thread_condition.h"
#include "mercury_util_error.h"

typedef struct hg_thread_pool hg_thread_pool_t;

struct hg_thread_pool {
    unsigned int sleeping_worker_count;
    HG_QUEUE_HEAD(hg_thread_work) queue;
    int shutdown;
    hg_thread_mutex_t mutex;
    hg_thread_cond_t cond;
};

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
static HG_UTIL_INLINE int
hg_thread_pool_post(hg_thread_pool_t *pool, struct hg_thread_work *work);

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_pool_post(hg_thread_pool_t *pool, struct hg_thread_work *work)
{
    int ret = HG_UTIL_SUCCESS;

    if (!pool) {
        HG_UTIL_LOG_ERROR("Thread pool not initialized");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (!work) {
        HG_UTIL_LOG_ERROR("Thread work cannot be NULL");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (!work->func) {
        HG_UTIL_LOG_ERROR("Function pointer cannot be NULL");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    hg_thread_mutex_lock(&pool->mutex);

    /* Are we shutting down ? */
    if (pool->shutdown) {
        HG_UTIL_LOG_ERROR("Pool is shutting down");
        ret = HG_UTIL_FAIL;
        goto unlock;
    }

    /* Add task to task queue */
    HG_QUEUE_PUSH_TAIL(&pool->queue, work, entry);

    /* Wake up sleeping worker */
    if (pool->sleeping_worker_count) {
        if (hg_thread_cond_signal(&pool->cond) != HG_UTIL_SUCCESS) {
            HG_UTIL_LOG_ERROR("Cannot signal pool condition");
            ret = HG_UTIL_FAIL;
        }
    }

unlock:
    hg_thread_mutex_unlock(&pool->mutex);

done:
    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_POOL_H */
