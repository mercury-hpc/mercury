/*
 * Copyright (C) 2013-2018 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_thread_pool.h"

#include <stdlib.h>

struct hg_thread_pool_private {
    struct hg_thread_pool pool;
    unsigned int thread_count;
    hg_thread_t *threads;
};

/**
 * Worker thread run by the thread pool
 */
static HG_THREAD_RETURN_TYPE
hg_thread_pool_worker(void *args)
{
    hg_thread_ret_t ret = 0;
    hg_thread_pool_t *pool = (hg_thread_pool_t*) args;
    struct hg_thread_work *work;

    while (1) {
        hg_thread_mutex_lock(&pool->mutex);

        /* If not shutting down and nothing to do, worker sleeps */
        while (!pool->shutdown && HG_QUEUE_IS_EMPTY(&pool->queue)) {
            pool->sleeping_worker_count++;
            if (hg_thread_cond_wait(&pool->cond, &pool->mutex) != HG_UTIL_SUCCESS) {
                HG_UTIL_LOG_ERROR("Thread cannot wait on condition variable");
                goto unlock;
            }
            pool->sleeping_worker_count--;
        }

        if (pool->shutdown && HG_QUEUE_IS_EMPTY(&pool->queue)) {
            goto unlock;
        }

        /* Grab our task */
        work = HG_QUEUE_FIRST(&pool->queue);
        HG_QUEUE_POP_HEAD(&pool->queue, entry);

        /* Unlock */
        hg_thread_mutex_unlock(&pool->mutex);

        /* Get to work */
        (*work->func)(work->args);
    }

unlock:
    hg_thread_mutex_unlock(&pool->mutex);
    hg_thread_exit(ret);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_pool_init(unsigned int thread_count, hg_thread_pool_t **pool_ptr)
{
    int ret = HG_UTIL_SUCCESS;
    struct hg_thread_pool_private *priv_pool = NULL;
    unsigned int i;

    if (!pool_ptr) {
        HG_UTIL_LOG_ERROR("Cannot pass NULL pointer");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    priv_pool = (struct hg_thread_pool_private *) malloc(
        sizeof(struct hg_thread_pool_private));
    if (!priv_pool) {
        HG_UTIL_LOG_ERROR("Could not allocate thread pool");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    priv_pool->pool.sleeping_worker_count = 0;
    priv_pool->thread_count = thread_count;
    priv_pool->threads = NULL;
    HG_QUEUE_INIT(&priv_pool->pool.queue);
    priv_pool->pool.shutdown = 0;

    if (hg_thread_mutex_init(&priv_pool->pool.mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_LOG_ERROR("Could not initialize mutex");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (hg_thread_cond_init(&priv_pool->pool.cond) != HG_UTIL_SUCCESS) {
        HG_UTIL_LOG_ERROR("Could not initialize thread condition");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    priv_pool->threads = (hg_thread_t*) malloc(thread_count * sizeof(hg_thread_t));
    if (!priv_pool->threads) {
        HG_UTIL_LOG_ERROR("Could not allocate thread pool array");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* Start worker threads */
    for (i = 0; i < thread_count; i++) {
        if (hg_thread_create(&priv_pool->threads[i], hg_thread_pool_worker,
                (void*) priv_pool) != HG_UTIL_SUCCESS) {
            HG_UTIL_LOG_ERROR("Could not create thread");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    }

    *pool_ptr = (struct hg_thread_pool *) priv_pool;

done:
    if (ret != HG_UTIL_SUCCESS) {
        if (priv_pool) {
            hg_thread_pool_destroy((struct hg_thread_pool *) priv_pool);
        }
        priv_pool = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_pool_destroy(hg_thread_pool_t *pool)
{
    struct hg_thread_pool_private *priv_pool =
        (struct hg_thread_pool_private *) pool;
    int ret = HG_UTIL_SUCCESS;
    unsigned int i;

    if (!priv_pool) goto done;

    if (priv_pool->threads) {
        hg_thread_mutex_lock(&priv_pool->pool.mutex);

        priv_pool->pool.shutdown = 1;

        if (hg_thread_cond_broadcast(&priv_pool->pool.cond) != HG_UTIL_SUCCESS) {
            HG_UTIL_LOG_ERROR("Could not broadcast condition signal");
            ret = HG_UTIL_FAIL;
        }

        hg_thread_mutex_unlock(&priv_pool->pool.mutex);

        if (ret != HG_UTIL_SUCCESS) goto done;

        for(i = 0; i < priv_pool->thread_count; i++) {
            if (hg_thread_join(priv_pool->threads[i]) != HG_UTIL_SUCCESS) {
                HG_UTIL_LOG_ERROR("Could not join thread");
                ret = HG_UTIL_FAIL;
                goto done;
            }
        }
    }

    free(priv_pool->threads);
    priv_pool->threads = NULL;

    if (hg_thread_mutex_destroy(&priv_pool->pool.mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_LOG_ERROR("Could not destroy mutex");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (hg_thread_cond_destroy(&priv_pool->pool.cond) != HG_UTIL_SUCCESS){
        HG_UTIL_LOG_ERROR("Could not destroy thread condition");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    free(priv_pool);

done:
    return ret;
}
