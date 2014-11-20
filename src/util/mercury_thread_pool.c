/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_thread_pool.h"
#include "mercury_thread_condition.h"
#include "mercury_util_error.h"

#include <stdlib.h>

typedef struct hg_thread_work hg_thread_work_t;

struct hg_thread_work {
    hg_thread_func_t func;
    void *args;
    hg_thread_work_t *next;
};

struct hg_thread_pool {
    unsigned int sleeping_worker_count;
    unsigned int thread_count;
    hg_thread_t *threads;
    unsigned int queue_size;
    hg_thread_work_t *queue_head;
    hg_thread_work_t *queue_tail;
    int shutdown;
    hg_thread_mutex_t mutex;
    hg_thread_cond_t cond;
};

/**
 * Worker thread run by the thread pool
 */
static HG_THREAD_RETURN_TYPE
hg_thread_pool_worker(void *args)
{
    hg_thread_ret_t ret = 0;
    hg_thread_pool_t *pool = (hg_thread_pool_t*) args;
    hg_thread_work_t *work;

    while (1) {
        if (hg_thread_mutex_lock(&pool->mutex) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Cannot lock pool mutex");
            goto done;
        }

        /* If not shutting down and nothing to do, worker sleeps */
        while (!pool->shutdown && (pool->queue_size == 0)) {
            pool->sleeping_worker_count ++;
            if (hg_thread_cond_wait(&pool->cond, &pool->mutex) != HG_UTIL_SUCCESS) {
                HG_UTIL_ERROR_DEFAULT("Thread cannot wait on condition variable");
                goto unlock;
            }
            pool->sleeping_worker_count --;
        }

        if (pool->shutdown && (pool->queue_size == 0)) {
            goto unlock;
        }

        /* Grab our task */
        work = pool->queue_head;
        if (!work) {
            HG_UTIL_ERROR_DEFAULT("Work task cannot be NULL");
            goto unlock;
        }
        pool->queue_size --;
        if (pool->queue_size == 0) {
            pool->queue_head = NULL;
            pool->queue_tail = NULL;
        } else {
            if (!work->next) {
                HG_UTIL_ERROR_DEFAULT("Next work task cannot be NULL");
                goto unlock;
            }
            pool->queue_head = work->next;
        }

        /* Unlock */
        if (hg_thread_mutex_unlock(&pool->mutex) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Cannot unlock pool mutex");
            goto done;
        }

        /* Get to work */
        (*work->func)(work->args);

        free(work);
    }

unlock:
    if (hg_thread_mutex_unlock(&pool->mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Cannot unlock pool mutex");
        goto done;
    }

done:
    hg_thread_exit(ret);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_pool_init(unsigned int thread_count, hg_thread_pool_t **pool)
{
    int ret = HG_UTIL_SUCCESS;
    hg_thread_pool_t *priv_pool = NULL;
    unsigned int i;

    if (!pool) {
        HG_UTIL_ERROR_DEFAULT("Cannot pass NULL pointer");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    priv_pool = (hg_thread_pool_t*) malloc(sizeof(hg_thread_pool_t));
    if (!priv_pool) {
        HG_UTIL_ERROR_DEFAULT("Could not allocate thread pool");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    priv_pool->sleeping_worker_count = 0;
    priv_pool->thread_count = thread_count;
    priv_pool->threads = NULL;
    priv_pool->queue_size = 0;
    priv_pool->queue_head = NULL;
    priv_pool->queue_tail = NULL;
    priv_pool->shutdown = 0;

    if (hg_thread_mutex_init(&priv_pool->mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Could not initialize mutex");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (hg_thread_cond_init(&priv_pool->cond) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Could not initialize thread condition");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    priv_pool->threads = (hg_thread_t*) malloc(thread_count * sizeof(hg_thread_t));
    if (!priv_pool->threads) {
        HG_UTIL_ERROR_DEFAULT("Could not allocate thread pool array");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* Start worker threads */
    for (i = 0; i < thread_count; i++) {
        if (hg_thread_create(&priv_pool->threads[i], hg_thread_pool_worker,
                (void*) priv_pool) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Could not create thread");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    }

    *pool = priv_pool;

done:
    if (ret != HG_UTIL_SUCCESS) {
        if (priv_pool) {
            hg_thread_pool_destroy(priv_pool);
        }
        priv_pool = NULL;
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_pool_destroy(hg_thread_pool_t *pool)
{
    int ret = HG_UTIL_SUCCESS;
    unsigned int i;

    if (!pool) goto done;

    if (pool->threads) {
        if (hg_thread_mutex_lock(&pool->mutex) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Cannot lock pool mutex");
            ret = HG_UTIL_FAIL;
            goto done;
        }

        pool->shutdown = 1;

        if (hg_thread_cond_broadcast(&pool->cond) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Could not broadcast condition signal");
            ret = HG_UTIL_FAIL;
        }

        if (hg_thread_mutex_unlock(&pool->mutex) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Cannot unlock pool mutex");
            ret = HG_UTIL_FAIL;
            goto done;
        }

        if (ret != HG_UTIL_SUCCESS) goto done;

        for(i = 0; i < pool->thread_count; i++) {
            if (hg_thread_join(pool->threads[i]) != HG_UTIL_SUCCESS) {
                HG_UTIL_ERROR_DEFAULT("Could not join thread");
                ret = HG_UTIL_FAIL;
                goto done;
            }
        }
    }

    free(pool->threads);
    pool->threads = NULL;

    if (hg_thread_mutex_destroy(&pool->mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Could not destroy mutex");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    if (hg_thread_cond_destroy(&pool->cond) != HG_UTIL_SUCCESS){
        HG_UTIL_ERROR_DEFAULT("Could not destroy thread condition");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    free(pool);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_pool_post(hg_thread_pool_t *pool, hg_thread_func_t f, void *args)
{
    int ret = HG_UTIL_SUCCESS;
    hg_thread_work_t *work = NULL;

    if (!pool) {
        HG_UTIL_ERROR_DEFAULT("Thread pool not initialized");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (!f) {
        HG_UTIL_ERROR_DEFAULT("Function pointer cannot be NULL");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    work = (hg_thread_work_t*) malloc(sizeof(hg_thread_work_t));
    if (!work) {
        HG_UTIL_ERROR_DEFAULT("Could not allocate pool work");
        ret = HG_UTIL_FAIL;
        goto done;
    }
    work->func = f;
    work->args = args;
    work->next = NULL;

    if (hg_thread_mutex_lock(&pool->mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Cannot lock pool mutex");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* Are we shutting down ? */
    if (pool->shutdown) {
        HG_UTIL_ERROR_DEFAULT("Pool is shutting down");
        ret = HG_UTIL_FAIL;
        goto unlock;
    }

    /* Add task to task queue */
    if(pool->queue_size == 0) {
        pool->queue_head = work;
        pool->queue_tail = pool->queue_head;
    } else {
        pool->queue_tail->next = work;
        pool->queue_tail = work;
    }
    pool->queue_size++;

    /* Wake up sleeping worker */
    if (pool->sleeping_worker_count) {
        if (hg_thread_cond_signal(&pool->cond) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Cannot signal pool condition");
            ret = HG_UTIL_FAIL;
        }
    }

unlock:
    if (hg_thread_mutex_unlock(&pool->mutex) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Cannot unlock pool mutex");
        ret = HG_UTIL_FAIL;
    }

done:
    if (ret != HG_UTIL_SUCCESS) {
        free(work);
    }
    return ret;
}
