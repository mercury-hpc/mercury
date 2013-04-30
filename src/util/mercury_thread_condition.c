/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_thread_condition.h"
#include "mercury_error.h"

#ifndef _WIN32
#include <sys/time.h>
#include <stdlib.h>
#endif

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cond_init
 *
 * Purpose:     Initialize the condition
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cond_init(hg_thread_cond_t *cond)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    InitializeConditionVariable(cond);
#else
    if (pthread_cond_init(cond, NULL)) ret = HG_FAIL;
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cond_destroy
 *
 * Purpose:     Destroy the condition
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cond_destroy(hg_thread_cond_t *cond)
{
    int ret = HG_SUCCESS;

#ifndef _WIN32
    if (pthread_cond_destroy(cond)) ret = HG_FAIL;
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cond_signal
 *
 * Purpose:     Wake one thread waiting for the condition to change
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cond_signal(hg_thread_cond_t *cond)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    WakeConditionVariable(cond);
#else
    if (pthread_cond_signal(cond)) ret = HG_FAIL;
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cond_wait
 *
 * Purpose:     Wait for the condition to change
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cond_wait(hg_thread_cond_t *cond, hg_thread_mutex_t *mutex)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    if (!SleepConditionVariableCS(cond, mutex, INFINITE)) ret = HG_FAIL;
#else
    if (pthread_cond_wait(cond, mutex)) ret = HG_FAIL;
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cond_timedwait
 *
 * Purpose:     Wait timeout (ms) for the condition to change
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cond_timedwait(hg_thread_cond_t *cond, hg_thread_mutex_t *mutex, unsigned int timeout)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    if (!SleepConditionVariableCS(cond, mutex, timeout)) ret = HG_FAIL;
#else
    int pret;
    struct timeval now;
    struct timespec abs_timeout;
    long int abs_timeout_us;
    ldiv_t ld;

    /* Need to convert timeout (ms) to absolute time */
    gettimeofday(&now, NULL);
    abs_timeout_us = now.tv_usec + timeout * 1000L;
    /* Get sec / nsec */
    ld = ldiv(abs_timeout_us, 1000000L);
    abs_timeout.tv_sec = now.tv_sec + ld.quot;
    abs_timeout.tv_nsec = ld.rem * 1000L;

    pret = pthread_cond_timedwait(cond, mutex, &abs_timeout);
    if (pret) {
        switch (pret) {
            case ETIMEDOUT:
                HG_ERROR_DEFAULT("Timeout");
                break;
            default:
                HG_ERROR_DEFAULT("Unknown error return");
                break;
        }
        ret = HG_FAIL;
    }
#endif

    return ret;
}
