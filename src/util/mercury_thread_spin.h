/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_THREAD_SPIN_H
#define MERCURY_THREAD_SPIN_H

#include "mercury_util_config.h"
#if defined(_WIN32)
# include <windows.h>
typedef volatile LONG hg_thread_spin_t;
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
# include <pthread.h>
# include <errno.h>
typedef pthread_spinlock_t hg_thread_spin_t;
#else
/* Default to hg_thread_mutex_t if pthread_spinlock_t is not supported */
# include "mercury_thread_mutex.h"
typedef hg_thread_mutex_t hg_thread_spin_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the spin lock.
 *
 * \param lock [IN/OUT]         pointer to lock object
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_thread_spin_init(hg_thread_spin_t *lock);

/**
 * Destroy the spin lock.
 *
 * \param lock [IN/OUT]         pointer to lock object
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_thread_spin_destroy(hg_thread_spin_t *lock);

/**
 * Lock the spin lock.
 *
 * \param lock [IN/OUT]         pointer to lock object
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_thread_spin_lock(hg_thread_spin_t *lock);

/**
 * Try locking the spin lock.
 *
 * \param mutex [IN/OUT]        pointer to lock object
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_thread_spin_try_lock(hg_thread_spin_t *lock);

/**
 * Unlock the spin lock.
 *
 * \param mutex [IN/OUT]        pointer to lock object
 *
 * \return Non-negative on success or negative on failure
 */
static HG_UTIL_INLINE int
hg_thread_spin_unlock(hg_thread_spin_t *lock);

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_spin_init(hg_thread_spin_t *lock)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    *lock = 0;
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
    if (pthread_spin_init(lock, 0)) ret = HG_UTIL_FAIL;
#else
    ret = hg_thread_mutex_init(lock);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_spin_destroy(hg_thread_spin_t *lock)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    (void) lock;
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
    if (pthread_spin_destroy(lock)) ret = HG_UTIL_FAIL;
#else
    ret = hg_thread_mutex_destroy(lock);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_spin_lock(hg_thread_spin_t *lock)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    while (InterlockedExchange(lock, EBUSY)) {
        /* Don't lock while waiting */
        while (*lock) {
            YieldProcessor();

            /* Compiler barrier. Prevent caching of *lock */
            MemoryBarrier();
        }
    }
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
    if (pthread_spin_lock(lock)) ret = HG_UTIL_FAIL;
#else
    ret = hg_thread_mutex_lock(lock);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_spin_try_lock(hg_thread_spin_t *lock)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    ret = InterlockedExchange(lock, EBUSY);
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
    if (pthread_spin_trylock(lock)) ret = HG_UTIL_FAIL;
#else
    ret = hg_thread_mutex_try_lock(lock);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_UTIL_INLINE int
hg_thread_spin_unlock(hg_thread_spin_t *lock)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    /* Compiler barrier. The store below acts with release semantics */
    MemoryBarrier();

    *lock = 0;
#elif defined(HG_UTIL_HAS_PTHREAD_SPINLOCK_T)
    if (pthread_spin_unlock(lock)) ret = HG_UTIL_FAIL;
#else
    ret = hg_thread_mutex_unlock(lock);
#endif

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_SPIN_H */
