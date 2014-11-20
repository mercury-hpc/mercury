/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_THREAD_MUTEX_H
#define MERCURY_THREAD_MUTEX_H

#include "mercury_util_config.h"
#ifdef _WIN32
  #include <windows.h>
  typedef CRITICAL_SECTION hg_thread_mutex_t;
#else
  #include <pthread.h>
  #include <errno.h>
  typedef pthread_mutex_t hg_thread_mutex_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the mutex.
 *
 * \param mutex [IN/OUT]        pointer to mutex object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_mutex_init(hg_thread_mutex_t *mutex);

/**
 * Destroy the mutex.
 *
 * \param mutex [IN/OUT]        pointer to mutex object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_mutex_destroy(hg_thread_mutex_t *mutex);

/**
 * Lock the mutex.
 *
 * \param mutex [IN/OUT]        pointer to mutex object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_mutex_lock(hg_thread_mutex_t *mutex);

/**
 * Try locking the mutex.
 *
 * \param mutex [IN/OUT]        pointer to mutex object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_mutex_try_lock(hg_thread_mutex_t *mutex);

/**
 * Unlock the mutex.
 *
 * \param mutex [IN/OUT]        pointer to mutex object
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_thread_mutex_unlock(hg_thread_mutex_t *mutex);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_MUTEX_H */
