/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_thread.h"
#include "mercury_error.h"

/*---------------------------------------------------------------------------
 * Function:    hg_thread_init
 *
 * Purpose:     Initialize the mutex
 *
 * Returns:     None
 *
 *---------------------------------------------------------------------------
 */
void hg_thread_init(hg_thread_t *thread)
{
#ifdef _WIN32
    *thread = NULL;
#else
    *thread = 0;
#endif
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_create
 *
 * Purpose:     Create a new thread for the given function
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_create(hg_thread_t *thread, hg_thread_func_t f, void *data)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    *thread = CreateThread(NULL, 0, f, data, 0, NULL);
    if (*thread == NULL) ret = HG_FAIL;
#else
    if (pthread_create(thread, NULL, f, data)) {
        HG_ERROR_DEFAULT("pthread_create failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_join
 *
 * Purpose:     Wait for thread completion
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_join(hg_thread_t thread)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    if (pthread_join(thread, NULL)) {
        HG_ERROR_DEFAULT("pthread_join failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_cancel
 *
 * Purpose:     Terminate the thread
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_cancel(hg_thread_t thread)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    WaitForSingleObject(thread, 0);
    CloseHandle(thread);
#else
    if (pthread_cancel(thread)) {
        HG_ERROR_DEFAULT("pthread_cancel failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_key_create
 *
 * Purpose:     Create a thread-specific data key visible to all threads in the process
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_key_create(hg_thread_key_t *key)
{
    int ret = HG_SUCCESS;

    if (!key) {
        HG_ERROR_DEFAULT("NULL pointer to hg_thread_key_t");
        ret = HG_FAIL;
        return ret;
    }

#ifdef _WIN32
    if ((*key = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
        HG_ERROR_DEFAULT("TlsAlloc failed");
        ret = HG_FAIL;
    }
#else
    if (pthread_key_create(key, NULL)) {
        HG_ERROR_DEFAULT("pthread_key_create failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_key_delete
 *
 * Purpose:     Delete a thread-specific data key previously returned by hg_thread_key_create()
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_key_delete(hg_thread_key_t key)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    if (!TlsFree(key)) {
        HG_ERROR_DEFAULT("TlsFree failed");
        ret = HG_FAIL;
    }
#else
    if (pthread_key_delete(key)) {
        HG_ERROR_DEFAULT("pthread_key_delete failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_getspecific
 *
 * Purpose:     Get value from specified key
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void *hg_thread_getspecific(hg_thread_key_t key)
{
    void *ret;

#ifdef _WIN32
    ret = TlsGetValue(key);
#else
    ret = pthread_getspecific(key);
#endif

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_thread_setspecific
 *
 * Purpose:     Set value to specified key
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_thread_setspecific(hg_thread_key_t key, const void *value)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    if (!TlsSetValue(key, value)) {
        HG_ERROR_DEFAULT("TlsSetValue failed");
        ret = HG_FAIL;
    }
#else
    if (pthread_setspecific(key, value)) {
        HG_ERROR_DEFAULT("pthread_setspecific failed");
        ret = HG_FAIL;
    }
#endif

    return ret;
}
