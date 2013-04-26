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
    if (pthread_create(thread, NULL, f, data)) ret = HG_FAIL;
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
    if (pthread_join(thread, NULL)) ret = HG_FAIL;
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
    if (pthread_cancel(thread)) ret = HG_FAIL;
#endif

    return ret;
}
