/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_thread.h"
#include "mercury_util_error.h"

/*---------------------------------------------------------------------------*/
void
hg_thread_init(hg_thread_t *thread)
{
#ifdef _WIN32
    *thread = NULL;
#else
    *thread = 0;
#endif
}

/*---------------------------------------------------------------------------*/
int
hg_thread_create(hg_thread_t *thread, hg_thread_func_t f, void *data)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    *thread = CreateThread(NULL, 0, f, data, 0, NULL);
    if (*thread == NULL) ret = HG_UTIL_FAIL;
#else
    if (pthread_create(thread, NULL, f, data)) {
        HG_UTIL_ERROR_DEFAULT("pthread_create failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
void
hg_thread_exit(hg_thread_ret_t ret)
{
#ifdef _WIN32
    ExitThread(ret);
#else
    pthread_exit(ret);
#endif
}

/*---------------------------------------------------------------------------*/
int
hg_thread_join(hg_thread_t thread)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    if (pthread_join(thread, NULL)) {
        HG_UTIL_ERROR_DEFAULT("pthread_join failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_cancel(hg_thread_t thread)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    WaitForSingleObject(thread, 0);
    CloseHandle(thread);
#else
    if (pthread_cancel(thread)) {
        HG_UTIL_ERROR_DEFAULT("pthread_cancel failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_key_create(hg_thread_key_t *key)
{
    int ret = HG_UTIL_SUCCESS;

    if (!key) {
        HG_UTIL_ERROR_DEFAULT("NULL pointer to hg_thread_key_t");
        ret = HG_UTIL_FAIL;
        return ret;
    }

#ifdef _WIN32
    if ((*key = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
        HG_UTIL_ERROR_DEFAULT("TlsAlloc failed");
        ret = HG_UTIL_FAIL;
    }
#else
    if (pthread_key_create(key, NULL)) {
        HG_UTIL_ERROR_DEFAULT("pthread_key_create failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_key_delete(hg_thread_key_t key)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    if (!TlsFree(key)) {
        HG_UTIL_ERROR_DEFAULT("TlsFree failed");
        ret = HG_UTIL_FAIL;
    }
#else
    if (pthread_key_delete(key)) {
        HG_UTIL_ERROR_DEFAULT("pthread_key_delete failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
void *
hg_thread_getspecific(hg_thread_key_t key)
{
    void *ret;

#ifdef _WIN32
    ret = TlsGetValue(key);
#else
    ret = pthread_getspecific(key);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_thread_setspecific(hg_thread_key_t key, const void *value)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    if (!TlsSetValue(key, (LPVOID) value)) {
        HG_UTIL_ERROR_DEFAULT("TlsSetValue failed");
        ret = HG_UTIL_FAIL;
    }
#else
    if (pthread_setspecific(key, value)) {
        HG_UTIL_ERROR_DEFAULT("pthread_setspecific failed");
        ret = HG_UTIL_FAIL;
    }
#endif

    return ret;
}
