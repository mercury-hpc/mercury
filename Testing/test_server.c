/*
 * Copyright (C) 2013-2018 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

#include <stdio.h>
#include <stdlib.h>

#define HG_TEST_PROGRESS_TIMEOUT    100
#define HG_TEST_TRIGGER_TIMEOUT     HG_MAX_IDLE_TIME

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_progress_thread(void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    struct hg_test_context_info *hg_test_context_info =
        (struct hg_test_context_info *) HG_Context_get_data(context);
    HG_THREAD_RETURN_TYPE tret = (HG_THREAD_RETURN_TYPE) 0;
    hg_return_t ret = HG_SUCCESS;

    do {
        if (hg_atomic_get32(&hg_test_context_info->finalizing))
            break;

        ret = HG_Progress(context, HG_TEST_PROGRESS_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);

    printf("Exiting\n");
    hg_thread_exit(tret);
    return tret;
}

static HG_INLINE HG_THREAD_RETURN_TYPE
hg_progress_work(void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    struct hg_test_context_info *hg_test_context_info =
        (struct hg_test_context_info *) HG_Context_get_data(context);
    HG_THREAD_RETURN_TYPE tret = (HG_THREAD_RETURN_TYPE) 0;
    hg_return_t ret = HG_SUCCESS;

    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);

        if (hg_atomic_get32(&hg_test_context_info->finalizing)) {
            /* Make sure everything was progressed/triggered */
            do {
                ret = HG_Progress(context, 0);
                HG_Trigger(context, 0, 1, &actual_count);
            } while (ret == HG_SUCCESS);
            break;
        }

        /* Use same value as HG_TEST_TRIGGER_TIMEOUT for convenience */
        ret = HG_Progress(context, HG_TEST_TRIGGER_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);

    return tret;
}
#endif

/**
 *
 */
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = { 0 };
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    struct hg_thread_work *progress_workers = NULL;
#endif
    struct hg_test_context_info *hg_test_context_info;
    hg_return_t ret = HG_SUCCESS;

    /* Force to listen */
    hg_test_info.na_test_info.listen = NA_TRUE;
    ret = HG_Test_init(argc, argv, &hg_test_info);
    if (ret != HG_SUCCESS)
        return EXIT_FAILURE;

    hg_test_context_info =
        (struct hg_test_context_info *) HG_Context_get_data(
            hg_test_info.context);
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    if (!hg_test_info.secondary_contexts) {
        hg_thread_t progress_thread;

        hg_thread_create(&progress_thread, hg_progress_thread, hg_test_info.context);

        do {
            if (hg_atomic_get32(&hg_test_context_info->finalizing))
                break;

            ret = HG_Trigger(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT, 1, NULL);
        } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);

        hg_thread_join(progress_thread);
    } else {
        hg_uint8_t context_count = (hg_uint8_t)
            (hg_test_info.na_test_info.max_contexts);
        hg_uint8_t i;

        progress_workers = malloc(sizeof(struct hg_thread_work) * context_count);
        progress_workers[0].func = hg_progress_work;
        progress_workers[0].args = hg_test_info.context;
        hg_thread_pool_post(hg_test_info.thread_pool, &progress_workers[0]);
        for (i = 0; i < context_count - 1; i++) {
            progress_workers[i + 1].func = hg_progress_work;
            progress_workers[i + 1].args = hg_test_info.secondary_contexts[i];
            hg_thread_pool_post(hg_test_info.thread_pool, &progress_workers[i + 1]);
        }
    }
#else
    if (hg_test_info.secondary_contexts)
        HG_LOG_WARNING("Secondary contexts only supported with thread pool");

    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(hg_test_info.context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);

        if (hg_atomic_get32(&hg_test_context_info->finalizing))
            break;

        /* Use same value as HG_TEST_TRIGGER_TIMEOUT for convenience */
        ret = HG_Progress(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
#endif

    HG_Test_finalize(&hg_test_info);
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    free(progress_workers);
#endif

    return EXIT_SUCCESS;
}
