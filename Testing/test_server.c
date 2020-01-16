/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
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

/****************/
/* Local Macros */
/****************/

#define HG_TEST_PROGRESS_TIMEOUT    100
#define HG_TEST_TRIGGER_TIMEOUT     HG_MAX_IDLE_TIME

/************************************/
/* Local Type and Struct Definition */
/************************************/

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
struct hg_test_worker {
    struct hg_thread_work thread_work;
    hg_uint8_t context_id;
};
#endif

/********************/
/* Local Prototypes */
/********************/

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_test_progress_thread(void *arg);
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_test_progress_work(void *arg);
#endif

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
#ifdef MERCURY_TESTING_HAS_THREAD_POOL

static HG_INLINE HG_THREAD_RETURN_TYPE
hg_test_progress_thread(void *arg)
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
    HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        tret, (HG_THREAD_RETURN_TYPE) 0, "HG_Progress() failed (%s)",
        HG_Error_to_string(ret));

done:
    printf("Exiting\n");
    hg_thread_exit(tret);
    return tret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE HG_THREAD_RETURN_TYPE
hg_test_progress_work(void *arg)
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
        HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
            tret, (HG_THREAD_RETURN_TYPE) 0, "HG_Trigger() failed (%s)",
            HG_Error_to_string(ret));

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
    HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        tret, (HG_THREAD_RETURN_TYPE) 0, "HG_Progress() failed (%s)",
        HG_Error_to_string(ret));

done:
    return tret;
}
#endif

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = { 0 };
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    struct hg_thread_work *progress_workers = NULL;
#endif
    struct hg_test_context_info *hg_test_context_info;
    hg_return_t ret = HG_SUCCESS;
    int rc = EXIT_SUCCESS;

    /* Force to listen */
    hg_test_info.na_test_info.listen = NA_TRUE;
    ret = HG_Test_init(argc, argv, &hg_test_info);
    HG_TEST_CHECK_ERROR(ret != HG_SUCCESS, done, rc, EXIT_FAILURE,
        "HG_Test_init() failed");

    hg_test_context_info = (struct hg_test_context_info *) HG_Context_get_data(
        hg_test_info.context);

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    if (hg_test_info.na_test_info.max_contexts > 1) {
        hg_uint8_t context_count = (hg_uint8_t)
            (hg_test_info.na_test_info.max_contexts);
        hg_uint8_t i;

        progress_workers = malloc(
            sizeof(struct hg_thread_work) * context_count);
        HG_TEST_CHECK_ERROR(progress_workers == NULL, done, rc, EXIT_FAILURE,
            "Could not allocate progress_workers");

        progress_workers[0].func = hg_test_progress_work;
        progress_workers[0].args = hg_test_info.context;

        for (i = 0; i < context_count - 1; i++) {
            progress_workers[i + 1].func = hg_test_progress_work;
            progress_workers[i + 1].args = hg_test_info.secondary_contexts[i];
            hg_thread_pool_post(hg_test_info.thread_pool, &progress_workers[i + 1]);
        }
        /* Use main thread for progress on main context */
        hg_test_progress_work(progress_workers[0].args);
    } else {
        hg_thread_t progress_thread;

        hg_thread_create(&progress_thread, hg_test_progress_thread,
            hg_test_info.context);

        do {
            if (hg_atomic_get32(&hg_test_context_info->finalizing))
                break;

            ret = HG_Trigger(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT, 1,
                NULL);
        } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
        HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
            rc, EXIT_FAILURE, "HG_Trigger() failed (%s)",
            HG_Error_to_string(ret));

        hg_thread_join(progress_thread);
    }
#else
    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(hg_test_info.context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);
        HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
            rc, EXIT_FAILURE, "HG_Trigger() failed (%s)",
            HG_Error_to_string(ret));

        if (hg_atomic_get32(&hg_test_context_info->finalizing))
            break;

        /* Use same value as HG_TEST_TRIGGER_TIMEOUT for convenience */
        ret = HG_Progress(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
    HG_TEST_CHECK_ERROR(ret != HG_SUCCESS && ret != HG_TIMEOUT, done,
        rc, EXIT_FAILURE, "HG_Progress() failed (%s)",
        HG_Error_to_string(ret));
#endif

done:
    ret = HG_Test_finalize(&hg_test_info);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Test_finalize() failed");

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    free(progress_workers);
#endif

    return rc;
}
