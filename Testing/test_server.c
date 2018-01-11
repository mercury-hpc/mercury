/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
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
static HG_THREAD_RETURN_TYPE
hg_progress_thread(void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    hg_class_t *hg_class = HG_Context_get_class(context);
    struct hg_test_info *hg_test_info =
        (struct hg_test_info *) HG_Class_get_data(hg_class);
    HG_THREAD_RETURN_TYPE tret = (HG_THREAD_RETURN_TYPE) 0;
    hg_return_t ret = HG_SUCCESS;

    do {
        if (hg_atomic_cas32(&hg_test_info->finalizing_count, 1, 1))
            break;

        ret = HG_Progress(context, HG_TEST_PROGRESS_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);

    printf("Exiting\n");
    hg_thread_exit(tret);
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
    hg_thread_t progress_thread;
#endif
    hg_return_t ret = HG_SUCCESS;

    /* Force to listen */
    hg_test_info.na_test_info.listen = NA_TRUE;
    HG_Test_init(argc, argv, &hg_test_info);

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_create(&progress_thread, hg_progress_thread, hg_test_info.context);

    do {
        if (hg_atomic_cas32(&hg_test_info.finalizing_count, 1, 1))
            break;

        ret = HG_Trigger(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT, 1, NULL);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
#else
    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(hg_test_info.context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);

        if (hg_atomic_cas32(&hg_test_info.finalizing_count, 1, 1))
            break;

        /* Use same value as HG_TEST_TRIGGER_TIMEOUT for convenience */
        ret = HG_Progress(hg_test_info.context, HG_TEST_TRIGGER_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
#endif

    printf("# Finalizing...\n");

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_join(progress_thread);
#endif

    HG_Test_finalize(&hg_test_info);

    return EXIT_SUCCESS;
}
