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

#include "mercury_atomic.h"
#include "mercury_thread.h"

#include <stdio.h>
#include <stdlib.h>

extern hg_atomic_int32_t hg_test_finalizing_count_g;
extern hg_addr_t *hg_addr_table;

#ifdef MERCURY_TESTING_HAS_BUSY_WAIT
#define HG_TEST_PROGRESS_TIMEOUT    0
#define HG_TEST_TRIGGER_TIMEOUT     0
#else
#define HG_TEST_PROGRESS_TIMEOUT    100
#define HG_TEST_TRIGGER_TIMEOUT     HG_MAX_IDLE_TIME
#endif

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
static HG_THREAD_RETURN_TYPE
hg_progress_thread(void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    HG_THREAD_RETURN_TYPE tret = (HG_THREAD_RETURN_TYPE) 0;
    hg_return_t ret = HG_SUCCESS;

    do {
        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 1))
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
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    unsigned int number_of_peers;
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_t progress_thread;
#endif
    hg_return_t ret = HG_SUCCESS;

    hg_class = HG_Test_server_init(argc, argv, &hg_addr_table,
            NULL, &number_of_peers, &context);
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_create(&progress_thread, hg_progress_thread, context);

    do {
        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 1))
            break;

        ret = HG_Trigger(context, HG_TEST_TRIGGER_TIMEOUT, 1, NULL);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
#else
    do {
        unsigned int actual_count = 0;

        do {
            ret = HG_Trigger(context, 0, 1, &actual_count);
        } while ((ret == HG_SUCCESS) && actual_count);

        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 1))
            break;

        /* Use same value as HG_TEST_TRIGGER_TIMEOUT for convenience */
        ret = HG_Progress(context, HG_TEST_TRIGGER_TIMEOUT);
    } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
#endif

    printf("# Finalizing...\n");
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_join(progress_thread);
#endif
    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
