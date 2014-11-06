/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
static hg_class_t *hg_class = NULL;
static hg_context_t *context = NULL;

static HG_THREAD_RETURN_TYPE
hg_test_server_trigger(void *arg)
{
    hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;
    unsigned int actual_count = 0;
    hg_return_t ret = HG_SUCCESS;

    do {
        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 1))
            break;

        ret = HG_Trigger(hg_class, context, HG_MAX_IDLE_TIME, 1, &actual_count);
    } while ((ret == HG_SUCCESS) && actual_count);

    hg_thread_exit(thread_ret);
    return thread_ret;
}

/**
 *
 */
int
main(int argc, char *argv[])
{
    hg_thread_t thread;
    unsigned int number_of_peers;
    hg_return_t ret = HG_SUCCESS;

    hg_class = HG_Test_server_init(argc, argv, NULL, NULL,
            &number_of_peers, &context);

    hg_thread_create(&thread, hg_test_server_trigger, NULL);

    do {
        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 1))
            break;

        ret = HG_Progress(hg_class, context, HG_MAX_IDLE_TIME);
    } while (ret == HG_SUCCESS);

    hg_thread_join(thread);

    printf("# Finalizing...\n");
    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
