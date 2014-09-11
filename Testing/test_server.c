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

#include <stdio.h>
#include <stdlib.h>

extern hg_atomic_int32_t hg_test_finalizing_count_g;

/**
 *
 */
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_bool_t finalizing = HG_FALSE;
    unsigned int number_of_peers;
    hg_return_t ret = HG_SUCCESS;

    hg_class = HG_Test_server_init(argc, argv, NULL, NULL,
            &number_of_peers);

    context = HG_Context_create(hg_class);

    while (!finalizing) {
        hg_return_t trigger_ret;
        unsigned int actual_count = 0;

        do {
            trigger_ret = HG_Trigger(hg_class, context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 0))
            finalizing = HG_TRUE;

        HG_Progress(hg_class, context, HG_MAX_IDLE_TIME);
    }

    printf("# Finalizing...\n");

    HG_Context_destroy(context);
    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
