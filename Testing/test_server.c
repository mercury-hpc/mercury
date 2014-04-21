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
    hg_bool_t finalizing = HG_FALSE;
    unsigned int number_of_peers;
    hg_return_t hg_ret;

    hg_ret = HG_Test_server_init(argc, argv, NULL, NULL,
            &number_of_peers);

//    for (i = 0; i < number_of_peers; i++) {
//        /* Receive new function calls */
//        hg_ret = HG_Handler_process(HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
//        if (hg_ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not receive function call\n");
//            return EXIT_FAILURE;
//        }
//    }

    while (!finalizing) {
        hg_status_t status = HG_FALSE;

        /* Receive new function calls */
        hg_ret = HG_Handler_process(NA_MAX_IDLE_TIME, &status);
        if (hg_ret == HG_SUCCESS && status) {
            /* printf("# Request processed\n"); */
        }

//        while (!status) {
//            printf("Processing...\n");
//        hg_ret = HG_Handler_process(1000, &status);
//        if (hg_ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not receive function call\n");
//            return EXIT_FAILURE;
//        }

        if (hg_atomic_cas32(&hg_test_finalizing_count_g, 1, 0))
            finalizing = HG_TRUE;
    }

    printf("# Finalizing...\n");

    HG_Test_finalize();

    return EXIT_SUCCESS;
}
