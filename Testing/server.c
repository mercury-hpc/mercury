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

#include "mercury_thread.h"
#include "mercury_thread_mutex.h"
#include "mercury_thread_pool.h"
#include "mercury_list.h"

#include <stdio.h>
#include <stdlib.h>

/* TODO use atomic increment */

#define USE_THREAD_POOL /* use thread pool */

static unsigned int finalizing_count = 0;
static hg_thread_mutex_t finalizing_mutex;

#ifdef USE_THREAD_POOL
static hg_thread_pool_t *thread_pool = NULL;
#endif

/**
 *
 */
static hg_return_t
server_finalize(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_thread_mutex_lock(&finalizing_mutex);

    finalizing_count++;

    hg_thread_mutex_unlock(&finalizing_mutex);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

/**
 *
 */
int
main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    hg_return_t hg_ret;
    na_return_t na_ret;
    hg_bool_t finalizing = HG_FALSE;

    unsigned int number_of_peers;

    network_class = HG_Test_server_init(argc, argv, NULL, NULL,
            &number_of_peers);

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        return EXIT_FAILURE;
    }

#ifdef USE_THREAD_POOL
    hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS, &thread_pool);
    printf("# Starting server with %d threads...\n", MERCURY_TESTING_NUM_THREADS);
#endif

    /* Register test routines */
    HG_Test_register();

    MERCURY_REGISTER("finalize", void, void, server_finalize);

    hg_thread_mutex_init(&finalizing_mutex);

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

        hg_thread_mutex_lock(&finalizing_mutex);
        finalizing = (hg_bool_t) (finalizing_count > 0);
        hg_thread_mutex_unlock(&finalizing_mutex);
    }

    printf("# Finalizing...\n");

    hg_thread_mutex_destroy(&finalizing_mutex);

#ifdef USE_THREAD_POOL
    hg_thread_pool_destroy(thread_pool);
#endif

    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Finalize(network_class);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
