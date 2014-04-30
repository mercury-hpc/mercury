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
#include "na_test.h"
#include "mercury_rpc_cb.h"

#include "mercury_atomic.h"
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
#include "mercury_thread_pool.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/*******************/
/* Local Variables */
/*******************/
static na_class_t *hg_test_na_class_g = NULL;
static hg_bool_t hg_test_is_client_g = HG_FALSE;
static na_addr_t hg_test_addr_g = NA_ADDR_NULL;
static int hg_test_rank_g = 0;

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
hg_thread_pool_t *hg_test_thread_pool_g = NULL;
#endif

/* test_rpc */
hg_id_t hg_test_rpc_open_id_g = 0;

/* test_bulk */
hg_id_t hg_test_bulk_write_id_g = 0;

/* test_bulk_seg */
hg_id_t hg_test_bulk_seg_write_id_g = 0;

/* test_pipeline */
hg_id_t hg_test_pipeline_write_id_g = 0;

/* test_posix */
hg_id_t hg_test_posix_open_id_g = 0;
hg_id_t hg_test_posix_write_id_g = 0;
hg_id_t hg_test_posix_read_id_g = 0;
hg_id_t hg_test_posix_close_id_g = 0;

/* test_scale */
hg_id_t hg_test_scale_open_id_g = 0;
hg_id_t hg_test_scale_write_id_g = 0;

/* test_finalize */
hg_id_t hg_test_finalize_id_g = 0;
hg_atomic_int32_t hg_test_finalizing_count_g;

/*---------------------------------------------------------------------------*/
static void
hg_test_finalize_rpc(void)
{
    hg_return_t hg_ret;
    hg_request_t request;
    hg_status_t status;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(hg_test_addr_g, hg_test_finalize_id_g, NULL, NULL,
            &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
    }

    /* Free request */
    hg_ret = HG_Request_free(request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
    }
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_cb(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_atomic_incr32(&hg_test_finalizing_count_g);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Handler_free(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_test_register(void)
{
    /* test_rpc */
    hg_test_rpc_open_id_g = MERCURY_REGISTER("hg_test_rpc_open", rpc_open_in_t,
            rpc_open_out_t, hg_test_rpc_open_cb);

    /* test_bulk */
    hg_test_bulk_write_id_g = MERCURY_REGISTER("hg_test_bulk_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_write_cb);

    /* test_bulk_seg */
    hg_test_bulk_seg_write_id_g = MERCURY_REGISTER("hg_test_bulk_seg_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_seg_write_cb);

    /* test_pipeline */
    hg_test_pipeline_write_id_g = MERCURY_REGISTER("hg_test_pipeline_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_pipeline_write_cb);

    /* test_posix */
    hg_test_posix_open_id_g = MERCURY_REGISTER("hg_test_posix_open",
            open_in_t, open_out_t, hg_test_posix_open_cb);
    hg_test_posix_write_id_g = MERCURY_REGISTER("hg_test_posix_write",
            write_in_t, write_out_t, hg_test_posix_write_cb);
    hg_test_posix_read_id_g = MERCURY_REGISTER("hg_test_posix_read",
            read_in_t, read_out_t, hg_test_posix_read_cb);
    hg_test_posix_close_id_g = MERCURY_REGISTER("hg_test_posix_close",
            close_in_t, close_out_t, hg_test_posix_close_cb);

    /* test_scale */
    hg_test_scale_open_id_g = MERCURY_REGISTER("hg_test_scale_open",
            open_in_t, open_out_t, hg_test_scale_open_cb);
    hg_test_scale_write_id_g = MERCURY_REGISTER("hg_test_scale_write",
            write_in_t, write_out_t, hg_test_scale_write_cb);

    /* test_finalize */
    hg_test_finalize_id_g = MERCURY_REGISTER("hg_test_finalize",
            void, void, hg_test_finalize_cb);
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_client_init(int argc, char *argv[], na_addr_t *addr, int *rank)
{
    char test_addr_name[NA_TEST_MAX_ADDR_NAME];
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

    hg_test_na_class_g = NA_Test_client_init(argc, argv, test_addr_name,
            NA_TEST_MAX_ADDR_NAME, &hg_test_rank_g);

    ret = HG_Init(hg_test_na_class_g);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        goto done;
    }

    if ((argc > 2 && strcmp("self", argv[2]) == 0) ||
            (argc > 3 && strcmp("self", argv[3]) == 0)) {
        /* Self addr */
        NA_Addr_self(hg_test_na_class_g, &hg_test_addr_g);

        /* In case of self we need the local thread pool */
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
        hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS, &hg_test_thread_pool_g);
        printf("# Starting server with %d threads...\n", MERCURY_TESTING_NUM_THREADS);
#endif
    } else {
        /* Look up addr using port name info */
        na_ret = NA_Addr_lookup_wait(hg_test_na_class_g, test_addr_name,
                &hg_test_addr_g);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not find addr %s\n", test_addr_name);
            ret = HG_INVALID_PARAM;
            goto done;
        }
    }

    /* Register routines */
    hg_test_register();

    /* When finalize is called we need to free the addr etc */
    hg_test_is_client_g = HG_TRUE;

    if (addr) *addr = hg_test_addr_g;
    if (rank) *rank = hg_test_rank_g;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_server_init(int argc, char *argv[], char ***addr_table,
        unsigned int *addr_table_size, unsigned int *max_number_of_peers)
{
    hg_return_t ret = HG_SUCCESS;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

    hg_test_na_class_g = NA_Test_server_init(argc, argv, addr_table,
            addr_table_size, max_number_of_peers);

    /* Initalize atomic variable to finalize server */
    hg_atomic_set32(&hg_test_finalizing_count_g, 0);

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS, &hg_test_thread_pool_g);
    printf("# Starting server with %d threads...\n", MERCURY_TESTING_NUM_THREADS);
#endif

    ret = HG_Init(hg_test_na_class_g);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        goto done;
    }

    /* Register test routines */
    hg_test_register();

    /* Used by CTest Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    NA_Test_barrier();

    if (hg_test_is_client_g) {
        /* Terminate server */
        if (hg_test_rank_g == 0) hg_test_finalize_rpc();

        /* Free addr id */
        na_ret = NA_Addr_free(hg_test_na_class_g, hg_test_addr_g);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not free addr\n");
            goto done;
        }
        hg_test_addr_g = NA_ADDR_NULL;
    }

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
        hg_thread_pool_destroy(hg_test_thread_pool_g);
#endif

    /* Finalize interface */
    ret = HG_Finalize();
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        goto done;
    }

    na_ret = NA_Test_finalize(hg_test_na_class_g);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        goto done;
    }
    hg_test_na_class_g = NULL;

done:
     return ret;
}
