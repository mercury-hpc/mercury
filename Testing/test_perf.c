/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"
#include "na_test.h"

#include "mercury_time.h"

#include <stdio.h>
#include <stdlib.h>

#define RPC_SKIP 20
#define BULK_SKIP 20

extern int na_test_comm_rank_g;
extern int na_test_comm_size_g;

extern hg_id_t hg_test_perf_rpc_id_g;
extern hg_id_t hg_test_perf_bulk_id_g;

static hg_return_t
hg_test_perf_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_request_complete((hg_request_t *) callback_info->arg);

    return HG_SUCCESS;
}

/**
 *
 */
static hg_return_t
measure_rpc(hg_class_t *hg_class, hg_context_t *context, na_addr_t addr,
        hg_request_class_t *request_class)
{
    int avg_iter;
    double time_read = 0, min_time_read = 0, max_time_read = 0;
    hg_return_t ret = HG_SUCCESS;

    size_t i;

    if (na_test_comm_rank_g == 0) {
        printf("# Executing RPC with %d client(s) -- loop %d time(s)\n",
                na_test_comm_size_g, MERCURY_TESTING_MAX_LOOP);
    }

    if (na_test_comm_rank_g == 0) printf("# Warming up...\n");

    /* Warm up for RPC */
    for (i = 0; i < RPC_SKIP; i++) {
        hg_request_t *request;
        hg_handle_t handle;

        request = hg_request_create(request_class);

        ret = HG_Create(hg_class, context, addr, hg_test_perf_rpc_id_g, &handle);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not start call\n");
            goto done;
        }

        ret = HG_Forward(handle, hg_test_perf_forward_cb, request, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        /* Complete */
        ret = HG_Destroy(handle);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete\n");
            goto done;
        }

        hg_request_destroy(request);
    }

    NA_Test_barrier();

    if (na_test_comm_rank_g == 0) printf("%*s%*s%*s%*s%*s%*s",
            10, "# Time (s)", 10, "Min (s)", 10, "Max (s)",
            12, "Calls (c/s)", 12, "Min (c/s)", 12, "Max (c/s)");
    if (na_test_comm_rank_g == 0) printf("\n");

    /* RPC benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_request_t *request;
        hg_handle_t handle;
        hg_time_t t1, t2;
        double td, part_time_read;
        double calls_per_sec, min_calls_per_sec, max_calls_per_sec;

        request = hg_request_create(request_class);

        ret = HG_Create(hg_class, context, addr, hg_test_perf_rpc_id_g, &handle);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not start call\n");
            goto done;
        }

        hg_time_get_current(&t1);

        ret = HG_Forward(handle, hg_test_perf_forward_cb, request, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        NA_Test_barrier();

        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (!min_time_read) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;

        /* Complete */
        ret = HG_Destroy(handle);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete\n");
            goto done;
        }

        hg_request_destroy(request);

        part_time_read = time_read / (avg_iter + 1);
        calls_per_sec = na_test_comm_size_g / part_time_read;
        min_calls_per_sec = na_test_comm_size_g / max_time_read;
        max_calls_per_sec = na_test_comm_size_g / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (na_test_comm_rank_g == 0) {
            printf("%*f%*f%*f%*.*f%*.*f%*.*f\r",
                10, part_time_read, 10, min_time_read, 10, max_time_read,
                12, 2, calls_per_sec, 12, 2, min_calls_per_sec, 12, 2,
                max_calls_per_sec);
        }
    }
    if (na_test_comm_rank_g == 0) printf("\n");

done:
    return ret;
}

/**
 *
 */
static hg_return_t
measure_bulk_transfer(hg_class_t *hg_class, hg_context_t *context,
        na_addr_t addr, hg_request_class_t *request_class)
{
    write_in_t in_struct;

    int *bulk_buf;
    void *buf_ptr[1];
    size_t count = (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE) / sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t nbytes;
    double nmbytes;
    hg_handle_t handle;

    int avg_iter;
    double time_read = 0, min_time_read = 0, max_time_read = 0;

    struct hg_info *hg_info = NULL;

    hg_return_t ret = HG_SUCCESS;
    size_t i;

    /* Prepare bulk_buf */
    nbytes = count * sizeof(int);
    nmbytes = (double) nbytes / (1024 * 1024);
    if (na_test_comm_rank_g == 0) {
        printf("# Reading Bulk Data (%f MB) with %d client(s) -- loop %d time(s)\n",
                nmbytes, na_test_comm_size_g, MERCURY_TESTING_MAX_LOOP);
    }

    bulk_buf = (int *) malloc(nbytes);
    for (i = 0; i < count; i++) {
        bulk_buf[i] = (int) i;
    }
    *buf_ptr = bulk_buf;

    ret = HG_Create(hg_class, context, addr, hg_test_perf_bulk_id_g,
            &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Must get info to retrieve bulk class if not provided by user */
    hg_info = HG_Get_info(handle);

    /* Register memory */
    ret = HG_Bulk_create(hg_info->hg_bulk_class, 1, buf_ptr, &nbytes,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        goto done;
    }

    /* Fill input structure */
    in_struct.fd = 0;
    in_struct.bulk_handle = bulk_handle;

    if (na_test_comm_rank_g == 0) printf("# Warming up...\n");

    /* Warm up for bulk data */
    for (i = 0; i < BULK_SKIP; i++) {
        hg_request_t *request;

        request = hg_request_create(request_class);

        ret = HG_Forward(handle, hg_test_perf_forward_cb, request, &in_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        hg_request_destroy(request);
    }

    NA_Test_barrier();

    if (na_test_comm_rank_g == 0) printf("%*s%*s%*s%*s%*s%*s",
            10, "# Time (s)", 10, "Min (s)", 10, "Max (s)",
            12, "BW (MB/s)", 12, "Min (MB/s)", 12, "Max (MB/s)");
    if (na_test_comm_rank_g == 0) printf("\n");

    /* Bulk data benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_request_t *request;
        hg_time_t t1, t2;
        double td, part_time_read;
        double read_bandwidth, min_read_bandwidth, max_read_bandwidth;

        request = hg_request_create(request_class);

        hg_time_get_current(&t1);

        ret = HG_Forward(handle, hg_test_perf_forward_cb, request, &in_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        NA_Test_barrier();

        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (!min_time_read) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;

        hg_request_destroy(request);

        part_time_read = time_read / (avg_iter + 1);
        read_bandwidth = nmbytes * na_test_comm_size_g / part_time_read;
        min_read_bandwidth = nmbytes * na_test_comm_size_g / max_time_read;
        max_read_bandwidth = nmbytes * na_test_comm_size_g / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (na_test_comm_rank_g == 0) {
            printf("%*f%*f%*f%*.*f%*.*f%*.*f\r",
                10, part_time_read, 10, min_time_read, 10, max_time_read,
                12, 2, read_bandwidth, 12, 2, min_read_bandwidth, 12, 2,
                max_read_bandwidth);
        }
    }
    if (na_test_comm_rank_g == 0) printf("\n");

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        goto done;
    }

    /* Free bulk data */
    free(bulk_buf);

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        goto done;
    }

done:
    return ret;
}

/*****************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    na_addr_t addr;

    hg_class = HG_Test_client_init(argc, argv, &addr, &na_test_comm_rank_g,
            &context, &request_class);

    /* Run RPC test */
    measure_rpc(hg_class, context, addr, request_class);

    NA_Test_barrier();

    /* Run Bulk test */
    measure_bulk_transfer(hg_class, context, addr, request_class);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
