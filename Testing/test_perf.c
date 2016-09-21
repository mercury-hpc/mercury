/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
#define NDIGITS 9
#define NWIDTH 13

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
measure_rpc(hg_context_t *context, hg_addr_t addr,
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

        ret = HG_Create(context, addr, hg_test_perf_rpc_id_g, &handle);
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
        NWIDTH, "#    Time (s)", NWIDTH, "Min (s)", NWIDTH, "Max (s)",
        NWIDTH, "Calls (c/s)", NWIDTH, "Min (c/s)", NWIDTH, "Max (c/s)");
    if (na_test_comm_rank_g == 0) printf("\n");

    /* RPC benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_request_t *request;
        hg_handle_t handle;
        hg_time_t t1, t2;
        double td, part_time_read;
        double calls_per_sec, min_calls_per_sec, max_calls_per_sec;

        request = hg_request_create(request_class);

        ret = HG_Create(context, addr, hg_test_perf_rpc_id_g, &handle);
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
            printf("%*.*f%*.*f%*.*f%*.*g%*.*g%*.*g\r", NWIDTH, NDIGITS,
                part_time_read, NWIDTH, NDIGITS, min_time_read, NWIDTH, NDIGITS,
                max_time_read, NWIDTH, NDIGITS, calls_per_sec, NWIDTH, NDIGITS,
                min_calls_per_sec, NWIDTH, NDIGITS, max_calls_per_sec);
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
    hg_addr_t addr, size_t total_size, size_t segment_size,
    hg_request_class_t *request_class)
{
    bulk_write_in_t in_struct;

    void **buf_ptrs;
    size_t *buf_sizes;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t nbytes;
    double nmbytes;
    unsigned int nsegments;
    hg_handle_t handle;

    int avg_iter;
    double time_read = 0, min_time_read = 0, max_time_read = 0;

    hg_return_t ret = HG_SUCCESS;
    size_t i;

    /* Prepare bulk_buf */
    nbytes = (total_size / sizeof(int)) * sizeof(int);
    nmbytes = (double) nbytes / (1024 * 1024);
    nsegments = (unsigned int)(nbytes / segment_size);
    if (na_test_comm_rank_g == 0) {
        if (segment_size == total_size)
            printf("# Reading Bulk Data (%f MB) with %d client(s) -- loop %d time(s)\n",
                nmbytes, na_test_comm_size_g, MERCURY_TESTING_MAX_LOOP);
        else
            printf("# Reading Bulk Data (%f MB, %d segments) with %d client(s) -- loop %d time(s)\n",
                nmbytes, nsegments, na_test_comm_size_g, MERCURY_TESTING_MAX_LOOP);
    }

    if (segment_size == total_size) {
        int *bulk_buf = (int *) malloc(nbytes);
        for (i = 0; i < nbytes / sizeof(int); i++) {
            bulk_buf[i] = (int) i;
        }
        buf_ptrs = (void **) malloc(sizeof(void *));
        *buf_ptrs = bulk_buf;
        buf_sizes = &nbytes;
    } else {
        int **bulk_buf = (int **) malloc(nsegments * sizeof(int *));
        buf_sizes = (size_t *) malloc(nsegments * sizeof(size_t));
        for (i = 0; i < nsegments; i++) {
            size_t j;

            bulk_buf[i] = (int *) malloc(segment_size);
            buf_sizes[i] = segment_size;
            for (j = 0; j < segment_size / sizeof(int); j++)
                bulk_buf[i][j] = (int) (j + i * segment_size / sizeof(int));
        }
        buf_ptrs = (void **) bulk_buf;
    }

    ret = HG_Create(context, addr, hg_test_perf_bulk_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Register memory */
    ret = HG_Bulk_create(hg_class, nsegments, buf_ptrs, (hg_size_t *) buf_sizes,
        HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        goto done;
    }

    /* Fill input structure */
    in_struct.fildes = 0;
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
        NWIDTH, "#    Time (s)", NWIDTH, "Min (s)", NWIDTH, "Max (s)",
        NWIDTH, "BW (MB/s)", NWIDTH, "Min (MB/s)", NWIDTH, "Max (MB/s)");
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
            printf("%*.*f%*.*f%*.*f%*.*g%*.*g%*.*g\r", NWIDTH, NDIGITS,
                part_time_read, NWIDTH, NDIGITS, min_time_read, NWIDTH, NDIGITS,
                max_time_read, NWIDTH, NDIGITS, read_bandwidth, NWIDTH, NDIGITS,
                min_read_bandwidth, NWIDTH, NDIGITS, max_read_bandwidth);
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
    if (segment_size != total_size) {
        for (i = 0; i < nsegments; i++)
            free(buf_ptrs[i]);
        free(buf_sizes);
    } else {
        free(*buf_ptrs);
    }
    free(buf_ptrs);

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
    size_t size_small = 1024; /* Use small values for eager message */
    size_t size_big = (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE);
    hg_addr_t addr;

    hg_class = HG_Test_client_init(argc, argv, &addr, &na_test_comm_rank_g,
            &context, &request_class);

    if (na_test_comm_rank_g == 0) {
        printf("###############################################################################\n");
        printf("# RPC test\n");
        printf("###############################################################################\n");
    }

    /* Run RPC test */
    measure_rpc(context, addr, request_class);

    NA_Test_barrier();

    if (na_test_comm_rank_g == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (eager mode)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (eager) */
    measure_bulk_transfer(hg_class, context, addr, size_small, size_small, request_class);

    if (na_test_comm_rank_g == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (rma)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (rma) */
    measure_bulk_transfer(hg_class, context, addr, size_big, size_big, request_class);

    if (na_test_comm_rank_g == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (rma non-contiguous)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (non-contiguous) */
    measure_bulk_transfer(hg_class, context, addr, size_big, size_big / 1024, request_class);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
