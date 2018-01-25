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
#include "na_test.h"

#include "mercury_time.h"
#include "mercury_atomic.h"

#include <stdio.h>
#include <stdlib.h>

#define RPC_SKIP 20
#define BULK_SKIP 20
#define NDIGITS 9
#define NWIDTH 13
#define LOW_PERF_THRESHOLD 5000

extern hg_id_t hg_test_perf_rpc_id_g;
extern hg_id_t hg_test_perf_bulk_id_g;

struct hg_test_perf_args {
    hg_request_t *request;
    unsigned int op_count;
    hg_atomic_int32_t op_completed_count;
};

static hg_return_t
hg_test_perf_forward_cb1(const struct hg_cb_info *callback_info)
{
    hg_request_complete((hg_request_t *) callback_info->arg);

    return HG_SUCCESS;
}

static hg_return_t
hg_test_perf_forward_cb2(const struct hg_cb_info *callback_info)
{
    struct hg_test_perf_args *args =
        (struct hg_test_perf_args *) callback_info->arg;

    if ((unsigned int) hg_atomic_incr32(&args->op_completed_count)
        == args->op_count) {
        hg_request_complete(args->request);
    }

    return HG_SUCCESS;
}

/**
 *
 */
static hg_return_t
measure_rpc1(struct hg_test_info *hg_test_info)
{
    int avg_iter;
    double time_read = 0, min_time_read = -1, max_time_read = 0;
    hg_handle_t handle;
    hg_request_t *request;
    hg_return_t ret = HG_SUCCESS;

    size_t i;

    if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
        printf("# Executing RPC with %d client(s) -- loop %d time(s)\n",
            hg_test_info->na_test_info.mpi_comm_size,
            hg_test_info->na_test_info.loop);
    }

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("# Warming up...\n");

    ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
        hg_test_perf_rpc_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    request = hg_request_create(hg_test_info->request_class);

    /* Warm up for RPC */
    for (i = 0; i < RPC_SKIP; i++) {
        ret = HG_Forward(handle, hg_test_perf_forward_cb1, request, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_request_reset(request);
    }

    NA_Test_barrier(&hg_test_info->na_test_info);

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("%*s%*s%*s%*s%*s%*s", NWIDTH, "#    Time (s)", NWIDTH, "Min (s)",
            NWIDTH, "Max (s)", NWIDTH, "Calls (c/s)", NWIDTH, "Min (c/s)",
            NWIDTH, "Max (c/s)");
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("\n");

    /* RPC benchmark */
    for (avg_iter = 0; avg_iter < hg_test_info->na_test_info.loop; avg_iter++) {
        hg_time_t t1, t2;
        double td, part_time_read;
        double calls_per_sec, min_calls_per_sec, max_calls_per_sec;

        hg_time_get_current(&t1);

        ret = HG_Forward(handle, hg_test_perf_forward_cb1, request, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        NA_Test_barrier(&hg_test_info->na_test_info);

        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (min_time_read < 0) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;

        hg_request_reset(request);

        part_time_read = time_read / (avg_iter + 1);
        calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / part_time_read;
        min_calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / max_time_read;
        max_calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
            printf("%*.*f%*.*f%*.*f%*.*g%*.*g%*.*g\r", NWIDTH, NDIGITS,
                part_time_read, NWIDTH, NDIGITS, min_time_read, NWIDTH, NDIGITS,
                max_time_read, NWIDTH, NDIGITS, calls_per_sec, NWIDTH, NDIGITS,
                min_calls_per_sec, NWIDTH, NDIGITS, max_calls_per_sec);
        }
    }
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("\n");

    hg_request_destroy(request);

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        goto done;
    }

done:
    return ret;
}

static hg_return_t
measure_rpc2(struct hg_test_info *hg_test_info)
{
    hg_handle_t *handles = NULL;
    hg_request_t *request;
    struct hg_test_perf_args args;
    double time_read = 0, min_time_read = -1, max_time_read = 0;
    unsigned int nhandles = MERCURY_TESTING_NUM_THREADS_DEFAULT * 2;
    hg_return_t ret = HG_SUCCESS;
    size_t i;
    unsigned int op_count = 0;
    unsigned int low_perf_count = 0;

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("# Executing RPC with %d client(s) -- loop %d time(s) (%u handles)\n",
            hg_test_info->na_test_info.mpi_comm_size,
            hg_test_info->na_test_info.loop, nhandles);

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("# Warming up...\n");

    handles = malloc(nhandles * sizeof(hg_handle_t));

    for (i = 0; i < nhandles; i++) {
        ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
            hg_test_perf_rpc_id_g, &handles[i]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not start call\n");
            goto done;
        }
    }

    request = hg_request_create(hg_test_info->request_class);
    hg_atomic_set32(&args.op_completed_count, 0);
    args.op_count = nhandles;
    args.request = request;

    /* Warm up for RPC */
    for (i = 0; i < nhandles; i++) {
        ret = HG_Forward(handles[i], hg_test_perf_forward_cb2, &args, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
    hg_request_reset(request);

    NA_Test_barrier(&hg_test_info->na_test_info);

    /* RPC benchmark */
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("%*s%*s%*s%*s%*s%*s", NWIDTH, "#    Time (s)", NWIDTH, "Min (s)",
            NWIDTH, "Max (s)", NWIDTH, "Calls (c/s)", NWIDTH, "Min (c/s)",
            NWIDTH, "Max (c/s)");
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("\n");

    /* RPC benchmark */
    while (op_count < (unsigned int) hg_test_info->na_test_info.loop) {
        hg_time_t t1, t2;
        double td, tb, part_time_read;
        double calls_per_sec, min_calls_per_sec, max_calls_per_sec;

        if (((unsigned int) hg_test_info->na_test_info.loop - op_count) < nhandles) {
            args.op_count = (unsigned int) hg_test_info->na_test_info.loop - op_count;
        }
        hg_atomic_set32(&args.op_completed_count, 0);

        hg_time_get_current(&t1);
        for (i = 0;
            i < nhandles
            && op_count < (unsigned int) hg_test_info->na_test_info.loop;
            i++, op_count++) {
            ret = HG_Forward(handles[i], hg_test_perf_forward_cb2, &args, NULL);
            if (ret != HG_SUCCESS) {
                fprintf(stderr, "Could not forward call\n");
                goto done;
            }
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_time_get_current(&t2);

        td = hg_time_to_double(hg_time_subtract(t2, t1));
        hg_request_reset(request);

        time_read += td;
        tb = td / (double) args.op_count;
        if (min_time_read < 0) min_time_read = tb;
        min_time_read = (tb < min_time_read) ? tb : min_time_read;
        max_time_read = (tb > max_time_read) ? tb : max_time_read;

        part_time_read = time_read / (double) op_count;
        calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / part_time_read;
        min_calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / max_time_read;
        max_calls_per_sec = hg_test_info->na_test_info.mpi_comm_size / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
            printf("%*.*f%*.*f%*.*f%*.*g%*.*g%*.*g\r", NWIDTH, NDIGITS,
                part_time_read, NWIDTH, NDIGITS, min_time_read, NWIDTH, NDIGITS,
                max_time_read, NWIDTH, NDIGITS, calls_per_sec, NWIDTH, NDIGITS,
                min_calls_per_sec, NWIDTH, NDIGITS, max_calls_per_sec);
        }
        if (min_calls_per_sec < LOW_PERF_THRESHOLD)
            low_perf_count++;
    }
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("\nLow perf count: %u\n", low_perf_count);

    hg_request_destroy(request);

    NA_Test_barrier(&hg_test_info->na_test_info);

    /* Complete */
    for (i = 0; i < nhandles; i++) {
        ret = HG_Destroy(handles[i]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete\n");
            goto done;
        }
    }

done:
    free(handles);
    return ret;
}

/**
 *
 */
static hg_return_t
measure_bulk_transfer(struct hg_test_info *hg_test_info, size_t total_size,
    size_t segment_size)
{
    bulk_write_in_t in_struct;

    void **buf_ptrs;
    size_t *buf_sizes;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t nbytes = total_size;
    double nmbytes;
    unsigned int nsegments;
    hg_handle_t handle;
    hg_request_t *request;

    int avg_iter;
    double time_read = 0, min_time_read = -1, max_time_read = 0;

    hg_return_t ret = HG_SUCCESS;
    size_t i;

    /* Prepare bulk_buf */
    nmbytes = (double) nbytes / (1024 * 1024);
    nsegments = (unsigned int)(nbytes / segment_size);
    if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
        if (segment_size == total_size)
            printf("# Reading Bulk Data (%f MB) with %d client(s) -- loop %d time(s)\n",
                nmbytes, hg_test_info->na_test_info.mpi_comm_size,
                hg_test_info->na_test_info.loop);
        else
            printf("# Reading Bulk Data (%f MB, %d segments) with %d client(s) -- loop %d time(s)\n",
                nmbytes, nsegments, hg_test_info->na_test_info.mpi_comm_size,
                hg_test_info->na_test_info.loop);
    }

    if (segment_size == total_size) {
        char *bulk_buf = (char *) malloc(nbytes);
        for (i = 0; i < nbytes; i++) {
            bulk_buf[i] = (char) i;
        }
        buf_ptrs = (void **) malloc(sizeof(void *));
        *buf_ptrs = bulk_buf;
        buf_sizes = &nbytes;
    } else {
        char **bulk_buf = (char **) malloc(nsegments * sizeof(char *));
        buf_sizes = (size_t *) malloc(nsegments * sizeof(size_t));
        for (i = 0; i < nsegments; i++) {
            size_t j;

            bulk_buf[i] = (char *) malloc(segment_size);
            buf_sizes[i] = segment_size;
            for (j = 0; j < segment_size; j++)
                bulk_buf[i][j] = (char) (j + i * segment_size);
        }
        buf_ptrs = (void **) bulk_buf;
    }

    ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
        hg_test_perf_bulk_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    request = hg_request_create(hg_test_info->request_class);

    /* Register memory */
    ret = HG_Bulk_create(hg_test_info->hg_class, nsegments, buf_ptrs,
        (hg_size_t *) buf_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        goto done;
    }

    /* Fill input structure */
    in_struct.fildes = 0;
    in_struct.bulk_handle = bulk_handle;

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("# Warming up...\n");

    /* Warm up for bulk data */
    for (i = 0; i < BULK_SKIP; i++) {
        ret = HG_Forward(handle, hg_test_perf_forward_cb1, request, &in_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_request_reset(request);
    }

    NA_Test_barrier(&hg_test_info->na_test_info);

    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("%*s%*s%*s%*s%*s%*s", NWIDTH, "#    Time (s)", NWIDTH, "Min (s)",
            NWIDTH, "Max (s)", NWIDTH, "BW (MB/s)", NWIDTH, "Min (MB/s)",
            NWIDTH, "Max (MB/s)");
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        printf("\n");

    /* Bulk data benchmark */
    for (avg_iter = 0; avg_iter < hg_test_info->na_test_info.loop; avg_iter++) {
        hg_time_t t1, t2;
        double td, part_time_read;
        double read_bandwidth, min_read_bandwidth, max_read_bandwidth;

        hg_time_get_current(&t1);

        ret = HG_Forward(handle, hg_test_perf_forward_cb1, request, &in_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        NA_Test_barrier(&hg_test_info->na_test_info);

        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (min_time_read < 0) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;

        hg_request_reset(request);

        part_time_read = time_read / (avg_iter + 1);
        read_bandwidth = nmbytes * hg_test_info->na_test_info.mpi_comm_size / part_time_read;
        min_read_bandwidth = nmbytes * hg_test_info->na_test_info.mpi_comm_size / max_time_read;
        max_read_bandwidth = nmbytes * hg_test_info->na_test_info.mpi_comm_size / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (hg_test_info->na_test_info.mpi_comm_rank == 0) {
            printf("%*.*f%*.*f%*.*f%*.*g%*.*g%*.*g\r", NWIDTH, NDIGITS,
                part_time_read, NWIDTH, NDIGITS, min_time_read, NWIDTH, NDIGITS,
                max_time_read, NWIDTH, NDIGITS, read_bandwidth, NWIDTH, NDIGITS,
                min_read_bandwidth, NWIDTH, NDIGITS, max_read_bandwidth);
        }
    }
    if (hg_test_info->na_test_info.mpi_comm_rank == 0) printf("\n");

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

    hg_request_destroy(request);

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
    struct hg_test_info hg_test_info = { 0 };
    size_t size_small = 1024; /* Use small values for eager message */
    size_t size_big = (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE);

    HG_Test_init(argc, argv, &hg_test_info);

    if (hg_test_info.na_test_info.mpi_comm_rank == 0) {
        printf("###############################################################################\n");
        printf("# RPC test\n");
        printf("###############################################################################\n");
    }

    /* Run RPC test */
    measure_rpc1(&hg_test_info);

    /* Run RPC test */
    measure_rpc2(&hg_test_info);

    NA_Test_barrier(&hg_test_info.na_test_info);

    if (hg_test_info.na_test_info.mpi_comm_rank == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (eager mode)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (eager) */
    measure_bulk_transfer(&hg_test_info, size_small, size_small);

    if (hg_test_info.na_test_info.mpi_comm_rank == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (rma)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (rma) */
    measure_bulk_transfer(&hg_test_info, size_big, size_big);

    if (hg_test_info.na_test_info.mpi_comm_rank == 0) {
        printf("###############################################################################\n");
        printf("# Bulk test (rma non-contiguous)\n");
        printf("###############################################################################\n");
    }

    /* Run Bulk test (non-contiguous) */
    measure_bulk_transfer(&hg_test_info, size_big, size_big / 1024);

    HG_Test_finalize(&hg_test_info);

    return EXIT_SUCCESS;
}
