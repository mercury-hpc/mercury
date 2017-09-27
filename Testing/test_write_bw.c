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

#define BENCHMARK_NAME "Write BW (server bulk pull)"
#define STRING(s) #s
#define XSTRING(s) STRING(s)
#define VERSION_NAME \
    XSTRING(HG_VERSION_MAJOR) \
    "." \
    XSTRING(HG_VERSION_MINOR) \
    "." \
    XSTRING(HG_VERSION_PATCH)

#define SMALL_SKIP 20
#define LARGE_SKIP 10
#define LARGE_SIZE 8192

#define NDIGITS 2
#define NWIDTH 20
#define MAX_MSG_SIZE (1<<22)

extern int na_test_comm_rank_g;
extern int na_test_comm_size_g;

extern hg_id_t hg_test_perf_bulk_id_g;

static hg_return_t
hg_test_perf_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_request_complete((hg_request_t *) callback_info->arg);

    return HG_SUCCESS;
}

static hg_return_t
measure_bulk_transfer(hg_class_t *hg_class, hg_context_t *context,
    hg_addr_t addr, size_t total_size, hg_request_class_t *request_class)
{
    bulk_write_in_t in_struct;
    void *bulk_buf;
    void **buf_ptrs;
    size_t *buf_sizes;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t nbytes = total_size;
    double nmbytes = (double) total_size / (1024 * 1024);
    size_t skip = (total_size > LARGE_SIZE) ? LARGE_SKIP : SMALL_SKIP;
    hg_handle_t handle;
    hg_request_t *request;
    int avg_iter;
    double time_read = 0, min_time_read = -1, max_time_read = 0;
    hg_return_t ret = HG_SUCCESS;
    size_t i;

    /* Prepare bulk_buf */
    bulk_buf = malloc(nbytes);
    buf_ptrs = &bulk_buf;
    buf_sizes = &nbytes;

    ret = HG_Create(context, addr, hg_test_perf_bulk_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    request = hg_request_create(request_class);

    /* Register memory */
    ret = HG_Bulk_create(hg_class, 1, buf_ptrs, (hg_size_t *) buf_sizes,
        HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        goto done;
    }

    /* Fill input structure */
    in_struct.fildes = 0;
    in_struct.bulk_handle = bulk_handle;

    /* Warm up for bulk data */
    for (i = 0; i < skip; i++) {
        ret = HG_Forward(handle, hg_test_perf_forward_cb, request, &in_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            goto done;
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_request_reset(request);
    }

    NA_Test_barrier();

    /* Bulk data benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_time_t t1, t2;
        double td, part_time_read;
        double read_bandwidth;
//        double min_read_bandwidth, max_read_bandwidth;

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
        if (min_time_read < 0) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;

        hg_request_reset(request);

        part_time_read = time_read / (avg_iter + 1);
        read_bandwidth = nmbytes * na_test_comm_size_g / part_time_read;
//        min_read_bandwidth = nmbytes * na_test_comm_size_g / max_time_read;
//        max_read_bandwidth = nmbytes * na_test_comm_size_g / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (na_test_comm_rank_g == 0) {
            fprintf(stdout, "%-*d%*.*f\r", 10, (int) nbytes, NWIDTH,
                NDIGITS, read_bandwidth);
        }
    }
    if (na_test_comm_rank_g == 0) fprintf(stdout, "\n");

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        goto done;
    }

    /* Free bulk data */
    free(*buf_ptrs);

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
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    size_t size;
    hg_addr_t addr;

    hg_class = HG_Test_client_init(argc, argv, &addr, &na_test_comm_rank_g,
            &context, &request_class);

    if (na_test_comm_rank_g == 0) {
        fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
        fprintf(stdout, "%-*s%*s\n", 10, "# Size", NWIDTH,
                "Bandwidth (MB/s)");
        fflush(stdout);
    }

    for (size = 1; size <= MAX_MSG_SIZE; size *= 2) {
        measure_bulk_transfer(hg_class, context, addr, size, request_class);
    }

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
