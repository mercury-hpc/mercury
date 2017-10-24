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
#define MAX_MSG_SIZE (MERCURY_TESTING_BUFFER_SIZE * 1024 * 1024)
#define MAX_HANDLES 16

extern int na_test_comm_rank_g;
extern int na_test_comm_size_g;

extern hg_id_t hg_test_perf_bulk_write_id_g;

struct hg_test_perf_args {
    hg_request_t *request;
    unsigned int op_count;
    hg_atomic_int32_t op_completed_count;
};

static hg_return_t
hg_test_perf_forward_cb(const struct hg_cb_info *callback_info)
{
    struct hg_test_perf_args *args =
        (struct hg_test_perf_args *) callback_info->arg;

    if ((unsigned int) hg_atomic_incr32(&args->op_completed_count)
        == args->op_count) {
        hg_request_complete(args->request);
    }

    return HG_SUCCESS;
}

static hg_return_t
measure_bulk_transfer(hg_class_t *hg_class, hg_context_t *context,
    hg_addr_t addr, size_t total_size, unsigned int nhandles,
    hg_request_class_t *request_class)
{
    bulk_write_in_t in_struct;
    char *bulk_buf;
    void **buf_ptrs;
    size_t *buf_sizes;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t nbytes = total_size;
    double nmbytes = (double) total_size / (1024 * 1024);
    size_t loop = (total_size > LARGE_SIZE) ? MERCURY_TESTING_MAX_LOOP :
        MERCURY_TESTING_MAX_LOOP * 10;
    size_t skip = (total_size > LARGE_SIZE) ? LARGE_SKIP : SMALL_SKIP;
    hg_handle_t *handles = NULL;
    hg_request_t *request;
    struct hg_test_perf_args args;
    size_t avg_iter;
    double time_read = 0, read_bandwidth;
    hg_return_t ret = HG_SUCCESS;
    size_t i;

    /* Prepare bulk_buf */
    bulk_buf = malloc(nbytes);
    for (i = 0; i < nbytes; i++)
        bulk_buf[i] = (char) i;
    buf_ptrs = (void **) &bulk_buf;
    buf_sizes = &nbytes;

    /* Create handles */
    handles = malloc(nhandles * sizeof(hg_handle_t));
    for (i = 0; i < nhandles; i++) {
        ret = HG_Create(context, addr, hg_test_perf_bulk_write_id_g, &handles[i]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not start call\n");
            goto done;
        }
    }

    request = hg_request_create(request_class);
    hg_atomic_init32(&args.op_completed_count, 0);
    args.op_count = nhandles;
    args.request = request;

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
        unsigned int j;

        for (j = 0; j < nhandles; j++) {
            ret = HG_Forward(handles[j], hg_test_perf_forward_cb, &args, &in_struct);
            if (ret != HG_SUCCESS) {
                fprintf(stderr, "Could not forward call\n");
                goto done;
            }
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_request_reset(request);
        hg_atomic_set32(&args.op_completed_count, 0);
    }

    NA_Test_barrier();

    /* Bulk data benchmark */
    for (avg_iter = 0; avg_iter < loop; avg_iter++) {
        hg_time_t t1, t2;
        unsigned int j;

        hg_time_get_current(&t1);

        for (j = 0; j < nhandles; j++) {
            ret = HG_Forward(handles[j], hg_test_perf_forward_cb, &args, &in_struct);
            if (ret != HG_SUCCESS) {
                fprintf(stderr, "Could not forward call\n");
                goto done;
            }
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        NA_Test_barrier();
        hg_time_get_current(&t2);
        time_read += hg_time_to_double(hg_time_subtract(t2, t1));

        hg_request_reset(request);
        hg_atomic_set32(&args.op_completed_count, 0);

#ifdef MERCURY_TESTING_PRINT_PARTIAL
        read_bandwidth = nmbytes
            * (double) (nhandles * (avg_iter + 1) * (unsigned int) na_test_comm_size_g)
            / time_read;

        /* At this point we have received everything so work out the bandwidth */
        if (na_test_comm_rank_g == 0)
            fprintf(stdout, "%-*d%*.*f\r", 10, (int) nbytes, NWIDTH,
                NDIGITS, read_bandwidth);
#endif
    }
#ifndef MERCURY_TESTING_PRINT_PARTIAL
    read_bandwidth = nmbytes
        * (double) (nhandles * loop * (unsigned int) na_test_comm_size_g)
        / time_read;

    /* At this point we have received everything so work out the bandwidth */
    if (na_test_comm_rank_g == 0)
        fprintf(stdout, "%-*d%*.*f", 10, (int) nbytes, NWIDTH, NDIGITS,
            read_bandwidth);
#endif
    if (na_test_comm_rank_g == 0) fprintf(stdout, "\n");

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        goto done;
    }

    /* Complete */
    hg_request_destroy(request);
    for (i = 0; i < nhandles; i++) {
        ret = HG_Destroy(handles[i]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete\n");
            goto done;
        }
    }

done:
    free(bulk_buf);
    free(handles);
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
    unsigned int nhandles;

    hg_class = HG_Test_client_init(argc, argv, &addr, &na_test_comm_rank_g,
            &context, &request_class);

    for (nhandles = 1; nhandles <= MAX_HANDLES; nhandles *= 2) {
        if (na_test_comm_rank_g == 0) {
            fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
            fprintf(stdout, "# Loop %d times from size %d to %d byte(s) with "
                "%u handle(s)\n",
                MERCURY_TESTING_MAX_LOOP, 1, MAX_MSG_SIZE, nhandles);
#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
            fprintf(stdout, "# WARNING verifying data, output will be slower\n");
#endif
            fprintf(stdout, "%-*s%*s\n", 10, "# Size", NWIDTH,
                "Bandwidth (MB/s)");
            fflush(stdout);
        }

        for (size = 1; size <= MAX_MSG_SIZE; size *= 2)
            measure_bulk_transfer(hg_class, context, addr, size, nhandles,
                request_class);

        fprintf(stdout, "\n");
    }

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
