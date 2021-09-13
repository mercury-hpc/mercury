/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_atomic.h"
#include "mercury_test.h"
#include "mercury_time.h"

/****************/
/* Local Macros */
/****************/

#define BENCHMARK_NAME "RPC latency"
#define STRING(s)      #s
#define XSTRING(s)     STRING(s)
#define VERSION_NAME                                                           \
    XSTRING(HG_VERSION_MAJOR)                                                  \
    "." XSTRING(HG_VERSION_MINOR) "." XSTRING(HG_VERSION_PATCH)

#define SMALL_SKIP 100
#define LARGE_SKIP 10
#define LARGE_SIZE 8192

#define NDIGITS 2
#define NWIDTH  20

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct hg_test_perf_args {
    struct hg_test_info *hg_test_info;
    hg_request_t *request;
    unsigned int op_count;
    hg_atomic_int32_t op_completed_count;
};

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_perf_forward_cb(const struct hg_cb_info *callback_info);
static hg_return_t
measure_rpc_latency(struct hg_test_info *hg_test_info, size_t total_size,
    unsigned int nhandles);

/*******************/
/* Local Variables */
/*******************/

extern hg_id_t hg_test_perf_rpc_id_g;
extern hg_id_t hg_test_perf_rpc_lat_id_g;
extern hg_id_t hg_test_perf_rpc_lat_bi_id_g;

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_perf_forward_cb(const struct hg_cb_info *callback_info)
{
    struct hg_test_perf_args *args =
        (struct hg_test_perf_args *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    if (args->hg_test_info->bidirectional) {
        perf_rpc_lat_out_t out_struct = {NULL, 0};

        /* Get output struct */
        ret = HG_Get_output(callback_info->info.forward.handle, &out_struct);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

        /* Get output struct */
        ret = HG_Free_output(callback_info->info.forward.handle, &out_struct);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));
    }

done:
    if ((unsigned int) hg_atomic_incr32(&args->op_completed_count) ==
        args->op_count)
        hg_request_complete(args->request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
measure_rpc_latency(
    struct hg_test_info *hg_test_info, size_t total_size, unsigned int nhandles)
{
    perf_rpc_lat_in_t in_struct;
    char *bulk_buf = NULL;
    size_t nbytes = (total_size > sizeof(in_struct.buf_size))
                        ? total_size - sizeof(in_struct.buf_size)
                        : 0;
    size_t loop = (total_size > LARGE_SIZE)
                      ? (size_t) hg_test_info->na_test_info.loop
                      : (size_t) hg_test_info->na_test_info.loop * 100;
    size_t skip = (total_size > LARGE_SIZE) ? LARGE_SKIP : SMALL_SKIP;
    hg_handle_t *handles = NULL;
    hg_request_t *request;
    struct hg_test_perf_args args;
    size_t avg_iter;
    double time_read = 0, read_lat;
    hg_return_t ret = HG_SUCCESS;
    hg_bool_t bidir = hg_test_info->bidirectional ? HG_TRUE : HG_FALSE;
    size_t i;
    hg_id_t rpc_id = 0;

    /* Prepare bulk_buf */
    if (nbytes) {
        bulk_buf = malloc(nbytes);
        HG_TEST_CHECK_ERROR(bulk_buf == NULL, done, ret, HG_NOMEM_ERROR,
            "Could not allocate bulk buf");
        for (i = 0; i < nbytes; i++)
            bulk_buf[i] = (char) i;
    }

    /* Create handles */
    handles = malloc(nhandles * sizeof(hg_handle_t));
    HG_TEST_CHECK_ERROR(handles == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate handles");

    /* Use NULL RPC ID to skip proc encoding if total_size = 0 */
    if (total_size == 0)
        rpc_id = hg_test_perf_rpc_id_g;
    else if (hg_test_info->bidirectional)
        rpc_id = hg_test_perf_rpc_lat_bi_id_g;
    else
        rpc_id = hg_test_perf_rpc_lat_id_g;

    for (i = 0; i < nhandles; i++) {
        ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
            rpc_id, &handles[i]);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));
    }

    request = hg_request_create(hg_test_info->request_class);
    hg_atomic_init32(&args.op_completed_count, 0);
    args.op_count = nhandles;
    args.request = request;
    args.hg_test_info = hg_test_info;

    /* Fill input structure */
    in_struct.buf_size = (hg_uint32_t) nbytes;
    in_struct.buf = bulk_buf;

    /* Warm up for RPC */
    for (i = 0; i < skip; i++) {
        unsigned int j;

        for (j = 0; j < nhandles; j++) {
again:
            ret = HG_Forward(
                handles[j], hg_test_perf_forward_cb, &args, &in_struct);
            if (ret == HG_AGAIN) {
                hg_request_wait(request, 0, NULL);
                goto again;
            }
            HG_TEST_CHECK_HG_ERROR(
                done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        hg_request_reset(request);
        hg_atomic_set32(&args.op_completed_count, 0);
    }

    NA_Test_barrier(&hg_test_info->na_test_info);

    /* RPC latency benchmark */
    for (avg_iter = 0; avg_iter < loop; avg_iter++) {
        hg_time_t t1, t2;
        unsigned int j;

        hg_time_get_current(&t1);

        for (j = 0; j < nhandles; j++) {
            /* Assign handles to multiple targets */
            if (hg_test_info->na_test_info.max_contexts > 1) {
                ret = HG_Set_target_id(handles[j],
                    (hg_uint8_t) (avg_iter %
                                  hg_test_info->na_test_info.max_contexts));
                HG_TEST_CHECK_HG_ERROR(done, ret,
                    "HG_Set_target_id() failed (%s)", HG_Error_to_string(ret));
            }

            ret = HG_Forward(
                handles[j], hg_test_perf_forward_cb, &args, &in_struct);
            HG_TEST_CHECK_HG_ERROR(
                done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));
        }

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
        NA_Test_barrier(&hg_test_info->na_test_info);
        hg_time_get_current(&t2);
        time_read += hg_time_to_double(hg_time_subtract(t2, t1));

        hg_request_reset(request);
        hg_atomic_set32(&args.op_completed_count, 0);

        /* We have received everything so calculate the bandwidth */
#ifdef HG_TEST_PRINT_PARTIAL
        read_lat =
            time_read * 1.0e6 /
            (double) (nhandles * (avg_iter + 1) * (bidir ? 2 : 1) *
                      (unsigned int) hg_test_info->na_test_info.mpi_comm_size);
        if (hg_test_info->na_test_info.mpi_comm_rank == 0)
            fprintf(stdout, "%-*d%*.*f%*d\r", 10, (int) total_size, NWIDTH,
                NDIGITS, (read_lat), NWIDTH, (int) (1.0e6 / read_lat));
#endif
    }
#ifndef HG_TEST_PRINT_PARTIAL
    read_lat =
        time_read * 1.0e6 /
        (double) (nhandles * loop * (bidir ? 2 : 1) *
                  (unsigned int) hg_test_info->na_test_info.mpi_comm_size);
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        fprintf(stdout, "%-*d%*.*f%*d\r", 10, (int) total_size, NWIDTH, NDIGITS,
            (read_lat), NWIDTH, (int) (1.0e6 / read_lat));
#endif
    if (hg_test_info->na_test_info.mpi_comm_rank == 0)
        fprintf(stdout, "\n");

    /* Complete */
    hg_request_destroy(request);
    for (i = 0; i < nhandles; i++) {
        ret = HG_Destroy(handles[i]);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));
    }

done:
    free(bulk_buf);
    free(handles);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = {0};
    unsigned int nhandles;
    size_t size;
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    hg_ret = HG_Test_init(argc, argv, &hg_test_info);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "HG_Test_init() failed");

    for (nhandles = 1; nhandles <= hg_test_info.handle_max; nhandles *= 2) {
        if (hg_test_info.na_test_info.mpi_comm_rank == 0) {
            fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
            fprintf(stdout,
                "# Loop %d times from size %" PRIu64 " to %" PRIu64
                " byte(s) with %u  handle(s)\n",
                hg_test_info.na_test_info.loop, hg_test_info.buf_size_min,
                hg_test_info.buf_size_max, nhandles);
#ifdef HG_TEST_HAS_VERIFY_DATA
            fprintf(
                stdout, "# WARNING verifying data, output will be slower\n");
#endif
            fprintf(stdout, "%-*s%*s%*s\n", 10, "# Size", NWIDTH,
                "Latency (us)", NWIDTH, "RPC rate (RPC/s)");
            fflush(stdout);
        }

        /* NULL RPC */
        hg_ret = measure_rpc_latency(&hg_test_info, 0, nhandles);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "measure_rpc_latency() failed");

        /* RPC with different sizes */
        for (size = MAX(hg_test_info.buf_size_min, sizeof(hg_uint32_t));
             size <= hg_test_info.buf_size_max; size *= 2) {
            hg_ret = measure_rpc_latency(&hg_test_info, size, nhandles);
            HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
                "measure_rpc_latency() failed");
        }

        fprintf(stdout, "\n");
    }

done:
    hg_ret = HG_Test_finalize(&hg_test_info);
    HG_TEST_CHECK_ERROR_DONE(hg_ret != HG_SUCCESS, "HG_Test_finalize() failed");

    return ret;
}
