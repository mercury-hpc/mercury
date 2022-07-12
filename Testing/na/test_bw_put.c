/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_perf.h"

/****************/
/* Local Macros */
/****************/
#define BENCHMARK_NAME "NA_Put() Bandwidth"

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static na_return_t
na_test_perf_run(struct na_test_perf_info *info, size_t buf_size);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_perf_run(struct na_test_perf_info *info, size_t buf_size)
{
    size_t loop = (size_t) info->na_test_info.loop;
    unsigned int mpi_comm_size =
        (unsigned int) info->na_test_info.mpi_comm_size;
    int mpi_comm_rank = info->na_test_info.mpi_comm_rank;
    size_t iter_cur;
    hg_time_t time_add = hg_time_from_ms(0);
    hg_time_t t1, t2;
    double avg_time, avg_bw;
    na_return_t ret;
    size_t i;

    /* Warm up */
    for (i = 0; i < SMALL_SKIP; i++) {
        hg_request_reset(info->request);

        if (info->na_test_info.force_register) {
            ret = NA_Mem_handle_create(info->na_class, info->rma_buf,
                info->rma_size_max, NA_MEM_READ_ONLY, &info->local_handle);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "NA_Mem_handle_create() failed (%s)", NA_Error_to_string(ret));

            ret = NA_Mem_register(
                info->na_class, info->local_handle, NA_MEM_TYPE_HOST, 0);
            NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_register() failed (%s)",
                NA_Error_to_string(ret));
        }

        /* Post put */
        ret =
            NA_Put(info->na_class, info->context, na_test_perf_request_complete,
                info->request, info->local_handle, 0, info->remote_handle, 0,
                buf_size, info->target_addr, 0, info->rma_op_id);
        NA_TEST_CHECK_NA_ERROR(
            error, ret, "NA_Put() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

        if (info->na_test_info.force_register) {
            NA_Mem_deregister(info->na_class, info->local_handle);
            NA_Mem_handle_free(info->na_class, info->local_handle);
            info->local_handle = NA_MEM_HANDLE_NULL;
        }
    }

    if (info->na_test_info.mpi_comm_size > 1)
        NA_Test_barrier(&info->na_test_info);

    hg_time_get_current(&t1);

    /* Actual benchmark */
    for (iter_cur = 0; iter_cur < loop; iter_cur++) {
        hg_request_reset(info->request);
        if (info->na_test_info.verify)
            memset(info->verify_buf, 0, buf_size);

        if (info->na_test_info.force_register) {
            ret = NA_Mem_handle_create(info->na_class, info->rma_buf,
                info->rma_size_max, NA_MEM_READ_ONLY, &info->local_handle);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "NA_Mem_handle_create() failed (%s)", NA_Error_to_string(ret));

            ret = NA_Mem_register(
                info->na_class, info->local_handle, NA_MEM_TYPE_HOST, 0);
            NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_register() failed (%s)",
                NA_Error_to_string(ret));
        }

        /* Post put */
        ret =
            NA_Put(info->na_class, info->context, na_test_perf_request_complete,
                info->request, info->local_handle, 0, info->remote_handle, 0,
                buf_size, info->target_addr, 0, info->rma_op_id);
        NA_TEST_CHECK_NA_ERROR(
            error, ret, "NA_Put() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

        if (info->na_test_info.verify) {
            hg_request_reset(info->request);

            /* Post get */
            ret = NA_Get(info->na_class, info->context,
                na_test_perf_request_complete, info->request,
                info->verify_handle, 0, info->remote_handle, 0, buf_size,
                info->target_addr, 0, info->rma_op_id);
            NA_TEST_CHECK_NA_ERROR(
                error, ret, "NA_Get() failed (%s)", NA_Error_to_string(ret));

            hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

            ret = na_test_perf_verify_data(info->verify_buf, buf_size, 0);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "na_test_perf_verify_data() failed (%s)",
                NA_Error_to_string(ret));
        }

        if (info->na_test_info.force_register) {
            NA_Mem_deregister(info->na_class, info->local_handle);
            NA_Mem_handle_free(info->na_class, info->local_handle);
            info->local_handle = NA_MEM_HANDLE_NULL;
        }
    }

    if (info->na_test_info.mpi_comm_size > 1)
        NA_Test_barrier(&info->na_test_info);

    hg_time_get_current(&t2);
    time_add = hg_time_subtract(t2, t1);

    avg_time =
        hg_time_to_double(time_add) * 1.0e6 / (double) (loop * mpi_comm_size);
    avg_bw = (double) (buf_size * loop * mpi_comm_size) /
             (hg_time_to_double(time_add) * 1024 * 1024);

    if (mpi_comm_rank == 0)
        fprintf(stdout, "%-*zu%*.*f%*.*f", 10, buf_size, NWIDTH, NDIGITS,
            avg_bw, NWIDTH, NDIGITS, avg_time);

    if (mpi_comm_rank == 0)
        fprintf(stdout, "\n");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_test_perf_info info;
    size_t size;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_test_perf_init(argc, argv, false, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_test_perf_init() failed (%s)",
        NA_Error_to_string(na_ret));

    /* init data */
    na_test_perf_init_data(info.rma_buf, info.rma_size_max, 0);

    /* Retrieve server memory handle */
    na_ret = na_test_perf_mem_handle_recv(&info, NA_TEST_PERF_TAG_PUT);
    NA_TEST_CHECK_NA_ERROR(error, na_ret,
        "na_test_perf_mem_handle_recv() failed (%s)",
        NA_Error_to_string(na_ret));

    /* Header info */
    if (info.na_test_info.mpi_comm_rank == 0) {
        fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
        fprintf(stdout, "# Loop %d times from size %zu to %zu byte(s)\n",
            info.na_test_info.loop, info.rma_size_min, info.rma_size_max);
        if (info.na_test_info.verify)
            fprintf(
                stdout, "# WARNING verifying data, output will be slower\n");
        if (info.na_test_info.force_register)
            fprintf(
                stdout, "# WARNING forcing registration on every iteration\n");
        fprintf(stdout, "%-*s%*s%*s\n", 10, "# Size", NWIDTH,
            "Bandwidth (MB/s)", NWIDTH, "Time (us)");
        fflush(stdout);
    }

    /* Msg with different sizes */
    for (size = info.rma_size_min; size <= info.rma_size_max; size *= 2) {
        na_ret = na_test_perf_run(&info, size);
        NA_TEST_CHECK_NA_ERROR(error, na_ret,
            "na_test_perf_run(%zu) failed (%s)", size,
            NA_Error_to_string(na_ret));
    }

    /* Finalize interface */
    if (info.na_test_info.mpi_comm_rank == 0)
        na_test_perf_send_finalize(&info);

    na_test_perf_cleanup(&info);

    return EXIT_SUCCESS;

error:
    na_test_perf_cleanup(&info);

    return EXIT_FAILURE;
}
