/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_perf.h"

/****************/
/* Local Macros */
/****************/
#define BENCHMARK_NAME "Message latency"

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
    double msg_lat;
    na_return_t ret;
    size_t i;

    /* Warm up */
    for (i = 0; i < SMALL_SKIP; i++) {
        hg_request_reset(info->request);

        /* Post recv */
        ret = NA_Msg_recv_expected(info->na_class, info->context,
            na_test_perf_request_complete, info->request, info->msg_exp_buf,
            buf_size, info->msg_exp_data, info->target_addr, 0,
            NA_TEST_PERF_TAG_LAT_INIT, info->msg_exp_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
            NA_Error_to_string(ret));

        /* Post send */
        ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
            info->msg_unexp_buf, buf_size, info->msg_unexp_data,
            info->target_addr, 0, NA_TEST_PERF_TAG_LAT_INIT,
            info->msg_unexp_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "NA_Msg_send_unexpected() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);
    }

    if (info->na_test_info.mpi_comm_size > 1)
        NA_Test_barrier(&info->na_test_info);

    hg_time_get_current(&t1);

    /* Actual benchmark */
    for (iter_cur = 0; iter_cur < loop; iter_cur++) {
        hg_request_reset(info->request);
        if (info->na_test_info.verify) {
            memset(info->msg_exp_buf, 0, buf_size);

            ret = NA_Msg_init_expected(
                info->na_class, info->msg_exp_buf, info->msg_exp_size_max);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "NA_Msg_init_unexpected() failed (%s)",
                NA_Error_to_string(ret));
        }

        /* Post recv */
        ret = NA_Msg_recv_expected(info->na_class, info->context,
            na_test_perf_request_complete, info->request, info->msg_exp_buf,
            buf_size, info->msg_exp_data, info->target_addr, 0,
            NA_TEST_PERF_TAG_LAT, info->msg_exp_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
            NA_Error_to_string(ret));

        /* Post send */
        ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
            info->msg_unexp_buf, buf_size, info->msg_unexp_data,
            info->target_addr, 0, NA_TEST_PERF_TAG_LAT, info->msg_unexp_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "NA_Msg_send_unexpected() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

        if (info->na_test_info.verify) {
            ret = na_test_perf_verify_data(
                info->msg_exp_buf, buf_size, info->msg_exp_header_size);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "na_test_perf_verify_data() failed (%s)",
                NA_Error_to_string(ret));
        }
    }

    if (info->na_test_info.mpi_comm_size > 1)
        NA_Test_barrier(&info->na_test_info);

    hg_time_get_current(&t2);
    time_add = hg_time_subtract(t2, t1);

    msg_lat = hg_time_to_double(time_add) * 1.0e6 /
              (double) (loop * 2 * mpi_comm_size);

    if (mpi_comm_rank == 0)
        fprintf(stdout, "%-*zu%*.*f", 10, buf_size, NWIDTH, NDIGITS, msg_lat);

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
    size_t size, min_size;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_test_perf_init(argc, argv, false, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_test_perf_init() failed (%s)",
        NA_Error_to_string(na_ret));

    /* init data */
    na_test_perf_init_data(info.msg_unexp_buf, info.msg_unexp_size_max,
        info.msg_unexp_header_size);

    min_size =
        (info.msg_unexp_header_size > 0) ? info.msg_unexp_header_size : 1;

    /* Header info */
    if (info.na_test_info.mpi_comm_rank == 0) {
        fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
        fprintf(stdout, "# Loop %d times from size %zu to %zu byte(s)\n",
            info.na_test_info.loop, min_size, info.msg_unexp_size_max);
        if (info.na_test_info.verify)
            fprintf(
                stdout, "# WARNING verifying data, output will be slower\n");
        fprintf(stdout, "%-*s%*s\n", 10, "# Size", NWIDTH, "Avg Lat (us)");
        fflush(stdout);
    }

    /* Msg with different sizes */
    for (size = min_size; size <= info.msg_unexp_size_max; size *= 2) {
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
