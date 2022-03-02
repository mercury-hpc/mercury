/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_lat.h"

/****************/
/* Local Macros */
/****************/
#define BENCHMARK_NAME "Message latency"
#define STRING(s)      #s
#define XSTRING(s)     STRING(s)
#define VERSION_NAME                                                           \
    XSTRING(0)                                                                 \
    "." XSTRING(1) "." XSTRING(0)

#define SMALL_SKIP 1000

#define NDIGITS     2
#define NWIDTH      15
#define NA_TEST_TAG 1

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static na_return_t
na_test_lat_run(struct na_test_lat_info *info, size_t buf_size);

static na_return_t
na_test_lat_send_finalize(struct na_test_lat_info *info);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_lat_run(struct na_test_lat_info *info, size_t buf_size)
{
    size_t loop = (size_t) info->na_test_info.loop;
    unsigned int mpi_comm_size =
        (unsigned int) info->na_test_info.mpi_comm_size;
    int mpi_comm_rank = info->na_test_info.mpi_comm_rank;
    size_t iter_cur;
    hg_time_t time_add = hg_time_from_ms(0);
#ifndef HG_TEST_PRINT_PARTIAL
    hg_time_t t1, t2;
#endif
    double msg_lat;
    na_return_t ret;
    size_t i;

    /* Warm up */
    for (i = 0; i < SMALL_SKIP; i++) {
        hg_request_reset(info->request);
        memset(info->recv_buf, 0, buf_size);

        /* Post recv */
        ret = NA_Msg_recv_expected(info->na_class, info->context,
            na_test_lat_request_complete, info->request, info->recv_buf,
            buf_size, info->recv_buf_data, info->target_addr, 0, NA_TEST_TAG,
            info->recv_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
            NA_Error_to_string(ret));

        /* Post send */
        ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
            info->send_buf, buf_size, info->send_buf_data, info->target_addr, 0,
            NA_TEST_TAG, info->send_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "NA_Msg_send_unexpected() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);
    }

    if (info->na_test_info.mpi_comm_size > 1)
        NA_Test_barrier(&info->na_test_info);

#ifndef HG_TEST_PRINT_PARTIAL
    hg_time_get_current(&t1);
#endif

    /* Actual benchmark */
    for (iter_cur = 0; iter_cur < loop; iter_cur++) {
#ifdef HG_TEST_PRINT_PARTIAL
        hg_time_t t1, t2;
#endif

        hg_request_reset(info->request);
#ifdef HG_TEST_HAS_VERIFY_DATA
        memset(info->recv_buf, 0, buf_size);
#endif

#ifdef HG_TEST_PRINT_PARTIAL
        hg_time_get_current(&t1);
#endif

        /* Post recv */
        ret = NA_Msg_recv_expected(info->na_class, info->context,
            na_test_lat_request_complete, info->request, info->recv_buf,
            buf_size, info->recv_buf_data, info->target_addr, 0, NA_TEST_TAG,
            info->recv_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
            NA_Error_to_string(ret));

        /* Post send */
        ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
            info->send_buf, buf_size, info->send_buf_data, info->target_addr, 0,
            NA_TEST_TAG, info->send_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "NA_Msg_send_unexpected() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

        if (info->na_test_info.mpi_comm_size > 1)
            NA_Test_barrier(&info->na_test_info);

#ifdef HG_TEST_HAS_VERIFY_DATA
        ret = na_test_lat_verify_data(
            info->recv_buf, buf_size, info->header_size);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "na_test_lat_verify_data() failed (%s)", NA_Error_to_string(ret));
#endif

#ifdef HG_TEST_PRINT_PARTIAL
        hg_time_get_current(&t2);
        time_add = hg_time_add(hg_time_subtract(t2, t1), time_add);

        /* Partial latency */
        msg_lat = hg_time_to_double(time_add) * 1.0e6 /
                  (double) ((iter_cur + 1) * 2 * mpi_comm_size);

        if (mpi_comm_rank == 0)
            fprintf(
                stdout, "%-*zu%*.*f\r", 10, buf_size, NWIDTH, NDIGITS, msg_lat);
#endif
    }
#ifndef HG_TEST_PRINT_PARTIAL
    hg_time_get_current(&t2);
    time_add = hg_time_subtract(t2, t1);

    msg_lat = hg_time_to_double(time_add) * 1.0e6 /
              (double) (loop * 2 * mpi_comm_size);

    if (mpi_comm_rank == 0)
        fprintf(stdout, "%-*zu%*.*f", 10, buf_size, NWIDTH, NDIGITS, msg_lat);
#endif
    if (mpi_comm_rank == 0)
        fprintf(stdout, "\n");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_lat_send_finalize(struct na_test_lat_info *info)
{
    na_return_t ret;

    /* Reset */
    hg_request_reset(info->request);

    /* Post recv */
    ret = NA_Msg_recv_expected(info->na_class, info->context,
        na_test_lat_request_complete, info->request, info->recv_buf, 1,
        info->recv_buf_data, info->target_addr, 0, NA_TEST_TAG_DONE,
        info->recv_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
        NA_Error_to_string(ret));

    /* Post send */
    ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
        info->send_buf, 1, info->send_buf_data, info->target_addr, 0,
        NA_TEST_TAG_DONE, info->send_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_send_unexpected() failed (%s)",
        NA_Error_to_string(ret));

    hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_test_lat_info info;
    size_t size;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_test_lat_init(argc, argv, false, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_test_lat_init() failed (%s)",
        NA_Error_to_string(na_ret));

    /* Header info */
    if (info.na_test_info.mpi_comm_rank == 0) {
        fprintf(stdout, "# %s v%s\n", BENCHMARK_NAME, VERSION_NAME);
        fprintf(stdout, "# Loop %d times from size %zu to %zu byte(s)\n",
            info.na_test_info.loop, info.header_size, info.max_buf_size);
#ifdef HG_TEST_HAS_VERIFY_DATA
        fprintf(stdout, "# WARNING verifying data, output will be slower\n");
#endif
        fprintf(stdout, "%-*s%*s\n", 10, "# Size", NWIDTH, "Avg Lat (us)");
        fflush(stdout);
    }

    /* Msg with different sizes */
    for (size = info.header_size; size <= info.max_buf_size; size *= 2) {
        na_ret = na_test_lat_run(&info, size);
        NA_TEST_CHECK_NA_ERROR(error, na_ret,
            "na_test_measure_latency(%zu) failed (%s)", size,
            NA_Error_to_string(na_ret));
    }

    /* Finalize interface */
    if (info.na_test_info.mpi_comm_rank == 0)
        na_test_lat_send_finalize(&info);

    na_test_lat_cleanup(&info);

    return EXIT_SUCCESS;

error:
    na_test_lat_cleanup(&info);

    return EXIT_FAILURE;
}
