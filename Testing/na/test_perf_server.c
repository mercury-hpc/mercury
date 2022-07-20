/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_perf.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_test_perf_recv_info {
    struct na_cb_info_recv_unexpected recv;
    struct na_test_perf_info *info;
    na_return_t ret;
};

/********************/
/* Local Prototypes */
/********************/

static na_return_t
na_test_perf_loop(struct na_test_perf_info *info);

static int
na_test_perf_req_process(const struct na_cb_info *na_cb_info);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_perf_loop(struct na_test_perf_info *info)
{
    struct na_test_perf_recv_info recv_info;
    na_return_t ret;

    memset(&recv_info, 0, sizeof(recv_info));
    recv_info.info = info;

    while (recv_info.recv.tag != NA_TEST_PERF_TAG_DONE) {
        hg_request_reset(info->request);

        /* Post recv */
        ret = NA_Msg_recv_unexpected(info->na_class, info->context,
            na_test_perf_req_process, &recv_info, info->msg_unexp_buf,
            info->msg_unexp_size_max, info->msg_unexp_data,
            info->msg_unexp_op_id);
        NA_TEST_CHECK_NA_ERROR(error, ret,
            "NA_Msg_recv_unexpected() failed (%s)", NA_Error_to_string(ret));

        hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

        NA_TEST_CHECK_ERROR(recv_info.ret != NA_SUCCESS, error, ret,
            recv_info.ret, "NA_Msg_recv_unexpected() failed (%s)",
            NA_Error_to_string(recv_info.ret));
    }

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
na_test_perf_req_process(const struct na_cb_info *na_cb_info)
{
    struct na_test_perf_recv_info *recv_info =
        (struct na_test_perf_recv_info *) na_cb_info->arg;
    struct na_test_perf_info *info = recv_info->info;
    na_return_t ret = NA_SUCCESS;
    size_t i;

    recv_info->recv = na_cb_info->info.recv_unexpected;

    switch (recv_info->recv.tag) {
        case NA_TEST_PERF_TAG_LAT_INIT:
            /* init data separately to avoid a memcpy */
            na_test_perf_init_data(info->msg_exp_buf, info->msg_exp_size_max,
                info->msg_exp_header_size);
            hg_request_complete(info->request);
            break;
        case NA_TEST_PERF_TAG_LAT:
            /* Respond with same data */
            ret = NA_Msg_send_expected(info->na_class, info->context,
                na_test_perf_request_complete, info->request, info->msg_exp_buf,
                recv_info->recv.actual_buf_size, info->msg_exp_data,
                recv_info->recv.source, 0, recv_info->recv.tag,
                info->msg_exp_op_id);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "NA_Msg_send_expected() failed (%s)", NA_Error_to_string(ret));
            break;
        case NA_TEST_PERF_TAG_PUT:
            ret = na_test_perf_mem_handle_send(
                info, recv_info->recv.source, recv_info->recv.tag);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "na_test_perf_mem_handle_send() failed (%s)",
                NA_Error_to_string(ret));
            break;
        case NA_TEST_PERF_TAG_GET:
            /* Init data */
            for (i = 0; i < info->rma_count; i++)
                na_test_perf_init_data(
                    (char *) info->rma_buf + i * info->rma_size_max,
                    info->rma_size_max, 0);

            ret = na_test_perf_mem_handle_send(
                info, recv_info->recv.source, recv_info->recv.tag);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "na_test_perf_mem_handle_send() failed (%s)",
                NA_Error_to_string(ret));
            break;
        case NA_TEST_PERF_TAG_DONE:
            hg_request_complete(info->request);
            break;
        default:
            ret = NA_PROTOCOL_ERROR;
            hg_request_complete(info->request);
            break;
    }

    (void) NA_Addr_free(info->na_class, recv_info->recv.source);

done:
    recv_info->ret = ret;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_test_perf_info info;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_test_perf_init(argc, argv, true, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_test_perf_init() failed (%s)",
        NA_Error_to_string(na_ret));

    /* Loop */
    na_test_perf_loop(&info);

    /* Finalize interface */
    printf("Finalizing...\n");
    na_test_perf_cleanup(&info);

    return EXIT_SUCCESS;

error:
    return EXIT_FAILURE;
}
