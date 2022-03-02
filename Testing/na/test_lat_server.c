/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_lat.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_test_lat_recv_info {
    struct na_cb_info_recv_unexpected recv;
    struct na_test_lat_info *info;
    na_return_t ret;
};

/********************/
/* Local Prototypes */
/********************/

static na_return_t
na_test_lat_loop(struct na_test_lat_info *info);

static int
na_test_lat_respond(const struct na_cb_info *na_cb_info);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_lat_loop(struct na_test_lat_info *info)
{
    struct na_test_lat_recv_info recv_info;
    na_return_t ret;

    memset(&recv_info, 0, sizeof(recv_info));
    recv_info.info = info;

    while (recv_info.recv.tag != NA_TEST_TAG_DONE) {
        hg_request_reset(info->request);

        /* Post recv */
        ret = NA_Msg_recv_unexpected(info->na_class, info->context,
            na_test_lat_respond, &recv_info, info->recv_buf, info->max_buf_size,
            info->recv_buf_data, info->recv_op_id);
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
na_test_lat_respond(const struct na_cb_info *na_cb_info)
{
    struct na_test_lat_recv_info *recv_info =
        (struct na_test_lat_recv_info *) na_cb_info->arg;
    struct na_test_lat_info *info = recv_info->info;
    na_return_t ret = NA_SUCCESS;

    recv_info->recv = na_cb_info->info.recv_unexpected;
#ifdef HG_TEST_HAS_VERIFY_DATA
    if (recv_info->recv.tag != NA_TEST_TAG_DONE) {
        ret = na_test_lat_verify_data(
            info->recv_buf, recv_info->recv.actual_buf_size, info->header_size);
        NA_TEST_CHECK_NA_ERROR(done, ret,
            "na_test_lat_verify_data() failed (%s)", NA_Error_to_string(ret));
    }
#endif

    /* Post send */
    ret = NA_Msg_send_expected(info->na_class, info->context,
        na_test_lat_request_complete, info->request, info->send_buf,
        recv_info->recv.actual_buf_size, info->send_buf_data,
        recv_info->recv.source, 0, recv_info->recv.tag, info->send_op_id);
    NA_TEST_CHECK_NA_ERROR(done, ret, "NA_Msg_send_expected() failed (%s)",
        NA_Error_to_string(ret));

    (void) NA_Addr_free(info->na_class, recv_info->recv.source);

done:
    recv_info->ret = ret;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_test_lat_info info;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_test_lat_init(argc, argv, true, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_test_lat_init() failed (%s)",
        NA_Error_to_string(na_ret));

    /* Loop */
    na_test_lat_loop(&info);

    /* Finalize interface */
    printf("Finalizing...\n");
    na_test_lat_cleanup(&info);

    return EXIT_SUCCESS;

error:
    return EXIT_FAILURE;
}
