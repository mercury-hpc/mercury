/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_perf.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_perf_recv_info {
    struct na_perf_info *info;
    na_return_t ret;
    bool post_new_recv;
    bool done;
};

typedef na_return_t (*na_perf_recv_op_t)(na_class_t *na_class,
    na_context_t *context, na_cb_t callback, void *arg, void *buf,
    size_t buf_size, void *plugin_data, na_op_id_t *op_id);

/********************/
/* Local Prototypes */
/********************/

static na_return_t
na_perf_loop(
    struct na_perf_info *info, na_perf_recv_op_t recv_op, na_cb_t recv_op_cb);

static void
na_perf_recv_cb(const struct na_cb_info *na_cb_info);

static void
na_perf_multi_recv_cb(const struct na_cb_info *na_cb_info);

static void
na_perf_process_recv(struct na_perf_recv_info *recv_info, void *actual_buf,
    size_t actual_buf_size, na_addr_t source, na_tag_t tag);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static na_return_t
na_perf_loop(
    struct na_perf_info *info, na_perf_recv_op_t recv_op, na_cb_t recv_op_cb)
{
    struct na_perf_recv_info recv_info;
    na_return_t ret;

    memset(&recv_info, 0, sizeof(recv_info));
    recv_info.info = info;
    recv_info.post_new_recv = true;

    do {
        unsigned int actual_count = 0;

        if (recv_info.post_new_recv) {
            recv_info.post_new_recv = false;

            /* Post recv */
            ret = recv_op(info->na_class, info->context, recv_op_cb, &recv_info,
                info->msg_unexp_buf, info->msg_unexp_size_max,
                info->msg_unexp_data, info->msg_unexp_op_id);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "NA_Msg_recv_unexpected() failed (%s)",
                NA_Error_to_string(ret));
        }

        do {
            ret = NA_Trigger(info->context, 1, &actual_count);
            NA_TEST_CHECK_ERROR(recv_info.ret != NA_SUCCESS, error, ret,
                recv_info.ret, "NA_Msg_recv_unexpected() failed (%s)",
                NA_Error_to_string(recv_info.ret));
        } while ((ret == NA_SUCCESS) && actual_count);
        NA_TEST_CHECK_ERROR_NORET(ret != NA_SUCCESS, error,
            "NA_Trigger() failed (%s)", NA_Error_to_string(ret));

        if (recv_info.done)
            break;

        ret = NA_Progress(info->na_class, info->context, 1000);
    } while ((ret == NA_SUCCESS) || (ret == NA_TIMEOUT));
    NA_TEST_CHECK_ERROR_NORET(ret != NA_SUCCESS && ret != NA_TIMEOUT, error,
        "NA_Progress() failed (%s)", NA_Error_to_string(ret));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_perf_recv_cb(const struct na_cb_info *na_cb_info)
{
    struct na_perf_recv_info *recv_info =
        (struct na_perf_recv_info *) na_cb_info->arg;
    const struct na_cb_info_recv_unexpected *msg_info =
        &na_cb_info->info.recv_unexpected;

    na_perf_process_recv(recv_info, NULL, msg_info->actual_buf_size,
        msg_info->source, msg_info->tag);

    recv_info->post_new_recv = true;
}

/*---------------------------------------------------------------------------*/
static void
na_perf_multi_recv_cb(const struct na_cb_info *na_cb_info)
{
    struct na_perf_recv_info *recv_info =
        (struct na_perf_recv_info *) na_cb_info->arg;
    const struct na_cb_info_multi_recv_unexpected *msg_info =
        &na_cb_info->info.multi_recv_unexpected;

    na_perf_process_recv(recv_info, msg_info->actual_buf,
        msg_info->actual_buf_size, msg_info->source, msg_info->tag);

    recv_info->post_new_recv = msg_info->last;
}

/*---------------------------------------------------------------------------*/
static void
na_perf_process_recv(struct na_perf_recv_info *recv_info,
    void NA_UNUSED *actual_buf, size_t actual_buf_size, na_addr_t source,
    na_tag_t tag)
{
    struct na_perf_info *info = recv_info->info;
    na_return_t ret = NA_SUCCESS;
    size_t i;

    switch (tag) {
        case NA_PERF_TAG_LAT_INIT:
            /* init data separately to avoid a memcpy */
            na_perf_init_data(info->msg_exp_buf, info->msg_exp_size_max,
                info->msg_exp_header_size);
            break;
        case NA_PERF_TAG_LAT:
            /* Respond with same data */
            ret = NA_Msg_send_expected(info->na_class, info->context, NULL,
                NULL, info->msg_exp_buf, actual_buf_size, info->msg_exp_data,
                source, 0, tag, info->msg_exp_op_id);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "NA_Msg_send_expected() failed (%s)", NA_Error_to_string(ret));
            break;
        case NA_PERF_TAG_PUT:
            ret = na_perf_mem_handle_send(info, source, tag);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "na_perf_mem_handle_send() failed (%s)",
                NA_Error_to_string(ret));
            break;
        case NA_PERF_TAG_GET:
            /* Init data */
            for (i = 0; i < info->rma_count; i++)
                na_perf_init_data(
                    (char *) info->rma_buf + i * info->rma_size_max,
                    info->rma_size_max, 0);

            ret = na_perf_mem_handle_send(info, source, tag);
            NA_TEST_CHECK_NA_ERROR(done, ret,
                "na_perf_mem_handle_send() failed (%s)",
                NA_Error_to_string(ret));
            break;
        case NA_PERF_TAG_DONE:
            recv_info->done = true;
            break;
        default:
            ret = NA_PROTOCOL_ERROR;
            break;
    }

    NA_Addr_free(info->na_class, source);

done:
    recv_info->ret = ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_perf_info info;
    na_return_t na_ret;

    /* Initialize the interface */
    na_ret = na_perf_init(argc, argv, true, &info);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_perf_init() failed (%s)",
        NA_Error_to_string(na_ret));

    HG_TEST_READY_MSG();

    /* Loop */
    if (NA_Has_opt_feature(info.na_class, NA_OPT_MULTI_RECV) &&
        !info.na_test_info.no_multi_recv)
        na_ret = na_perf_loop(
            &info, NA_Msg_multi_recv_unexpected, na_perf_multi_recv_cb);
    else
        na_ret = na_perf_loop(&info, NA_Msg_recv_unexpected, na_perf_recv_cb);
    NA_TEST_CHECK_NA_ERROR(error, na_ret, "na_perf_loop() failed (%s)",
        NA_Error_to_string(na_ret));

    /* Finalize interface */
    printf("Finalizing...\n");
    na_perf_cleanup(&info);

    return EXIT_SUCCESS;

error:
    na_perf_cleanup(&info);

    return EXIT_FAILURE;
}
