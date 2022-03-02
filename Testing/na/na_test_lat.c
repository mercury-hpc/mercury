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

/********************/
/* Local Prototypes */
/********************/

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
int
na_test_lat_request_progress(unsigned int timeout, void *arg)
{
    struct na_test_lat_info *na_test_lat_info = (struct na_test_lat_info *) arg;
    unsigned int timeout_progress = 0;
    int ret = HG_UTIL_SUCCESS;

    /* Safe to block */
    if (NA_Poll_try_wait(na_test_lat_info->na_class, na_test_lat_info->context))
        timeout_progress = timeout;

    if (na_test_lat_info->poll_set && timeout_progress > 0) {
        struct hg_poll_event poll_event = {.events = 0, .data.ptr = NULL};
        unsigned int actual_events = 0;

        hg_poll_wait(na_test_lat_info->poll_set, timeout_progress, 1,
            &poll_event, &actual_events);
        if (actual_events == 0)
            return HG_UTIL_FAIL;

        timeout_progress = 0;
    }

    /* Progress */
    if (NA_Progress(na_test_lat_info->na_class, na_test_lat_info->context,
            timeout_progress) != NA_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
na_test_lat_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    struct na_test_lat_info *na_test_lat_info = (struct na_test_lat_info *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (NA_Trigger(na_test_lat_info->context, timeout, 1, NULL,
            &actual_count) != NA_SUCCESS)
        ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? true : false;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
na_test_lat_request_complete(const struct na_cb_info *na_cb_info)
{
    hg_request_t *request = (hg_request_t *) na_cb_info->arg;

    hg_request_complete(request);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_lat_init(
    int argc, char *argv[], bool listen, struct na_test_lat_info *info)
{
    char *send_data_ptr;
    size_t max_send_buf_size, max_recv_buf_size, send_data_size;
    size_t i;
    na_return_t ret;

    /* Initialize the interface */
    memset(info, 0, sizeof(*info));
    if (listen)
        info->na_test_info.listen = true;
    ret = NA_Test_init(argc, argv, &info->na_test_info);
    NA_TEST_CHECK_NA_ERROR(
        error, ret, "NA_Test_init() failed (%s)", NA_Error_to_string(ret));
    info->na_class = info->na_test_info.na_class;

    /* Set up */
    info->context = NA_Context_create(info->na_test_info.na_class);
    NA_TEST_CHECK_ERROR(info->context == NULL, error, ret, NA_NOMEM,
        "NA_Context_create() failed");

    info->poll_fd = NA_Poll_get_fd(info->na_class, info->context);
    if (info->poll_fd > 0) {
        struct hg_poll_event poll_event = {
            .events = HG_POLLIN, .data.ptr = NULL};
        int rc;

        info->poll_set = hg_poll_create();
        NA_TEST_CHECK_ERROR(info->poll_set == NULL, error, ret, NA_NOMEM,
            "hg_poll_create() failed");

        rc = hg_poll_add(info->poll_set, info->poll_fd, &poll_event);
        NA_TEST_CHECK_ERROR(
            rc != 0, error, ret, NA_PROTOCOL_ERROR, "hg_poll_add() failed");
    }

    info->request_class = hg_request_init(
        na_test_lat_request_progress, na_test_lat_request_trigger, info);
    NA_TEST_CHECK_ERROR(info->request_class == NULL, error, ret, NA_NOMEM,
        "hg_request_init() failed");

    /* Lookup target addr */
    if (!listen) {
        ret = NA_Addr_lookup(
            info->na_class, info->na_test_info.target_name, &info->target_addr);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Addr_lookup(%s) failed (%s)",
            info->na_test_info.target_name, NA_Error_to_string(ret));
    }

    /* Set max size */
    max_send_buf_size = (listen)
                            ? NA_Msg_get_max_expected_size(info->na_class)
                            : NA_Msg_get_max_unexpected_size(info->na_class);
    NA_TEST_CHECK_ERROR(max_send_buf_size == 0, error, ret, NA_INVALID_ARG,
        "max send size cannot be zero");

    max_recv_buf_size = (listen)
                            ? NA_Msg_get_max_unexpected_size(info->na_class)
                            : NA_Msg_get_max_expected_size(info->na_class);
    NA_TEST_CHECK_ERROR(max_recv_buf_size == 0, error, ret, NA_INVALID_ARG,
        "max recv size cannot be zero");

    info->max_buf_size = MIN(max_send_buf_size, max_recv_buf_size);

    /* Prepare send_buf */
    info->send_buf = NA_Msg_buf_alloc(
        info->na_class, info->max_buf_size, &info->send_buf_data);
    NA_TEST_CHECK_ERROR(info->send_buf == NULL, error, ret, NA_NOMEM,
        "NA_Msg_buf_alloc() failed");
    memset(info->send_buf, 0, info->max_buf_size);

    if (listen)
        ret = NA_Msg_init_expected(
            info->na_class, info->send_buf, info->max_buf_size);
    else
        ret = NA_Msg_init_unexpected(
            info->na_class, info->send_buf, info->max_buf_size);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_init_unexpected() failed (%s)",
        NA_Error_to_string(ret));

    /* Init with some non-zero values */
    info->header_size = MAX(NA_Msg_get_expected_header_size(info->na_class),
        NA_Msg_get_unexpected_header_size(info->na_class));
    send_data_ptr = (char *) info->send_buf + info->header_size;
    send_data_size = info->max_buf_size - info->header_size;
    for (i = 0; i < send_data_size; i++)
        send_data_ptr[i] = (char) i;

    /* Prepare recv_buf */
    info->recv_buf = NA_Msg_buf_alloc(
        info->na_class, info->max_buf_size, &info->recv_buf_data);
    NA_TEST_CHECK_ERROR(info->recv_buf == NULL, error, ret, NA_NOMEM,
        "NA_Msg_buf_alloc() failed");
    memset(info->recv_buf, 0, info->max_buf_size);

    /* Create operation IDs */
    info->send_op_id = NA_Op_create(info->na_class);
    NA_TEST_CHECK_ERROR(info->send_op_id == NULL, error, ret, NA_NOMEM,
        "NA_Op_create() failed");
    info->recv_op_id = NA_Op_create(info->na_class);
    NA_TEST_CHECK_ERROR(info->recv_op_id == NULL, error, ret, NA_NOMEM,
        "NA_Op_create() failed");

    /* Create request */
    info->request = hg_request_create(info->request_class);
    NA_TEST_CHECK_ERROR(info->request == NULL, error, ret, NA_NOMEM,
        "hg_request_create() failed");

    return NA_SUCCESS;

error:
    na_test_lat_cleanup(info);
    return ret;
}

/*---------------------------------------------------------------------------*/
void
na_test_lat_cleanup(struct na_test_lat_info *info)
{
    if (info->send_op_id != NULL)
        NA_Op_destroy(info->na_class, info->send_op_id);

    if (info->recv_op_id != NULL)
        NA_Op_destroy(info->na_class, info->recv_op_id);

    if (info->send_buf != NULL)
        NA_Msg_buf_free(info->na_class, info->send_buf, info->send_buf_data);

    if (info->recv_buf != NULL)
        NA_Msg_buf_free(info->na_class, info->recv_buf, info->recv_buf_data);

    if (info->target_addr != NA_ADDR_NULL)
        NA_Addr_free(info->na_class, info->target_addr);

    if (info->poll_fd > 0)
        hg_poll_remove(info->poll_set, info->poll_fd);

    if (info->poll_set != NULL)
        hg_poll_destroy(info->poll_set);

    if (info->request != NULL)
        hg_request_destroy(info->request);

    if (info->request_class != NULL)
        hg_request_finalize(info->request_class, NULL);

    if (info->context != NULL)
        NA_Context_destroy(info->na_class, info->context);

    NA_Test_finalize(&info->na_test_info);
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_lat_verify_data(const void *buf, size_t buf_size, size_t header_size)
{
    const char *buf_ptr = (const char *) buf + header_size;
    size_t data_size = buf_size - header_size;
    na_return_t ret;
    size_t i;

    for (i = 0; i < data_size; i++) {
        NA_TEST_CHECK_ERROR(buf_ptr[i] != (char) i, error, ret, NA_FAULT,
            "Error detected in bulk transfer, buf[%zu] = %d, "
            "was expecting %d!",
            i, buf_ptr[i], (char) i);
    }

    return NA_SUCCESS;

error:
    return ret;
}
