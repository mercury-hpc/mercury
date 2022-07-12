/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test_perf.h"

/****************/
/* Local Macros */
/****************/

/* Default RMA size max if not specified */
#define NA_TEST_RMA_SIZE_MAX (1 << 24)

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
na_test_perf_request_progress(unsigned int timeout, void *arg)
{
    struct na_test_perf_info *na_test_perf_info =
        (struct na_test_perf_info *) arg;
    unsigned int timeout_progress = 0;
    int ret = HG_UTIL_SUCCESS;

    /* Safe to block */
    if (NA_Poll_try_wait(
            na_test_perf_info->na_class, na_test_perf_info->context))
        timeout_progress = timeout;

    if (na_test_perf_info->poll_set && timeout_progress > 0) {
        struct hg_poll_event poll_event = {.events = 0, .data.ptr = NULL};
        unsigned int actual_events = 0;

        hg_poll_wait(na_test_perf_info->poll_set, timeout_progress, 1,
            &poll_event, &actual_events);
        if (actual_events == 0)
            return HG_UTIL_FAIL;

        timeout_progress = 0;
    }

    /* Progress */
    if (NA_Progress(na_test_perf_info->na_class, na_test_perf_info->context,
            timeout_progress) != NA_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
na_test_perf_request_trigger(
    unsigned int timeout, unsigned int *flag, void *arg)
{
    struct na_test_perf_info *na_test_perf_info =
        (struct na_test_perf_info *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (NA_Trigger(na_test_perf_info->context, timeout, 1, NULL,
            &actual_count) != NA_SUCCESS)
        ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? true : false;

    return ret;
}

/*---------------------------------------------------------------------------*/
int
na_test_perf_request_complete(const struct na_cb_info *na_cb_info)
{
    hg_request_t *request = (hg_request_t *) na_cb_info->arg;

    hg_request_complete(request);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_perf_init(
    int argc, char *argv[], bool listen, struct na_test_perf_info *info)
{
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
        na_test_perf_request_progress, na_test_perf_request_trigger, info);
    NA_TEST_CHECK_ERROR(info->request_class == NULL, error, ret, NA_NOMEM,
        "hg_request_init() failed");

    /* Lookup target addr */
    if (!listen) {
        ret = NA_Addr_lookup(
            info->na_class, info->na_test_info.target_name, &info->target_addr);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Addr_lookup(%s) failed (%s)",
            info->na_test_info.target_name, NA_Error_to_string(ret));
    }

    /* Set max sizes */
    info->msg_unexp_size_max = NA_Msg_get_max_unexpected_size(info->na_class);
    NA_TEST_CHECK_ERROR(info->msg_unexp_size_max == 0, error, ret,
        NA_INVALID_ARG, "max unexpected msg size cannot be zero");
    info->msg_unexp_header_size =
        NA_Msg_get_unexpected_header_size(info->na_class);

    info->msg_exp_size_max = NA_Msg_get_max_expected_size(info->na_class);
    NA_TEST_CHECK_ERROR(info->msg_exp_size_max == 0, error, ret, NA_INVALID_ARG,
        "max expected msg size cannot be zero");
    info->msg_exp_header_size =
        NA_Msg_get_unexpected_header_size(info->na_class);

    info->rma_size_min = info->na_test_info.buf_size_min;
    if (info->rma_size_min == 0)
        info->rma_size_min = 1;

    info->rma_size_max = info->na_test_info.buf_size_max;
    if (info->rma_size_max == 0)
        info->rma_size_max = NA_TEST_RMA_SIZE_MAX;

    /* Check that sizes are power of 2 */
    NA_TEST_CHECK_ERROR(!powerof2(info->rma_size_min), error, ret,
        NA_INVALID_ARG, "RMA size min must be a power of 2 (%zu)",
        info->rma_size_min);
    NA_TEST_CHECK_ERROR(!powerof2(info->rma_size_max), error, ret,
        NA_INVALID_ARG, "RMA size max must be a power of 2 (%zu)",
        info->rma_size_max);

    /* Prepare Msg buffers */
    info->msg_unexp_buf = NA_Msg_buf_alloc(
        info->na_class, info->msg_unexp_size_max, &info->msg_unexp_data);
    NA_TEST_CHECK_ERROR(info->msg_unexp_buf == NULL, error, ret, NA_NOMEM,
        "NA_Msg_buf_alloc() failed");
    memset(info->msg_unexp_buf, 0, info->msg_unexp_size_max);

    ret = NA_Msg_init_unexpected(
        info->na_class, info->msg_unexp_buf, info->msg_unexp_size_max);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_init_expected() failed (%s)",
        NA_Error_to_string(ret));

    info->msg_exp_buf = NA_Msg_buf_alloc(
        info->na_class, info->msg_exp_size_max, &info->msg_exp_data);
    NA_TEST_CHECK_ERROR(info->msg_exp_buf == NULL, error, ret, NA_NOMEM,
        "NA_Msg_buf_alloc() failed");
    memset(info->msg_exp_buf, 0, info->msg_exp_size_max);

    ret = NA_Msg_init_expected(
        info->na_class, info->msg_exp_buf, info->msg_exp_size_max);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_init_unexpected() failed (%s)",
        NA_Error_to_string(ret));

    /* Prepare RMA buf */
    info->rma_buf = malloc(info->rma_size_max);
    NA_TEST_CHECK_ERROR(info->rma_buf == NULL, error, ret, NA_NOMEM,
        "NA_Msg_buf_alloc() failed");
    memset(info->rma_buf, 0, info->rma_size_max);

    if (!info->na_test_info.force_register) {
        ret = NA_Mem_handle_create(info->na_class, info->rma_buf,
            info->rma_size_max, NA_MEM_READWRITE, &info->local_handle);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_handle_create() failed (%s)",
            NA_Error_to_string(ret));

        ret = NA_Mem_register(
            info->na_class, info->local_handle, NA_MEM_TYPE_HOST, 0);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_register() failed (%s)",
            NA_Error_to_string(ret));
    }

    if (info->na_test_info.verify) {
        info->verify_buf = malloc(info->rma_size_max);
        NA_TEST_CHECK_ERROR(info->verify_buf == NULL, error, ret, NA_NOMEM,
            "NA_Msg_buf_alloc() failed");
        memset(info->verify_buf, 0, info->rma_size_max);

        ret = NA_Mem_handle_create(info->na_class, info->verify_buf,
            info->rma_size_max, NA_MEM_READWRITE, &info->verify_handle);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_handle_create() failed (%s)",
            NA_Error_to_string(ret));

        ret = NA_Mem_register(
            info->na_class, info->verify_handle, NA_MEM_TYPE_HOST, 0);
        NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_register() failed (%s)",
            NA_Error_to_string(ret));
    }

    /* Create operation IDs */
    info->msg_unexp_op_id = NA_Op_create(info->na_class);
    NA_TEST_CHECK_ERROR(info->msg_unexp_op_id == NULL, error, ret, NA_NOMEM,
        "NA_Op_create() failed");
    info->msg_exp_op_id = NA_Op_create(info->na_class);
    NA_TEST_CHECK_ERROR(info->msg_exp_op_id == NULL, error, ret, NA_NOMEM,
        "NA_Op_create() failed");
    info->rma_op_id = NA_Op_create(info->na_class);
    NA_TEST_CHECK_ERROR(
        info->rma_op_id == NULL, error, ret, NA_NOMEM, "NA_Op_create() failed");

    /* Create request */
    info->request = hg_request_create(info->request_class);
    NA_TEST_CHECK_ERROR(info->request == NULL, error, ret, NA_NOMEM,
        "hg_request_create() failed");

    return NA_SUCCESS;

error:
    na_test_perf_cleanup(info);
    return ret;
}

/*---------------------------------------------------------------------------*/
void
na_test_perf_cleanup(struct na_test_perf_info *info)
{
    if (info->msg_unexp_op_id != NULL)
        NA_Op_destroy(info->na_class, info->msg_unexp_op_id);

    if (info->msg_exp_op_id != NULL)
        NA_Op_destroy(info->na_class, info->msg_exp_op_id);

    if (info->rma_op_id != NULL)
        NA_Op_destroy(info->na_class, info->rma_op_id);

    if (info->msg_unexp_buf != NULL)
        NA_Msg_buf_free(
            info->na_class, info->msg_unexp_buf, info->msg_unexp_data);

    if (info->msg_exp_buf != NULL)
        NA_Msg_buf_free(info->na_class, info->msg_exp_buf, info->msg_exp_data);

    if (info->local_handle != NA_MEM_HANDLE_NULL) {
        NA_Mem_deregister(info->na_class, info->local_handle);
        NA_Mem_handle_free(info->na_class, info->local_handle);
    }
    if (info->verify_handle != NA_MEM_HANDLE_NULL) {
        NA_Mem_deregister(info->na_class, info->verify_handle);
        NA_Mem_handle_free(info->na_class, info->verify_handle);
    }
    if (info->remote_handle != NA_MEM_HANDLE_NULL)
        NA_Mem_handle_free(info->na_class, info->remote_handle);
    free(info->rma_buf);
    free(info->verify_buf);

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
void
na_test_perf_init_data(void *buf, size_t buf_size, size_t header_size)
{
    char *buf_ptr = (char *) buf + header_size;
    size_t data_size = buf_size - header_size;
    size_t i;

    for (i = 0; i < data_size; i++)
        buf_ptr[i] = (char) i;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_perf_verify_data(const void *buf, size_t buf_size, size_t header_size)
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

/*---------------------------------------------------------------------------*/
na_return_t
na_test_perf_mem_handle_send(
    struct na_test_perf_info *info, na_addr_t src_addr, na_tag_t tag)
{
    na_return_t ret;

    /* Serialize local handle */
    ret = NA_Mem_handle_serialize(info->na_class, info->msg_exp_buf,
        info->msg_exp_size_max, info->local_handle);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Mem_handle_serialize() failed (%s)",
        NA_Error_to_string(ret));

    /* Send the serialized handle */
    ret = NA_Msg_send_expected(info->na_class, info->context,
        na_test_perf_request_complete, info->request, info->msg_exp_buf,
        info->msg_exp_size_max, info->msg_exp_data, src_addr, 0, tag,
        info->msg_exp_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_send_expected() failed (%s)",
        NA_Error_to_string(ret));

    return NA_SUCCESS;

error:
    hg_request_complete(info->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_perf_mem_handle_recv(struct na_test_perf_info *info, na_tag_t tag)
{
    na_return_t ret;

    hg_request_reset(info->request);

    /* Post recv */
    ret = NA_Msg_recv_expected(info->na_class, info->context,
        na_test_perf_request_complete, info->request, info->msg_exp_buf,
        info->msg_exp_size_max, info->msg_exp_data, info->target_addr, 0, tag,
        info->msg_exp_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_recv_expected() failed (%s)",
        NA_Error_to_string(ret));

    /* Ask server to send its handle */
    ret = NA_Msg_send_unexpected(info->na_class, info->context, NULL, NULL,
        info->msg_unexp_buf, info->msg_unexp_header_size, info->msg_unexp_data,
        info->target_addr, 0, tag, info->msg_unexp_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_send_unexpected() failed (%s)",
        NA_Error_to_string(ret));

    hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

    /* Retrieve handle */
    ret = NA_Mem_handle_deserialize(info->na_class, &info->remote_handle,
        info->msg_exp_buf, info->msg_exp_size_max);
    NA_TEST_CHECK_NA_ERROR(error, ret,
        "NA_Mem_handle_deserialize() failed (%s)", NA_Error_to_string(ret));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_perf_send_finalize(struct na_test_perf_info *info)
{
    na_return_t ret;

    /* Reset */
    hg_request_reset(info->request);

    /* Post one-way msg send */
    ret = NA_Msg_send_unexpected(info->na_class, info->context,
        na_test_perf_request_complete, info->request, info->msg_unexp_buf,
        info->msg_unexp_header_size, info->msg_unexp_data, info->target_addr, 0,
        NA_TEST_PERF_TAG_DONE, info->msg_unexp_op_id);
    NA_TEST_CHECK_NA_ERROR(error, ret, "NA_Msg_send_unexpected() failed (%s)",
        NA_Error_to_string(ret));

    hg_request_wait(info->request, NA_MAX_IDLE_TIME, NULL);

    return NA_SUCCESS;

error:
    return ret;
}
