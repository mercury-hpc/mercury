/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_test.h"

#include "mercury_poll.h"
#include "mercury_request.h" /* For convenience */
#include "mercury_time.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define NA_TEST_TAG_DONE 111

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct na_test_lat_info {
    na_class_t *na_class;
    na_context_t *context;
    hg_request_class_t *request_class;
    struct na_test_info na_test_info;
    hg_poll_set_t *poll_set;
    int fd;
};

struct na_test_source_recv_arg {
    void *recv_buf;
    void *send_buf;
    void *send_buf_data;
    na_tag_t tag;
    na_op_id_t *send_op_id;
    hg_request_t *request;
    struct na_test_lat_info *na_test_lat_info;
};

/********************/
/* Local Prototypes */
/********************/

static NA_INLINE int
na_test_request_progress(unsigned int timeout, void *arg);

static NA_INLINE int
na_test_request_trigger(unsigned int timeout, unsigned int *flag, void *arg);

static NA_INLINE int
na_test_recv_unexpected_cb(const struct na_cb_info *na_cb_info);

static NA_INLINE int
na_test_send_expected_cb(const struct na_cb_info *na_cb_info);

static na_return_t
na_test_loop_latency(struct na_test_lat_info *na_test_lat_info);

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_test_request_progress(unsigned int timeout, void *arg)
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
static NA_INLINE int
na_test_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    struct na_test_lat_info *na_test_lat_info = (struct na_test_lat_info *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (NA_Trigger(na_test_lat_info->context, timeout, 1, NULL,
            &actual_count) != NA_SUCCESS)
        ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? HG_UTIL_TRUE : HG_UTIL_FALSE;

    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_test_recv_unexpected_cb(const struct na_cb_info *na_cb_info)
{
    struct na_test_source_recv_arg *na_test_source_recv_arg =
        (struct na_test_source_recv_arg *) na_cb_info->arg;
    struct na_test_lat_info *na_test_lat_info =
        na_test_source_recv_arg->na_test_lat_info;
    na_return_t ret;

    na_test_source_recv_arg->tag = na_cb_info->info.recv_unexpected.tag;
#ifdef HG_TEST_HAS_VERIFY_DATA
    if (na_test_source_recv_arg->tag != NA_TEST_TAG_DONE) {
        /* Check recv buf */
        const char *recv_buf_ptr =
            (const char *) na_test_source_recv_arg->recv_buf;
        na_size_t i;

        for (i = NA_Msg_get_unexpected_header_size(na_test_lat_info->na_class);
             i < na_cb_info->info.recv_unexpected.actual_buf_size; i++) {
            if (recv_buf_ptr[i] != (char) i) {
                fprintf(stderr,
                    "Error detected in bulk transfer, buf[%d] = %d, "
                    "was expecting %d!\n",
                    (int) i, (char) recv_buf_ptr[i], (char) i);
                break;
            }
        }
    }
#endif

    /* Post send */
    ret = NA_Msg_send_expected(na_test_lat_info->na_class,
        na_test_lat_info->context, na_test_send_expected_cb,
        na_test_source_recv_arg->request, na_test_source_recv_arg->send_buf,
        na_cb_info->info.recv_unexpected.actual_buf_size,
        na_test_source_recv_arg->send_buf_data,
        na_cb_info->info.recv_unexpected.source, 0,
        na_cb_info->info.recv_unexpected.tag,
        na_test_source_recv_arg->send_op_id);
    if (ret != NA_SUCCESS) {
        NA_TEST_LOG_ERROR(
            "NA_Msg_send_expected() failed (%s)", NA_Error_to_string(ret));
    }

    NA_Addr_free(
        na_test_lat_info->na_class, na_cb_info->info.recv_unexpected.source);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE int
na_test_send_expected_cb(const struct na_cb_info *na_cb_info)
{
    hg_request_t *request = (hg_request_t *) na_cb_info->arg;

    hg_request_complete(request);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_loop_latency(struct na_test_lat_info *na_test_lat_info)
{
    struct na_test_source_recv_arg na_test_source_recv_arg = {0};
    char *send_buf = NULL, *recv_buf = NULL;
    void *send_buf_data, *recv_buf_data;
    na_op_id_t *send_op_id;
    na_op_id_t *recv_op_id;
    hg_request_t *send_request = NULL;
    na_size_t unexpected_size =
        NA_Msg_get_max_unexpected_size(na_test_lat_info->na_class);
    na_size_t expected_size =
        NA_Msg_get_max_expected_size(na_test_lat_info->na_class);
    na_size_t i;
    na_return_t ret = NA_SUCCESS;

    /* Prepare send_buf */
    send_buf = NA_Msg_buf_alloc(
        na_test_lat_info->na_class, expected_size, &send_buf_data);
    for (i = 0; i < expected_size; i++)
        send_buf[i] = (char) i;

    /* Prepare recv buf */
    recv_buf = NA_Msg_buf_alloc(
        na_test_lat_info->na_class, unexpected_size, &recv_buf_data);
    memset(recv_buf, 0, unexpected_size);

    /* Create operation IDs */
    send_op_id = NA_Op_create(na_test_lat_info->na_class);
    recv_op_id = NA_Op_create(na_test_lat_info->na_class);

    send_request = hg_request_create(na_test_lat_info->request_class);

    na_test_source_recv_arg.request = send_request;
    na_test_source_recv_arg.recv_buf = recv_buf;
    na_test_source_recv_arg.send_buf = send_buf;
    na_test_source_recv_arg.send_buf_data = send_buf_data;
    na_test_source_recv_arg.send_op_id = send_op_id;
    na_test_source_recv_arg.na_test_lat_info = na_test_lat_info;

    while (na_test_source_recv_arg.tag != NA_TEST_TAG_DONE) {
        /* Post recv */
        ret = NA_Msg_recv_unexpected(na_test_lat_info->na_class,
            na_test_lat_info->context, na_test_recv_unexpected_cb,
            &na_test_source_recv_arg, recv_buf, unexpected_size, recv_buf_data,
            recv_op_id);
        if (ret != NA_SUCCESS) {
            NA_TEST_LOG_ERROR("NA_Msg_recv_unexpected() failed (%s)",
                NA_Error_to_string(ret));
            goto done;
        }

        hg_request_wait(send_request, NA_MAX_IDLE_TIME, NULL);
        hg_request_reset(send_request);
    }

done:
    /* Clean up resources */
    hg_request_destroy(send_request);
    NA_Op_destroy(na_test_lat_info->na_class, send_op_id);
    NA_Op_destroy(na_test_lat_info->na_class, recv_op_id);
    NA_Msg_buf_free(na_test_lat_info->na_class, send_buf, send_buf_data);
    NA_Msg_buf_free(na_test_lat_info->na_class, recv_buf, recv_buf_data);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct na_test_lat_info na_test_lat_info = {0};
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    na_test_lat_info.na_test_info.listen = NA_TRUE;
    NA_Test_init(argc, argv, &na_test_lat_info.na_test_info);
    na_test_lat_info.na_class = na_test_lat_info.na_test_info.na_class;
    na_test_lat_info.context = NA_Context_create(na_test_lat_info.na_class);
    na_test_lat_info.request_class = hg_request_init(
        na_test_request_progress, na_test_request_trigger, &na_test_lat_info);
    na_test_lat_info.fd =
        NA_Poll_get_fd(na_test_lat_info.na_class, na_test_lat_info.context);
    if (na_test_lat_info.fd > 0) {
        struct hg_poll_event poll_event = {
            .events = HG_POLLIN, .data.ptr = NULL};
        na_test_lat_info.poll_set = hg_poll_create();
        hg_poll_add(
            na_test_lat_info.poll_set, na_test_lat_info.fd, &poll_event);
    }

    /* Process */
    na_test_loop_latency(&na_test_lat_info);

    printf("Finalizing...\n");

    /* Finalize interface */
    if (na_test_lat_info.fd > 0) {
        hg_poll_remove(na_test_lat_info.poll_set, na_test_lat_info.fd);
        hg_poll_destroy(na_test_lat_info.poll_set);
    }
    hg_request_finalize(na_test_lat_info.request_class, NULL);
    NA_Context_destroy(na_test_lat_info.na_class, na_test_lat_info.context);
    NA_Test_finalize(&na_test_lat_info.na_test_info);

    return ret;
}
