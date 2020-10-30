/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "na_test.h"

#define NA_TEST_BULK_SIZE    1024 * 1024
#define NA_TEST_SEND_TAG     100
#define NA_TEST_BULK_TAG     102
#define NA_TEST_BULK_ACK_TAG 103

static int test_done_g = 0;

/* Test parameters */
struct na_test_params {
    na_class_t *na_class;
    na_context_t *context;
    na_addr_t server_addr;
    char *send_buf;
    char *recv_buf;
    void *send_buf_plugin_data;
    void *recv_buf_plugin_data;
    unsigned int *bulk_buf;
    na_size_t send_buf_len;
    na_size_t recv_buf_len;
    na_size_t bulk_size;
    na_mem_handle_t local_mem_handle;
};

/* NA test routines */
static int
test_send(struct na_test_params *params);
#ifdef NA_HAS_CCI
static int
test_bulk(struct na_test_params *params);
#endif

/* NA test user-defined callbacks */
static int
lookup_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params =
        (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    params->server_addr = callback_info->info.lookup.addr;

    test_send(params);

    return NA_SUCCESS;
}

static int
msg_expected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params =
        (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret == NA_CANCELED) {
        printf("NA_Msg_recv_expected() was successfully canceled\n");
        return ret;
    } else {
        printf("NA_Msg_recv_expected() was not canceled\n");
    }

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Received msg (%s) from server\n", params->recv_buf);

#ifdef NA_HAS_CCI
    if (strcmp(NA_Get_class_name(params->na_class), "cci") == 0)
        test_bulk(params);
    else
#endif
        test_done_g = 1;

    return ret;
}

static int
msg_unexpected_send_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params =
        (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret == NA_CANCELED) {
        /* Try again */
        printf("NA_Msg_send_unexpected() was successfully canceled\n");
        sprintf(params->send_buf, "Hello again Server!");
        ret = NA_Msg_send_unexpected(params->na_class, params->context, NULL,
            NULL, params->send_buf, params->send_buf_len,
            params->send_buf_plugin_data, params->server_addr, 0,
            NA_TEST_SEND_TAG, NA_OP_ID_IGNORE);
        if (ret != NA_SUCCESS) {
            fprintf(stderr, "Could not start send of unexpected message\n");
        }
        return ret;
    } else {
        printf("NA_Msg_send_unexpected() was not canceled\n");
    }

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    return ret;
}

#ifdef NA_HAS_CCI
static int
ack_expected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params =
        (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;
    unsigned int i;
    na_bool_t error = 0;

    if (callback_info->ret == NA_CANCELED) {
        fprintf(stderr, "Error: NA_Msg_recv_expected() was canceled\n");
        return NA_PROTOCOL_ERROR;
    } else {
        printf("NA_Msg_recv_expected() was not canceled\n");
    }

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Bulk transfer complete\n");

    /* Check bulk buf */
    for (i = 0; i < params->bulk_size; i++) {
        if ((na_size_t) params->bulk_buf[i] != 0) {
            printf("Error detected in bulk transfer, bulk_buf[%u] = %d,\t"
                   " was expecting %d!\n",
                i, params->bulk_buf[i], 0);
            error = 1;
            break;
        }
    }
    if (!error)
        printf("Successfully reset %zu bytes!\n",
            (size_t) params->bulk_size * sizeof(int));

    ret = NA_Mem_deregister(params->na_class, params->local_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not unregister memory\n");
        return ret;
    }

    ret = NA_Mem_handle_free(params->na_class, params->local_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free memory handle\n");
        return ret;
    }

    test_done_g = 1;

    return ret;
}

static int
msg_expected_send_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params =
        (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret == NA_CANCELED) {
        /* Try again */
        printf("NA_Msg_send_expected() was successfully canceled\n");
        printf("Sending again local memory handle...\n");
        ret = NA_Msg_send_expected(params->na_class, params->context, NULL,
            NULL, params->send_buf, params->send_buf_len,
            params->send_buf_plugin_data, params->server_addr, 0,
            NA_TEST_BULK_TAG, NA_OP_ID_IGNORE);
        if (ret != NA_SUCCESS) {
            fprintf(stderr, "Could not start send of memory handle\n");
            return ret;
        }
        return ret;
    } else {
        printf("NA_Msg_send_expected() was not canceled\n");
    }

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    return ret;
}
#endif

/* NA test routines */
static int
test_send(struct na_test_params *params)
{
    na_tag_t send_tag = NA_TEST_SEND_TAG;
    na_op_id_t op_id = NA_OP_ID_NULL;
    na_return_t na_ret;

    /* Send a message to addr */
    sprintf(params->send_buf, "Hello Server!");

    /* Preposting response */
    na_ret = NA_Msg_recv_expected(params->na_class, params->context,
        msg_expected_recv_cb, params, params->recv_buf, params->recv_buf_len,
        params->recv_buf_plugin_data, params->server_addr, 0, send_tag + 1,
        &op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not prepost recv of expected message\n");
        return EXIT_FAILURE;
    }

    /* Cancel and repost message */
    na_ret = NA_Cancel(params->na_class, params->context, op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not cancel recv of expected message\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Msg_recv_expected(params->na_class, params->context,
        msg_expected_recv_cb, params, params->recv_buf, params->recv_buf_len,
        params->recv_buf_plugin_data, params->server_addr, 0, send_tag + 1,
        NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not prepost recv of expected message\n");
        return EXIT_FAILURE;
    }

    /* Try to cancel unexpected send */
    op_id = NA_OP_ID_NULL;
    na_ret = NA_Msg_send_unexpected(params->na_class, params->context,
        msg_unexpected_send_cb, params, params->send_buf, params->send_buf_len,
        params->send_buf_plugin_data, params->server_addr, 0, send_tag, &op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of unexpected message\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Cancel(params->na_class, params->context, op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not cancel send of unexpected message\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#ifdef NA_HAS_CCI
static int
test_bulk(struct na_test_params *params)
{
    na_tag_t bulk_tag = NA_TEST_BULK_TAG, ack_tag = NA_TEST_BULK_ACK_TAG;
    na_return_t na_ret;
    na_op_id_t op_id;

    /* Register memory */
    printf("Registering local memory...\n");
    na_ret = NA_Mem_handle_create(params->na_class, params->bulk_buf,
        sizeof(int) * params->bulk_size, NA_MEM_READWRITE,
        &params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not create bulk handle\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Mem_register(params->na_class, params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not create bulk handle\n");
        return EXIT_FAILURE;
    }

    /* Serialize mem handle */
    printf("Serializing bulk memory handle...\n");
    na_ret = NA_Mem_handle_serialize(params->na_class, params->send_buf,
        params->send_buf_len, params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not serialize memory handle\n");
        return EXIT_FAILURE;
    }

    /* Recv completion ack */
    printf("Preposting recv of transfer ack...\n");
    na_ret = NA_Msg_recv_expected(params->na_class, params->context,
        ack_expected_recv_cb, params, params->recv_buf, params->recv_buf_len,
        params->recv_buf_plugin_data, params->server_addr, 0, ack_tag,
        NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start receive of acknowledgment\n");
        return EXIT_FAILURE;
    }

    /* Send mem handle */
    printf("Sending local memory handle...\n");
    na_ret = NA_Msg_send_expected(params->na_class, params->context,
        msg_expected_send_cb, params, params->send_buf, params->send_buf_len,
        params->send_buf_plugin_data, params->server_addr, 0, bulk_tag, &op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of memory handle\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Cancel(params->na_class, params->context, op_id);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not cancel send of expected message\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
#endif

int
main(int argc, char **argv)
{
    struct na_test_info na_test_info = {0};
    char server_name[NA_TEST_MAX_ADDR_NAME];
    struct na_test_params params;
    na_return_t na_ret;
    unsigned int i;

    /* Initialize the interface */
    NA_Test_init(argc, argv, &na_test_info);

    params.na_class = na_test_info.na_class;
    params.context = NA_Context_create(params.na_class);

    /* Allocate send and recv bufs */
    params.send_buf_len = NA_Msg_get_max_unexpected_size(params.na_class);
    params.recv_buf_len = params.send_buf_len;
    params.send_buf = (char *) NA_Msg_buf_alloc(
        params.na_class, params.send_buf_len, &params.send_buf_plugin_data);
    params.recv_buf = (char *) NA_Msg_buf_alloc(
        params.na_class, params.recv_buf_len, &params.recv_buf_plugin_data);

    /* Prepare bulk_buf */
    params.bulk_size = NA_TEST_BULK_SIZE;
    params.bulk_buf =
        (unsigned int *) malloc(params.bulk_size * sizeof(unsigned int));
    for (i = 0; i < params.bulk_size; i++) {
        params.bulk_buf[i] = i;
    }

    /* Perform an address lookup on the target */
    na_ret = NA_Addr_lookup(params.na_class, params.context, lookup_cb, &params,
        server_name, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start lookup of addr %s\n", server_name);
        return EXIT_FAILURE;
    }

    while (!test_done_g) {
        na_return_t trigger_ret;
        unsigned int actual_count = 0;

        do {
            trigger_ret = NA_Trigger(params.context, 0, 1, NULL, &actual_count);
        } while ((trigger_ret == NA_SUCCESS) && actual_count);

        if (test_done_g)
            break;

        NA_Progress(params.na_class, params.context, NA_MAX_IDLE_TIME);
    }

    printf("Finalizing...\n");

    /* Free memory and addresses */
    na_ret = NA_Addr_free(params.na_class, params.server_addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    NA_Msg_buf_free(
        params.na_class, params.recv_buf, params.recv_buf_plugin_data);
    NA_Msg_buf_free(
        params.na_class, params.send_buf, params.send_buf_plugin_data);
    free(params.bulk_buf);

    NA_Context_destroy(params.na_class, params.context);

    NA_Test_finalize(&na_test_info);

    return EXIT_SUCCESS;
}
