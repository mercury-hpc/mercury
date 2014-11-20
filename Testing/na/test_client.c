/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NA_TEST_BULK_SIZE 1024 * 1024
#define NA_TEST_SEND_TAG 100
#define NA_TEST_BULK_TAG 102
#define NA_TEST_BULK_ACK_TAG 103

static int test_done_g = 0;

/* Test parameters */
struct na_test_params {
    na_class_t *network_class;
    na_context_t *context;
    na_addr_t server_addr;
    char *send_buf;
    char *recv_buf;
    int *bulk_buf;
    na_size_t send_buf_len;
    na_size_t recv_buf_len;
    na_size_t bulk_size;
    na_mem_handle_t local_mem_handle;
};

/* NA test routines */
static int test_send(struct na_test_params *params, na_tag_t send_tag);
static int test_bulk(struct na_test_params *params);

/* NA test user-defined callbacks */
static na_return_t
lookup_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_tag_t send_tag = NA_TEST_SEND_TAG;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    params->server_addr = callback_info->info.lookup.addr;

    test_send(params, send_tag);

    return ret;
}

static na_return_t
msg_expected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Received msg (%s) from server\n", params->recv_buf);

    test_bulk(params);

    return ret;
}

static na_return_t
ack_expected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;
    unsigned int i;
    na_bool_t error = 0;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Bulk transfer complete\n");

    /* Check bulk buf */
    for (i = 0; i < params->bulk_size; i++) {
        if ((na_size_t) params->bulk_buf[i] != 0) {
            printf("Error detected in bulk transfer, bulk_buf[%u] = %d,\t"
                    " was expecting %d!\n", i, params->bulk_buf[i], 0);
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully reset %lu bytes!\n",
            params->bulk_size * sizeof(int));

    ret = NA_Mem_deregister(params->network_class, params->local_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not unregister memory\n");
        return ret;
    }

    ret = NA_Mem_handle_free(params->network_class, params->local_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free memory handle\n");
        return ret;
    }

    test_done_g = 1;

    return ret;
}

/* NA test routines */
static int
test_send(struct na_test_params *params, na_tag_t send_tag)
{
    na_return_t na_ret;

    /* Send a message to addr */
    sprintf(params->send_buf, "Hello Server!");

    /* Preposting response */
    na_ret = NA_Msg_recv_expected(params->network_class, params->context,
            &msg_expected_recv_cb, params, params->recv_buf,
            params->recv_buf_len, params->server_addr, send_tag + 1,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not prepost recv of expected message\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Msg_send_unexpected(params->network_class, params->context,
            NULL, NULL, params->send_buf, params->send_buf_len,
            params->server_addr, send_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of unexpected message\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
test_bulk(struct na_test_params *params)
{
    na_tag_t bulk_tag = NA_TEST_BULK_TAG, ack_tag = NA_TEST_BULK_ACK_TAG;
    na_return_t na_ret;

    /* Register memory */
    printf("Registering local memory...\n");
    na_ret = NA_Mem_handle_create(params->network_class, params->bulk_buf,
            sizeof(int) * params->bulk_size, NA_MEM_READWRITE,
            &params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not create bulk handle\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Mem_register(params->network_class, params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not create bulk handle\n");
        return EXIT_FAILURE;
    }

    /* Serialize mem handle */
    printf("Serializing bulk memory handle...\n");
    na_ret = NA_Mem_handle_serialize(params->network_class, params->send_buf,
            params->send_buf_len, params->local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not serialize memory handle\n");
        return EXIT_FAILURE;
    }

    /* Recv completion ack */
    printf("Preposting recv of transfer ack...\n");
    na_ret = NA_Msg_recv_expected(params->network_class, params->context,
            &ack_expected_recv_cb, params, params->recv_buf,
            params->recv_buf_len, params->server_addr, ack_tag,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start receive of acknowledgment\n");
        return EXIT_FAILURE;
    }

    /* Send mem handle */
    printf("Sending local memory handle...\n");
    na_ret = NA_Msg_send_expected(params->network_class, params->context,
            NULL, NULL, params->send_buf, params->send_buf_len,
            params->server_addr, bulk_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of memory handle\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
    char server_name[NA_TEST_MAX_ADDR_NAME];
    struct na_test_params params;
    na_return_t na_ret;
    unsigned int i;

    /* Initialize the interface */
    params.network_class = NA_Test_client_init(argc, argv, server_name,
            NA_TEST_MAX_ADDR_NAME, NULL);

    params.context = NA_Context_create(params.network_class);

    /* Allocate send and recv bufs */
    params.send_buf_len = NA_Msg_get_max_unexpected_size(params.network_class);
    params.recv_buf_len = params.send_buf_len;
    params.send_buf = (char*) calloc(params.send_buf_len, sizeof(char));
    params.recv_buf = (char*) calloc(params.recv_buf_len, sizeof(char));

    /* Prepare bulk_buf */
    params.bulk_size = NA_TEST_BULK_SIZE;
    params.bulk_buf = (int*) malloc(params.bulk_size * sizeof(int));
    for (i = 0; i < params.bulk_size; i++) {
        params.bulk_buf[i] = i;
    }

    /* Perform an address lookup on the ION */
    na_ret = NA_Addr_lookup(params.network_class, params.context, &lookup_cb,
            &params, server_name, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start lookup of addr %s\n", server_name);
        return EXIT_FAILURE;
    }

    while(!test_done_g) {
        na_return_t trigger_ret;
        unsigned int actual_count = 0;

        do {
            trigger_ret = NA_Trigger(params.context, 0, 1, &actual_count);
        } while ((trigger_ret == NA_SUCCESS) && actual_count);

        if (test_done_g) break;

        NA_Progress(params.network_class, params.context, NA_MAX_IDLE_TIME);
    }

    printf("Finalizing...\n");

    /* Free memory and addresses */
    na_ret = NA_Addr_free(params.network_class, params.server_addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    free(params.recv_buf);
    free(params.send_buf);
    free(params.bulk_buf);

    NA_Context_destroy(params.network_class, params.context);

    NA_Test_finalize(params.network_class);

    return EXIT_SUCCESS;
}
