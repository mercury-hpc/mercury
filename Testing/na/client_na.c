/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na.h"
#include "mercury_error.h"
#include "mercury_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NA_TEST_BULK_SIZE 1024 * 1024
#define NA_TEST_SEND_TAG 100
#define NA_TEST_BULK_TAG 102
#define NA_TEST_BULK_ACK_TAG 103

/* Test parameters */
struct na_test_params {
    na_class_t *network_class;
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
lookup_cb(const struct na_cb_info *info)
{
    struct na_test_params *params = (struct na_test_params *) info->arg;
    na_tag_t send_tag = NA_TEST_SEND_TAG;
    na_return_t ret = NA_SUCCESS;

    if (info->ret != NA_SUCCESS) {
        return ret;
    }

    params->server_addr = info->lookup.addr;

    test_send(params, send_tag);

    test_bulk(params);

    return ret;
}

static na_return_t
msg_expected_recv_cb(const struct na_cb_info *info)
{
    struct na_test_params *params = (struct na_test_params *) info->arg;
    na_return_t ret = NA_SUCCESS;

    if (info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Received msg (%s) from server\n", params->recv_buf);

    return ret;
}

static na_return_t
ack_expected_recv_cb(const struct na_cb_info *info)
{
    struct na_test_params *params = (struct na_test_params *) info->arg;
    na_return_t ret = NA_SUCCESS;

    if (info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Bulk transfer complete\n");

    ret = NA_Mem_deregister(params->network_class, params->local_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not unregister memory\n");
    }

    return ret;
}

/* NA test routines */
static int
test_send(struct na_test_params *params, na_tag_t send_tag)
{
    na_return_t na_ret;

    /* Send a message to addr */
    sprintf(params->send_buf, "Hello Server!\n");
    na_ret = NA_Msg_send_unexpected(params->network_class, NULL, NULL,
            params->send_buf, params->send_buf_len, params->server_addr,
            send_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of unexpected message\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Msg_recv_expected(params->network_class, &msg_expected_recv_cb,
            params, params->recv_buf, params->recv_buf_len, params->server_addr,
            send_tag + 1, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start recv of message\n");
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
            sizeof(int) * params->bulk_size, NA_MEM_READ_ONLY,
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

    /* Send mem handle */
    printf("Sending local memory handle...\n");
    na_ret = NA_Msg_send_expected(params->network_class, NULL, NULL,
            params->send_buf, params->send_buf_len, params->server_addr,
            bulk_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of memory handle\n");
        return EXIT_FAILURE;
    }

    /* Recv completion ack */
    printf("Receiving end of transfer ack...\n");
    na_ret = NA_Msg_recv_expected(params->network_class, &ack_expected_recv_cb,
            params, params->recv_buf, params->recv_buf_len, params->server_addr,
            ack_tag, NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start receive of acknowledgment\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
    char *server_name;
    na_addr_t server_addr = NA_ADDR_NULL;
    struct na_test_params params;
    na_return_t na_ret;
    unsigned int i;

    /* Initialize the interface */
    params.network_class = HG_Test_client_init(argc, argv, &server_name, NULL);

    /* Allocate send and recv bufs */
    params.send_buf_len = NA_Msg_get_max_unexpected_size(params.network_class);
    params.recv_buf_len = params.send_buf_len;
    params.send_buf = (char*) malloc(params.send_buf_len);
    params.recv_buf = (char*) malloc(params.recv_buf_len);

    /* Prepare bulk_buf */
    params.bulk_size = NA_TEST_BULK_SIZE;
    params.bulk_buf = (int*) malloc(sizeof(int) * params.bulk_size);
    for (i = 0; i < params.bulk_size; i++) {
        params.bulk_buf[i] = i;
    }

    /* Perform an address lookup on the ION */
    na_ret = NA_Addr_lookup(params.network_class, &lookup_cb, &params, server_name,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start lookup of addr %s\n", server_name);
        return EXIT_FAILURE;
    }

    /* TODO change condition */
    while(1) {
        int cb_triggered = 0;
        if (NA_Progress(params.network_class, NA_MAX_IDLE_TIME) == NA_SUCCESS) {
            NA_Trigger(0, 1, &cb_triggered);
        }
    }

    printf("Finalizing...\n");

    /* Free memory and addresses */
    na_ret = NA_Addr_free(params.network_class, server_addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    free(params.recv_buf);
    free(params.send_buf);
    free(params.bulk_buf);

    HG_Test_finalize(params.network_class);

    return EXIT_SUCCESS;
}
