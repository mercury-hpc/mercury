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
#define NA_TEST_BULK_TAG 102
#define NA_TEST_BULK_ACK_TAG 103

static int test_done_g = 0;

/* Test parameters */
struct na_test_params {
    na_class_t *network_class;
    na_context_t *context;
    na_addr_t source_addr;
    char *send_buf;
    char *recv_buf;
    int *bulk_buf;
    na_size_t send_buf_len;
    na_size_t recv_buf_len;
    na_size_t bulk_size;
    na_mem_handle_t local_mem_handle;
    na_mem_handle_t remote_mem_handle;
};

/* NA test routines */
static int test_send_respond(struct na_test_params *params, na_tag_t send_tag);
static int test_bulk_prepare(struct na_test_params *params);

static na_return_t
msg_unexpected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_tag_t recv_tag;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    printf("Received msg (%s) from client\n", params->recv_buf);

    params->source_addr = callback_info->info.recv_unexpected.source;
    recv_tag = callback_info->info.recv_unexpected.tag;

    test_bulk_prepare(params);
    test_send_respond(params, recv_tag + 1);

    return ret;
}

static na_return_t
msg_expected_send_final_cb(const struct na_cb_info *callback_info)
{
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    test_done_g = 1;

    return ret;
}

static na_return_t
bulk_put_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_tag_t ack_tag = NA_TEST_BULK_ACK_TAG;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Send completion ack */
    printf("Sending end of transfer ack...\n");
    ret = NA_Msg_send_expected(params->network_class,  params->context,
            msg_expected_send_final_cb, NULL,  params->send_buf,
            params->send_buf_len, params->source_addr, ack_tag,
            NA_OP_ID_IGNORE);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of acknowledgment\n");
        return ret;
    }

    /* Free memory and addresses */
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
    ret = NA_Mem_handle_free(params->network_class, params->remote_mem_handle);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free memory handle\n");
        return ret;
    }

    return ret;
}

static na_return_t
bulk_get_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;
    unsigned int i;
    na_bool_t error = 0;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Check bulk buf */
    for (i = 0; i < params->bulk_size; i++) {
        if ((na_size_t) params->bulk_buf[i] != i) {
            printf("Error detected in bulk transfer, bulk_buf[%u] = %d,\t"
                    " was expecting %u!\n", i, params->bulk_buf[i], i);
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully transfered %lu bytes!\n",
            params->bulk_size * sizeof(int));

    /* Reset bulk_buf */
    printf("Resetting buffer\n");
    memset(params->bulk_buf, 0, params->bulk_size * sizeof(int));

    /* Now do a put */
    printf("Putting %d bytes to remote...\n",
            (int) (params->bulk_size * sizeof(int)));

    ret = NA_Put(params->network_class, params->context, &bulk_put_cb, params,
            params->local_mem_handle, 0, params->remote_mem_handle, 0,
            params->bulk_size * sizeof(int), params->source_addr,
            NA_OP_ID_IGNORE);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start put\n");
    }

    return ret;
}

static na_return_t
mem_handle_expected_recv_cb(const struct na_cb_info *callback_info)
{
    struct na_test_params *params = (struct na_test_params *) callback_info->arg;
    na_return_t ret = NA_SUCCESS;

    if (callback_info->ret != NA_SUCCESS) {
        return ret;
    }

    /* Deserialize memory handle */
    printf("Deserializing remote memory handle...\n");
    ret = NA_Mem_handle_deserialize(params->network_class,
            &params->remote_mem_handle, params->recv_buf, params->recv_buf_len);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not deserialize memory handle\n");
        return ret;
    }

    /* Do a get */
    printf("Getting %d bytes from remote...\n",
            (int) (params->bulk_size * sizeof(int)));

    ret = NA_Get(params->network_class, params->context, &bulk_get_cb, params,
            params->local_mem_handle, 0, params->remote_mem_handle, 0,
            params->bulk_size * sizeof(int), params->source_addr,
            NA_OP_ID_IGNORE);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start get\n");
    }

    return ret;
}

static int
test_send_respond(struct na_test_params *params, na_tag_t send_tag)
{
    na_return_t na_ret;

    /* Respond back */
    sprintf(params->send_buf, "Hello Client!");

    na_ret = NA_Msg_send_expected(params->network_class, params->context,
            NULL, NULL, params->send_buf,
            params->send_buf_len, params->source_addr, send_tag,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start send of message\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int
test_bulk_prepare(struct na_test_params *params)
{
    na_tag_t bulk_tag = NA_TEST_BULK_TAG;
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

    /* Recv memory handle */
    printf("Receiving remote memory handle...\n");
    na_ret = NA_Msg_recv_expected(params->network_class, params->context,
            &mem_handle_expected_recv_cb, params, params->recv_buf,
            params->recv_buf_len, params->source_addr, bulk_tag,
            NA_OP_ID_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not start recv of memory handle\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    unsigned int number_of_peers;
    unsigned int peer;
    struct na_test_params params;
    na_return_t na_ret;

    /* Initialize the interface */
    params.network_class = NA_Test_server_init(argc, argv, NA_TRUE, NULL, NULL,
            &number_of_peers);

    params.context = NA_Context_create(params.network_class);

    /* Allocate send/recv/bulk bufs */
    params.send_buf_len = NA_Msg_get_max_unexpected_size(params.network_class);
    params.recv_buf_len = params.send_buf_len;
    params.send_buf = (char*) calloc(params.send_buf_len, sizeof(char));
    params.recv_buf = (char*) calloc(params.recv_buf_len, sizeof(char));

    /* Prepare bulk_buf */
    params.bulk_size = NA_TEST_BULK_SIZE;
    params.bulk_buf = (int*) malloc(params.bulk_size * sizeof(int));

    for (peer = 0; peer < number_of_peers; peer++) {
        unsigned int i;

        /* Reset to 0 */
        for (i = 0; i < params.bulk_size; i++) {
            params.bulk_buf[i] = 0;
        }

        /* Recv a message from a client */
        na_ret = NA_Msg_recv_unexpected(params.network_class, params.context,
                &msg_unexpected_recv_cb, &params, params.recv_buf,
                params.recv_buf_len, NA_OP_ID_IGNORE);

        while(!test_done_g) {
            na_return_t trigger_ret;
            unsigned int actual_count = 0;

            do {
                trigger_ret = NA_Trigger(params.context, 0, 1, &actual_count);
            } while ((trigger_ret == NA_SUCCESS) && actual_count);

            if (test_done_g) break;

            NA_Progress(params.network_class, params.context, NA_MAX_IDLE_TIME);
        }

        na_ret = NA_Addr_free(params.network_class, params.source_addr);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not free addr\n");
            return EXIT_FAILURE;
        }
        params.source_addr = NA_ADDR_NULL;
        test_done_g = 0;
    }

    printf("Finalizing...\n");

    free(params.bulk_buf);
    free(params.recv_buf);
    free(params.send_buf);

    NA_Context_destroy(params.network_class, params.context);

    NA_Test_finalize(params.network_class);

    return EXIT_SUCCESS;
}
