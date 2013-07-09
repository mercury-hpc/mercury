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

int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;

    char *recv_buf = NULL;
    char *send_buf = NULL;

    na_size_t send_buf_len;

    int *bulk_buf = NULL;
    int bulk_size = 1024 * 1024;

    unsigned int number_of_peers;
    unsigned int peer;

    int na_ret;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, &number_of_peers);

    /* Allocate send/recv/bulk bufs */
    send_buf_len = NA_Msg_get_maximum_size(network_class);
    send_buf = malloc(send_buf_len);
    recv_buf = malloc(send_buf_len);
    bulk_buf = malloc(sizeof(int) * bulk_size);

    for (peer = 0; peer < number_of_peers; peer++) {
        na_size_t recv_buf_len = 0;

        na_tag_t recv_tag = 100;
        na_tag_t send_tag = 101;
        na_tag_t bulk_tag = 102;
        na_tag_t ack_tag = 103;

        na_mem_handle_t local_mem_handle = NA_MEM_HANDLE_NULL;
        na_mem_handle_t remote_mem_handle = NA_MEM_HANDLE_NULL;

        na_addr_t recv_addr = NA_ADDR_NULL;
        na_request_t recv_request = NA_REQUEST_NULL;
        na_request_t send_request = NA_REQUEST_NULL;

        na_request_t bulk_request = NA_REQUEST_NULL;
        na_request_t ack_request = NA_REQUEST_NULL;
        na_request_t get_request = NA_REQUEST_NULL;
        int i, error = 0;
        
        na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, recv_tag, &bulk_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv\n");
            return EXIT_FAILURE;
        }

        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        printf("Received from CN: %s\n", recv_buf);

        break;
        /* ======================================*/

        /* Recv a message from a client */
        do {
            na_ret = NA_Msg_recv_unexpected(network_class, recv_buf, send_buf_len,
                    &recv_buf_len, &recv_addr, &recv_tag, &recv_request, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not recv message\n");
                return EXIT_FAILURE;
            }
        } while (!recv_buf_len);

        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        printf("Received from CN: %s\n", recv_buf);

        /* Respond back */
        sprintf(send_buf, "Hello CN!\n");
        send_tag = recv_tag + 1;
        na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, recv_addr, send_tag, &send_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send message\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

        /* Prepare bulk_buf */
        for (i = 0; i < bulk_size; i++) {
            bulk_buf[i] = 0;
        }

        /* Register memory */
        printf("Registering local memory...\n");
        na_ret = NA_Mem_register(network_class, bulk_buf, sizeof(int) * bulk_size, NA_MEM_READWRITE, &local_mem_handle);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not register memory\n");
            return EXIT_FAILURE;
        }

        /* Recv memory handle */
        recv_buf_len = send_buf_len;
        printf("Receiving remote memory handle...\n");
        na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, bulk_tag, &bulk_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv memory handle\n");
            return EXIT_FAILURE;
        }

        na_ret = NA_Wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

        /* Deserialize memory handle */
        printf("Deserializing remote memory handle...\n");
        na_ret = NA_Mem_handle_deserialize(network_class, &remote_mem_handle, recv_buf, recv_buf_len);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not deserialize memory handle\n");
            return EXIT_FAILURE;
        }

        /* Do a get */
        printf("Getting %d bytes from remote...\n", (int) (bulk_size * sizeof(int)));

        na_ret = NA_Get(network_class, local_mem_handle, 0, remote_mem_handle, 0, bulk_size * sizeof(int), recv_addr, &get_request);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not get data\n");
            return EXIT_FAILURE;
        }

        na_ret = NA_Wait(network_class, get_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

        /* Check bulk buf */
        for (i = 0; i < bulk_size; i++) {
            if (bulk_buf[i] != i) {
                printf("Error detected in bulk transfer, bulk_buf[%d] = %d, was expecting %d!\n", i, bulk_buf[i], i);
                error = 1;
                break;
            }
        }
        if (!error) printf("Successfully transfered %lu bytes!\n", bulk_size * sizeof(int));

        /* Send completion ack */
        printf("Sending end of transfer ack...\n");
        na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, recv_addr, ack_tag, &ack_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send acknowledgment\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

        /* Free memory and addresses */
        na_ret = NA_Mem_handle_free(network_class, remote_mem_handle);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not free memory handle\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Mem_deregister(network_class, local_mem_handle);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not unregister memory\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Addr_free(network_class, recv_addr);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not free addr\n");
            return EXIT_FAILURE;
        }
        recv_addr = NA_ADDR_NULL;
    }

    printf("Finalizing...\n");

    free(bulk_buf);
    bulk_buf = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    na_ret = NA_Finalize(network_class);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize interface\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
