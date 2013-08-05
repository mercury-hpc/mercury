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

double gettimeofday_sec()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (double)tv.tv_usec*1e-6;
}

int buflen = 4;
int bench_buf_size = 1024*1024;

int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;

    char *recv_buf = NULL;
    char *send_buf = NULL;
    char *bench_buf[buflen];
    int i;
    for(i = 0; i < buflen; i++){
        bench_buf[i] = malloc(bench_buf_size);
    }

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
    send_buf_len = NA_Msg_get_max_unexpected_size(network_class);
    send_buf = malloc(send_buf_len);
    recv_buf = malloc(send_buf_len);
    bulk_buf = malloc(sizeof(int) * bulk_size);

    /* number of benchmark cycle */
    int n = 4;

    for (peer = 0; peer < number_of_peers; peer++) {
        na_size_t recv_buf_len = 0;
        recv_buf_len = send_buf_len;

        na_tag_t recv_tag = 100;
        na_tag_t send_tag = 101;
        na_tag_t bulk_tag = 102;
        na_tag_t ack_tag = 103;
        na_tag_t single_bench_tag = 105;

        na_mem_handle_t local_mem_handle = NA_MEM_HANDLE_NULL;
        na_mem_handle_t remote_mem_handle = NA_MEM_HANDLE_NULL;
        na_mem_handle_t local_bench_mem_handle[buflen];
        na_mem_handle_t remote_bench_mem_handle[buflen];

        na_addr_t recv_addr = NA_ADDR_NULL;
        na_request_t recv_request = NA_REQUEST_NULL;
        na_request_t send_request = NA_REQUEST_NULL;

        na_request_t bulk_request = NA_REQUEST_NULL;
        na_request_t bulk_request2 = NA_REQUEST_NULL;
        na_request_t ack_request = NA_REQUEST_NULL;
        na_request_t get_request = NA_REQUEST_NULL;
        na_request_t bench_request[buflen];
        na_request_t single_bench_request = NA_REQUEST_NULL;
        int error = 0;
        
        na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, recv_tag, &recv_request, NULL);
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
        printf("Unexp recv\n\n");

        na_ret = NA_Msg_recv_unexpected(network_class, recv_buf, send_buf_len,
                &recv_buf_len, &recv_addr, &recv_tag, &recv_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv message\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        printf("Received from CN: %s\n", recv_buf);
        na_ret = NA_Msg_recv_unexpected(network_class, recv_buf, send_buf_len,
                &recv_buf_len, &recv_addr, &recv_tag, &recv_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv message\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        printf("Received from CN: %s\n", recv_buf);
        /* PUT / GET */
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
        printf("%lu\n", *((unsigned long *)recv_buf));
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

        /* Benchmark */
        na_size_t bench_len = 4096;
        /* send single */
        puts("===send single===");
        double st = gettimeofday_sec();
        long bytes = (bench_len * n);
        printf("len = %d, bytes = %ld\n", bench_len, bytes);
        for(i = 0; i < n; i++){
            /*printf("send %d\n", i);*/
            na_ret = NA_Msg_send(network_class, send_buf, bench_len, recv_addr, single_bench_tag, &single_bench_request, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not send acknowledgment\n");
                return EXIT_FAILURE;
            }
            na_ret = NA_Wait(network_class, single_bench_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
        }
        double ed = gettimeofday_sec();
        printf("time = %f, %f msg/s, %f MB/s\n", ed - st, n/(ed-st), bytes/(ed-st)/1048576.0);


        /* Recv ack */
        recv_buf_len = send_buf_len;
        printf("Receiving remote memory handle...\n");
        na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, ack_tag, &ack_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv memory handle\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

        /* register bench buffers */
        puts("Register bench buffers");
        for(i = 0; i < buflen; i++){
            na_ret = NA_Mem_register(network_class, bench_buf[i], bench_buf_size, NA_MEM_READWRITE, &local_bench_mem_handle[i]);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not register memory\n");
                return EXIT_FAILURE;
            }
        }

        /* Serialize and exchange bench bufs */
        puts("Serialize and exchange bench buffers");
        for(i = 0; i < buflen; i++){
            printf("\tbufnumber = %d\n", i);
            /* serialize */
            na_ret = NA_Mem_handle_serialize(network_class, send_buf, send_buf_len, local_bench_mem_handle[i]);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not serialize memory handle\n");
                return EXIT_FAILURE;
            }
            /* recv */
            na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, bulk_tag, &bulk_request2, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not recv memory handle\n");
                return EXIT_FAILURE;
            }
            /* send */
            na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, recv_addr, bulk_tag, &bulk_request, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not send memory handle\n");
                return EXIT_FAILURE;
            }
            na_ret = NA_Wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            /* wait recv */
            na_ret = NA_Wait(network_class, bulk_request2, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            /* deserialize */
            na_ret = NA_Mem_handle_deserialize(network_class, &remote_bench_mem_handle[i], recv_buf, recv_buf_len);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not deserialize memory handle\n");
                return EXIT_FAILURE;
            }
        }

        /* put single */
        puts("===put single===");
        for(i = 0; i < n; i++){
            na_ret = NA_Put(network_class, local_bench_mem_handle[0], 0, remote_bench_mem_handle[0], 0, bench_buf_size, recv_addr, &single_bench_request);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not put data\n");
                return EXIT_FAILURE;
            }
            na_ret = NA_Wait(network_class, single_bench_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
        }


        /* unexpected send */
        puts("===unexpected send==="); 

        /* Recv final ack */
        puts("recv final ack");
        na_ret = NA_Msg_recv_unexpected(network_class, recv_buf, send_buf_len,
                &recv_buf_len, &recv_addr, &recv_tag, &recv_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv message\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        /* send ack */
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

        break;  //TODO
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
        break;
        /* ======================================*/
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
