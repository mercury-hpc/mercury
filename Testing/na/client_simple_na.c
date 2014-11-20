/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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
#include <unistd.h>
#define min(a, b) ((a) < (b) ? (a) : (b))
#define MAX_TRANSFER_SIZE_MB 1200

int get_nn(unsigned int cycle, unsigned long size)
{
    return min(cycle, MAX_TRANSFER_SIZE_MB*1024*1024 / size);
}

int main(int argc, char *argv[])
{
    char *ion_name;
    na_class_t *network_class = NULL;
    na_addr_t ion_target = 0;

    na_tag_t send_tag = 100;
    na_tag_t recv_tag = 101;
    na_tag_t exchange_tag = 110;
    na_tag_t single_bench_tag = 111;
    na_tag_t ack_tag = 112;

    int nbenchbufs = 32;
    na_request_t send_request = NA_REQUEST_NULL;
    na_request_t recv_request = NA_REQUEST_NULL;
    na_request_t bench_request[nbenchbufs];

    char *send_buf = NULL;
    char *recv_buf = NULL;

    na_size_t send_buf_len;
    na_size_t recv_buf_len;

    int *bulk_buf = NULL;
    int bulk_size = 1024*1024;
    na_mem_handle_t local_mem_handle = NA_MEM_HANDLE_NULL;
    na_mem_handle_t local_bench_mem_handle[nbenchbufs];
    char *bench_buf[nbenchbufs];

    na_tag_t bulk_tag = 102;

    na_request_t bulk_request = NA_REQUEST_NULL;
    na_request_t ack_request = NA_REQUEST_NULL;

    int i;
    int na_ret;
    unsigned int cycle;
    na_size_t bench_buf_size = atoi(argv[argc-2]);
    cycle = atoi(argv[argc-1]);
    cycle = get_nn(cycle, bench_buf_size);
    for(i = 0; i < nbenchbufs; i++){
        bench_buf[i] = malloc(bench_buf_size);
        memset(bench_buf[i], 0, bench_buf_size);
    }
    printf("Bench buf size = %lu\n", (uint64_t)bench_buf_size);
    printf("Cycle = %d\n", cycle);
    argc -= 2;

    /* Initialize the interface */
    network_class = HG_Test_client_init(argc, argv, &ion_name, NULL);

    /* Perform an address lookup on the ION */
    na_ret = NA_Addr_lookup(network_class, ion_name, &ion_target);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        return EXIT_FAILURE;
    }

    /* Allocate send and recv bufs */
    send_buf_len = min( NA_Msg_get_max_unexpected_size(network_class), 4096);
    recv_buf_len = send_buf_len;
    send_buf = malloc(send_buf_len);
    recv_buf = malloc(recv_buf_len);

    /* Send a message to addr */
    sprintf(send_buf, "Hello ION!\n");
    na_ret = NA_Msg_send_unexpected(network_class, send_buf, send_buf_len, ion_target, send_tag, &send_request, NULL);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not send unexpected message\n");
        return EXIT_FAILURE;
    }
    na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, ion_target, recv_tag, &recv_request, NULL);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not recv message\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Wait(network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    printf("Received from ION: %s\n", recv_buf);

    /* Prepare bulk_buf */
    bulk_buf = malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Register memory */
    printf("Registering local memory...\n");
    na_ret = NA_Mem_register(network_class, bulk_buf, sizeof(int) * bulk_size, NA_MEM_READ_ONLY, &local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not register memory\n");
        return EXIT_FAILURE;
    }

    /* Serialize mem handle */
    printf("Serializing local memory handle...\n");
    na_ret = NA_Mem_handle_serialize(network_class, send_buf, send_buf_len, local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not serialize memory handle\n");
        return EXIT_FAILURE;
    }

    /* Send mem handle */
    printf("Sending local memory handle...\n");
    na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, ion_target, bulk_tag, &bulk_request, NULL);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not send memory handle\n");
        return EXIT_FAILURE;
    }

    /* Recv completion ack */
    printf("Receiving end of transfer ack...\n");
    na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, ion_target, ack_tag, &ack_request, NULL);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not receive acknowledgment\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    na_ret = NA_Wait(network_class, ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }

    /* Benchmark */
    /* register bench buffers */
    puts("Register bench buffers");
    for(i = 0; i < nbenchbufs; i++){
        na_ret = NA_Mem_register(network_class, bench_buf[i], 
                bench_buf_size, NA_MEM_READWRITE, &local_bench_mem_handle[i]);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not register memory\n");
            return EXIT_FAILURE;
        }
    }

    /* Serialize and benchmark buffers */
    printf("Serializing benchmark memory handles\n");
    for( i = 0; i < nbenchbufs; i++ ){
        //printf("\trecv = %d\n", i);
        na_ret = NA_Mem_handle_serialize(network_class, send_buf, send_buf_len, local_bench_mem_handle[i]);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not serialize memory handle\n");
            return EXIT_FAILURE;
        }
        /* send */
        na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, ion_target, exchange_tag, &bulk_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send memory handle\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }

    }

    /* Single send bandwidth benchmark */
    printf("Single send bandwidth benchmark\n");
    for( i = 0; i < (int) cycle; i++ ){
        na_ret = NA_Msg_recv(network_class, bench_buf[0], bench_buf_size, ion_target, single_bench_tag, &bench_request[0], NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send acknowledgment\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, bench_request[0], NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, ion_target, ack_tag, &send_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send ack\n");
            return EXIT_FAILURE;
        }
        na_ret = NA_Wait(network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
    }

    /* Send pipeline */
    na_tag_t tag_pipe = 200;
    puts("Send pipeline");
    for( i = 0; i < nbenchbufs; i++) {
        na_ret = NA_Msg_recv(network_class, bench_buf[i], bench_buf_size, ion_target, tag_pipe++, &bench_request[i], NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not send acknowledgment\n");
            return EXIT_FAILURE;
        }
    }
    puts("wait");
    for( i = 0; i < nbenchbufs; i++) {
        na_ret = NA_Wait(network_class, bench_request[i], NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
    }
    /* Send remote completion */
    na_ret = NA_Msg_send(network_class, send_buf, send_buf_len, ion_target, ack_tag, &send_request, NULL);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not send ack\n");
        return EXIT_FAILURE;
    }
    na_ret = NA_Wait(network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }


    sleep(1);
    printf("Finalizing...\n");

    /* Free memory and addresses */
    na_ret = NA_Mem_deregister(network_class, local_mem_handle);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not unregister memory\n");
        return EXIT_FAILURE;
    }
    free(bulk_buf);
    bulk_buf = NULL;

    na_ret = NA_Addr_free(network_class, ion_target);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }
    ion_target = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    HG_Test_finalize(network_class);

    return EXIT_SUCCESS;
}
