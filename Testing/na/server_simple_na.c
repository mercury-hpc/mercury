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
#include <sys/time.h>
#include <unistd.h>

#define min(a, b) ((a)<(b)?(a):(b))
#define max(a, b) ((a)>(b)?(a):(b))
#define bytes2mb(a) (a/1024.0/1024.0)

#define MAX_TRANSFER_SIZE_MB 1200

double gettimeofday_sec()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (double)tv.tv_usec*1e-6;
}

int get_nn(unsigned int cycle, unsigned long size)
{
    return min(cycle, MAX_TRANSFER_SIZE_MB*1024*1024 / size);
}

int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;

    char *recv_buf = NULL;
    char *send_buf = NULL;

    na_size_t send_buf_len;

    int *bulk_buf = NULL;
    int bulk_size = 1024 * 1024;
    int nbenchbufs = 32;
    unsigned long bytes;
    char *bench_buf[nbenchbufs];

    unsigned int number_of_peers;
    unsigned int peer;

    int na_ret;
    int ctr;
    unsigned int cycle;
    double st, es, st2;
    double sum;
    na_size_t bench_buf_size = atoi(argv[argc-2]);
    cycle = atoi(argv[argc-1]);
    cycle = get_nn(cycle, bench_buf_size);
    for(ctr = 0; ctr < nbenchbufs; ctr++){
        bench_buf[ctr] = malloc(bench_buf_size);
        memset(bench_buf[ctr], 0, bench_buf_size);
    }
    printf("Bench buf size = %lu\n", (uint64_t)bench_buf_size);
    printf("Cycle = %d\n", cycle);
    argc -= 2;

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, NULL, NULL, &number_of_peers);

    /* Allocate send/recv/bulk bufs */
    send_buf_len = min( NA_Msg_get_max_unexpected_size(network_class), 4096);
    send_buf = malloc(send_buf_len);
    recv_buf = malloc(send_buf_len);
    bulk_buf = malloc(sizeof(int) * bulk_size);

    for (peer = 0; peer < number_of_peers; peer++) {
        na_size_t recv_buf_len = 0;

        na_tag_t recv_tag = 0;
        na_tag_t send_tag = 0;
        na_tag_t bulk_tag = 102;

        na_tag_t exchange_tag = 110;
        na_tag_t single_bench_tag = 111;
        na_tag_t ack_tag = 112;

        na_mem_handle_t local_mem_handle = NA_MEM_HANDLE_NULL;
        na_mem_handle_t remote_mem_handle = NA_MEM_HANDLE_NULL;
        na_mem_handle_t local_bench_mem_handle[nbenchbufs];
        na_mem_handle_t remote_bench_mem_handle[nbenchbufs];

        na_addr_t recv_addr = NA_ADDR_NULL;
        na_request_t recv_request = NA_REQUEST_NULL;
        na_request_t send_request = NA_REQUEST_NULL;
        na_request_t bench_request[nbenchbufs];

        na_request_t bulk_request = NA_REQUEST_NULL;
        na_request_t ack_request = NA_REQUEST_NULL;
        na_request_t get_request = NA_REQUEST_NULL;
        int i, error = 0;

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

        /* receive mem handles of remote bench buffers */
        for( i = 0; i < nbenchbufs; i++){ 
            //printf("\trecv = %d\n", i);
            na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, exchange_tag, &bulk_request, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not recv memory handle\n");
                return EXIT_FAILURE;
            }

            na_ret = NA_Wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            /* deserialize the remote memory handle */
            na_ret = NA_Mem_handle_deserialize(network_class, &remote_bench_mem_handle[i], recv_buf, recv_buf_len);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not deserialize memory handle\n");
                return EXIT_FAILURE;
            }
        }
        
        /* Single send benchmark*/
        printf("Single send bandwidth benchmark\n");
        bytes = bench_buf_size * cycle;
        st = gettimeofday_sec();
        sum = 0;
        for( i = 0; i < (int) cycle; i++ ){
            /* Recv completion */
            na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, ack_tag, &recv_request, NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not recv memory handle\n");
                return EXIT_FAILURE;
            }
            st2 = gettimeofday_sec();
            na_ret = NA_Msg_send(network_class, bench_buf[0], bench_buf_size, recv_addr, single_bench_tag, &bench_request[0], NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not send acknowledgment\n");
                return EXIT_FAILURE;
            }
            na_ret = NA_Wait(network_class, bench_request[0], NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            /* Wait for response */
            na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            sum += gettimeofday_sec() - st2;
            
        }
        es = gettimeofday_sec() - st;
        if(peer==0){
            printf("result(send_single, %lu): time %f, msg/s %f, MB/s %f, RTT(ms) %f\n", (uint64_t) bench_buf_size, es, cycle / es, bytes2mb(bytes) / es, (sum / cycle )*1000);
        }
        
        /* Pipelined send */
        sleep(1);
        puts("Pipelined send");
        /* Recv completion */
        na_ret = NA_Msg_recv(network_class, recv_buf, recv_buf_len, recv_addr, ack_tag, &recv_request, NULL);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not recv memory handle\n");
            return EXIT_FAILURE;
        }
        na_tag_t tag_pipe = 200;
        st = gettimeofday_sec();
        for( i = 0; i < nbenchbufs; i++ ){
            na_ret = NA_Msg_send(network_class, bench_buf[i], bench_buf_size, recv_addr, tag_pipe++, &bench_request[i], NULL);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Could not send acknowledgment\n");
                return EXIT_FAILURE;
            }
        }
        for ( i = 0; i < nbenchbufs; i++ ){
            na_ret = NA_Wait(network_class, bench_request[i], NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
            if (na_ret != NA_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
        }
        /* Wait for remote completion */
        na_ret = NA_Wait(network_class, recv_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
        bytes = nbenchbufs * bench_buf_size;
        es = gettimeofday_sec() - st;
        if(peer==0){
            printf("result(send_pipeline, %lu): time %f, msg/s %f, MB/s %f\n", (uint64_t) bench_buf_size, es, cycle / es, bytes2mb(bytes) / es);
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

    /* TODO add free of bench buffers */
    free(bulk_buf);
    bulk_buf = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    HG_Test_finalize(network_class);

    return EXIT_SUCCESS;
}
