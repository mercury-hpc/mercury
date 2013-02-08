/*
 * server_na.c
 */

#include "network_abstraction.h"
#include "shipper_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    char *recv_buf = NULL;
    char *send_buf = NULL;

    na_size_t send_buf_len;

    int *bulk_buf = NULL;
    int bulk_size = 1024 * 1024;

    unsigned int number_of_peers;
    unsigned int peer;

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    /* Allocate send/recv/bulk bufs */
    send_buf_len = na_get_unexpected_size(network_class);
    send_buf = malloc(send_buf_len);
    recv_buf = malloc(send_buf_len);
    bulk_buf = malloc(sizeof(int) * bulk_size);

    for (peer = 0; peer < number_of_peers; peer++) {
        na_size_t recv_buf_len = 0;

        na_tag_t recv_tag = 0;
        na_tag_t send_tag = 0;
        na_tag_t bulk_tag = 102;
        na_tag_t ack_tag = 103;

        na_mem_handle_t local_mem_handle = NULL;
        na_mem_handle_t remote_mem_handle = NULL;

        na_addr_t recv_addr = NULL;
        na_request_t send_request = NULL;

        na_request_t bulk_request = NULL;
        na_request_t ack_request = NULL;
        na_request_t get_request = NULL;
        int i, error = 0;

        /* Recv a message from a client (blocking for now) */
        na_recv_unexpected(network_class, recv_buf, &recv_buf_len, &recv_addr, &recv_tag, NULL, NULL);
        printf("Received from CN: %s\n", recv_buf);

        /* Respond back */
        sprintf(send_buf, "Hello CN!\n");
        send_tag = recv_tag + 1;
        na_send(network_class, send_buf, send_buf_len, recv_addr, send_tag, &send_request, NULL);

        na_wait(network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

        /* Prepare bulk_buf */
        for (i = 0; i < bulk_size; i++) {
            bulk_buf[i] = 0;
        }

        /* Register memory */
        printf("Registering local memory...\n");
        na_mem_register(network_class, bulk_buf, sizeof(int) * bulk_size, NA_MEM_READWRITE, &local_mem_handle);

        /* Recv memory handle */
        recv_buf_len = send_buf_len;
        printf("Receiving remote memory handle...\n");
        na_recv(network_class, recv_buf, recv_buf_len, recv_addr, bulk_tag, &bulk_request, NULL);

        na_wait(network_class, bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

        /* Deserialize memory handle */
        printf("Deserializing remote memory handle...\n");
        na_mem_handle_deserialize(network_class, &remote_mem_handle, recv_buf, recv_buf_len);

        /* Do a get */
        printf("Getting %d bytes from remote...\n", (int) (bulk_size * sizeof(int)));

        na_get(network_class, local_mem_handle, 0, remote_mem_handle, 0, bulk_size * sizeof(int), recv_addr, &get_request);

        na_wait(network_class, get_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

        /* Check bulk buf */
        for (i = 0; i < bulk_size; i++) {
            if (bulk_buf[i] != i) {
                fprintf(stderr, "Error detected in bulk transfer, bulk_buf[%d] = %d, was expecting %d!\n", i, bulk_buf[i], i);
                error = 1;
                break;
            }
        }
        if (!error) printf("No error found during transfer!\n");

        /* Send completion ack */
        printf("Sending end of transfer ack...\n");
        na_send(network_class, send_buf, send_buf_len, recv_addr, ack_tag, &ack_request, NULL);
        na_wait(network_class, ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

        /* Free memory and addresses */
        na_mem_handle_free(network_class, remote_mem_handle);
        na_mem_deregister(network_class, local_mem_handle);
        na_addr_free(network_class, recv_addr);
        recv_addr = NULL;
    }

    printf("Finalizing...\n");

    free(bulk_buf);
    bulk_buf = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    na_finalize(network_class);
    return EXIT_SUCCESS;
}
