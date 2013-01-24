/*
 * server_na.c
 */

#include "iofsl_compat.h"
#include "network_mpi.h"
#include "network_bmi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *recv_buf = NULL;
    char *send_buf = NULL;

    na_size_t recv_buf_len = 0;

    na_tag_t recv_tag = 0;
    na_tag_t send_tag = 0;

    na_addr_t recv_addr = NULL;

    na_request_t send_request = NULL;

    int *bulk_buf = NULL;
    int bulk_size = 1024*1024;
    na_mem_handle_t local_mem_handle = NULL;
    na_mem_handle_t remote_mem_handle = NULL;

    na_tag_t bulk_tag = 102;
    na_tag_t ack_tag = 103;

    na_request_t bulk_request = NULL;
    na_request_t ack_request = NULL;
    na_request_t get_request = NULL;

    int i, error = 0;

    /* Initialize the interface */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        na_mpi_init(NULL, MPI_INIT_SERVER);
    } else {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return EXIT_FAILURE;
        }
        na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }

    /* Allocate send and recv bufs */
    send_buf = malloc(na_get_unexpected_size());
    recv_buf = malloc(na_get_unexpected_size());

    /* Recv a message from a client (blocking for now) */
    na_recv_unexpected(recv_buf, &recv_buf_len, &recv_addr, &recv_tag, NULL, NULL);
    printf("Received from CN: %s\n", recv_buf);

    /* Respond back */
    sprintf(send_buf, "Hello CN!\n");
    send_tag = recv_tag + 1;
    na_send(send_buf, na_get_unexpected_size(), recv_addr, send_tag, &send_request, NULL);

    na_wait(send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

    /* Prepare bulk_buf */
    bulk_buf = malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = 0;
    }

    /* Register memory */
    printf("Registering local memory...\n");
    na_mem_register(bulk_buf, sizeof(int) * bulk_size, NA_MEM_ORIGIN_PUT, &local_mem_handle);

    /* Recv memory handle */
    printf("Receiving remote memory handle...\n");
    na_recv(recv_buf, na_get_unexpected_size(), recv_addr, bulk_tag, &bulk_request, NULL);

    na_wait(bulk_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

    /* Deserialize memory handle */
    printf("Deserializing remote memory handle...\n");
    na_mem_handle_deserialize(&remote_mem_handle, recv_buf, na_get_unexpected_size());

    /* Do a get */
    printf("Getting %d bytes from remote...\n", bulk_size  * (int) sizeof(int));

    na_get(local_mem_handle, 0, remote_mem_handle, 0, bulk_size * sizeof(int), recv_addr, &get_request);

    na_wait(get_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

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
    na_send(send_buf, na_get_unexpected_size(), recv_addr, ack_tag, &ack_request, NULL);
    na_wait(ack_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

    printf("Finalizing...\n");

    /* Free memory and addresses */
    na_mem_handle_free(remote_mem_handle);
    na_mem_deregister(local_mem_handle);
    free(bulk_buf);
    bulk_buf = NULL;

    na_addr_free(recv_addr);
    recv_addr = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    na_finalize();
    return EXIT_SUCCESS;
}
