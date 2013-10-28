/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_multiple.h"
#include "mercury_test.h"
#include "mercury.h"
#include "mercury_handler.h"

#include <stdio.h>
#include <stdlib.h>

hg_id_t bla_open_fwd_id, bla_write_fwd_id;
na_addr_t *server_addr = NULL;
char **addr_table = NULL;
unsigned int addr_table_size = 0;

/* Actual definition of the function that needs to be executed */
int
bla_open(const char *path, bla_handle_t handle, int *event_id)
{
    printf("Called bla_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return HG_SUCCESS;
}

size_t
bla_write(int fildes, const void *buf, size_t nbyte)
{
    size_t i;
    int error = 0;
    const int *bulk_buf = (const int*) buf;

    printf("Executing bla_write with fildes %d...\n", fildes);

    if (nbyte == 0) {
        HG_ERROR_DEFAULT("Error detected in bulk transfer, nbyte is zero!\n");
        error = 1;
    }

    printf("Checking data...\n");

    /* Check bulk buf */
    for (i = 0; i < (nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != (int) i) {
            printf("Error detected in bulk transfer, bulk_buf[%lu] = %d, "
                    "was expecting %d!\n", i, bulk_buf[i], (int) i);
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully transfered %lu bytes!\n", nbyte);

    return nbyte;
}


/******************************************************************************/
int
fs_bla_open_fwd(hg_handle_t handle)
{
    int ret = HG_SUCCESS;
    hg_request_t request;

    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;

    /* Get input buffer */
    ret = HG_Handler_get_input(handle, &bla_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Directly forwards to next server */
    HG_Forward(server_addr[1], bla_open_fwd_id, &bla_open_in_struct,
            &bla_open_out_struct, &request);

    /* Wait for completion */
    HG_Wait(request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Free request */
    ret = HG_Request_free(request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
        return EXIT_FAILURE;
    }

    return ret;
}

int
fs_bla_open(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;

    hg_const_string_t bla_open_path;
    bla_handle_t bla_open_handle;
    int bla_open_event_id;
    int bla_open_ret;

    /* Get input buffer */
    ret = HG_Handler_get_input(handle, &bla_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bla_open_path = bla_open_in_struct.path;
    bla_open_handle = bla_open_in_struct.handle;

    /* Call bla_open */
    bla_open_ret = bla_open(bla_open_path, bla_open_handle, &bla_open_event_id);

    /* Fill output structure */
    bla_open_out_struct.event_id = bla_open_event_id;
    bla_open_out_struct.ret = bla_open_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

int
fs_bla_write_fwd(hg_handle_t handle)
{
    int ret = HG_SUCCESS;
    hg_request_t request;

    bla_write_in_t  bla_write_in_struct;
    bla_write_in_t  bla_write_fwd_in_struct;
    bla_write_out_t bla_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bla_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_bulk_block_t bla_write_bulk_block_handle = HG_BULK_BLOCK_NULL;
    hg_bulk_request_t bla_write_bulk_request;

    void *bla_write_buf;
    size_t bla_write_nbytes;

    /* Get input buffer */
    ret = HG_Handler_get_input(handle, &bla_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bla_write_bulk_handle = bla_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bla_write_nbytes = HG_Bulk_handle_get_size(bla_write_bulk_handle);
    bla_write_buf = malloc(bla_write_nbytes);

    HG_Bulk_block_handle_create(bla_write_buf, bla_write_nbytes, HG_BULK_READWRITE,
            &bla_write_bulk_block_handle);

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read_all(source, bla_write_bulk_handle,
            bla_write_bulk_block_handle, &bla_write_bulk_request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    ret = HG_Bulk_wait(bla_write_bulk_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    /* Free block handle */
    ret = HG_Bulk_block_handle_free(bla_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

    /* Register memory */
    ret = HG_Bulk_handle_create(bla_write_buf, bla_write_nbytes, HG_BULK_READ_ONLY,
            &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return ret;
    }

    /* Fill input structure */
    bla_write_fwd_in_struct.fildes = bla_write_in_struct.fildes;
    bla_write_fwd_in_struct.bulk_handle = bulk_handle;

    /* Directly forwards to next server */
    HG_Forward(server_addr[1], bla_write_fwd_id, &bla_write_fwd_in_struct,
            &bla_write_out_struct, &request);

    /* Wait for completion */
    HG_Wait(request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

    /* Free request */
    ret = HG_Request_free(request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
        return EXIT_FAILURE;
    }

    /* Free memory handle */
    ret = HG_Bulk_handle_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return EXIT_FAILURE;
    }


    free(bla_write_buf);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

int
fs_bla_write(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

    bla_write_in_t  bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bla_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_block_t bla_write_bulk_block_handle = HG_BULK_BLOCK_NULL;
    hg_bulk_request_t bla_write_bulk_request;

    int bla_write_fildes;
    void *bla_write_buf;
    size_t bla_write_nbytes;
    size_t bla_write_ret;

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bla_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bla_write_fildes = bla_write_in_struct.fildes;
    bla_write_bulk_handle = bla_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bla_write_nbytes = HG_Bulk_handle_get_size(bla_write_bulk_handle);
    bla_write_buf = malloc(bla_write_nbytes);

    HG_Bulk_block_handle_create(bla_write_buf, bla_write_nbytes, HG_BULK_READWRITE,
            &bla_write_bulk_block_handle);

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read_all(source, bla_write_bulk_handle,
            bla_write_bulk_block_handle, &bla_write_bulk_request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    ret = HG_Bulk_wait(bla_write_bulk_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    /* Call bla_write */
    bla_write_ret = bla_write(bla_write_fildes, bla_write_buf, bla_write_nbytes);

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Free block handle */
    ret = HG_Bulk_block_handle_free(bla_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

    free(bla_write_buf);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    unsigned int number_of_peers = 1;
    unsigned int i;
    int hg_ret, na_ret;

    if (argc < 2) {
        return EXIT_FAILURE;
    }

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, &addr_table, &addr_table_size,
            &number_of_peers);

    if (number_of_peers < 2) {
        fprintf(stderr, "Test requires 2 servers\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Handler_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury handler\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Bulk_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    /* We do the lookup here but this may not be optimal */
    server_addr = (na_addr_t *) malloc(addr_table_size * sizeof(na_addr_t));
    for (i = 0; i < addr_table_size; i++) {
        na_ret = NA_Addr_lookup(network_class, addr_table[i], &server_addr[i]);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not find addr\n");
            return EXIT_FAILURE;
        }
    }

    /* Register routines
     * bla_open gets forwarded to another server which in turn executes bla_open */
    MERCURY_HANDLER_REGISTER("bla_open", fs_bla_open_fwd, bla_open_in_t, bla_open_out_t);
    bla_open_fwd_id = MERCURY_REGISTER("bla_open_fwd", bla_open_in_t, bla_open_out_t);
    MERCURY_HANDLER_REGISTER("bla_open_fwd", fs_bla_open, bla_open_in_t, bla_open_out_t);

    MERCURY_HANDLER_REGISTER("bla_write", fs_bla_write_fwd, bla_write_in_t, bla_write_out_t);
    bla_write_fwd_id = MERCURY_REGISTER("bla_write_fwd", bla_write_in_t, bla_write_out_t);
    MERCURY_HANDLER_REGISTER("bla_write_fwd", fs_bla_write, bla_write_in_t, bla_write_out_t);

    for (i = 0; i < number_of_peers * 2; i++) {
        /* Receive new function calls */
        hg_ret = HG_Handler_process(HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
        }
    }

    printf("Finalizing...\n");

    for (i = 0; i < addr_table_size; i++) {
        NA_Addr_free(network_class, server_addr[i]);
    }
    free(server_addr);

    /* Finalize the interface */
    hg_ret = HG_Bulk_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Handler_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury handler\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        return EXIT_FAILURE;
    }

    HG_Test_finalize(network_class);

    return EXIT_SUCCESS;
}
