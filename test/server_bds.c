/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_bds.h"
#include "shipper_test.h"
#include "function_shipper_handler.h"
#include "bulk_data_shipper.h"

#include <stdio.h>
#include <stdlib.h>

/* Actual definition of the function that needs to be executed */
size_t bla_write(int fildes, const void *buf, size_t nbyte)
{
    size_t i;
    int error = 0;
    int *bulk_buf = (int*) buf;

    printf("Executing bla_write...\n");

    if (nbyte == 0) {
        S_ERROR_DEFAULT("Error detected in bulk transfer, nbyte is zero!\n");
        error = 1;
    }

    printf("Checking data...\n");

    /* Check bulk buf */
    for (i = 0; i < (nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != i) {
            printf("Error detected in bulk transfer, bulk_buf[%lu] = %d, was expecting %lu!\n", i, bulk_buf[i], i);
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully transfered %lu bytes!\n", nbyte);

    return nbyte;
}

/******************************************************************************/
int fs_bla_write(fs_handle_t handle)
{
    int ret = S_SUCCESS;

    bla_write_in_t  bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;

    na_addr_t source = fs_handler_get_addr(handle);
    bds_handle_t bla_write_bds_handle = NULL;
    bds_block_handle_t bla_write_bds_block_handle = NULL;

    int bla_write_fildes;
    void *bla_write_buf;
    size_t bla_write_nbytes;
    int bla_write_ret;

    /* Get input parameters and data */
    ret = fs_handler_get_input(handle, &bla_write_in_struct);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get function call input\n");
        return ret;
    }

    bla_write_fildes = bla_write_in_struct.fildes;
    bla_write_bds_handle = bla_write_in_struct.bds_handle;

    /* Read bulk data here and wait for the data to be here  */
    ret = bds_read(bla_write_bds_handle, source, &bla_write_bds_block_handle);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    ret = bds_wait(bla_write_bds_block_handle, BDS_MAX_IDLE_TIME);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    /* Call bla_write */
    bla_write_buf = bds_block_handle_get_data(bla_write_bds_block_handle);
    bla_write_nbytes = bds_block_handle_get_size(bla_write_bds_block_handle);

    bla_write_ret = bla_write(bla_write_fildes, bla_write_buf, bla_write_nbytes);

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Free handle and send response back (and free input struct fields) */
    ret = fs_handler_complete(handle, &bla_write_out_struct);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not complete function call\n");
        return ret;
    }

    /* Free block handle */
    ret = bds_block_handle_free(bla_write_bds_block_handle);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;
    unsigned int number_of_peers;
    unsigned int i;
    int fs_ret;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_ret = fs_handler_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper handler\n");
        return EXIT_FAILURE;
    }

    fs_ret = bds_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Register routine */
    IOFSL_SHIPPER_HANDLER_REGISTER("bla_write", fs_bla_write, bla_write_in_t, bla_write_out_t);

    for (i = 0; i < number_of_peers; i++) {
        /* Receive new function calls */
        fs_ret = fs_handler_receive();
        if (fs_ret != S_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
        }
    }

    printf("Finalizing...\n");

    /* Finalize the interface */
    fs_ret = bds_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    fs_ret = fs_handler_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper handler\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
