/*
 * server_bds.c
 */

#include "function_shipper_handler.h"
#include "bulk_data_shipper.h"
#include "bulk_data_proc.h"
#include "generic_macros.h"
#include "shipper_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Dummy function that needs to be shipped */
size_t bla_write(int fildes, const void *buf, size_t nbyte)
{
    size_t i;
    const char message[] = "Hi, I'm bla_write";
    int error = 0;
    int *bulk_buf = (int*) buf;

    printf("%s\n", message);

    if (nbyte == 0) {
        S_ERROR_DEFAULT("Error detected in bulk transfer, nbyte is zero!\n");
        error = 1;
    }

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

/*****************************************************************************/
/* Generate processor for input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_PROC( bla_write_in_t, ((int32_t)(fildes)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_write_out_t, ((uint64_t)(ret)) )

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
    fs_handler_get_input(handle, &bla_write_in_struct);
    bla_write_fildes = bla_write_in_struct.fildes;
    bla_write_bds_handle = bla_write_in_struct.bds_handle;

    /* Read bulk data here and wait for the data to be here  */
    bds_read(bla_write_bds_handle, source, &bla_write_bds_block_handle);
    bds_wait(bla_write_bds_block_handle, BDS_MAX_IDLE_TIME);

    /* Call bla_write */
    bla_write_buf = bds_block_handle_get_data(bla_write_bds_block_handle);
    bla_write_nbytes = bds_block_handle_get_size(bla_write_bds_block_handle);
    bla_write_ret = bla_write(bla_write_fildes, bla_write_buf, bla_write_nbytes);

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Free handle and send response back */
    fs_handler_complete(handle, &bla_write_out_struct);

    /* Free bulk handles */
    bds_block_handle_free(bla_write_bds_block_handle);
    bds_handle_free(bla_write_bds_handle);

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;
    unsigned int number_of_peers;
    unsigned int i;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_handler_init(network_class);
    bds_init(network_class);

    /* Register routine */
    fs_handler_register("bla_write", fs_bla_write, fs_proc_bla_write_in_t, fs_proc_bla_write_out_t);

    for (i = 0; i < number_of_peers; i++) {
        /* Receive new function calls */
        fs_handler_receive();
    }

    printf("Finalizing...\n");

    /* Finalize the interface */
    bds_finalize();
    fs_handler_finalize();

    return EXIT_SUCCESS;
}
