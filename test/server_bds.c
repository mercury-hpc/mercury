/*
 * server_bds.c
 */

#include "function_shipper.h"
#include "bulk_data_shipper.h"
#include "shipper_error.h"
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
            fprintf(stderr, "Error detected in bulk transfer, bulk_buf[%lu] = %d, was expecting %lu!\n", i, bulk_buf[i], i);
            error = 1;
            break;
        }
    }
    if (!error) printf("No error found during transfer!\n");

    return nbyte;
}

/******************************************************************************/
/* Can be automatically generated using macros */
typedef struct bla_write_in {
    int  fildes;
    char bds_handle_buf[BDS_MAX_HANDLE_SIZE];
} bla_write_in_t;

typedef struct bla_write_out {
    size_t bla_write_ret;
} bla_write_out_t;

int bla_write_dec(void *in_struct, const void *buf, size_t buf_len)
{
    int ret = S_SUCCESS;
    bla_write_in_t *bla_write_in_struct = (bla_write_in_t*) in_struct;

    if (buf_len < sizeof(bla_write_in_t)) {
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(bla_write_in_struct, buf, sizeof(bla_write_in_t));
    }

    return ret;
}

int bla_write_enc(void *buf, size_t buf_len, const void *out_struct)
{
    int ret = S_SUCCESS;
    bla_write_out_t *bla_write_out_struct = (bla_write_out_t*) out_struct;

    if (buf_len < sizeof(bla_write_out_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bla_write_out_struct, sizeof(bla_write_out_t));
    }

    return ret;
}

int bla_write_exe(const void *in_struct, void *out_struct, fs_info_t info)
{
    int ret = S_SUCCESS;
    bla_write_in_t *bla_write_in_struct = (bla_write_in_t*) in_struct;
    bla_write_out_t *bla_write_out_struct = (bla_write_out_t*) out_struct;
    int fildes;
    void *bla_write_buf;
    size_t bla_write_nbytes;
    int bla_write_ret;

    bds_handle_t bla_write_bds_handle = NULL;
    bds_block_handle_t bla_write_bds_block_handle = NULL;

    /* Get input parameters and data */
    fildes = bla_write_in_struct->fildes;
    bds_handle_deserialize(&bla_write_bds_handle, bla_write_in_struct->bds_handle_buf, BDS_MAX_HANDLE_SIZE);

    /* Read bulk data here and wait for the data to be here  */
    bds_read(bla_write_bds_handle, info, &bla_write_bds_block_handle);
    bds_wait(bla_write_bds_block_handle, BDS_MAX_IDLE_TIME);

    /* Call bla_write */
    bla_write_buf = bds_block_handle_get_data(bla_write_bds_block_handle);
    bla_write_nbytes = bds_block_handle_get_size(bla_write_bds_block_handle);
    bla_write_ret = bla_write(fildes, bla_write_buf, bla_write_nbytes);

    /* Fill output structure */
    bla_write_out_struct->bla_write_ret = bla_write_ret;

    /* Free handles */
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

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_init(network_class);
    bds_init(network_class);

    /* Register routine */
    fs_server_register("bla_write", sizeof(bla_write_in_t), sizeof(bla_write_out_t),
            bla_write_dec, bla_write_exe, bla_write_enc);

    for (i = 0; i < number_of_peers; i++) {
        void *func_in_struct;
        void *func_out_struct;
        fs_id_t   func_id;
        fs_info_t func_info;

        /* Receive a new function call */
        fs_server_receive(&func_id, &func_info, &func_in_struct);

        /* TODO Get dependency here ? */
        /* Execute the call */
        fs_server_execute(func_id, func_info, func_in_struct, &func_out_struct);

        /* Respond back */
        fs_server_respond(func_id, func_info, func_out_struct);

        /* Free memory and addresses */
        free(func_in_struct);
        func_in_struct = NULL;

        free(func_out_struct);
        func_out_struct = NULL;
    }

    printf("Finalizing...\n");

    /* Finalize the interface */
    bds_finalize();
    fs_finalize();

    return EXIT_SUCCESS;
}
