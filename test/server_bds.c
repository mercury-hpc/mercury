/*
 * server_bds.c
 */

#include "network_bmi.h"
#include "network_mpi.h"
#include "function_shipper.h"
#include "bulk_data_shipper.h"
#include "iofsl_compat.h"
#include "shipper_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Dummy function that needs to be shipped */
size_t bla_write(int fildes, const void *buf, size_t nbyte)
{
    size_t i;
    const char message[] = "Hi, I'm bla_write";
    int error;
    int *bulk_buf = (int*) buf;

    printf("%s\n", message);

    /* Check bulk buf */
    for (i = 0; i < nbyte; i++) {
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

int bla_write_dec(void **in_struct, void *buf, int buf_len)
{
    int ret = S_SUCCESS;
    bla_write_in_t *bla_write_in_struct;

    if (buf_len < sizeof(bla_write_in_t)) {
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = S_FAIL;
    } else {
        bla_write_in_struct = malloc(sizeof(bla_write_in_t));
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(bla_write_in_struct, buf, sizeof(bla_write_in_t));
        *in_struct = bla_write_in_struct;
    }

    return ret;
}

int bla_write_enc(void *buf, int buf_len, void *out_struct)
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

int bla_write_exe(void *in_struct, void **out_struct)
{
    int ret = S_SUCCESS;
    bla_write_in_t *bla_write_in_struct = (bla_write_in_t*) in_struct;
    bla_write_out_t *bla_write_out_struct;
    int fildes;
    int bla_write_ret;
    void *bla_write_buf;
    size_t bla_write_nbytes;

    bds_handle_t bla_write_bds_handle;
    bds_block_handle_t bla_write_bds_block_handle;

    /* Get input parameters and data */
    fildes = bla_write_in_struct->fildes;
    bds_handle_deserialize(&bla_write_bds_handle, bla_write_in_struct->bds_handle_buf, BDS_MAX_HANDLE_SIZE);

    /* Read bulk data here and wait for the data to be here  */
    bds_read(bla_write_bds_handle, &bla_write_bds_block_handle);
    bds_wait(bla_write_bds_block_handle, BDS_MAX_IDLE_TIME);

    /* Call bla_write */
    bla_write_buf = bds_block_handle_get_data(bla_write_bds_block_handle);
    bla_write_nbytes = bds_block_handle_get_size(bla_write_bds_block_handle);
    bla_write_ret = bla_write(fildes, bla_write_buf, bla_write_nbytes);

    /* Fill output structure */
    bla_write_out_struct = malloc(sizeof(bla_write_out_t));
    bla_write_out_struct->bla_write_ret = bla_write_ret;
    *out_struct = bla_write_out_struct;

    /* Free handles */
    bds_block_handle_free(bla_write_bds_block_handle);
    bds_handle_free(bla_write_bds_handle);

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    void *func_in_struct;
    void *func_out_struct;
    fs_id_t func_id;
    fs_tag_t func_tag;
    fs_peer_t func_peer;

    /* Initialize the interface */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        network_class = na_mpi_init(NULL, MPI_INIT_SERVER);
    } else {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return EXIT_FAILURE;
        }
        network_class = na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }

    fs_init(network_class);
    bds_init(network_class);

    /* Register routine */
    fs_server_register("bla_write", bla_write_dec, bla_write_exe, bla_write_enc);

    /* Receive a new function call */
    fs_server_receive(&func_peer, &func_id, &func_tag, &func_in_struct);

    /* Execute the call */
    fs_server_execute(func_id, func_in_struct, &func_out_struct);

    /* Respond back */
    fs_server_respond(func_peer, func_id, func_tag, func_out_struct);

    printf("Finalizing...\n");

    /* Free memory and addresses */
    fs_peer_free(func_peer);
    func_peer = NULL;

    free(func_in_struct);
    free(func_out_struct);

    fs_finalize();
    bds_finalize();
    return EXIT_SUCCESS;
}
