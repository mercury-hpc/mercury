/*
 * client_bds.c
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
    const char message[] = "Hi, I'm bla_write";
    printf("%s\n", message);
    return write(fildes, buf, nbyte);
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

int bla_write_enc(void *buf, int buf_len, void *in_struct)
{
    int ret = S_SUCCESS;
    bla_write_in_t *bla_write_in_struct = (bla_write_in_t*) in_struct;

    if (buf_len < sizeof(bla_write_in_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bla_write_in_struct, sizeof(bla_write_in_t));
    }
    return ret;
}

int bla_write_dec(void *out_struct, void *buf, int buf_len)
{
    int ret = S_SUCCESS;
    bla_write_out_t *bla_write_out_struct = out_struct;

    if (buf_len < sizeof(bla_write_out_t)) {
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(bla_write_out_struct, buf, sizeof(bla_write_out_t));
    }
    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    fs_peer_t peer;
    na_network_class_t *network_class = NULL;

    /* dummy function parameters */
    int fildes = 12345;
    int *bulk_buf = NULL;
    int bulk_size = 1024*1024;

    fs_id_t bla_write_id;
    bla_write_in_t bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;
    fs_request_t bla_write_request;
    int bla_write_ret = 0;

    bds_handle_t bla_bulk_handle;

    int i;

    /* Prepare bulk_buf */
    bulk_buf = malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Initialize the interface */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        FILE *config;
        network_class = na_mpi_init(NULL, 0);
        if ((config = fopen("port.cfg", "r")) != NULL) {
            char mpi_port_name[MPI_MAX_PORT_NAME];
            fread(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
            printf("Using MPI port name: %s.\n", mpi_port_name);
            fclose(config);
            setenv(ION_ENV, mpi_port_name, 1);
        }
    } else {
        network_class = na_bmi_init(NULL, NULL, 0);
    }
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
    }
    fs_init(network_class);
    bds_init(network_class);

    /* Look up peer id */
    fs_peer_lookup(ion_name, &peer);

    /* Register function and encoding/decoding functions */
    bla_write_id = fs_register("bla_write", bla_write_enc, bla_write_dec);

    /* Register memory */
    bds_handle_create(bulk_buf, sizeof(int) * bulk_size, &bla_bulk_handle);

    /* Fill input structure */
    bla_write_in_struct.fildes = fildes;

    /* Serialize memory handle */
    bds_handle_serialize(bla_write_in_struct.bds_handle_buf, sizeof(bla_write_in_struct.bds_handle_buf),
            bla_bulk_handle);

    /* Forward call to peer */
    fs_forward(peer, bla_write_id, &bla_write_in_struct, &bla_write_out_struct, &bla_write_request);

    /* Wait for call to be executed and return value to be sent back */
    fs_wait(bla_write_request, FS_MAX_IDLE_TIME, FS_STATUS_IGNORE);

    /* Get output parameter */
    bla_write_ret = bla_write_out_struct.bla_write_ret;

    printf("bla_write returned: %d\n", bla_write_ret);

    /* Free memory handle */
    bds_handle_free(bla_bulk_handle);

    /* Free bulk data */
    free(bulk_buf);

    /* Free peer id */
    fs_peer_free(peer);

    /* Finalize interface */
    fs_finalize();
    bds_finalize();
    return EXIT_SUCCESS;
}
