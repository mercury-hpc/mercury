/*
 * client_fs.c
 */

#include "network_bmi.h"
#include "network_mpi.h"
#include "function_shipper.h"
#include "iofsl_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dummy function that needs to be shipped */
int bla_initialize(MPI_Comm comm)
{
    const char message[] = "Hi, I'm bla_initialize";
    printf("%s\n", message);
    return strlen(message);
}

typedef struct bla_initialize_in {
    MPI_Comm comm;
} bla_initialize_in_t;

typedef struct bla_initialize_out {
    int bla_initialize_ret;
} bla_initialize_out_t;

int bla_initialize_enc(void *buf, int buf_len, void *in_struct)
{
    int ret = FS_SUCCESS;
    bla_initialize_in_t *bla_initialize_in_struct = (bla_initialize_in_t*) in_struct;

    if (buf_len < sizeof(bla_initialize_in_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = FS_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bla_initialize_in_struct, sizeof(bla_initialize_in_t));
    }
    return ret;
}

int bla_initialize_dec(void *out_struct, void *buf, int buf_len)
{
    int ret = FS_SUCCESS;
    bla_initialize_out_t *bla_initialize_out_struct = out_struct;

    if (buf_len < sizeof(bla_initialize_out_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(bla_initialize_out_struct, buf, sizeof(bla_initialize_out_t));
    }
    return ret;
}

int main(int argc, char *argv[])
{
    char *ion_name;
    fs_peer_t peer;;
    na_network_class_t *network_class = NULL;

    fs_id_t bla_initialize_id;
    bla_initialize_in_t bla_initialize_in_struct;
    bla_initialize_out_t bla_initialize_out_struct;
    fs_request_t bla_initialize_request;

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

    /* Look up peer id */
    fs_peer_lookup(ion_name, &peer);

    /* Register function and encoding/decoding functions */
    bla_initialize_id = fs_register("bla_initialize", bla_initialize_enc, bla_initialize_dec);

    /* Forward call to peer */
    fs_forward(peer, bla_initialize_id, &bla_initialize_in_struct, &bla_initialize_out_struct, &bla_initialize_request);

    /* Wait for call to be executed and return value to be sent back */
    fs_wait(bla_initialize_request, NA_MAX_IDLE_TIME, FS_STATUS_IGNORE);

    /* Free peer id */
    fs_peer_free(peer);

    /* Finalize interface */
    fs_finalize();
    return EXIT_SUCCESS;
}
