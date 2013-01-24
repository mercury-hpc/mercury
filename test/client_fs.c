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

int main(int argc, char *argv[])
{
    char *ion_name;
    fs_request_t request;

    /* Initialize the interface */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        FILE *config;
        na_mpi_init(NULL, 0);
        if ((config = fopen("port.cfg", "r")) != NULL) {
            char mpi_port_name[MPI_MAX_PORT_NAME];
            fread(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
            printf("Using MPI port name: %s.\n", mpi_port_name);
            fclose(config);
            setenv(ION_ENV, mpi_port_name, 1);
        }
    } else {
        na_bmi_init(NULL, NULL, 0);
    }
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
    }

    fs_init();

//    fs_register();
//
//    fs_forward();
//
//    fs_wait();

    fs_finalize();
}
