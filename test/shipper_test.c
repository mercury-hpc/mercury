/*
 * shipper_test.c
 *
 */

#include "shipper_test.h"
#include "shipper_config.h"
#include "network_bmi.h"
#include "network_mpi.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

na_network_class_t *shipper_test_client_init(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return NULL;
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

    return network_class;
}

na_network_class_t *shipper_test_server_init(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return NULL;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        network_class = na_mpi_init(NULL, MPI_INIT_SERVER);
    } else {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return NULL;
        }
        network_class = na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }

    return network_class;
}
