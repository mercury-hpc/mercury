/*
 * shipper_test.c
 */

#include "shipper_test.h"
#include "shipper_config.h"
#include "network_bmi.h"
#include "network_mpi.h"
#include "shipper_config_test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*---------------------------------------------------------------------------
 *
 * Function:    shipper_test_client_init
 *
 *---------------------------------------------------------------------------
 */
na_network_class_t *shipper_test_client_init(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi>\n", argv[0]);
        return NULL;
    }

#ifdef IOFSL_SHIPPER_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        FILE *config;
        network_class = na_mpi_init(NULL, 0);
        if ((config = fopen("port.cfg", "r")) != NULL) {
            char mpi_port_name[MPI_MAX_PORT_NAME];
            fread(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
            printf("Using MPI port name: %s.\n", mpi_port_name);
            fclose(config);
            setenv(ION_ENV, mpi_port_name, 1);
        }
    }
#endif

#ifdef IOFSL_SHIPPER_HAS_BMI
    if (strcmp("bmi", argv[1]) == 0) {
        network_class = na_bmi_init(NULL, NULL, 0);
    }
#endif

    return network_class;
}

/*---------------------------------------------------------------------------
 *
 * Function:    shipper_test_server_init
 *
 *---------------------------------------------------------------------------
 */
na_network_class_t *shipper_test_server_init(int argc, char *argv[], unsigned int *max_number_of_peers)
{
    na_network_class_t *network_class = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi>\n", argv[0]);
        return NULL;
    }

#ifdef IOFSL_SHIPPER_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        network_class = na_mpi_init(NULL, MPI_INIT_SERVER);
    }
#endif


#ifdef IOFSL_SHIPPER_HAS_BMI
    if (strcmp("bmi", argv[1]) == 0) {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return NULL;
        }
        network_class = na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }
#endif

    *max_number_of_peers = MPIEXEC_MAX_NUMPROCS;
    return network_class;
}
