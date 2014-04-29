/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_test.h"

#ifdef NA_HAS_MPI
#include "na_mpi.h"
#endif
#ifdef MERCURY_HAS_PARALLEL_TESTING
#include <mpi.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

/****************/
/* Local Macros */
/****************/

/*******************/
/* Local Variables */
/*******************/
static int na_test_rank_g = 0;

#ifdef MERCURY_HAS_PARALLEL_TESTING
static int mpi_internally_initialized = HG_FALSE;
#endif

static char **na_addr_table = NULL;
static unsigned int na_addr_table_size = 0;

/*---------------------------------------------------------------------------*/
#ifdef MERCURY_HAS_PARALLEL_TESTING
static void
na_test_mpi_init(hg_bool_t server)
{
    int mpi_initialized = 0;

    MPI_Initialized(&mpi_initialized);
    if (!mpi_initialized) {
#ifdef NA_MPI_HAS_GNI_SETUP
        /* Setup GNI job before initializing MPI */
        if (NA_MPI_Gni_job_setup() != NA_SUCCESS) {
            fprintf(stderr, "Could not setup GNI job\n");
            return;
        }
#endif
        if (server) {
            int provided;

            MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
            if (provided != MPI_THREAD_MULTIPLE) {
                fprintf(stderr, "MPI_THREAD_MULTIPLE cannot be set\n");
            }
        } else {
            MPI_Init(NULL, NULL);
        }
        mpi_internally_initialized = HG_TRUE;
    }
}

/*---------------------------------------------------------------------------*/
static void
na_test_mpi_finalize(void)
{
    int mpi_finalized = 0;

    MPI_Finalized(&mpi_finalized);
    if (!mpi_finalized && mpi_internally_initialized) {
        MPI_Finalize();
        mpi_internally_initialized = HG_FALSE;
    }
}
#endif

/*---------------------------------------------------------------------------*/
static void
na_test_set_config(const char *addr_name)
{
    FILE *config = NULL;
    int my_rank = 0, my_size = 1;
    int max_port_name_length = 256; /* default set to 256 */
    int i;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &my_size);
    max_port_name_length = MPI_MAX_PORT_NAME;
#endif

    /* Allocate table addrs */
    na_addr_table = (char**) malloc(my_size * sizeof(char*));
    for (i = 0; i < my_size; i++) {
        na_addr_table[i] = (char*) malloc(max_port_name_length);
    }

    strcpy(na_addr_table[my_rank], addr_name);

    na_addr_table_size = my_size;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    for (i = 0; i < my_size; i++) {
        MPI_Bcast(na_addr_table[i], MPI_MAX_PORT_NAME,
                MPI_BYTE, i, MPI_COMM_WORLD);
    }
#endif

    /* Only rank 0 writes file */
    if (my_rank == 0) {
        config = fopen("port.cfg", "w+");
        if (config != NULL) {
            for (i = 0; i < my_size; i++) {
                fprintf(config, "%s\n", na_addr_table[i]);
            }
            fclose(config);
        }
    }
}

/*---------------------------------------------------------------------------*/
static void
na_test_get_config(char *addr_name, size_t len, int *rank)
{
    FILE *config = NULL;
    int my_rank = 0;
    char config_addr_name[NA_TEST_MAX_ADDR_NAME];

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
#endif

    /* Only rank 0 reads file */
    if (my_rank == 0) {
        config = fopen("port.cfg", "r");
        if (config != NULL) {
            fgets(config_addr_name, NA_TEST_MAX_ADDR_NAME, config);
        }
        fclose(config);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Broadcast port name */
    MPI_Bcast(config_addr_name, NA_TEST_MAX_ADDR_NAME, MPI_BYTE, 0,
            MPI_COMM_WORLD);
#endif

    strncpy(addr_name, config_addr_name,
            (len < NA_TEST_MAX_ADDR_NAME) ? len : NA_TEST_MAX_ADDR_NAME);

    if (rank) *rank = my_rank;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Test_client_init(int argc, char *argv[], char *addr_name, size_t max_addr_name,
        int *rank)
{
    char test_addr_name[NA_TEST_MAX_ADDR_NAME];
    na_class_t *na_class = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(HG_FALSE);
#endif

    /* Get config from file */
    na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME,
            &na_test_rank_g);

#ifdef NA_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        na_class = NA_Initialize("tcp@mpi://0.0.0.0:0", NA_FALSE);
    } else
#endif
    {
        na_class = NA_Initialize(test_addr_name, NA_FALSE);
    }

    strncpy(addr_name, test_addr_name,
            (max_addr_name < NA_TEST_MAX_ADDR_NAME) ?
                    max_addr_name : NA_TEST_MAX_ADDR_NAME);
    if (rank) *rank = na_test_rank_g;

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Test_server_init(int argc, char *argv[], char ***addr_table,
        unsigned int *addr_table_size, unsigned int *max_number_of_peers)
{
    na_class_t *na_class = NULL;
    char addr_name[NA_TEST_MAX_ADDR_NAME];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(HG_TRUE);
    MPI_Comm_rank(MPI_COMM_WORLD, &na_test_rank_g);
#endif

#ifdef NA_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        na_class = NA_Initialize("tcp@mpi://0.0.0.0:0", NA_TRUE);

        /* Gather addresses */
        strcpy(addr_name, NA_MPI_Get_port_name(na_class));
    }
#endif

#ifdef NA_HAS_BMI
    if (strcmp("bmi", argv[1]) == 0) {
        /* Although we could run some tests without MPI, need it for test setup */
        char hostname[NA_TEST_MAX_ADDR_NAME];
        unsigned int port_number = 22222;

        /* Generate a port number depending on server rank */
        port_number += na_test_rank_g;
        gethostname(hostname, NA_TEST_MAX_ADDR_NAME);
        sprintf(addr_name, "tcp://%s:%u", hostname, port_number);

        na_class = NA_Initialize(addr_name, NA_TRUE);
    }
#endif

#ifdef NA_HAS_SSM
    if (strcmp("ssm", argv[1]) == 0) {
        char hostname[NA_TEST_MAX_ADDR_NAME];
        unsigned int port_number = 22222;

        /* Generate a port number depending on server rank */
        port_number += na_test_rank_g;
        gethostname(hostname, NA_TEST_MAX_ADDR_NAME);
        sprintf(addr_name, "tcp@ssm://%s:%u", hostname, port_number);

        na_class = NA_Initialize(addr_name, NA_TRUE);
    }
#endif

    /* Gather addresses */
    na_test_set_config(addr_name);

    /* As many entries in addr table as number of server ranks */
    if (addr_table_size) *addr_table_size = na_addr_table_size;

    /* Point addr table to NA MPI addr table */
    if (addr_table) *addr_table = na_addr_table;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    if (max_number_of_peers) *max_number_of_peers = MPIEXEC_MAX_NUMPROCS;
#else
    if (max_number_of_peers) *max_number_of_peers = 1;
#endif

    /* Used by CTest Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_finalize(na_class_t *na_class)
{
    na_return_t ret;
    unsigned int i;

    ret = NA_Finalize(na_class);
    if (ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        goto done;
    }

    if (na_addr_table_size && na_addr_table) {
        for (i = 0; i < na_addr_table_size; i++) {
            free(na_addr_table[i]);
        }
        free(na_addr_table);
        na_addr_table = NULL;
        na_addr_table_size = 0;
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    na_test_mpi_finalize();
#endif

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Test_barrier(void)
{
#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(MPI_COMM_WORLD);
#endif
}
