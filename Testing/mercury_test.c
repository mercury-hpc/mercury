/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"
#include "mercury_rpc_cb.h"

#include "mercury_atomic.h"
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
#include "mercury_thread_pool.h"
#endif

#ifdef NA_HAS_MPI
#include "na_mpi.h"
#endif
#ifdef NA_HAS_SSM
#include "na_ssm.h"
#endif
#ifdef MERCURY_HAS_PARALLEL_TESTING
#include <mpi.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/
#define HG_TEST_MAX_ADDR_NAME 256

/*******************/
/* Local Variables */
/*******************/
static na_class_t *hg_na_class_g = NULL;
static hg_bool_t hg_test_is_client_g = HG_FALSE;
static na_addr_t hg_test_addr_g = NA_ADDR_NULL;
static int hg_test_rank_g = 0;

#ifdef MERCURY_HAS_PARALLEL_TESTING
static int mpi_internally_initialized = HG_FALSE;
#endif

static char **na_addr_table = NULL;
static unsigned int na_addr_table_size = 0;

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
hg_thread_pool_t *hg_test_thread_pool_g = NULL;
#endif

/* test_rpc */
hg_id_t hg_test_rpc_open_id_g = 0;

/* test_bulk */
hg_id_t hg_test_bulk_write_id_g = 0;

/* test_bulk_seg */
hg_id_t hg_test_bulk_seg_write_id_g = 0;

/* test_pipeline */
hg_id_t hg_test_pipeline_write_id_g = 0;

/* test_posix */
hg_id_t hg_test_posix_open_id_g = 0;
hg_id_t hg_test_posix_write_id_g = 0;
hg_id_t hg_test_posix_read_id_g = 0;
hg_id_t hg_test_posix_close_id_g = 0;

/* test_scale */
hg_id_t hg_test_scale_open_id_g = 0;
hg_id_t hg_test_scale_write_id_g = 0;

/* test_finalize */
hg_id_t hg_test_finalize_id_g = 0;
hg_atomic_int32_t hg_test_finalizing_count_g;

/*---------------------------------------------------------------------------*/
static void
hg_test_finalize_rpc(void)
{
    hg_return_t hg_ret;
    hg_request_t request;
    hg_status_t status;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(hg_test_addr_g, hg_test_finalize_id_g, NULL, NULL,
            &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
    }

    /* Free request */
    hg_ret = HG_Request_free(request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
    }
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_finalize_cb(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    hg_atomic_incr32(&hg_test_finalizing_count_g);

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Handler_free(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
hg_test_register(void)
{
    /* test_rpc */
    hg_test_rpc_open_id_g = MERCURY_REGISTER("hg_test_rpc_open", rpc_open_in_t,
            rpc_open_out_t, hg_test_rpc_open_cb);

    /* test_bulk */
    hg_test_bulk_write_id_g = MERCURY_REGISTER("hg_test_bulk_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_write_cb);

    /* test_bulk_seg */
    hg_test_bulk_seg_write_id_g = MERCURY_REGISTER("hg_test_bulk_seg_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_bulk_seg_write_cb);

    /* test_pipeline */
    hg_test_pipeline_write_id_g = MERCURY_REGISTER("hg_test_pipeline_write",
            bulk_write_in_t, bulk_write_out_t, hg_test_pipeline_write_cb);

    /* test_posix */
    hg_test_posix_open_id_g = MERCURY_REGISTER("hg_test_posix_open",
            open_in_t, open_out_t, hg_test_posix_open_cb);
    hg_test_posix_write_id_g = MERCURY_REGISTER("hg_test_posix_write",
            write_in_t, write_out_t, hg_test_posix_write_cb);
    hg_test_posix_read_id_g = MERCURY_REGISTER("hg_test_posix_read",
            read_in_t, read_out_t, hg_test_posix_read_cb);
    hg_test_posix_close_id_g = MERCURY_REGISTER("hg_test_posix_close",
            close_in_t, close_out_t, hg_test_posix_close_cb);

    /* test_scale */
    hg_test_scale_open_id_g = MERCURY_REGISTER("hg_test_scale_open",
            open_in_t, open_out_t, hg_test_scale_open_cb);
    hg_test_scale_write_id_g = MERCURY_REGISTER("hg_test_scale_write",
            write_in_t, write_out_t, hg_test_scale_write_cb);

    /* test_finalize */
    hg_test_finalize_id_g = MERCURY_REGISTER("hg_test_finalize",
            void, void, hg_test_finalize_cb);
}

/*---------------------------------------------------------------------------*/
#ifdef MERCURY_HAS_PARALLEL_TESTING
static void
hg_test_mpi_init(hg_bool_t server)
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
hg_test_mpi_finalize(void)
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
hg_test_set_config(const char *addr_name)
{
    FILE *config = NULL;
    int my_rank = 0, my_size = 1;
    int i;
    int max_port_name_length = 256; /* default set to 256 */

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
hg_test_get_config(char *addr_name, size_t len, int *rank)
{
    FILE *config = NULL;
    int my_rank = 0;
    char config_addr_name[HG_TEST_MAX_ADDR_NAME];

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
#endif

    /* Only rank 0 reads file */
    if (my_rank == 0) {
        config = fopen("port.cfg", "r");
        if (config != NULL) {
            fgets(config_addr_name, HG_TEST_MAX_ADDR_NAME, config);
        }
        fclose(config);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Broadcast port name */
    MPI_Bcast(config_addr_name, HG_TEST_MAX_ADDR_NAME, MPI_BYTE, 0,
            MPI_COMM_WORLD);
#endif

    strncpy(addr_name, config_addr_name,
            (len < HG_TEST_MAX_ADDR_NAME) ? len : HG_TEST_MAX_ADDR_NAME);

    if (rank) *rank = my_rank;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_client_init(int argc, char *argv[], na_addr_t *addr, int *rank)
{
    char test_addr_name[HG_TEST_MAX_ADDR_NAME];
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    hg_test_mpi_init(HG_FALSE);
#endif

    /* Get config from file */
    hg_test_get_config(test_addr_name, HG_TEST_MAX_ADDR_NAME,
            &hg_test_rank_g);

#ifdef NA_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        hg_na_class_g = NA_Initialize("tcp@mpi://0.0.0.0:0", NA_FALSE);
    } else
#endif
    {
        hg_na_class_g = NA_Initialize(test_addr_name, NA_FALSE);
    }

    if (argc > 2 && strcmp("self", argv[2]) == 0) {
        strcpy(test_addr_name, "self");
    }
    if (argc > 3 && strcmp("self", argv[3]) == 0) {
        strcpy(test_addr_name, "self");
    }

    ret = HG_Init(hg_na_class_g);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        goto done;
    }

    if (strcmp(test_addr_name, "self") == 0) {
        /* Self addr */
        na_ret = NA_Addr_self(hg_na_class_g, &hg_test_addr_g);
    } else {
        /* Look up addr using port name info */
        na_ret = NA_Addr_lookup_wait(hg_na_class_g, test_addr_name,
                &hg_test_addr_g);
    }
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", test_addr_name);
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Register routines */
    hg_test_register();

    /* When finalize is called we need to free the addr etc */
    hg_test_is_client_g = HG_TRUE;

    if (addr) *addr = hg_test_addr_g;
    if (rank) *rank = hg_test_rank_g;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_server_init(int argc, char *argv[], char ***addr_table,
        unsigned int *addr_table_size, unsigned int *max_number_of_peers)
{
    hg_return_t ret = HG_SUCCESS;
    char addr_name[HG_TEST_MAX_ADDR_NAME];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmi|mpi|ssm>\n", argv[0]);
        exit(0);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    hg_test_mpi_init(HG_TRUE);
    MPI_Comm_rank(MPI_COMM_WORLD, &hg_test_rank_g);
#endif

#ifdef NA_HAS_MPI
    if (strcmp("mpi", argv[1]) == 0) {
        hg_na_class_g = NA_Initialize("tcp@mpi://0.0.0.0:0", NA_TRUE);

        /* Gather addresses */
        strcpy(addr_name, NA_MPI_Get_port_name(hg_na_class_g));
    }
#endif

#ifdef NA_HAS_BMI
    if (strcmp("bmi", argv[1]) == 0) {
        /* Although we could run some tests without MPI, need it for test setup */
        char hostname[HG_TEST_MAX_ADDR_NAME];
        unsigned int port_number = 22222;

        /* Generate a port number depending on server rank */
        port_number += hg_test_rank_g;
        gethostname(hostname, HG_TEST_MAX_ADDR_NAME);
        sprintf(addr_name, "tcp://%s:%u", hostname, port_number);

        hg_na_class_g = NA_Initialize(addr_name, NA_TRUE);
    }
#endif

#ifdef NA_HAS_SSM
    if (strcmp("ssm", argv[1]) == 0) {
        char hostname[HG_TEST_MAX_ADDR_NAME];
        unsigned int port_number = 22222;

        /* Generate a port number depending on server rank */
        port_number += hg_test_rank_g;
        gethostname(hostname, HG_TEST_MAX_ADDR_NAME);
        sprintf(addr_name, "tcp@ssm://%s:%u", hostname, port_number);

        hg_na_class_g = NA_Initialize(addr_name, NA_TRUE);
    }
#endif

    /* Gather addresses */
    hg_test_set_config(addr_name);

    /* Initalize atomic variable to finalize server */
    hg_atomic_set32(&hg_test_finalizing_count_g, 0);

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_pool_init(MERCURY_TESTING_NUM_THREADS, &hg_test_thread_pool_g);
    printf("# Starting server with %d threads...\n", MERCURY_TESTING_NUM_THREADS);
#endif

    /* As many entries in addr table as number of server ranks */
    if (addr_table_size) *addr_table_size = na_addr_table_size;

    /* Point addr table to NA MPI addr table */
    if (addr_table) *addr_table = na_addr_table;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    if (max_number_of_peers) *max_number_of_peers = MPIEXEC_MAX_NUMPROCS;
#else
    if (max_number_of_peers) *max_number_of_peers = 1;
#endif

    ret = HG_Init(hg_na_class_g);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        goto done;
    }

    /* Register test routines */
    hg_test_register();

    /* Used by CTest Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Test_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;
    na_return_t na_ret;
    unsigned int i;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(MPI_COMM_WORLD);
#endif

    if (hg_test_is_client_g) {
        /* Terminate server */
        if (hg_test_rank_g == 0) hg_test_finalize_rpc();

        /* Free addr id */
        na_ret = NA_Addr_free(hg_na_class_g, hg_test_addr_g);
        if (na_ret != NA_SUCCESS) {
            fprintf(stderr, "Could not free addr\n");
            goto done;
        }
        hg_test_addr_g = NA_ADDR_NULL;
    } else {
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
        hg_thread_pool_destroy(hg_test_thread_pool_g);
#endif
    }

    /* Finalize interface */
    ret = HG_Finalize();
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        goto done;
    }

    na_ret = NA_Finalize(hg_na_class_g);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        goto done;
    }
    hg_na_class_g = NULL;

    if (na_addr_table_size && na_addr_table) {
        for (i = 0; i < na_addr_table_size; i++) {
            free(na_addr_table[i]);
        }
        free(na_addr_table);
        na_addr_table = NULL;
        na_addr_table_size = 0;
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    hg_test_mpi_finalize();
#endif

done:
     return ret;
}
