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

#include "mercury_time.h"

#include <stdio.h>
#include <stdlib.h>

#define RPC_SKIP 20
#define BULK_SKIP 20

#ifdef MERCURY_HAS_PARALLEL_TESTING
#include <mpi.h>
static MPI_Comm split_comm = MPI_COMM_WORLD;
#endif

static int client_rank = 0, client_size = 1;

extern hg_id_t hg_test_scale_open_id_g;
extern hg_id_t hg_test_scale_write_id_g;

/**
 *
 */
static int
measure_rpc(na_addr_t addr)
{
    rpc_open_in_t rpc_open_in_struct;
    rpc_open_out_t rpc_open_out_struct;
    hg_request_t rpc_open_request;
    hg_status_t rpc_open_status;

    hg_const_string_t rpc_open_path = "/scratch/hdf/test.h5";
    rpc_handle_t rpc_open_handle;

    int avg_iter;
    double time_read = 0, min_time_read = 0, max_time_read = 0;
    double calls_per_sec, min_calls_per_sec, max_calls_per_sec;

    int hg_ret;
    size_t i;

    if (client_rank == 0) {
        printf("# Executing RPC with %d client(s) -- loop %d time(s)\n",
                client_size, MERCURY_TESTING_MAX_LOOP);
    }

    /* Fill input structure */
    rpc_open_handle.cookie = 12345;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    if (client_rank == 0) printf("# Warming up...\n");

    /* Warm up for RPC */
    for (i = 0; i < RPC_SKIP; i++) {
        hg_ret = HG_Forward(addr, hg_test_scale_open_id_g,
                &rpc_open_in_struct, &rpc_open_out_struct, &rpc_open_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            return HG_FAIL;
        }

        hg_ret = HG_Wait(rpc_open_request, HG_MAX_IDLE_TIME, &rpc_open_status);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return HG_FAIL;
        }

        hg_ret = HG_Request_free(rpc_open_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free request\n");
            return HG_FAIL;
        }
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(split_comm);
#endif

    if (client_rank == 0) printf("%*s%*s%*s%*s%*s%*s",
            10, "# Time (s)", 10, "Min (s)", 10, "Max (s)",
            12, "Calls (c/s)", 12, "Min (c/s)", 12, "Max (c/s)");
    if (client_rank == 0) printf("\n");

    /* RPC benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_time_t t1, t2;
        double td;

        hg_time_get_current(&t1);

        /* Forward call to remote addr and get a new request */
        hg_ret = HG_Forward(addr, hg_test_scale_open_id_g,
                &rpc_open_in_struct, &rpc_open_out_struct, &rpc_open_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            return HG_FAIL;
        }

        /* Wait for call to be executed and return value to be sent back
         * (Request is freed when the call completes)
         */
        hg_ret = HG_Wait(rpc_open_request, HG_MAX_IDLE_TIME, &rpc_open_status);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return HG_FAIL;
        }
        if (!rpc_open_status) {
            fprintf(stderr, "Operation did not complete\n");
            return HG_FAIL;
        } else {
            /* printf("Call completed\n"); */
        }

        /* Free request */
        hg_ret = HG_Request_free(rpc_open_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free request\n");
            return HG_FAIL;
        }

#ifdef MERCURY_HAS_PARALLEL_TESTING
        MPI_Barrier(split_comm);
#endif
        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (!min_time_read) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;
    }

    time_read = time_read / MERCURY_TESTING_MAX_LOOP;
    calls_per_sec = client_size / time_read;
    min_calls_per_sec = client_size / max_time_read;
    max_calls_per_sec = client_size / min_time_read;

    /* At this point we have received everything so work out the bandwidth */
    printf("%*f%*f%*f%*.*f%*.*f%*.*f\n",
            10, time_read, 10, min_time_read, 10, max_time_read,
            12, 2, calls_per_sec, 12, 2, min_calls_per_sec, 12, 2, max_calls_per_sec);

    return HG_SUCCESS;
}

/**
 *
 */
static int
measure_bulk_transfer(na_addr_t addr)
{
    bulk_write_in_t bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;
    hg_request_t bulk_write_request;
    hg_status_t bulk_write_status;

    int fildes = 12345;
    int *bulk_buf;
    size_t bulk_size = 1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE / sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t bulk_write_ret = 0;
    size_t nbytes;
    double nmbytes;

    int avg_iter;
    double time_read = 0, min_time_read = 0, max_time_read = 0;
    double read_bandwidth, min_read_bandwidth, max_read_bandwidth;

    int hg_ret;
    size_t i;

    /* Prepare bulk_buf */
    nbytes = bulk_size * sizeof(int);
    nmbytes = (double) nbytes / (1024 * 1024);
    if (client_rank == 0) {
        printf("# Reading Bulk Data (%f MB) with %d client(s) -- loop %d time(s)\n",
                nmbytes, client_size, MERCURY_TESTING_MAX_LOOP);
    }

    bulk_buf = (int*) malloc(nbytes);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = (int) i;
    }

    /* Register memory */
    hg_ret = HG_Bulk_handle_create(bulk_buf, nbytes,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return HG_FAIL;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    if (client_rank == 0) printf("# Warming up...\n");

    /* Warm up for bulk data */
    for (i = 0; i < BULK_SKIP; i++) {
        hg_ret = HG_Forward(addr, hg_test_scale_write_id_g,
                &bulk_write_in_struct, &bulk_write_out_struct, &bulk_write_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            return HG_FAIL;
        }

        hg_ret = HG_Wait(bulk_write_request, HG_MAX_IDLE_TIME, &bulk_write_status);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return HG_FAIL;
        }


        /* Free request */
        hg_ret = HG_Request_free(bulk_write_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free request\n");
            return HG_FAIL;
        }
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(split_comm);
#endif

    if (client_rank == 0) printf("%*s%*s%*s%*s%*s%*s",
            10, "# Time (s)", 10, "Min (s)", 10, "Max (s)",
            12, "BW (MB/s)", 12, "Min (MB/s)", 12, "Max (MB/s)");
    if (client_rank == 0) printf("\n");

    /* Bulk data benchmark */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_time_t t1, t2;
        double td;

        hg_time_get_current(&t1);

        /* Forward call to remote addr and get a new request */
        hg_ret = HG_Forward(addr, hg_test_scale_write_id_g,
                &bulk_write_in_struct, &bulk_write_out_struct, &bulk_write_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            return HG_FAIL;
        }

        /* Wait for call to be executed and return value to be sent back
         * (Request is freed when the call completes)
         */
        hg_ret = HG_Wait(bulk_write_request, HG_MAX_IDLE_TIME, &bulk_write_status);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return HG_FAIL;
        }
        if (!bulk_write_status) {
            fprintf(stderr, "Operation did not complete\n");
            return HG_FAIL;
        } else {
            /* printf("Call completed\n"); */
        }

        /* Get output parameters */
        bulk_write_ret = bulk_write_out_struct.ret;
        if (bulk_write_ret != (bulk_size * sizeof(int))) {
            fprintf(stderr, "Data not correctly processed\n");
        }

        /* Free request */
        hg_ret = HG_Request_free(bulk_write_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free request\n");
            return HG_FAIL;
        }

#ifdef MERCURY_HAS_PARALLEL_TESTING
        MPI_Barrier(split_comm);
#endif
        hg_time_get_current(&t2);
        td = hg_time_to_double(hg_time_subtract(t2, t1));

        time_read += td;
        if (!min_time_read) min_time_read = time_read;
        min_time_read = (td < min_time_read) ? td : min_time_read;
        max_time_read = (td > max_time_read) ? td : max_time_read;
    }

    time_read = time_read / MERCURY_TESTING_MAX_LOOP;
    read_bandwidth = nmbytes * client_size / time_read;
    min_read_bandwidth = nmbytes * client_size / max_time_read;
    max_read_bandwidth = nmbytes * client_size / min_time_read;

    /* At this point we have received everything so work out the bandwidth */
    printf("%*f%*f%*f%*.*f%*.*f%*.*f\n",
            10, time_read, 10, min_time_read, 10, max_time_read,
            12, 2, read_bandwidth, 12, 2, min_read_bandwidth, 12, 2, max_read_bandwidth);

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return HG_FAIL;
    }
    free(bulk_buf);

    return HG_SUCCESS;
}

/**
 *
 */
//static int
//server_finalize(na_addr_t addr)
//{
//    hg_request_t finalize_request;
//    int hg_ret;
//
//    /* Forward call to remote addr and get a new request */
//    hg_ret = HG_Forward(addr, finalize_id, NULL, NULL, &finalize_request);
//    if (hg_ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not forward call\n");
//        return HG_FAIL;
//    }
//
//    /* Wait for call to be executed and return value to be sent back
//     * (Request is freed when the call completes)
//     */
//    hg_ret = HG_Wait(finalize_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
//    if (hg_ret != HG_SUCCESS) {
//        fprintf(stderr, "Error during wait\n");
//        return HG_FAIL;
//    }
//
//    /* Free request */
//    hg_ret = HG_Request_free(finalize_request);
//    if (hg_ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not free request\n");
//        return HG_FAIL;
//    }
//
//    return HG_SUCCESS;
//}

/*****************************************************************************/
int
main(int argc, char *argv[])
{
    na_addr_t addr;
    char *port_name;
    na_class_t *network_class = NULL;

    int hg_ret, na_ret;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(split_comm, &client_rank);
    MPI_Comm_size(split_comm, &client_size);
#endif

    network_class = HG_Test_client_init(argc, argv, &port_name, NULL);

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        return EXIT_FAILURE;
    }

    if (strcmp(port_name, "self") == 0) {
        /* Self addr */
        na_ret = NA_Addr_self(network_class, &addr);
    } else {
        /* Look up addr using port name info */
        na_ret = NA_Addr_lookup_wait(network_class, port_name, &addr);
    }
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", port_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    HG_Test_register();

    /* Run RPC test */
    measure_rpc(addr);

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(split_comm);
#endif

    /* Run Bulk test */
    measure_bulk_transfer(addr);

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(split_comm);
#endif

//    if (client_rank == 0) {
//        server_finalize(addr);
//    }

    /* Free addr id */
    na_ret = NA_Addr_free(network_class, addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    /* Finalize interface */
    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Finalize(network_class);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        return EXIT_FAILURE;
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Finalize();
#endif


    return EXIT_SUCCESS;
}
