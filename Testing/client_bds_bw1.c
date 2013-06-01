/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_bds_bw1.h"
#include "mercury_test.h"
#include "na_config.h"
#include "na_mpi.h"
#include "mercury.h"
#include "mercury_bulk.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define BULK_BUF_SIZE 1024*1024*4

/* TODO Test only supports MPI for now */

/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_addr_t addr;
    na_class_t *network_class = NULL;

    hg_id_t bla_write_id, finalize_id;
    bla_write_in_t bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;
    hg_request_t bla_write_request, finalize_request;

    int fildes = 12345;
    int *bulk_buf;
    int bulk_size = BULK_BUF_SIZE;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    int bla_write_ret = 0;
    size_t nbytes;
    double nmbytes;
    size_t pipeline_buffer_size;

    hg_status_t bla_open_status;
    int hg_ret, na_ret;
    int i;

    MPI_Comm split_comm;
    int color;
    int global_rank;
    int client_rank, client_size;

    int provided;
    /* Need a MPI_THREAD_MULTIPLE level if onesided thread required */
    MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);

    MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
    /* Color is 1 for server, 2 for client */
    color = 2;
    MPI_Comm_split(MPI_COMM_WORLD, color, global_rank, &split_comm);
    MPI_Comm_rank(split_comm, &client_rank);
    MPI_Comm_size(split_comm, &client_size);

    network_class = NA_MPI_Init(&split_comm, 0);

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Bulk_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    na_ret = NA_Addr_lookup(network_class, "nil", &addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find connect\n");
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    bla_write_id = MERCURY_REGISTER("bla_write", bla_write_in_t, bla_write_out_t);
    finalize_id = MERCURY_REGISTER_FINALIZE();

    /* Prepare bulk_buf */
    nbytes = bulk_size * sizeof(int);
    nmbytes = nbytes / (1024 * 1024);
    if (client_rank == 0) printf("# Reading Bulk Data (%f MB) with %d clients\n", nmbytes, client_size);

    bulk_buf = malloc(nbytes);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Register memory */
    hg_ret = HG_Bulk_handle_create(bulk_buf, nbytes,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    bla_write_in_struct.fildes = fildes;
    bla_write_in_struct.bulk_handle = bulk_handle;

    if (client_rank == 0) printf("%-*s%*s%*s", 18, "# Buffer Size (KB) ", 20, "Time (s)", 20, "Bandwidth (MB/s)");
    if (client_rank == 0) printf("\n");

    for (pipeline_buffer_size = nbytes / PIPELINE_SIZE;
            pipeline_buffer_size > MIN_BUFFER_SIZE;
            pipeline_buffer_size /= 2) {
        int avg_iter;
        double time_read = 0;
        double read_bandwidth;

        bla_write_in_struct.pipeline_buffer_size = pipeline_buffer_size;

        for (avg_iter = 0; avg_iter < AVERAGE; avg_iter++) {
            struct timeval tv1, tv2;
            double td1, td2;

            MPI_Barrier(split_comm);

            gettimeofday(&tv1, NULL);

            /* Forward call to remote addr and get a new request */
            /* printf("Forwarding bla_write, op id: %u...\n", bla_write_id); */
            hg_ret = HG_Forward(addr, bla_write_id,
                    &bla_write_in_struct, &bla_write_out_struct, &bla_write_request);
            if (hg_ret != HG_SUCCESS) {
                fprintf(stderr, "Could not forward call\n");
                return EXIT_FAILURE;
            }

            /* Wait for call to be executed and return value to be sent back
             * (Request is freed when the call completes)
             */
            hg_ret = HG_Wait(bla_write_request, HG_MAX_IDLE_TIME, &bla_open_status);
            if (hg_ret != HG_SUCCESS) {
                fprintf(stderr, "Error during wait\n");
                return EXIT_FAILURE;
            }
            if (!bla_open_status) {
                fprintf(stderr, "Operation did not complete\n");
                return EXIT_FAILURE;
            } else {
                /* printf("Call completed\n"); */
            }

            MPI_Barrier(split_comm);
            gettimeofday(&tv2, NULL);

            td1 = tv1.tv_sec + tv1.tv_usec / 1000000.0;
            td2 = tv2.tv_sec + tv2.tv_usec / 1000000.0;

            /* Get output parameters */
            bla_write_ret = bla_write_out_struct.ret;
            if (bla_write_ret != (bulk_size * (int)sizeof(int))) {
                fprintf(stderr, "Data not correctly processed\n");
            }
            time_read += td2 - td1;
        }

        time_read = time_read / AVERAGE;
        read_bandwidth = nmbytes * client_size / time_read;

        /* At this point we have received everything so work out the bandwidth */
        printf("%-*d%*f%*.*f\n", 18, (int)pipeline_buffer_size / 1024, 20,
                time_read, 20, 2, read_bandwidth);
    }

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return EXIT_FAILURE;
    }
    free(bulk_buf);

    if (client_rank == 0) {
        /* Forward call to remote addr and get a new request */
        hg_ret = HG_Forward(addr, finalize_id, NULL, NULL, &finalize_request);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not forward call\n");
            return EXIT_FAILURE;
        }

        /* Wait for call to be executed and return value to be sent back
         * (Request is freed when the call completes)
         */
        hg_ret = HG_Wait(finalize_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Error during wait\n");
            return EXIT_FAILURE;
        }
    }
    MPI_Barrier(split_comm);

    /* Free addr id */
    na_ret = NA_Addr_free(network_class, addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    /* Finalize interface */
    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Bulk_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    MPI_Finalize();

    return EXIT_SUCCESS;
}
