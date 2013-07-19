/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_bulk.h"
#include "mercury_test.h"
#include "mercury_handler.h"
#include "mercury_bulk.h"
#include "mercury_time.h"

#include <stdio.h>
#include <stdlib.h>

#define PIPELINE_SIZE 4
#define MIN_BUFFER_SIZE 2<<11 /* Stop at 4KB buffer size */

#define FORCE_MPI_PROGRESS
#define FORCE_PIPELINE_SLEEP

static unsigned int number_of_peers;
static unsigned int number_of_executed_requests = 0;
static double raw_time_read = 0;
static size_t bla_write_nbytes;

/* Actual definition of the function that needs to be executed */
void bla_write_pipeline(size_t chunk_size,
        hg_bulk_request_t bulk_request, hg_status_t *status, bool nosleep)
{
    int ret;
    double sleep_time = chunk_size * raw_time_read / bla_write_nbytes;
    hg_time_t t1, t2;
    double time_remaining;

    time_remaining = sleep_time;

#ifdef FORCE_MPI_PROGRESS
    /* Force MPI progress for time_remaining ms */
    if (bulk_request != HG_BULK_REQUEST_NULL) {
        hg_time_get_current(&t1);

        ret = HG_Bulk_wait(bulk_request, time_remaining, status);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Error while waiting\n");
        }

        hg_time_get_current(&t2);
        time_remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
    }
#endif

    if (!nosleep && time_remaining > 0) {
        /* Should use nanosleep or equivalent */
        hg_time_sleep(hg_time_from_double(time_remaining), NULL);
    }
}

size_t bla_write_check(const void *buf, size_t nbyte)
{
    size_t i;
    int *bulk_buf = (int*) buf;

    /* Check bulk buf */
    for (i = 0; i < (nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != (int) i) {
            printf("Error detected in bulk transfer, bulk_buf[%lu] = %d, "
                    "was expecting %d!\n", i, bulk_buf[i], (int) i);
            break;
        }
    }
    return nbyte;
}


/*****************************************************************************/
int bla_write_rpc(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

    bla_write_in_t  bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bla_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_block_t bla_write_bulk_block_handle = HG_BULK_BLOCK_NULL;
    hg_bulk_request_t bla_write_bulk_request[PIPELINE_SIZE];
    int pipeline_iter;
    size_t pipeline_buffer_size;

    void *bla_write_buf;
    size_t bla_write_ret = 0;

    /* For timing */
    static int first_call = 1; /* Only used for dummy printf */
    double nmbytes;
    int avg_iter;
    double proc_time_read = 0;
    double raw_read_bandwidth, proc_read_bandwidth;

    if (first_call) printf("# Received new request\n");

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bla_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    /* unused bla_write_fildes = bla_write_in_struct.fildes; */
    bla_write_bulk_handle = bla_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bla_write_nbytes = HG_Bulk_handle_get_size(bla_write_bulk_handle);
    bla_write_buf = malloc(bla_write_nbytes);

    HG_Bulk_block_handle_create(bla_write_buf, bla_write_nbytes, HG_BULK_READWRITE,
            &bla_write_bulk_block_handle);

    /* Timing info */
    nmbytes = bla_write_nbytes / (1024 * 1024);
    if (first_call) printf("# Reading Bulk Data (%f MB)\n", nmbytes);

    /* Work out BW without pipeline and without processing data */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_time_t t1, t2;

        hg_time_get_current(&t1);

        ret = HG_Bulk_read(source, bla_write_bulk_handle, 0,
                bla_write_bulk_block_handle, 0, bla_write_nbytes,
                &bla_write_bulk_request[0]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not read bulk data\n");
            return ret;
        }

        ret = HG_Bulk_wait(bla_write_bulk_request[0],
                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete bulk data read\n");
            return ret;
        }

        hg_time_get_current(&t2);

        raw_time_read += hg_time_to_double(hg_time_subtract(t2, t1));
    }

    raw_time_read = raw_time_read / MERCURY_TESTING_MAX_LOOP;
    raw_read_bandwidth = nmbytes / raw_time_read;
    if (first_call) printf("# Raw read time: %f s (%.*f MB/s)\n", raw_time_read, 2, raw_read_bandwidth);

    /* Work out BW without pipeline and with processing data */
    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
        hg_time_t t1, t2;

        hg_time_get_current(&t1);

        ret = HG_Bulk_read(source, bla_write_bulk_handle, 0,
                bla_write_bulk_block_handle, 0, bla_write_nbytes,
                &bla_write_bulk_request[0]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not read bulk data\n");
            return ret;
        }

        ret = HG_Bulk_wait(bla_write_bulk_request[0],
                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete bulk data read\n");
            return ret;
        }

        /* Call bla_write */
        bla_write_pipeline(bla_write_nbytes, HG_BULK_REQUEST_NULL, HG_STATUS_IGNORE, 0);

        hg_time_get_current(&t2);

        proc_time_read += hg_time_to_double(hg_time_subtract(t2, t1));
    }

    proc_time_read = proc_time_read / MERCURY_TESTING_MAX_LOOP;
    proc_read_bandwidth = nmbytes / proc_time_read;
    if (first_call) printf("# Proc read time: %f s (%.*f MB/s)\n", proc_time_read, 2, proc_read_bandwidth);

    if (first_call) printf("%-*s%*s%*s%*s%*s%*s%*s", 12, "# Size (kB) ",
            10, "Time (s)", 10, "Min (s)", 10, "Max (s)",
            12, "BW (MB/s)", 12, "Min (MB/s)", 12, "Max (MB/s)");
    if (first_call) printf("\n");

    if (!PIPELINE_SIZE) fprintf(stderr, "PIPELINE_SIZE must be > 0!\n");

    for (pipeline_buffer_size = bla_write_nbytes / PIPELINE_SIZE;
            pipeline_buffer_size > MIN_BUFFER_SIZE;
            pipeline_buffer_size /= 2) {
        double time_read = 0, min_time_read = 0, max_time_read = 0;
        double read_bandwidth, min_read_bandwidth, max_read_bandwidth;

        for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
            size_t start_offset = 0;
            size_t total_bytes_read = 0;
            size_t chunk_size;

            hg_time_t t1, t2;
            double td;

            chunk_size = (PIPELINE_SIZE == 1) ? bla_write_nbytes : pipeline_buffer_size;

            hg_time_get_current(&t1);

            /* Initialize pipeline */
            for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
                size_t write_offset = start_offset + pipeline_iter * chunk_size;

                ret = HG_Bulk_read(source, bla_write_bulk_handle, write_offset,
                        bla_write_bulk_block_handle, write_offset, chunk_size,
                        &bla_write_bulk_request[pipeline_iter]);
                if (ret != HG_SUCCESS) {
                    fprintf(stderr, "Could not read bulk data\n");
                    return ret;
                }
            }

            while (total_bytes_read != bla_write_nbytes) {
                /* Alternate wait and read to receives pieces */
                for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
                    size_t write_offset = start_offset + pipeline_iter * chunk_size;
                    hg_status_t status;
                    int pipeline_next;

                    if (bla_write_bulk_request[pipeline_iter] != HG_BULK_REQUEST_NULL) {
                        ret = HG_Bulk_wait(bla_write_bulk_request[pipeline_iter],
                                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
                        if (ret != HG_SUCCESS) {
                            fprintf(stderr, "Could not complete bulk data read\n");
                            return ret;
                        }
                        bla_write_bulk_request[pipeline_iter] = HG_BULK_REQUEST_NULL;
                    }
                    total_bytes_read += chunk_size;
                    /* printf("total_bytes_read: %lu\n", total_bytes_read); */

                    /* Call bla_write */
                    pipeline_next = (pipeline_iter < PIPELINE_SIZE - 1) ?
                            pipeline_iter + 1 : 0;
#ifdef FORCE_PIPELINE_SLEEP
                    bla_write_pipeline(chunk_size, bla_write_bulk_request[pipeline_next], &status, 0);
#else
                    bla_write_pipeline(chunk_size, bla_write_bulk_request[pipeline_next], &status, 1);
#endif
                    if (status) bla_write_bulk_request[pipeline_next] = HG_BULK_REQUEST_NULL;

                    /* Start another read (which is PIPELINE_SIZE far) */
                    write_offset += chunk_size * PIPELINE_SIZE;
                    if (write_offset < bla_write_nbytes) {
                        ret = HG_Bulk_read(source, bla_write_bulk_handle, write_offset,
                                bla_write_bulk_block_handle, write_offset, chunk_size,
                                &bla_write_bulk_request[pipeline_iter]);
                        if (ret != HG_SUCCESS) {
                            fprintf(stderr, "Could not read bulk data\n");
                            return ret;
                        }
                    }
                    /* TODO should also check remaining data */
                }
                start_offset += chunk_size * PIPELINE_SIZE;
            }

            hg_time_get_current(&t2);

            td = hg_time_to_double(hg_time_subtract(t2, t1));

            time_read += td;
            if (!min_time_read) min_time_read = time_read;
            min_time_read = (td < min_time_read) ? td : min_time_read;
            max_time_read = (td > max_time_read) ? td : max_time_read;
        }

        time_read = time_read / MERCURY_TESTING_MAX_LOOP;
        read_bandwidth = nmbytes / time_read;
        min_read_bandwidth = nmbytes / max_time_read;
        max_read_bandwidth = nmbytes / min_time_read;

        /* At this point we have received everything so work out the bandwidth */
        printf("%-*d%*f%*f%*f%*.*f%*.*f%*.*f\n", 12, (int) pipeline_buffer_size / 1024,
                10, time_read, 10, min_time_read, 10, max_time_read,
                12, 2, read_bandwidth, 12, 2, min_read_bandwidth, 12, 2, max_read_bandwidth);

        /* Check data */
        bla_write_ret = bla_write_check(bla_write_buf, bla_write_nbytes);
    }

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Free block handle */
    ret = HG_Bulk_block_handle_free(bla_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

    free(bla_write_buf);

    first_call = 0;

    return ret;
}

/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    int hg_ret, na_ret;

    /* Used by Test Driver */
    printf("# Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, &number_of_peers);

    hg_ret = HG_Handler_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper handler\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Bulk_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Register routine */
    MERCURY_HANDLER_REGISTER("bla_write", bla_write_rpc,
            bla_write_in_t, bla_write_out_t);

    while (number_of_executed_requests != number_of_peers) {
        hg_status_t status;

        /* Receive new function calls */
        hg_ret = HG_Handler_process(1, &status);
        if (hg_ret == HG_SUCCESS && status) {
            printf("# Request processed\n");
            number_of_executed_requests++;
        }
    }

    printf("# Finalizing...\n");

    /* Finalize the interface */
    hg_ret = HG_Bulk_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Handler_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper handler\n");
        return EXIT_FAILURE;
    }

    na_ret = NA_Finalize(network_class);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not finalize NA interface\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
