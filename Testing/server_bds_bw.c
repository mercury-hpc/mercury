/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_bds.h"
#include "mercury_test.h"
#include "mercury_handler.h"
#include "mercury_bulk.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define AVERAGE 5
#define PIPELINE_SIZE 4
#define MIN_BUFFER_SIZE 2<<8 /* Stop at 1KB buffer size */

/* #define USE_PROGRESS_THREAD */
/* #define USE_MPI_PROGRESS */

static unsigned int number_of_peers;
double raw_time_read = 0;
size_t bla_write_nbytes;

/* Actual definition of the function that needs to be executed */
void bla_write_pipeline(size_t chunk_size,
        hg_bulk_request_t bulk_request, hg_bulk_status_t *status, bool nosleep)
{
    int ret;
    /* Convert raw_time_read to ms */
    double msleep_time = chunk_size * raw_time_read * 1000 / bla_write_nbytes;
    struct timeval t1, t2;
    double time_remaining;

    time_remaining = msleep_time;

    if (bulk_request != HG_BULK_REQUEST_NULL) {
        gettimeofday(&t1, NULL);

        ret = HG_Bulk_wait(bulk_request, time_remaining, status);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Error while waiting\n");
        }

        gettimeofday(&t2, NULL);
        time_remaining -= (t2.tv_sec - t1.tv_sec) * 1000 +
                (t2.tv_usec - t1.tv_usec) / 1000;
    }

    if (!nosleep && time_remaining > 0) {
        usleep(time_remaining * 1000);
    }
}

size_t bla_write_check(const void *buf, size_t nbyte)
{
    int i;
    int *bulk_buf = (int*) buf;

    /* Check bulk buf */
    for (i = 0; i < (int)(nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != i) {
            printf("Error detected in bulk transfer, bulk_buf[%d] = %d, "
                    "was expecting %d!\n", i, bulk_buf[i], i);
            break;
        }
    }
    return nbyte;
}


/*****************************************************************************/
int fs_bla_write(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

    void           *bla_write_in_buf;
    size_t          bla_write_in_buf_size;
    bla_write_in_t  bla_write_in_struct;

    void           *bla_write_out_buf;
    size_t          bla_write_out_buf_size;
    bla_write_out_t bla_write_out_struct;

    hg_proc_t proc;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bla_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_block_t bla_write_bulk_block_handle = HG_BULK_BLOCK_NULL;
    hg_bulk_request_t bla_write_bulk_request[PIPELINE_SIZE];
    int pipeline_iter;
    size_t pipeline_buffer_size;

    void *bla_write_buf;
    int bla_write_ret = 0;

    /* For timing */
    static int first_call = 1; /* Only used for dummy printf */
    int avg_iter;
    double nmbytes;
    double proc_time_read = 0, time_read = 0;
    double raw_read_bandwidth, proc_read_bandwidth, read_bandwidth;

    if (first_call) printf("# Received new request\n");

    /* Get input parameters and data */
    ret = HG_Handler_get_input_buf(handle, &bla_write_in_buf, &bla_write_in_buf_size);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    hg_proc_create(bla_write_in_buf, bla_write_in_buf_size, HG_DECODE, &proc);
    hg_proc_bla_write_in_t(proc, &bla_write_in_struct);
    hg_proc_free(proc);

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
    for (avg_iter = 0; avg_iter < AVERAGE; avg_iter++) {
        struct timeval tv1, tv2;
        double td1, td2;

        gettimeofday(&tv1, NULL);

        ret = HG_Bulk_read(source, bla_write_bulk_handle, 0,
                bla_write_bulk_block_handle, 0, bla_write_nbytes,
                &bla_write_bulk_request[0]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not read bulk data\n");
            return ret;
        }

        ret = HG_Bulk_wait(bla_write_bulk_request[0],
                HG_BULK_MAX_IDLE_TIME, HG_BULK_STATUS_IGNORE);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete bulk data read\n");
            return ret;
        }

        gettimeofday(&tv2, NULL);

        td1 = tv1.tv_sec + tv1.tv_usec / 1000000.0;
        td2 = tv2.tv_sec + tv2.tv_usec / 1000000.0;

        raw_time_read += td2 - td1;
    }

    raw_time_read = raw_time_read / AVERAGE;
    raw_read_bandwidth = nmbytes / raw_time_read;
    if (first_call) printf("# Raw read time: %f s (%.*f MB/s)\n", raw_time_read, 2, raw_read_bandwidth);

    /* Work out BW without pipeline and with processing data */
    for (avg_iter = 0; avg_iter < AVERAGE; avg_iter++) {
        struct timeval tv1, tv2;
        double td1, td2;

        gettimeofday(&tv1, NULL);

        ret = HG_Bulk_read(source, bla_write_bulk_handle, 0,
                bla_write_bulk_block_handle, 0, bla_write_nbytes,
                &bla_write_bulk_request[0]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not read bulk data\n");
            return ret;
        }

        ret = HG_Bulk_wait(bla_write_bulk_request[0],
                HG_BULK_MAX_IDLE_TIME, HG_BULK_STATUS_IGNORE);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not complete bulk data read\n");
            return ret;
        }

        /* Call bla_write */
        bla_write_pipeline(bla_write_nbytes, HG_BULK_REQUEST_NULL, HG_BULK_STATUS_IGNORE, 0);

        gettimeofday(&tv2, NULL);

        td1 = tv1.tv_sec + tv1.tv_usec / 1000000.0;
        td2 = tv2.tv_sec + tv2.tv_usec / 1000000.0;

        proc_time_read += td2 - td1;
    }

    proc_time_read = proc_time_read / AVERAGE;
    proc_read_bandwidth = nmbytes / proc_time_read;
    if (first_call) printf("# Proc read time: %f s (%.*f MB/s)\n", proc_time_read, 2, proc_read_bandwidth);

    if (first_call) printf("%-*s%*s%*s", 18, "# Buffer Size (KB) ", 20, "Time (s)", 20, "Bandwidth (MB/s)");
    if (first_call) printf("\n");

    if (!PIPELINE_SIZE) fprintf(stderr, "PIPELINE_SIZE must be > 0!\n");

    for (pipeline_buffer_size = bla_write_nbytes / PIPELINE_SIZE;
            pipeline_buffer_size > MIN_BUFFER_SIZE;
            pipeline_buffer_size /= 2) {
        time_read = 0;

        for (avg_iter = 0; avg_iter < AVERAGE; avg_iter++) {
            size_t start_offset = 0;
            size_t total_bytes_read = 0;
            size_t chunk_size;

            struct timeval tv1, tv2;
            double td1, td2;

            chunk_size = (PIPELINE_SIZE == 1) ? bla_write_nbytes : pipeline_buffer_size;

            gettimeofday(&tv1, NULL);

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
                    hg_bulk_status_t status;
                    int pipeline_next;

                    if (bla_write_bulk_request[pipeline_iter] != HG_BULK_REQUEST_NULL) {
                        ret = HG_Bulk_wait(bla_write_bulk_request[pipeline_iter],
                                HG_BULK_MAX_IDLE_TIME, HG_BULK_STATUS_IGNORE);
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
                    bla_write_pipeline(chunk_size, bla_write_bulk_request[pipeline_next], &status, 0);
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

            gettimeofday(&tv2, NULL);

            td1 = tv1.tv_sec + tv1.tv_usec / 1000000.0;
            td2 = tv2.tv_sec + tv2.tv_usec / 1000000.0;

            time_read += td2 - td1;
        }

        time_read = time_read / AVERAGE;
        read_bandwidth = nmbytes / time_read;

        /* At this point we have received everything so work out the bandwidth */
        printf("%-*d%*f%*.*f\n", 18, (int)pipeline_buffer_size / 1024, 20, time_read, 20, 2, read_bandwidth);

        /* Check data */
        bla_write_ret = bla_write_check(bla_write_buf, bla_write_nbytes);
    }

    /* Fill output structure */
    bla_write_out_struct.ret = bla_write_ret;

    /* Create a new encoding proc */
    HG_Handler_get_output_buf(handle, &bla_write_out_buf, &bla_write_out_buf_size);

    hg_proc_create(bla_write_out_buf, bla_write_out_buf_size, HG_ENCODE, &proc);
    hg_proc_bla_write_out_t(proc, &bla_write_out_struct);
    hg_proc_free(proc);

    /* Free handle and send response back */
    ret = HG_Handler_start_response(handle, NULL, 0);
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

    /* Also free memory allocated during decoding */
    hg_proc_create(NULL, 0, HG_FREE, &proc);
    hg_proc_bla_write_in_t(proc, &bla_write_in_struct);
    hg_proc_free(proc);

    first_call = 0;

    return ret;
}

/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    unsigned int i;
    int hg_ret;

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
    MERCURY_HANDLER_REGISTER_CALLBACK("bla_write", fs_bla_write);

    for (i = 0; i < number_of_peers; i++) {
        /* Receive new function calls */
        hg_ret = HG_Handler_process(HG_HANDLER_MAX_IDLE_TIME, HG_STATUS_IGNORE);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
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

    return EXIT_SUCCESS;
}
