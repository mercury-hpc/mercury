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

#define AVERAGE 1
#define PIPELINE_SIZE 8
#define PIPELINE_BUFFER_SIZE 4096

static unsigned int number_of_peers;

/* Actual definition of the function that needs to be executed */
void bla_write_pipeline(size_t chunk_size)
{
    /* We will wait 1s per MB */
    float msleep_time = chunk_size * 1000 / (1024 * 1024);
    /* printf("# Now sleeping %f ms\n", msleep_time); */
    /* usleep(msleep_time * 1000); */
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

    void *bla_write_buf;
    size_t bla_write_nbytes;
    int bla_write_ret;

    /* For timing */
    static int first_call = 1; /* Only used for dummy printf */
    int avg_iter;
    double nmbytes;
    struct timeval tv1, tv2;
    double td1, td2;
    double time_read = 0;
    double read_bandwidth;

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
    if (first_call) printf("%-*s%*s", 10, "# NumProcs", 20, "Bandwidth (MB/s)\n");

    if (!PIPELINE_SIZE) fprintf(stderr, "PIPELINE_SIZE must be > 0!\n");

    for (avg_iter = 0; avg_iter < AVERAGE; avg_iter++) {
        size_t start_offset = 0;
        size_t total_bytes_read = 0;

        gettimeofday(&tv1, NULL);

        /* Initialize pipeline */
        for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
            size_t write_offset = start_offset + pipeline_iter * PIPELINE_BUFFER_SIZE;

            ret = HG_Bulk_read(source, bla_write_bulk_handle, write_offset,
                    bla_write_bulk_block_handle, write_offset, PIPELINE_BUFFER_SIZE,
                    &bla_write_bulk_request[pipeline_iter]);
            if (ret != HG_SUCCESS) {
                fprintf(stderr, "Could not read bulk data\n");
                return ret;
            }
        }

        while (total_bytes_read != bla_write_nbytes) {
            /* Alternate wait and read to receives pieces */
            for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
                size_t write_offset = start_offset + pipeline_iter * PIPELINE_BUFFER_SIZE;

                ret = HG_Bulk_wait(bla_write_bulk_request[pipeline_iter],
                        HG_BULK_MAX_IDLE_TIME, HG_BULK_STATUS_IGNORE);
                if (ret != HG_SUCCESS) {
                    fprintf(stderr, "Could not complete bulk data read\n");
                    return ret;
                }
                total_bytes_read += PIPELINE_BUFFER_SIZE;

                /* Call bla_write */
                bla_write_pipeline(PIPELINE_BUFFER_SIZE);

                /* Start another read (which is PIPELINE_SIZE far) */
                write_offset += PIPELINE_BUFFER_SIZE * PIPELINE_SIZE;
                if (write_offset < bla_write_nbytes) {
                    ret = HG_Bulk_read(source, bla_write_bulk_handle, write_offset,
                            bla_write_bulk_block_handle, write_offset, PIPELINE_BUFFER_SIZE,
                            &bla_write_bulk_request[pipeline_iter]);
                    if (ret != HG_SUCCESS) {
                        fprintf(stderr, "Could not read bulk data\n");
                        return ret;
                    }
                }
                /* TODO should also check remaining data */
            }
            start_offset += PIPELINE_BUFFER_SIZE * PIPELINE_SIZE;
        }

        gettimeofday(&tv2, NULL);

        td1 = tv1.tv_sec + tv1.tv_usec / 1000000.0;
        td2 = tv2.tv_sec + tv2.tv_usec / 1000000.0;

        time_read += td2 - td1;
    }

    time_read = time_read / AVERAGE;
    read_bandwidth = nmbytes / time_read;

    /* At this point we have received everything so work out the bandwidth */
    printf("%-*d%*.*f\n", 10, number_of_peers, 20, 2, read_bandwidth);

    /* Check data */
    bla_write_ret = bla_write_check(bla_write_buf, bla_write_nbytes);

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
