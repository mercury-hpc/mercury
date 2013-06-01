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
#include "mercury_handler.h"
#include "mercury_bulk.h"
#include "mercury_thread.h"
#include "mercury_thread_mutex.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#define SPAWN_REQUEST_THREAD /* want to spawn threads */
#define FORCE_MPI_PROGRESS /* want to have mpi progress */
//#define FORCE_PIPELINE_SLEEP /* don't want the sleep */

static bool finalizing = 0;

static double raw_time_read = 0;
static size_t bla_write_nbytes;

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

#ifdef FORCE_MPI_PROGRESS
    /* Force MPI progress for time_remaining ms */
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
#endif

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
int server_finalize(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

    finalizing = 1;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

int bla_write_rpc(hg_handle_t handle)
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
    size_t start_offset = 0;
    size_t total_bytes_read = 0;
    size_t chunk_size;

    void *bla_write_buf;
    int bla_write_ret = 0;

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
    pipeline_buffer_size = bla_write_in_struct.pipeline_buffer_size;
    bla_write_bulk_handle = bla_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bla_write_nbytes = HG_Bulk_handle_get_size(bla_write_bulk_handle);
    bla_write_buf = malloc(bla_write_nbytes);

    HG_Bulk_block_handle_create(bla_write_buf, bla_write_nbytes, HG_BULK_READWRITE,
            &bla_write_bulk_block_handle);

    chunk_size = (PIPELINE_SIZE == 1) ? bla_write_nbytes : pipeline_buffer_size;

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

    /* Check data */
    //bla_write_ret = bla_write_check(bla_write_buf, bla_write_nbytes);
    bla_write_ret = bla_write_nbytes;

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

    return ret;
}

/* Thread to handle request */
void *bla_write_rpc_thread(void *arg)
{
    hg_handle_t handle = (hg_handle_t) arg;
    bla_write_rpc(handle);

    return NULL;
}

int bla_write_rpc_spawn(hg_handle_t handle)
{
    int ret = HG_SUCCESS;

#ifdef SPAWN_REQUEST_THREAD
    hg_thread_t thread;
    hg_thread_create(&thread, bla_write_rpc_thread, handle);
#else
    bla_write_rpc_thread(handle);
#endif

    return ret;
}


/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    int hg_ret;
    unsigned int cmake_number_of_peers;

    /* Used by Test Driver */
    printf("# Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, &cmake_number_of_peers);

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
    MERCURY_HANDLER_REGISTER_CALLBACK("bla_write", bla_write_rpc_spawn);
    MERCURY_HANDLER_REGISTER_FINALIZE(server_finalize);

    while (!finalizing) {
        hg_status_t status;

        /* Receive new function calls */
        hg_ret = HG_Handler_process(1, &status);
        if (hg_ret == HG_SUCCESS && status) {
            /* printf("# Request processed\n"); */
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
