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

#define HG_TEST_CORESIDENT

/*---------------------------------------------------------------------------*/
/* Actual definition of the functions that need to be executed */
/*---------------------------------------------------------------------------*/
static
int rpc_open(const char *path, rpc_handle_t handle, int *event_id)
{
    printf("Called rpc_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
size_t
bulk_write(int fildes, const void *buf, size_t offset, size_t nbyte)
{
    size_t i;
    int error = 0;
    const int *bulk_buf = (const int*) buf;

    printf("Executing bulk_write with fildes %d...\n", fildes);

    if (nbyte == 0) {
        HG_ERROR_DEFAULT("Error detected in bulk transfer, nbyte is zero!\n");
        error = 1;
    }

    printf("Checking data...\n");

    /* Check bulk buf */
    for (i = 0; i < (nbyte / sizeof(int)); i++) {
        if (bulk_buf[i] != (int) (i + offset)) {
            printf("Error detected in bulk transfer, bulk_buf[%lu] = %d, "
                    "was expecting %d!\n", i, bulk_buf[i], (int) (i + offset));
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully transfered %lu bytes!\n", nbyte);

    return nbyte;
}

/*---------------------------------------------------------------------------*/
/* RPC callbacks */
/*---------------------------------------------------------------------------*/
hg_return_t
rpc_open_cb(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    rpc_open_in_t  rpc_open_in_struct;
    rpc_open_out_t rpc_open_out_struct;

    hg_const_string_t rpc_open_path;
    rpc_handle_t rpc_open_handle;
    int rpc_open_event_id;
    int rpc_open_ret;

    /* Get input buffer */
    ret = HG_Handler_get_input(handle, &rpc_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    rpc_open_path = rpc_open_in_struct.path;
    rpc_open_handle = rpc_open_in_struct.handle;

    /* Call rpc_open */
    rpc_open_ret = rpc_open(rpc_open_path, rpc_open_handle, &rpc_open_event_id);

    /* Fill output structure */
    rpc_open_out_struct.event_id = rpc_open_event_id;
    rpc_open_out_struct.ret = rpc_open_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &rpc_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Handler_free_input(handle, &rpc_open_in_struct);
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
bulk_write_cb(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t  bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bulk_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_t bulk_write_bulk_block_handle = HG_BULK_NULL;
    hg_bulk_request_t bulk_write_bulk_request;

    int bulk_write_fildes;
    hg_bulk_segment_t bulk_write_segment;
    size_t bulk_write_nbytes;
    size_t bulk_write_ret;

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bulk_write_fildes = bulk_write_in_struct.fildes;
    bulk_write_bulk_handle = bulk_write_in_struct.bulk_handle;

    bulk_write_nbytes = HG_Bulk_handle_get_size(bulk_write_bulk_handle);

#ifdef HG_TEST_CORESIDENT
    /* When using mirror API, data is not copied when running in coresident mode
     * (i.e., addr is self) */
    ret = HG_Bulk_mirror(source, bulk_write_bulk_handle, 0, bulk_write_nbytes,
            &bulk_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create mirror handle\n");
        return ret;
    }
    ret = HG_Bulk_sync(bulk_write_bulk_block_handle, HG_BULK_READ,
            &bulk_write_bulk_request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not sync mirror\n");
        return ret;
    }
#else
    /* Create a new block handle to read the data */
    bulk_write_segment.address = (hg_ptr_t) malloc(bulk_write_nbytes);
    bulk_write_segment.size = bulk_write_nbytes;

    HG_Bulk_handle_create((void *) bulk_write_segment.address,
            bulk_write_segment.size, HG_BULK_READWRITE,
            &bulk_write_bulk_block_handle);

    /* Read bulk data here and wait for the data to be here  */
    ret = HG_Bulk_read_all(source, bulk_write_bulk_handle,
            bulk_write_bulk_block_handle, &bulk_write_bulk_request);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }
#endif

    ret = HG_Bulk_wait(bulk_write_bulk_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

#ifdef HG_TEST_CORESIDENT
    ret = HG_Bulk_handle_access(bulk_write_bulk_block_handle, 0,
            bulk_write_nbytes, HG_BULK_READWRITE, 1, &bulk_write_segment, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not access handle\n");
        return ret;
    }
#endif

    /* Call bulk_write */
    bulk_write_ret = bulk_write(bulk_write_fildes,
            (const void *) bulk_write_segment.address, 0,
            bulk_write_segment.size);

    /* Fill output structure */
    bulk_write_out_struct.ret = bulk_write_ret;

    /* Free block handle */
    ret = HG_Bulk_handle_free(bulk_write_bulk_block_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

#ifndef HG_TEST_CORESIDENT
    free((void *) bulk_write_segment.address);
#endif

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Handler_free_input(handle, &bulk_write_in_struct);
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
bulk_seg_write(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t  bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bulk_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_t bulk_write_bulk_block_handle1 = HG_BULK_NULL;
    hg_bulk_t bulk_write_bulk_block_handle2 = HG_BULK_NULL;
    size_t bulk_write_nbytes_read;
    ptrdiff_t bulk_write_offset;
    hg_bulk_request_t bulk_write_bulk_request1;
    hg_bulk_request_t bulk_write_bulk_request2;

    int bulk_write_fildes;
#ifdef HG_TEST_CORESIDENT
    hg_bulk_segment_t bulk_write_segment;
#else
    void *bulk_write_buf;
#endif
    size_t bulk_write_nbytes;
    int bulk_write_ret = 0;

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bulk_write_fildes = bulk_write_in_struct.fildes;
    bulk_write_bulk_handle = bulk_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_write_nbytes = HG_Bulk_handle_get_size(bulk_write_bulk_handle);

    /* For testing purposes try to read the data in two blocks of different sizes */
    bulk_write_nbytes_read = bulk_write_nbytes / 2 + 16;

    printf("Start reading first chunk of %lu bytes...\n", bulk_write_nbytes_read);

#ifdef HG_TEST_CORESIDENT
    /* When using mirror API, data is not copied when running in coresident mode
     * (i.e., addr is self) */
    ret = HG_Bulk_mirror(source, bulk_write_bulk_handle, 0, bulk_write_nbytes_read,
            &bulk_write_bulk_block_handle1);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create mirror handle\n");
        return ret;
    }
    ret = HG_Bulk_sync(bulk_write_bulk_block_handle1, HG_BULK_READ,
            &bulk_write_bulk_request1);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not sync mirror\n");
        return ret;
    }
#else
    bulk_write_buf = malloc(bulk_write_nbytes);

    HG_Bulk_handle_create(bulk_write_buf, bulk_write_nbytes, HG_BULK_READWRITE,
            &bulk_write_bulk_block_handle1);

    ret = HG_Bulk_read(source, bulk_write_bulk_handle, 0,
            bulk_write_bulk_block_handle1, 0, bulk_write_nbytes_read, &bulk_write_bulk_request1);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }
#endif

    bulk_write_offset = bulk_write_nbytes_read;
    bulk_write_nbytes_read = bulk_write_nbytes - bulk_write_nbytes_read;

    printf("Start reading second chunk of %lu bytes...\n", bulk_write_nbytes_read);

#ifdef HG_TEST_CORESIDENT
    /* When using mirror API, data is not copied when running in coresident mode
     * (i.e., addr is self) */
    ret = HG_Bulk_mirror(source, bulk_write_bulk_handle, bulk_write_offset,
            bulk_write_nbytes_read, &bulk_write_bulk_block_handle2);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create mirror handle\n");
        return ret;
    }
    ret = HG_Bulk_sync(bulk_write_bulk_block_handle2, HG_BULK_READ,
            &bulk_write_bulk_request2);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not sync mirror\n");
        return ret;
    }
#else
    ret = HG_Bulk_read(source, bulk_write_bulk_handle, bulk_write_offset,
            bulk_write_bulk_block_handle1, bulk_write_offset,
            bulk_write_nbytes_read, &bulk_write_bulk_request2);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }
#endif

    printf("Waiting for first chunk...\n");
    ret = HG_Bulk_wait(bulk_write_bulk_request1, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    printf("Waiting for second chunk...\n");
    ret = HG_Bulk_wait(bulk_write_bulk_request2, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return ret;
    }

    /* Call bulk_write */
#ifdef HG_TEST_CORESIDENT
    /* Continue until we get all the segments */
    while ((size_t) bulk_write_ret != HG_Bulk_handle_get_size(bulk_write_bulk_block_handle1)) {
        size_t offset = bulk_write_ret;

        ret = HG_Bulk_handle_access(bulk_write_bulk_block_handle1, offset,
                bulk_write_nbytes, HG_BULK_READWRITE, 1, &bulk_write_segment, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not access handle\n");
            return ret;
        }

        bulk_write_ret += bulk_write(bulk_write_fildes,
                (const void *) bulk_write_segment.address,
                bulk_write_ret / sizeof(int),
                bulk_write_segment.size);
    }

    /* Continue until we get all the segments */
    while ((size_t) bulk_write_ret != bulk_write_nbytes) {
        size_t offset = bulk_write_ret - bulk_write_offset;

        ret = HG_Bulk_handle_access(bulk_write_bulk_block_handle2, offset,
                bulk_write_nbytes, HG_BULK_READWRITE, 1, &bulk_write_segment, NULL);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not access handle\n");
            return ret;
        }

        bulk_write_ret += bulk_write(bulk_write_fildes,
                (const void *) bulk_write_segment.address,
                bulk_write_ret / sizeof(int),
                bulk_write_segment.size);
    }
#else
    bulk_write_ret = bulk_write(bulk_write_fildes, bulk_write_buf, 0,
            bulk_write_nbytes);
#endif

    /* Fill output structure */
    bulk_write_out_struct.ret = bulk_write_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Free block handle */
    ret = HG_Bulk_handle_free(bulk_write_bulk_block_handle1);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }
    ret = HG_Bulk_handle_free(bulk_write_bulk_block_handle2);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return ret;
    }

#ifndef HG_TEST_CORESIDENT
    free(bulk_write_buf);
#endif

    printf("\n");

    HG_Handler_free_input(handle, &bulk_write_in_struct);
    return ret;
}

/*---------------------------------------------------------------------------*/

#define PIPELINE_SIZE 4
#define MIN_BUFFER_SIZE (2 << 11) /* Stop at 4KB buffer size */

static hg_return_t
bulk_write_rpc(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t  bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;

    na_addr_t source = HG_Handler_get_addr(handle);
    hg_bulk_t bulk_write_bulk_handle = HG_BULK_NULL;
    hg_bulk_t bulk_write_bulk_block_handle[PIPELINE_SIZE];
    hg_bulk_request_t bulk_write_bulk_request[PIPELINE_SIZE];
    size_t bulk_write_nbytes;
    int pipeline_iter;
    size_t pipeline_buffer_size;
    size_t start_offset = 0;
    size_t total_bytes_read = 0;
    size_t chunk_size;

    void *bulk_write_buf[PIPELINE_SIZE];
    size_t bulk_write_ret = 0;

    /* Get input parameters and data */
    ret = HG_Handler_get_input(handle, &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    /* unused bulk_write_fildes = bulk_write_in_struct.fildes; */
    pipeline_buffer_size = bulk_write_in_struct.pipeline_buffer_size;
    bulk_write_bulk_handle = bulk_write_in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_write_nbytes = HG_Bulk_handle_get_size(bulk_write_bulk_handle);
    chunk_size = (PIPELINE_SIZE == 1) ? bulk_write_nbytes : pipeline_buffer_size;

    for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
        bulk_write_buf[pipeline_iter] = malloc(pipeline_buffer_size);
        HG_Bulk_handle_create(bulk_write_buf[pipeline_iter],
                pipeline_buffer_size, HG_BULK_READWRITE,
                &bulk_write_bulk_block_handle[pipeline_iter]);
    }

    /* Initialize pipeline */
    for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
        size_t write_offset = start_offset + pipeline_iter * chunk_size;

        ret = HG_Bulk_read(source, bulk_write_bulk_handle, write_offset,
                bulk_write_bulk_block_handle[pipeline_iter], 0, chunk_size,
                &bulk_write_bulk_request[pipeline_iter]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not read bulk data\n");
            return ret;
        }
    }

    while (total_bytes_read != bulk_write_nbytes) {
        /* Alternate wait and read to receives pieces */
        for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
            size_t write_offset = start_offset + pipeline_iter * chunk_size;
            hg_status_t status = 0;
            int pipeline_next;

            if (bulk_write_bulk_request[pipeline_iter] != HG_BULK_REQUEST_NULL) {
                ret = HG_Bulk_wait(bulk_write_bulk_request[pipeline_iter],
                        HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
                if (ret != HG_SUCCESS) {
                    fprintf(stderr, "Could not complete bulk data read\n");
                    return ret;
                }
                bulk_write_bulk_request[pipeline_iter] = HG_BULK_REQUEST_NULL;
            }
            total_bytes_read += chunk_size;
            /* printf("total_bytes_read: %lu\n", total_bytes_read); */

            /* Call bulk_write */
            pipeline_next = (pipeline_iter < PIPELINE_SIZE - 1) ?
                    pipeline_iter + 1 : 0;
            bulk_write_progress(bulk_write_bulk_request[pipeline_next], &status);
            if (status) bulk_write_bulk_request[pipeline_next] =
                    HG_BULK_REQUEST_NULL;

            /* Start another read (which is PIPELINE_SIZE far) */
            write_offset += chunk_size * PIPELINE_SIZE;
            if (write_offset < bulk_write_nbytes) {
                ret = HG_Bulk_read(source, bulk_write_bulk_handle, write_offset,
                        bulk_write_bulk_block_handle[pipeline_iter], 0, chunk_size,
                        &bulk_write_bulk_request[pipeline_iter]);
                if (ret != HG_SUCCESS) {
                    fprintf(stderr, "Could not read bulk data\n");
                    return ret;
                }
            }
            /* TODO should also check remaining data */
        }
        start_offset += chunk_size * PIPELINE_SIZE;
    }

    /* Do not check data as we measure on the client */
    /* bulk_write_ret = bulk_write_check(bulk_write_buf, bulk_write_nbytes); */
    bulk_write_ret = bulk_write_nbytes;

    /* Fill output structure */
    bulk_write_out_struct.ret = bulk_write_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start response\n");
        return ret;
    }

    /* Free block handles */
    for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
        ret = HG_Bulk_handle_free(bulk_write_bulk_block_handle[pipeline_iter]);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free block call\n");
            return ret;
        }

        free(bulk_write_buf[pipeline_iter]);
    }

    return ret;
}
