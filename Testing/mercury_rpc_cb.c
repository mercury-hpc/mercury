/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

#include "mercury_time.h"
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
#include "mercury_thread_pool.h"
#endif
#include "mercury_atomic.h"

/****************/
/* Local Macros */
/****************/
#define PIPELINE_SIZE 4
#define MIN_BUFFER_SIZE (2 << 15) /* 11 Stop at 4KB buffer size */

#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
#define HG_TEST_ALLOC(size) calloc(size, sizeof(char))
#else
#define HG_TEST_ALLOC(size) malloc(size)
#endif

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
#define HG_TEST_RPC_CB(func_name, handle) \
    static hg_return_t \
    func_name ## _thread_cb(hg_handle_t handle)

/* Assuming func_name_cb is defined, calling HG_TEST_THREAD_CB(func_name)
 * will define func_name_thread and func_name_thread_cb that can be used
 * to execute RPC callback from a thread
 */
#define HG_TEST_THREAD_CB(func_name) \
        static HG_THREAD_RETURN_TYPE \
        func_name ## _thread \
        (void *arg) \
        { \
            hg_handle_t handle = (hg_handle_t) arg; \
            hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0; \
            \
            func_name ## _thread_cb(handle); \
            \
            return thread_ret; \
        } \
        hg_return_t \
        func_name ## _cb(hg_handle_t handle) \
        { \
            hg_return_t ret = HG_SUCCESS; \
            \
            hg_thread_pool_post(hg_test_thread_pool_g, func_name ## _thread, \
                    handle); \
            \
            return ret; \
        }
#else
#define HG_TEST_RPC_CB(func_name, handle) \
    hg_return_t \
    func_name ## _cb(hg_handle_t handle)
#define HG_TEST_THREAD_CB(func_name)
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

#ifdef _WIN32
#  ifndef _SSIZE_T_DEFINED
    typedef SSIZE_T ssize_t;
#  endif
#endif

struct hg_test_bulk_args {
    hg_handle_t handle;
    int fildes;
    size_t nbytes;
    hg_atomic_int32_t completed_transfers;
    ssize_t ret;
};

/*******************/
/* Local Variables */
/*******************/
#ifdef MERCURY_TESTING_HAS_THREAD_POOL
extern hg_thread_pool_t *hg_test_thread_pool_g;
#endif
extern hg_bulk_t hg_test_local_bulk_handle_g;

/*---------------------------------------------------------------------------*/
/* Actual definition of the functions that need to be executed */
/*---------------------------------------------------------------------------*/
static HG_INLINE int
rpc_open(const char *path, rpc_handle_t handle, int *event_id)
{
    printf("Called rpc_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE size_t
bulk_write(int fildes, const void *buf, size_t offset, size_t nbyte, int verbose)
{
#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
    size_t i;
    int error = 0;
    const int *bulk_buf = (const int*) buf;

    if (verbose)
        printf("Executing bulk_write with fildes %d...\n", fildes);

    if (nbyte == 0) {
        fprintf(stderr, "Error detected in bulk transfer, nbyte is zero!\n");
        error = 1;
    }

    if (verbose)
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
    if (!error && verbose) printf("Successfully transfered %lu bytes!\n", nbyte);
#else
    (void) fildes;
    (void) buf;
    (void) offset;
    (void) verbose;
#endif

    return nbyte;
}

///*---------------------------------------------------------------------------*/
//static void
//pipeline_bulk_write(double sleep_time, hg_bulk_request_t bulk_request,
//        hg_status_t *status)
//{
//    int ret;
//    hg_time_t t1, t2;
//    double time_remaining;
//
//    time_remaining = sleep_time;
//
//    /* Force MPI progress for time_remaining ms */
//    if (bulk_request != HG_BULK_REQUEST_NULL) {
//        hg_time_get_current(&t1);
//
//        ret = HG_Bulk_wait(bulk_request, (unsigned int) time_remaining, status);
//        if (ret != HG_SUCCESS) {
//            fprintf(stderr, "Error while waiting\n");
//        }
//
//        hg_time_get_current(&t2);
//        time_remaining -= hg_time_to_double(hg_time_subtract(t2, t1));
//    }
//
//    if (time_remaining > 0) {
//        /* Should use nanosleep or equivalent */
//        hg_time_sleep(hg_time_from_double(time_remaining), NULL);
//    }
//}

/*---------------------------------------------------------------------------*/
/* RPC callbacks */
/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_rpc_open, handle)
{
    hg_return_t ret = HG_SUCCESS;

    rpc_open_in_t  in_struct;
    rpc_open_out_t out_struct;

    hg_const_string_t path;
    rpc_handle_t rpc_handle;
    int event_id;
    int open_ret;

    /* Get input buffer */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    path = in_struct.path;
    rpc_handle = in_struct.handle;

    /* Call rpc_open */
    open_ret = rpc_open(path, rpc_handle, &event_id);

    /* Fill output structure */
    out_struct.event_id = event_id;
    out_struct.ret = open_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);
    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_transfer_cb(const struct hg_bulk_cb_info *hg_bulk_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_bulk_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_bulk_cb_info->local_handle;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_out_t out_struct;

    void *buf;
    size_t write_ret;

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    write_ret = bulk_write(bulk_args->fildes, buf, 0, bulk_args->nbytes, 1);

    /* Fill output structure */
    out_struct.ret = write_ret;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(bulk_args->handle);
    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_bulk_write, handle)
{
    struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t in_struct;

    bulk_args = (struct hg_test_bulk_args *) malloc(
            sizeof(struct hg_test_bulk_args));

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input parameters and data */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bulk_args->fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;

    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);

    /* Create a new block handle to read the data */
    HG_Bulk_create(hg_info->hg_bulk_class, 1, NULL, &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);

    /* Read bulk data here  */
    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_bulk_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, origin_bulk_handle, 0,
            local_bulk_handle, 0, bulk_args->nbytes, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_seg_transfer_cb(const struct hg_bulk_cb_info *hg_bulk_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_bulk_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_bulk_cb_info->local_handle;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_out_t out_struct;

    void *buf;
    size_t write_ret;

    if (hg_atomic_incr32(&bulk_args->completed_transfers) != 2)
        goto done;

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    write_ret = bulk_write(bulk_args->fildes, buf, 0, bulk_args->nbytes, 1);

    /* Fill output structure */
    out_struct.ret = write_ret;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(bulk_args->handle);
    free(bulk_args);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_bulk_seg_write, handle)
{
    struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    size_t nbytes_read;
    ptrdiff_t offset;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t  in_struct;

    bulk_args = (struct hg_test_bulk_args *) malloc(
            sizeof(struct hg_test_bulk_args));

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input parameters and data */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bulk_args->fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;
    hg_atomic_set32(&bulk_args->completed_transfers, 0);

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);

    /* For testing purposes try to read the data in two blocks of different sizes */
    nbytes_read = bulk_args->nbytes / 2 + 16;

    printf("Start reading first chunk of %lu bytes...\n", nbytes_read);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_bulk_class, 1, NULL, &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);

    /* Read bulk data here  */
    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_bulk_seg_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, origin_bulk_handle, 0,
            local_bulk_handle, 0, nbytes_read, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    offset = nbytes_read;
    nbytes_read = bulk_args->nbytes - nbytes_read;

    printf("Start reading second chunk of %lu bytes...\n", nbytes_read);

    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_bulk_seg_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, origin_bulk_handle, offset,
            local_bulk_handle, offset, nbytes_read, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);

    return ret;
}

///*---------------------------------------------------------------------------*/
//HG_TEST_RPC_CB(hg_test_pipeline_write, handle)
//{
//    hg_return_t ret = HG_SUCCESS;
//
//    bulk_write_in_t  bulk_write_in_struct;
//    bulk_write_out_t bulk_write_out_struct;
//
//    na_addr_t source = HG_Handler_get_addr(handle);
//    hg_bulk_t bulk_write_bulk_handle = HG_BULK_NULL;
//    hg_bulk_t bulk_write_bulk_block_handle = HG_BULK_NULL;
//    hg_bulk_request_t bulk_write_bulk_request[PIPELINE_SIZE];
//    int pipeline_iter;
//    size_t pipeline_buffer_size;
//
//    void *bulk_write_buf;
//    size_t bulk_write_nbytes;
//    size_t bulk_write_ret = 0;
//
//    /* For timing */
//    static int first_call = 1; /* Only used for dummy printf */
//    double nmbytes;
//    int avg_iter;
//    double proc_time_read = 0;
//    double raw_read_bandwidth, proc_read_bandwidth;
//    static double raw_time_read = 0;
//
//    if (first_call) printf("# Received new request\n");
//
//    /* Get input parameters and data */
//    ret = HG_Handler_get_input(handle, &bulk_write_in_struct);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not get input\n");
//        return ret;
//    }
//
//    /* Get parameters */
//    /* unused bulk_write_fildes = bulk_write_in_struct.fildes; */
//    bulk_write_bulk_handle = bulk_write_in_struct.bulk_handle;
//
//    /* Create a new block handle to read the data */
//    bulk_write_nbytes = HG_Bulk_handle_get_size(bulk_write_bulk_handle);
//    bulk_write_buf = HG_TEST_ALLOC(bulk_write_nbytes);
//
//    HG_Bulk_handle_create(1, &bulk_write_buf, &bulk_write_nbytes,
//            HG_BULK_READWRITE, &bulk_write_bulk_block_handle);
//
//    /* Timing info */
//    nmbytes = (double) bulk_write_nbytes / (1024 * 1024);
//    if (first_call) printf("# Reading Bulk Data (%f MB)\n", nmbytes);
//
//    /* Work out BW without pipeline and without processing data */
//    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
//        hg_time_t t1, t2;
//
//        hg_time_get_current(&t1);
//
//        ret = HG_Bulk_transfer(HG_BULK_PULL, source, bulk_write_bulk_handle, 0,
//                bulk_write_bulk_block_handle, 0, bulk_write_nbytes,
//                &bulk_write_bulk_request[0]);
//        if (ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not read bulk data\n");
//            return ret;
//        }
//
//        ret = HG_Bulk_wait(bulk_write_bulk_request[0],
//                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
//        if (ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not complete bulk data read\n");
//            return ret;
//        }
//
//        hg_time_get_current(&t2);
//
//        raw_time_read += hg_time_to_double(hg_time_subtract(t2, t1));
//    }
//
//    raw_time_read = raw_time_read / MERCURY_TESTING_MAX_LOOP;
//    raw_read_bandwidth = nmbytes / raw_time_read;
//    if (first_call) printf("# Raw read time: %f s (%.*f MB/s)\n", raw_time_read, 2, raw_read_bandwidth);
//
//    /* Work out BW without pipeline and with processing data */
//    for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
//        hg_time_t t1, t2;
//
//        hg_time_get_current(&t1);
//
//        ret = HG_Bulk_transfer(HG_BULK_PULL, source, bulk_write_bulk_handle, 0,
//                bulk_write_bulk_block_handle, 0, bulk_write_nbytes,
//                &bulk_write_bulk_request[0]);
//        if (ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not read bulk data\n");
//            return ret;
//        }
//
//        ret = HG_Bulk_wait(bulk_write_bulk_request[0],
//                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
//        if (ret != HG_SUCCESS) {
//            fprintf(stderr, "Could not complete bulk data read\n");
//            return ret;
//        }
//
//        /* Call bulk_write */
//        pipeline_bulk_write(0, HG_BULK_REQUEST_NULL, HG_STATUS_IGNORE);
//
//        hg_time_get_current(&t2);
//
//        proc_time_read += hg_time_to_double(hg_time_subtract(t2, t1));
//    }
//
//    proc_time_read = proc_time_read / MERCURY_TESTING_MAX_LOOP;
//    proc_read_bandwidth = nmbytes / proc_time_read;
//    if (first_call) printf("# Proc read time: %f s (%.*f MB/s)\n", proc_time_read, 2, proc_read_bandwidth);
//
//    if (first_call) printf("%-*s%*s%*s%*s%*s%*s%*s", 12, "# Size (kB) ",
//            10, "Time (s)", 10, "Min (s)", 10, "Max (s)",
//            12, "BW (MB/s)", 12, "Min (MB/s)", 12, "Max (MB/s)");
//    if (first_call) printf("\n");
//
//    if (!PIPELINE_SIZE) fprintf(stderr, "PIPELINE_SIZE must be > 0!\n");
//
//    for (pipeline_buffer_size = bulk_write_nbytes / PIPELINE_SIZE;
//            pipeline_buffer_size > MIN_BUFFER_SIZE;
//            pipeline_buffer_size /= 2) {
//        double time_read = 0, min_time_read = 0, max_time_read = 0;
//        double read_bandwidth, min_read_bandwidth, max_read_bandwidth;
//
//        for (avg_iter = 0; avg_iter < MERCURY_TESTING_MAX_LOOP; avg_iter++) {
//            size_t start_offset = 0;
//            size_t total_bytes_read = 0;
//            size_t chunk_size;
//
//            hg_time_t t1, t2;
//            double td;
//            double sleep_time;
//
//            chunk_size = (PIPELINE_SIZE == 1) ? bulk_write_nbytes : pipeline_buffer_size;
//            sleep_time = chunk_size * raw_time_read / bulk_write_nbytes;
//
//            hg_time_get_current(&t1);
//
//            /* Initialize pipeline */
//            for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
//                size_t write_offset = start_offset + pipeline_iter * chunk_size;
//
//                ret = HG_Bulk_transfer(HG_BULK_PULL, source,
//                        bulk_write_bulk_handle, write_offset,
//                        bulk_write_bulk_block_handle, write_offset, chunk_size,
//                        &bulk_write_bulk_request[pipeline_iter]);
//                if (ret != HG_SUCCESS) {
//                    fprintf(stderr, "Could not read bulk data\n");
//                    return ret;
//                }
//            }
//
//            while (total_bytes_read != bulk_write_nbytes) {
//                /* Alternate wait and read to receives pieces */
//                for (pipeline_iter = 0; pipeline_iter < PIPELINE_SIZE; pipeline_iter++) {
//                    size_t write_offset = start_offset + pipeline_iter * chunk_size;
//                    hg_status_t status;
//                    int pipeline_next;
//
//                    if (bulk_write_bulk_request[pipeline_iter] != HG_BULK_REQUEST_NULL) {
//                        ret = HG_Bulk_wait(bulk_write_bulk_request[pipeline_iter],
//                                HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);
//                        if (ret != HG_SUCCESS) {
//                            fprintf(stderr, "Could not complete bulk data read\n");
//                            return ret;
//                        }
//                        bulk_write_bulk_request[pipeline_iter] = HG_BULK_REQUEST_NULL;
//                    }
//                    total_bytes_read += chunk_size;
//                    /* printf("total_bytes_read: %lu\n", total_bytes_read); */
//
//                    /* Call bulk_write */
//                    pipeline_next = (pipeline_iter < PIPELINE_SIZE - 1) ?
//                            pipeline_iter + 1 : 0;
//
//                    pipeline_bulk_write(sleep_time,
//                            bulk_write_bulk_request[pipeline_next], &status);
//
//                    if (status) bulk_write_bulk_request[pipeline_next] = HG_BULK_REQUEST_NULL;
//
//                    /* Start another read (which is PIPELINE_SIZE far) */
//                    write_offset += chunk_size * PIPELINE_SIZE;
//                    if (write_offset < bulk_write_nbytes) {
//                        ret = HG_Bulk_transfer(HG_BULK_PULL, source,
//                                bulk_write_bulk_handle, write_offset,
//                                bulk_write_bulk_block_handle, write_offset,
//                                chunk_size,
//                                &bulk_write_bulk_request[pipeline_iter]);
//                        if (ret != HG_SUCCESS) {
//                            fprintf(stderr, "Could not read bulk data\n");
//                            return ret;
//                        }
//                    }
//                    /* TODO should also check remaining data */
//                }
//                start_offset += chunk_size * PIPELINE_SIZE;
//            }
//
//            hg_time_get_current(&t2);
//
//            td = hg_time_to_double(hg_time_subtract(t2, t1));
//
//            time_read += td;
//            if (!min_time_read) min_time_read = time_read;
//            min_time_read = (td < min_time_read) ? td : min_time_read;
//            max_time_read = (td > max_time_read) ? td : max_time_read;
//        }
//
//        time_read = time_read / MERCURY_TESTING_MAX_LOOP;
//        read_bandwidth = nmbytes / time_read;
//        min_read_bandwidth = nmbytes / max_time_read;
//        max_read_bandwidth = nmbytes / min_time_read;
//
//        /* At this point we have received everything so work out the bandwidth */
//        printf("%-*d%*f%*f%*f%*.*f%*.*f%*.*f\n", 12, (int) pipeline_buffer_size / 1024,
//                10, time_read, 10, min_time_read, 10, max_time_read,
//                12, 2, read_bandwidth, 12, 2, min_read_bandwidth, 12, 2, max_read_bandwidth);
//
//        /* Check data */
//        bulk_write_ret = bulk_write(1, bulk_write_buf, 0, bulk_write_nbytes, 0);
//    }
//
//    /* Fill output structure */
//    bulk_write_out_struct.ret = bulk_write_ret;
//
//    /* Send response back */
//    ret = HG_Handler_start_output(handle, &bulk_write_out_struct);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not respond\n");
//        return ret;
//    }
//
//    /* Free block handle */
//    ret = HG_Bulk_handle_free(bulk_write_bulk_block_handle);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not free block call\n");
//        return ret;
//    }
//
//    free(bulk_write_buf);
//
//    first_call = 0;
//
//    HG_Handler_free_input(handle, &bulk_write_in_struct);
//    HG_Handler_free(handle);
//
//    return ret;
//}

/*---------------------------------------------------------------------------*/
#ifndef _WIN32
HG_TEST_RPC_CB(hg_test_posix_open, handle)
{
    hg_return_t ret = HG_SUCCESS;

    open_in_t in_struct;
    open_out_t out_struct;

    const char *path;
    int flags;
    mode_t mode;
    int open_ret;

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    path = in_struct.path;
    flags = in_struct.flags;
    mode = in_struct.mode;

    /* Call open */
    printf("Calling open with path: %s\n", path);
    open_ret = open(path, flags, mode);

    /* Fill output structure */
    out_struct.ret = open_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);
    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_posix_close, handle)
{
    hg_return_t ret = HG_SUCCESS;

    close_in_t in_struct;
    close_out_t out_struct;

    int fd;
    int close_ret;

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    fd = in_struct.fd;

    /* Call close */
    printf("Calling close with fd: %d\n", fd);
    close_ret = close(fd);

    /* Fill output structure */
    out_struct.ret = close_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);
    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_posix_write_transfer_cb(const struct hg_bulk_cb_info *hg_bulk_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_bulk_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_bulk_cb_info->local_handle;
    hg_return_t ret = HG_SUCCESS;

    write_out_t out_struct;

    void *buf;
    ssize_t write_ret;

    /* for debug */
    int i;
    const int *buf_ptr;

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    /* Check bulk buf */
    buf_ptr = (const int*) buf;
    for (i = 0; i < (int)(bulk_args->nbytes / sizeof(int)); i++) {
        if (buf_ptr[i] != i) {
            printf("Error detected in bulk transfer, buf[%d] = %d, was expecting %d!\n", i, buf_ptr[i], i);
            break;
        }
    }

    printf("Calling write with fd: %d\n", bulk_args->fildes);
    write_ret = write(bulk_args->fildes, buf, bulk_args->nbytes);

    /* Fill output structure */
    out_struct.ret = write_ret;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(bulk_args->handle);
    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_posix_write, handle)
{
    hg_return_t ret = HG_SUCCESS;

    write_in_t in_struct;

    struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;

    bulk_args = (struct hg_test_bulk_args *) malloc(
            sizeof(struct hg_test_bulk_args));

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    bulk_args->fildes = in_struct.fd;
    origin_bulk_handle = in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_bulk_class, 1, NULL, &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);

    /* Read bulk data here  */
    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_posix_write_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, origin_bulk_handle, 0,
            local_bulk_handle, 0, bulk_args->nbytes, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_posix_read_transfer_cb(const struct hg_bulk_cb_info *hg_bulk_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_bulk_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_bulk_cb_info->local_handle;
    hg_return_t ret = HG_SUCCESS;

    write_out_t out_struct;

    /* Fill output structure */
    out_struct.ret = bulk_args->ret;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(bulk_args->handle);
    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_posix_read, handle)
{
    hg_return_t ret = HG_SUCCESS;

    read_in_t in_struct;

    struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;

    void *buf;
    ssize_t read_ret;

    /* for debug */
    int i;
    const int *buf_ptr;

    bulk_args = (struct hg_test_bulk_args *) malloc(
            sizeof(struct hg_test_bulk_args));

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    bulk_args->fildes = in_struct.fd;
    origin_bulk_handle = in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_bulk_class, 1, NULL, &bulk_args->nbytes,
            HG_BULK_READ_ONLY, &local_bulk_handle);

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    printf("Calling read with fd: %d\n", bulk_args->fildes);
    read_ret = read(bulk_args->fildes, buf, bulk_args->nbytes);

    /* Check bulk buf */
    buf_ptr = (const int*) buf;
    for (i = 0; i < (int)(bulk_args->nbytes / sizeof(int)); i++) {
        if (buf_ptr[i] != i) {
            printf("Error detected after read, buf[%d] = %d, was expecting %d!\n", i, buf_ptr[i], i);
            break;
        }
    }

    /* Fill output structure */
    bulk_args->ret = read_ret;

    /* Read bulk data here  */
    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_posix_read_transfer_cb,
            bulk_args, HG_BULK_PUSH, hg_info->addr, origin_bulk_handle, 0,
            local_bulk_handle, 0, bulk_args->nbytes, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);

    return ret;
}
#endif /* _WIN32 */

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_rpc, handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_perf_bulk_transfer_cb(const struct hg_bulk_cb_info *hg_bulk_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_bulk_cb_info->arg;
    hg_return_t ret = HG_SUCCESS;

#ifdef MERCURY_TESTING_USE_LOCAL_BULK
    /* Free block handle */
    ret = HG_Bulk_free(hg_bulk_cb_info->local_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        goto done;
    }
#endif

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        goto done;
    }

    HG_Destroy(bulk_args->handle);
    free(bulk_args);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_bulk, handle)
{
    hg_return_t ret = HG_SUCCESS;

    bulk_write_in_t  in_struct;

    struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;

    bulk_args = (struct hg_test_bulk_args *) malloc(
            sizeof(struct hg_test_bulk_args));

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    bulk_args->fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;
    hg_atomic_set32(&bulk_args->completed_transfers, 0);

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);

#ifdef MERCURY_TESTING_USE_LOCAL_BULK
    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_bulk_class, 1, NULL, &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);
#else
    local_bulk_handle = hg_test_local_bulk_handle_g;
#endif

    /* Read bulk data here  */
    ret = HG_Bulk_transfer(hg_info->bulk_context, hg_test_perf_bulk_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, origin_bulk_handle, 0,
            local_bulk_handle, 0, bulk_args->nbytes, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_overflow, handle)
{
    hg_return_t ret = HG_SUCCESS;

    overflow_out_t out_struct;

    hg_string_t string;
    size_t string_len = 1024 * 4;

    string = (hg_string_t) malloc(string_len + 1);
    memset(string, 'h', string_len);
    string[string_len] = '\0';

    /* Fill output structure */
    out_struct.string = string;
    out_struct.string_len = string_len;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(handle);
    free(string);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_THREAD_CB(hg_test_rpc_open)
HG_TEST_THREAD_CB(hg_test_bulk_write)
HG_TEST_THREAD_CB(hg_test_bulk_seg_write)
//HG_TEST_THREAD_CB(hg_test_pipeline_write)
#ifndef _WIN32
HG_TEST_THREAD_CB(hg_test_posix_open)
HG_TEST_THREAD_CB(hg_test_posix_close)
HG_TEST_THREAD_CB(hg_test_posix_write)
HG_TEST_THREAD_CB(hg_test_posix_read)
#endif
HG_TEST_THREAD_CB(hg_test_perf_rpc)
HG_TEST_THREAD_CB(hg_test_perf_bulk)
HG_TEST_THREAD_CB(hg_test_overflow)

/*---------------------------------------------------------------------------*/
