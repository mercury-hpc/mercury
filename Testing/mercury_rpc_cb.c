/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
#include "mercury_thread_mutex.h"
#include "mercury_rpc_cb.h"

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
extern struct hg_thread_work *
hg_core_get_thread_work(
        hg_handle_t handle
        );

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
            struct hg_test_info *hg_test_info = \
                (struct hg_test_info *) HG_Class_get_data( \
                    HG_Get_info(handle)->hg_class); \
            struct hg_thread_work *work = hg_core_get_thread_work(handle); \
            hg_return_t ret = HG_SUCCESS; \
            \
            work->func = func_name ## _thread; \
            work->args = handle; \
            hg_thread_pool_post(hg_test_info->thread_pool, work); \
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
    size_t nbytes;
    hg_atomic_int32_t completed_transfers;
    ssize_t ret;
    int fildes;
};

/********************/
/* Local Prototypes */
/********************/
static hg_return_t
hg_test_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_bulk_seg_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_posix_write_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_posix_read_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_perf_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info);

/*******************/
/* Local Variables */
/*******************/

//extern hg_id_t hg_test_nested2_id_g;
//hg_addr_t *hg_addr_table;

/*---------------------------------------------------------------------------*/
/* Actual definition of the functions that need to be executed */
/*---------------------------------------------------------------------------*/
static HG_INLINE int
rpc_open(const char *path, rpc_handle_t handle, int *event_id)
{
    printf("Called rpc_open of %s with cookie %lu\n", path,
        (unsigned long) handle.cookie);
    *event_id = (int) handle.cookie;
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

    /* Free input */
    HG_Free_input(handle, &in_struct);

    /* Fill output structure */
    out_struct.event_id = event_id;
    out_struct.ret = open_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_rpc_open_no_resp, handle)
{
    hg_return_t ret = HG_SUCCESS;
    rpc_open_in_t  in_struct;
    hg_const_string_t path;
    rpc_handle_t rpc_handle;
    int event_id;

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
    rpc_open(path, rpc_handle, &event_id);

    HG_Free_input(handle, &in_struct);
    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_bulk_write, handle)
{
    const struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    bulk_write_in_t in_struct;
    hg_return_t ret = HG_SUCCESS;
    int fildes;

    hg_op_id_t hg_bulk_op_id;

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
    fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;

    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->fildes = fildes;

    /* Free input */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* Create a new block handle to read the data */
    HG_Bulk_create(hg_info->hg_class, 1, NULL, (hg_size_t *) &bulk_args->nbytes,
        HG_BULK_READWRITE, &local_bulk_handle);

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_bulk_transfer_cb,
        bulk_args, HG_BULK_PULL, hg_info->addr, hg_info->target_id,
        origin_bulk_handle, 0, local_bulk_handle, 0, bulk_args->nbytes,
        &hg_bulk_op_id);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    /* Test HG_Bulk_Cancel() */
    if (fildes < 0) {
        ret = HG_Bulk_cancel(hg_bulk_op_id);
        if (ret != HG_SUCCESS){
            fprintf(stderr, "Could not cancel bulk data\n");
            return ret;
        }
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_out_t out_struct;

    void *buf;
    size_t write_ret;

    if (hg_cb_info->ret == HG_CANCELED) {
        printf("HG_Bulk_transfer() was successfully canceled\n");

        /* Fill output structure */
        out_struct.ret = 0;
    } else if (hg_cb_info->ret != HG_SUCCESS) {
        HG_LOG_ERROR("Error in callback");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    if (hg_cb_info->ret == HG_SUCCESS) {
        /* Call bulk_write */
        HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes,
            HG_BULK_READWRITE, 1, &buf, NULL, NULL);

        write_ret = bulk_write(bulk_args->fildes, buf, 0,
            bulk_args->nbytes, 1);

        /* Fill output structure */
        out_struct.ret = write_ret;
    }

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }
    ret = HG_Bulk_free(origin_bulk_handle);
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

done:
    HG_Destroy(bulk_args->handle);
    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_bulk_seg_write, handle)
{
    const struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    size_t nbytes_read;
    size_t offset;
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
    origin_bulk_handle = in_struct.bulk_handle;
    hg_atomic_set32(&bulk_args->completed_transfers, 0);

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->fildes = in_struct.fildes;

    /* Free input and keep ref to bulk_handle */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* For testing purposes try to read the data in two blocks of different sizes */
    nbytes_read = bulk_args->nbytes / 2 + 16;

    printf("Start reading first chunk of %lu bytes...\n", nbytes_read);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_class, 1, NULL, (hg_size_t *) &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_bulk_seg_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, hg_info->target_id,
            origin_bulk_handle, 0, local_bulk_handle, 0, nbytes_read,
            HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    offset = nbytes_read;
    nbytes_read = bulk_args->nbytes - nbytes_read;

    printf("Start reading second chunk of %lu bytes...\n", nbytes_read);

    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_bulk_seg_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, hg_info->target_id,
            origin_bulk_handle, offset, local_bulk_handle, offset, nbytes_read,
            HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_seg_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
    hg_return_t ret = HG_SUCCESS;

    bulk_write_out_t out_struct;

    void *buf;
    size_t write_ret;

    if (hg_atomic_incr32(&bulk_args->completed_transfers) != 2)
        goto done;

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    write_ret = bulk_write(bulk_args->fildes, buf, 0,
        bulk_args->nbytes, 1);

    /* Fill output structure */
    out_struct.ret = write_ret;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Free origin handle */
    ret = HG_Bulk_free(origin_bulk_handle);
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

    /* Free input */
    HG_Free_input(handle, &in_struct);

    /* Fill output structure */
    out_struct.ret = open_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

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

    /* Free input */
    HG_Free_input(handle, &in_struct);

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

    HG_Destroy(handle);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_posix_write, handle)
{
    hg_return_t ret = HG_SUCCESS;

    const struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    bulk_write_in_t in_struct;

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

    origin_bulk_handle = in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->fildes = in_struct.fildes;

    /* Free input */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_class, 1, NULL, (hg_size_t *) &bulk_args->nbytes,
            HG_BULK_READWRITE, &local_bulk_handle);

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_posix_write_transfer_cb,
            bulk_args, HG_BULK_PULL, hg_info->addr, hg_info->target_id,
            origin_bulk_handle, 0, local_bulk_handle, 0, bulk_args->nbytes,
            HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_posix_write_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
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

    /* Free origin handle */
    ret = HG_Bulk_free(origin_bulk_handle);
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

    const struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    bulk_write_in_t in_struct;

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

    origin_bulk_handle = in_struct.bulk_handle;

    /* Create a new block handle to read the data */
    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->fildes = in_struct.fildes;

    /* Free input */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* Create a new bulk handle to read the data */
    HG_Bulk_create(hg_info->hg_class, 1, NULL, (hg_size_t *) &bulk_args->nbytes,
            HG_BULK_READ_ONLY, &local_bulk_handle);

    /* Call bulk_write */
    HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes, HG_BULK_READWRITE,
            1, &buf, NULL, NULL);

    printf("Calling read with fd: %d\n", in_struct.fildes);
    read_ret = read(in_struct.fildes, buf, bulk_args->nbytes);

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

    /* Push bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_posix_read_transfer_cb,
            bulk_args, HG_BULK_PUSH, hg_info->addr, hg_info->target_id,
            origin_bulk_handle, 0, local_bulk_handle, 0, bulk_args->nbytes,
            HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_posix_read_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args = (struct hg_test_bulk_args *)
            hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
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

    /* Free origin handle */
    ret = HG_Bulk_free(origin_bulk_handle);
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
HG_TEST_RPC_CB(hg_test_perf_rpc_lat, handle)
{
    hg_return_t ret = HG_SUCCESS;

#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
    perf_rpc_lat_in_t in_struct;

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    HG_Free_input(handle, &in_struct);
#endif

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
HG_TEST_RPC_CB(hg_test_perf_bulk, handle)
{
    hg_return_t ret = HG_SUCCESS;
    const struct hg_info *hg_info = NULL;
    struct hg_test_info *hg_test_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    bulk_write_in_t in_struct;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get test info */
    hg_test_info = (struct hg_test_info *) HG_Class_get_data(hg_info->hg_class);

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    origin_bulk_handle = in_struct.bulk_handle;

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_mutex_lock(&hg_test_info->bulk_handle_mutex);
#endif
    local_bulk_handle = hg_test_info->bulk_handle;

    /* Free input */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_perf_bulk_transfer_cb,
            handle, HG_BULK_PULL, hg_info->addr, hg_info->target_id,
            origin_bulk_handle, 0, local_bulk_handle, 0,
            HG_Bulk_get_size(origin_bulk_handle), HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_bulk_read, handle)
{
    hg_return_t ret = HG_SUCCESS;
    const struct hg_info *hg_info = NULL;
    struct hg_test_info *hg_test_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    bulk_write_in_t in_struct;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get test info */
    hg_test_info = (struct hg_test_info *) HG_Class_get_data(hg_info->hg_class);

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input struct\n");
        return ret;
    }

    origin_bulk_handle = in_struct.bulk_handle;

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_mutex_lock(&hg_test_info->bulk_handle_mutex);
#endif
    local_bulk_handle = hg_test_info->bulk_handle;

    /* Free input */
    HG_Bulk_ref_incr(origin_bulk_handle);
    HG_Free_input(handle, &in_struct);

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_perf_bulk_transfer_cb,
        handle, HG_BULK_PUSH, hg_info->addr, hg_info->target_id,
        origin_bulk_handle, 0, local_bulk_handle, 0,
        HG_Bulk_get_size(origin_bulk_handle),
        HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return ret;
    }

#ifdef MERCURY_TESTING_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_perf_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    hg_handle_t handle = (hg_handle_t) hg_cb_info->arg;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
    size_t size = HG_Bulk_get_size(hg_cb_info->info.bulk.origin_handle);
    void *buf;
    const char *buf_ptr;
    size_t i;
#endif
    hg_return_t ret = HG_SUCCESS;

#ifdef MERCURY_TESTING_HAS_VERIFY_DATA
    HG_Bulk_access(hg_cb_info->info.bulk.local_handle, 0,
        size, HG_BULK_READWRITE, 1, &buf, NULL, NULL);

    /* Check bulk buf */
    buf_ptr = (const char*) buf;
    for (i = 0; i < size; i++) {
        if (buf_ptr[i] != (char) i) {
            printf("Error detected in bulk transfer, buf[%d] = %d, "
                "was expecting %d!\n", (int) i, (char) buf_ptr[i], (char) i);
            break;
        }
    }
#endif

    /* Free origin handle */
    ret = HG_Bulk_free(origin_bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free HG bulk handle\n");
        return ret;
    }

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        goto done;
    }

done:
    HG_Destroy(handle);
    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_overflow, handle)
{
    size_t max_size =
        HG_Class_get_output_eager_size(HG_Get_info(handle)->hg_class);
    hg_return_t ret = HG_SUCCESS;

    overflow_out_t out_struct;

    hg_string_t string;
    size_t string_len = max_size * 2;

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
//static hg_return_t
//hg_test_nested1_forward_cb(const struct hg_cb_info *callback_info)
//{
//    hg_handle_t handle = (hg_handle_t) callback_info->arg;
//    hg_return_t ret = HG_SUCCESS;
//
//    printf("In hg_test_nested1_forward_cb\n");
//
//    /* Send response back */
//    ret = HG_Respond(handle, NULL, NULL, NULL);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not respond\n");
//        return ret;
//    }
//
//    HG_Destroy(handle);
//
//    return ret;
//}
//
///*---------------------------------------------------------------------------*/
//HG_TEST_RPC_CB(hg_test_nested1, handle)
//{
//    hg_handle_t forward_handle;
//    const struct hg_info *hg_info = NULL;
//    hg_return_t ret = HG_SUCCESS;
//
//    printf("In hg_test_nested1\n");
//
//    /* Get info from handle */
//    hg_info = HG_Get_info(handle);
//
//    ret = HG_Create(hg_info->context, hg_addr_table[1], hg_test_nested2_id_g,
//            &forward_handle);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not start call\n");
//        goto done;
//    }
//
//    /* Forward call to remote addr and get a new request */
//    printf("Forwarding call, op id: %u...\n", hg_test_nested2_id_g);
//    ret = HG_Forward(forward_handle, hg_test_nested1_forward_cb, handle, NULL);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not forward call\n");
//        goto done;
//    }
//
//    HG_Destroy(forward_handle);
//
//done:
//    return ret;
//}
//
///*---------------------------------------------------------------------------*/
//HG_TEST_RPC_CB(hg_test_nested2, handle)
//{
//    hg_return_t ret = HG_SUCCESS;
//
//    printf("In hg_test_nested2\n");
//
//    /* Send response back */
//    ret = HG_Respond(handle, NULL, NULL, NULL);
//    if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not respond\n");
//        return ret;
//    }
//
//    HG_Destroy(handle);
//
//    return ret;
//}

/*---------------------------------------------------------------------------*/
HG_TEST_THREAD_CB(hg_test_rpc_open)
HG_TEST_THREAD_CB(hg_test_rpc_open_no_resp)
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
HG_TEST_THREAD_CB(hg_test_perf_rpc_lat)
HG_TEST_THREAD_CB(hg_test_perf_bulk)
HG_TEST_THREAD_CB(hg_test_perf_bulk_read)
HG_TEST_THREAD_CB(hg_test_overflow)
//HG_TEST_THREAD_CB(hg_test_nested1)
//HG_TEST_THREAD_CB(hg_test_nested2)

/*---------------------------------------------------------------------------*/
