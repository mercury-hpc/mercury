/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

#include "mercury_time.h"
#ifdef HG_TEST_HAS_THREAD_POOL
#    include "mercury_thread_pool.h"
#endif
#include "mercury_atomic.h"
#include "mercury_rpc_cb.h"
#include "mercury_thread_mutex.h"

/****************/
/* Local Macros */
/****************/

#ifdef HG_TEST_HAS_VERIFY_DATA
#    define HG_TEST_ALLOC(size) calloc(size, sizeof(char))
#else
#    define HG_TEST_ALLOC(size) malloc(size)
#endif

#ifdef HG_TEST_HAS_THREAD_POOL
#    define HG_TEST_RPC_CB(func_name, handle)                                  \
        static hg_return_t func_name##_thread_cb(hg_handle_t handle)

/* Assuming func_name_cb is defined, calling HG_TEST_THREAD_CB(func_name)
 * will define func_name_thread and func_name_thread_cb that can be used
 * to execute RPC callback from a thread
 */
#    define HG_TEST_THREAD_CB(func_name)                                       \
        static HG_INLINE HG_THREAD_RETURN_TYPE func_name##_thread(void *arg)   \
        {                                                                      \
            hg_handle_t handle = (hg_handle_t) arg;                            \
            hg_thread_ret_t thread_ret = (hg_thread_ret_t) 0;                  \
                                                                               \
            func_name##_thread_cb(handle);                                     \
                                                                               \
            return thread_ret;                                                 \
        }                                                                      \
        hg_return_t func_name##_cb(hg_handle_t handle)                         \
        {                                                                      \
            struct hg_test_info *hg_test_info =                                \
                (struct hg_test_info *) HG_Class_get_data(                     \
                    HG_Get_info(handle)->hg_class);                            \
            hg_return_t ret = HG_SUCCESS;                                      \
                                                                               \
            if (hg_test_info->na_test_info.max_contexts > 1) {                 \
                func_name##_thread(handle);                                    \
            } else {                                                           \
                struct hg_thread_work *work = HG_Get_data(handle);             \
                work->func = func_name##_thread;                               \
                work->args = handle;                                           \
                hg_thread_pool_post(hg_test_info->thread_pool, work);          \
            }                                                                  \
                                                                               \
            return ret;                                                        \
        }
#else
#    define HG_TEST_RPC_CB(func_name, handle)                                  \
        hg_return_t func_name##_cb(hg_handle_t handle)
#    define HG_TEST_THREAD_CB(func_name)
#endif

/************************************/
/* Local Type and Struct Definition */
/************************************/

#ifdef _WIN32
#    ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#    endif
#endif

struct hg_test_bulk_args {
    hg_handle_t handle;
    hg_size_t nbytes;
    ssize_t ret;
    int fildes;
    hg_size_t transfer_size;
    hg_size_t origin_offset;
    hg_size_t target_offset;
};

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_bulk_bind_transfer_cb(const struct hg_cb_info *hg_cb_info);

static hg_return_t
hg_test_perf_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info);

/*******************/
/* Local Variables */
/*******************/

// extern hg_id_t hg_test_nested2_id_g;
// hg_addr_t *hg_addr_table;

/*---------------------------------------------------------------------------*/
/* Actual definition of the functions that need to be executed */
/*---------------------------------------------------------------------------*/
static HG_INLINE int
rpc_open(const char *path, rpc_handle_t handle, int *event_id)
{
    HG_TEST_LOG_DEBUG("Called rpc_open of %s with cookie %lu\n", path,
        (unsigned long) handle.cookie);
    *event_id = (int) handle.cookie;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE size_t
bulk_write(int fildes, const void *buf, size_t offset, size_t start_value,
    size_t nbyte, int verbose)
{
#ifdef HG_TEST_HAS_VERIFY_DATA
    size_t i;
    int error = 0;
    const char *buf_ptr = (const char *) buf;
    (void) fildes;

    if (verbose)
        HG_TEST_LOG_DEBUG("Executing bulk_write with fildes %d...", fildes);

    if (nbyte == 0) {
        HG_TEST_LOG_ERROR("Error detected in bulk transfer, nbyte is zero!");
        error = 1;
    }

    if (verbose)
        HG_TEST_LOG_DEBUG("Checking data...");

    /* Check bulk buf */
    for (i = offset; i < nbyte + offset; i++) {
        if (buf_ptr[i] != (char) (i + start_value)) {
            HG_TEST_LOG_ERROR("Error detected in bulk transfer, buf[%zu] = %d, "
                              "was expecting %d!\n",
                i, (char) buf_ptr[i], (char) (i + start_value));
            error = 1;
            nbyte = 0;
            break;
        }
    }
    if (!error && verbose)
        HG_TEST_LOG_DEBUG("Successfully transfered %zu bytes!", nbyte);
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
HG_TEST_RPC_CB(hg_test_rpc_null, handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_rpc_open, handle)
{
    rpc_open_in_t in_struct;
    rpc_open_out_t out_struct;
    hg_const_string_t path;
    rpc_handle_t rpc_handle;
    int event_id;
    int open_ret;
    hg_return_t ret = HG_SUCCESS;

    /* Get input buffer */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    /* Get parameters */
    path = in_struct.path;
    rpc_handle = in_struct.handle;

    /* Call rpc_open */
    open_ret = rpc_open(path, rpc_handle, &event_id);

    /* Free input */
    ret = HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));

    /* Fill output structure */
    out_struct.event_id = event_id;
    out_struct.ret = open_ret;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_rpc_open_no_resp, handle)
{
    rpc_open_in_t in_struct;
    hg_const_string_t path;
    rpc_handle_t rpc_handle;
    int event_id;
    hg_return_t ret = HG_SUCCESS;

    /* Get input buffer */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    /* Get parameters */
    path = in_struct.path;
    rpc_handle = in_struct.handle;

    /* Call rpc_open */
    rpc_open(path, rpc_handle, &event_id);

    ret = HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_overflow, handle)
{
    size_t max_size =
        HG_Class_get_output_eager_size(HG_Get_info(handle)->hg_class);
    overflow_out_t out_struct;
    hg_string_t string;
    size_t string_len = max_size * 2;
    hg_return_t ret = HG_SUCCESS;

    string = (hg_string_t) malloc(string_len + 1);
    HG_TEST_CHECK_ERROR(
        string == NULL, done, ret, HG_NOMEM_ERROR, "Could not allocate string");

    memset(string, 'h', string_len);
    string[string_len] = '\0';

    /* Fill output structure */
    out_struct.string = string;
    out_struct.string_len = string_len;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    free(string);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_cancel_rpc, handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Destroy twice and do not send expected response back */
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

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

    bulk_args =
        (struct hg_test_bulk_args *) malloc(sizeof(struct hg_test_bulk_args));
    HG_TEST_CHECK_ERROR(bulk_args == NULL, error, ret, HG_NOMEM_ERROR,
        "Could not allocate bulk_args");

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input parameters and data */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    /* Get parameters */
    fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;

    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->transfer_size = in_struct.transfer_size;
    bulk_args->origin_offset = in_struct.origin_offset;
    bulk_args->target_offset = in_struct.target_offset;
    bulk_args->fildes = fildes;

    ret = HG_Bulk_ref_incr(origin_bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Bulk_ref_incr() failed (%s)", HG_Error_to_string(ret));

    /* Free input */
    ret = HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));

    /* Create a new block handle to read the data */
    ret = HG_Bulk_create(hg_info->hg_class, 1, NULL,
        (hg_size_t *) &bulk_args->nbytes, HG_BULK_READWRITE,
        &local_bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    /* Pull bulk data */
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%zu, origin_offset=%zu, "
                      "target_offset=%zu",
        bulk_args->transfer_size, bulk_args->origin_offset,
        bulk_args->target_offset);
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_bulk_transfer_cb,
        bulk_args, HG_BULK_PULL, hg_info->addr, hg_info->context_id,
        origin_bulk_handle, bulk_args->origin_offset, local_bulk_handle,
        bulk_args->target_offset, bulk_args->transfer_size, &hg_bulk_op_id);
    HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Bulk_transfer_id() failed (%s)",
        HG_Error_to_string(ret));

    /* Test HG_Bulk_Cancel() */
    if (fildes < 0) {
        ret = HG_Bulk_cancel(hg_bulk_op_id);
        HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Bulk_cancel() failed (%s)",
            HG_Error_to_string(ret));
    }

    return ret;

error:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_bulk_bind_write, handle)
{
    const struct hg_info *hg_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    struct hg_test_bulk_args *bulk_args = NULL;
    bulk_write_in_t in_struct;
    hg_return_t ret = HG_SUCCESS;
    int fildes;

    bulk_args =
        (struct hg_test_bulk_args *) malloc(sizeof(struct hg_test_bulk_args));
    HG_TEST_CHECK_ERROR(bulk_args == NULL, error, ret, HG_NOMEM_ERROR,
        "Could not allocate bulk_args");

    /* Keep handle to pass to callback */
    bulk_args->handle = handle;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get input parameters and data */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    /* Get parameters */
    fildes = in_struct.fildes;
    origin_bulk_handle = in_struct.bulk_handle;

    bulk_args->nbytes = HG_Bulk_get_size(origin_bulk_handle);
    bulk_args->transfer_size = in_struct.transfer_size;
    bulk_args->origin_offset = in_struct.origin_offset;
    bulk_args->target_offset = in_struct.target_offset;
    bulk_args->fildes = fildes;

    /* Create a new block handle to read the data */
    ret = HG_Bulk_create(hg_info->hg_class, 1, NULL,
        (hg_size_t *) &bulk_args->nbytes, HG_BULK_READWRITE,
        &local_bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    /* Pull bulk data */
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%zu, origin_offset=%zu, "
                      "target_offset=%zu",
        bulk_args->transfer_size, bulk_args->origin_offset,
        bulk_args->target_offset);
    ret = HG_Bulk_bind_transfer(hg_info->context, hg_test_bulk_bind_transfer_cb,
        bulk_args, HG_BULK_PULL, origin_bulk_handle, bulk_args->origin_offset,
        local_bulk_handle, bulk_args->target_offset, bulk_args->transfer_size,
        HG_OP_ID_IGNORE);
    HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Bulk_bind_transfer() failed (%s)",
        HG_Error_to_string(ret));

    return ret;

error:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args =
        (struct hg_test_bulk_args *) hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
    hg_return_t ret = HG_SUCCESS;
    bulk_write_out_t out_struct;
    void *buf;
    size_t write_ret;

    if (hg_cb_info->ret == HG_CANCELED) {
        HG_TEST_LOG_DEBUG("HG_Bulk_transfer() was canceled\n");
        /* Fill output structure */
        out_struct.ret = 0;
        goto done;
    } else
        HG_TEST_CHECK_ERROR_NORET(hg_cb_info->ret != HG_SUCCESS, done,
            "Error in HG callback (%s)", HG_Error_to_string(hg_cb_info->ret));

    ret = HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes,
        HG_BULK_READ_ONLY, 1, &buf, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_access() failed (%s)", HG_Error_to_string(ret));

    /* Call bulk_write */
    write_ret = bulk_write(bulk_args->fildes, buf, bulk_args->target_offset,
        bulk_args->origin_offset - bulk_args->target_offset,
        bulk_args->transfer_size, 1);

    /* Fill output structure */
    out_struct.ret = write_ret;

done:
    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Bulk_free() failed (%s)",
        HG_Error_to_string(ret));

    ret = HG_Bulk_free(origin_bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Bulk_free() failed (%s)",
        HG_Error_to_string(ret));

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Destroy(bulk_args->handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_bind_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    struct hg_test_bulk_args *bulk_args =
        (struct hg_test_bulk_args *) hg_cb_info->arg;
    hg_bulk_t local_bulk_handle = hg_cb_info->info.bulk.local_handle;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
    hg_return_t ret = HG_SUCCESS;
    bulk_write_in_t in_struct = {.fildes = bulk_args->fildes,
        .transfer_size = bulk_args->transfer_size,
        .origin_offset = bulk_args->origin_offset,
        .target_offset = bulk_args->target_offset,
        .bulk_handle = origin_bulk_handle};
    bulk_bind_write_out_t out_struct;
    void *buf;
    size_t write_ret;

    if (hg_cb_info->ret == HG_CANCELED) {
        HG_TEST_LOG_DEBUG("HG_Bulk_transfer() was successfully canceled\n");
        /* Fill output structure */
        out_struct.ret = 0;
        goto done;
    } else
        HG_TEST_CHECK_ERROR_NORET(hg_cb_info->ret != HG_SUCCESS, done,
            "Error in HG callback (%s)", HG_Error_to_string(hg_cb_info->ret));

    ret = HG_Bulk_access(local_bulk_handle, 0, bulk_args->nbytes,
        HG_BULK_READ_ONLY, 1, &buf, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_access() failed (%s)", HG_Error_to_string(ret));

    /* Call bulk_write */
    write_ret = bulk_write(bulk_args->fildes, buf, bulk_args->target_offset,
        bulk_args->origin_offset - bulk_args->target_offset,
        bulk_args->transfer_size, 1);

    /* Fill output structure */
    out_struct.ret = write_ret;

done:
    /* Try to send the bulk handle back */
    out_struct.bulk_handle = origin_bulk_handle;

    /* Free block handle */
    ret = HG_Bulk_free(local_bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Bulk_free() failed (%s)",
        HG_Error_to_string(ret));

    /* Send response back */
    ret = HG_Respond(bulk_args->handle, NULL, NULL, &out_struct);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

    /* Free input */
    ret = HG_Free_input(bulk_args->handle, &in_struct);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Free_input() failed (%s)",
        HG_Error_to_string(ret));

    ret = HG_Destroy(bulk_args->handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    free(bulk_args);

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_rpc, handle)
{
    hg_return_t ret = HG_SUCCESS;

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_rpc_lat, handle)
{
    hg_return_t ret = HG_SUCCESS;
#ifdef HG_TEST_HAS_VERIFY_DATA
    perf_rpc_lat_in_t in_struct;

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));
#endif

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

done:
    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
HG_TEST_RPC_CB(hg_test_perf_bulk, handle)
{
    const struct hg_info *hg_info = NULL;
    struct hg_test_info *hg_test_info = NULL;
    hg_bulk_t origin_bulk_handle = HG_BULK_NULL;
    hg_bulk_t local_bulk_handle = HG_BULK_NULL;
    bulk_write_in_t in_struct;
    hg_return_t ret = HG_SUCCESS;

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get test info */
    hg_test_info = (struct hg_test_info *) HG_Class_get_data(hg_info->hg_class);
    HG_TEST_CHECK_ERROR(
        hg_test_info == NULL, error, ret, HG_INVALID_ARG, "NULL hg_test_info");

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    origin_bulk_handle = in_struct.bulk_handle;

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_lock(&hg_test_info->bulk_handle_mutex);
#endif
    local_bulk_handle = hg_test_info->bulk_handle;

    ret = HG_Bulk_ref_incr(origin_bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Bulk_ref_incr() failed (%s)", HG_Error_to_string(ret));

    /* Free input */
    HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_perf_bulk_transfer_cb,
        handle, HG_BULK_PULL, hg_info->addr, hg_info->context_id,
        origin_bulk_handle, 0, local_bulk_handle, 0,
        HG_Bulk_get_size(origin_bulk_handle), HG_OP_ID_IGNORE);
    HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Bulk_transfer_id() failed (%s)",
        HG_Error_to_string(ret));

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    return ret;

error:
#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

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
    HG_TEST_CHECK_ERROR(
        hg_test_info == NULL, error, ret, HG_INVALID_ARG, "NULL hg_test_info");

    /* Get input struct */
    ret = HG_Get_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Get_input() failed (%s)", HG_Error_to_string(ret));

    origin_bulk_handle = in_struct.bulk_handle;

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_lock(&hg_test_info->bulk_handle_mutex);
#endif
    local_bulk_handle = hg_test_info->bulk_handle;

    ret = HG_Bulk_ref_incr(origin_bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Bulk_ref_incr() failed (%s)", HG_Error_to_string(ret));

    /* Free input */
    ret = HG_Free_input(handle, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Free_input() failed (%s)", HG_Error_to_string(ret));

    /* Pull bulk data */
    ret = HG_Bulk_transfer_id(hg_info->context, hg_test_perf_bulk_transfer_cb,
        handle, HG_BULK_PUSH, hg_info->addr, hg_info->context_id,
        origin_bulk_handle, 0, local_bulk_handle, 0,
        HG_Bulk_get_size(origin_bulk_handle), HG_OP_ID_IGNORE);
    HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Bulk_transfer_id() failed (%s)",
        HG_Error_to_string(ret));

#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    return ret;

error:
#ifdef HG_TEST_HAS_THREAD_POOL
    hg_thread_mutex_unlock(&hg_test_info->bulk_handle_mutex);
#endif

    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_perf_bulk_transfer_cb(const struct hg_cb_info *hg_cb_info)
{
    hg_handle_t handle = (hg_handle_t) hg_cb_info->arg;
    hg_bulk_t origin_bulk_handle = hg_cb_info->info.bulk.origin_handle;
#ifdef HG_TEST_HAS_VERIFY_DATA
    size_t size = HG_Bulk_get_size(hg_cb_info->info.bulk.origin_handle);
    void *buf;
    const char *buf_ptr;
    size_t i;
#endif
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(hg_cb_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(hg_cb_info->ret));

#ifdef HG_TEST_HAS_VERIFY_DATA
    ret = HG_Bulk_access(hg_cb_info->info.bulk.local_handle, 0, size,
        HG_BULK_READWRITE, 1, &buf, NULL, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_access() failed (%s)", HG_Error_to_string(ret));

    /* Check bulk buf */
    buf_ptr = (const char *) buf;
    for (i = 0; i < size; i++) {
        HG_TEST_CHECK_ERROR(buf_ptr[i] != (char) i, done, ret, HG_SUCCESS,
            "Error detected in bulk transfer, buf[%d] = %d, "
            "was expecting %d!\n",
            (int) i, (char) buf_ptr[i], (char) i);
    }
#endif

done:
    /* Free origin handle */
    ret = HG_Bulk_free(origin_bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(ret != HG_SUCCESS, "HG_Bulk_free() failed (%s)",
        HG_Error_to_string(ret));

    /* Send response back */
    ret = HG_Respond(handle, NULL, NULL, NULL);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Respond() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(
        ret != HG_SUCCESS, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    return ret;
}

/*---------------------------------------------------------------------------*/
// static hg_return_t
// hg_test_nested1_forward_cb(const struct hg_cb_info *callback_info)
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
// HG_TEST_RPC_CB(hg_test_nested1, handle)
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
//    ret = HG_Forward(forward_handle, hg_test_nested1_forward_cb, handle,
//    NULL); if (ret != HG_SUCCESS) {
//        fprintf(stderr, "Could not forward call\n");
//        goto done;
//    }
//
//    HG_Destroy(forward_handle);
//
// done:
//    return ret;
//}
//
///*---------------------------------------------------------------------------*/
// HG_TEST_RPC_CB(hg_test_nested2, handle)
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
HG_TEST_THREAD_CB(hg_test_rpc_null)
HG_TEST_THREAD_CB(hg_test_rpc_open)
HG_TEST_THREAD_CB(hg_test_rpc_open_no_resp)
HG_TEST_THREAD_CB(hg_test_overflow)
HG_TEST_THREAD_CB(hg_test_cancel_rpc)

HG_TEST_THREAD_CB(hg_test_bulk_write)
HG_TEST_THREAD_CB(hg_test_bulk_bind_write)

HG_TEST_THREAD_CB(hg_test_perf_rpc)
HG_TEST_THREAD_CB(hg_test_perf_rpc_lat)
HG_TEST_THREAD_CB(hg_test_perf_bulk)
HG_TEST_THREAD_CB(hg_test_perf_bulk_read)
// HG_TEST_THREAD_CB(hg_test_nested1)
// HG_TEST_THREAD_CB(hg_test_nested2)

/*---------------------------------------------------------------------------*/
