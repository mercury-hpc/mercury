/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct forward_cb_args {
    hg_request_t *request;
    size_t expected_bytes;
    hg_return_t ret;
};

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_bulk_forward_cb(const struct hg_cb_info *callback_info);

/*******************/
/* Local Variables */
/*******************/

extern hg_id_t hg_test_bulk_write_id_g;
extern hg_id_t hg_test_bulk_bind_write_id_g;
extern hg_id_t hg_test_bulk_bind_forward_id_g;

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

    /* Get output */
    ret = HG_Get_output(handle, &bulk_write_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    HG_TEST_CHECK_ERROR(bulk_write_ret != args->expected_bytes, error,
        args->ret, HG_MSGSIZE, "Returned: %zu bytes, was expecting %zu",
        bulk_write_ret, args->expected_bytes);

error:
    /* Free request */
    ret = HG_Free_output(handle, &bulk_write_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_bind_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

    /* Get output */
    ret = HG_Get_output(handle, &bulk_write_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    HG_TEST_CHECK_ERROR(bulk_write_ret != args->expected_bytes, error,
        args->ret, HG_MSGSIZE, "Returned: %zu bytes, was expecting %zu",
        bulk_write_ret, args->expected_bytes);

error:
    /* Free request */
    ret = HG_Free_output(handle, &bulk_write_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_null(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t target_addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    char *bulk_buf = NULL;
    void *buf_ptrs[2] = {NULL, NULL};
    hg_size_t buf_sizes[2] = {0, 0};
    hg_id_t rpc_id = hg_test_bulk_write_id_g;
    hg_cb_t forward_cb = hg_test_bulk_forward_cb;

    /* Prepare bulk_buf */
    request = hg_request_create(request_class);

    /* Register memory */
    ret = HG_Bulk_create(
        hg_class, 2, buf_ptrs, buf_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Create(context, target_addr, rpc_id, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    bulk_write_in_struct.fildes = 0;
    bulk_write_in_struct.transfer_size = 0;
    bulk_write_in_struct.origin_offset = 0;
    bulk_write_in_struct.target_offset = 0;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%" PRIu64
                      ", origin_offset=%" PRIu64 ",  target_offset=%" PRIu64,
        bulk_write_in_struct.transfer_size, bulk_write_in_struct.origin_offset,
        bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding call with op id: %" PRIu64 "...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = 0;
    forward_cb_args.ret = HG_SUCCESS;
    ret =
        HG_Forward(handle, forward_cb, &forward_cb_args, &bulk_write_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    /* Free memory handle */
    cleanup_ret = HG_Bulk_free(bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Bulk_free() failed (%s)", HG_Error_to_string(cleanup_ret));

    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    /* Free bulk data */
    free(bulk_buf);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_contig(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_bool_t bind_addr, hg_bool_t forward,
    hg_addr_t target_addr, hg_size_t bulk_size, hg_size_t transfer_size,
    hg_size_t origin_offset, hg_size_t target_offset)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    char *bulk_buf = NULL;
    void *buf_ptrs[2];
    hg_size_t buf_sizes[2];
    hg_id_t rpc_id = hg_test_bulk_write_id_g;
    hg_cb_t forward_cb = hg_test_bulk_forward_cb;
    size_t i;

    HG_TEST_CHECK_ERROR(origin_offset + transfer_size > bulk_size, done, ret,
        HG_OVERFLOW, "Exceeding bulk size");

    /* Prepare bulk_buf */
    bulk_buf = malloc(bulk_size);
    HG_TEST_CHECK_ERROR(bulk_buf == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate bulk_buf");

    for (i = 0; i < bulk_size; i++)
        bulk_buf[i] = (char) i;
    buf_ptrs[0] = bulk_buf;
    buf_sizes[0] = bulk_size;
    buf_ptrs[1] = NULL;
    buf_sizes[1] = 0;

    request = hg_request_create(request_class);

    /* Register memory */
    ret = HG_Bulk_create(
        hg_class, 2, buf_ptrs, buf_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    if (bind_addr) {
        /* Bind local context to bulk, it is only necessary if this bulk handle
         * will be shared to another server by the server of this RPC, but it
         * should also work for normal case. Add here just to test the
         * functionality. */
        ret = HG_Bulk_bind(bulk_handle, context);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Bulk_bind() failed (%s)", HG_Error_to_string(ret));

        rpc_id = (forward) ? hg_test_bulk_bind_forward_id_g
                           : hg_test_bulk_bind_write_id_g;
        forward_cb = hg_test_bulk_bind_forward_cb;
    }

    ret = HG_Create(context, target_addr, rpc_id, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    bulk_write_in_struct.fildes = 0;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%" PRIu64
                      ", origin_offset=%" PRIu64 ",  target_offset=%" PRIu64,
        bulk_write_in_struct.transfer_size, bulk_write_in_struct.origin_offset,
        bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding call with op id: %" PRIu64 "...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret =
        HG_Forward(handle, forward_cb, &forward_cb_args, &bulk_write_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    /* Free memory handle */
    cleanup_ret = HG_Bulk_free(bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Bulk_free() failed (%s)", HG_Error_to_string(cleanup_ret));

    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    /* Free bulk data */
    free(bulk_buf);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_seg(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t target_addr,
    hg_size_t bulk_size, hg_size_t transfer_size, hg_size_t origin_offset,
    hg_size_t target_offset, hg_uint32_t origin_segment_count)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    void **buf_ptrs = NULL;
    hg_size_t *buf_sizes = NULL;
    size_t i;

    HG_TEST_CHECK_ERROR(origin_offset + transfer_size > bulk_size, done, ret,
        HG_OVERFLOW, "Exceeding bulk size");

    /* Prepare bulk_buf */
    buf_ptrs = (void **) malloc(origin_segment_count * sizeof(void *));
    HG_TEST_CHECK_ERROR(buf_ptrs == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate buf_ptrs");

    buf_sizes = (hg_size_t *) malloc(origin_segment_count * sizeof(hg_size_t));
    HG_TEST_CHECK_ERROR(buf_sizes == NULL, done, ret, HG_NOMEM_ERROR,
        "Could not allocate buf_sizes");

    for (i = 0; i < origin_segment_count; i++) {
        hg_size_t j;

        buf_sizes[i] = bulk_size / origin_segment_count;
        buf_ptrs[i] = malloc(buf_sizes[i]);
        HG_TEST_CHECK_ERROR(buf_ptrs == NULL, done, ret, HG_NOMEM_ERROR,
            "Could not allocate bulk_buf");

        for (j = 0; j < buf_sizes[i]; j++) {
            ((char **) buf_ptrs)[i][j] = (char) (i * buf_sizes[i] + j);
        }
    }

    request = hg_request_create(request_class);

    ret = HG_Create(context, target_addr, hg_test_bulk_write_id_g, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Register memory */
    ret = HG_Bulk_create(hg_class, origin_segment_count, buf_ptrs, buf_sizes,
        HG_BULK_READ_ONLY, &bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    bulk_write_in_struct.fildes = 0;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%" PRIu64
                      ", origin_offset=%" PRIu64 ",  target_offset=%" PRIu64,
        bulk_write_in_struct.transfer_size, bulk_write_in_struct.origin_offset,
        bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG(
        "Forwarding call with op id: %" PRIu64 "...", hg_test_bulk_write_id_g);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret = HG_Forward(handle, hg_test_bulk_forward_cb, &forward_cb_args,
        &bulk_write_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    /* Free memory handle */
    cleanup_ret = HG_Bulk_free(bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Bulk_free() failed (%s)", HG_Error_to_string(cleanup_ret));

    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    /* Free bulk data */
    if (buf_ptrs) {
        for (i = 0; i < origin_segment_count; i++)
            free(buf_ptrs[i]);
        free(buf_ptrs);
    }
    free(buf_sizes);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_small(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t target_addr,
    hg_size_t transfer_size, hg_size_t origin_offset, hg_size_t target_offset)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    char data[12];
    void *buf_ptrs[2] = {data, data + 8};
    hg_size_t buf_sizes[2] = {8, 4};
    hg_size_t bulk_size = 12;
    size_t i;

    HG_TEST_CHECK_ERROR(origin_offset + transfer_size > bulk_size, done, ret,
        HG_OVERFLOW, "Exceeding bulk size");

    /* Prepare bulk buf */
    for (i = 0; i < bulk_size; i++)
        data[i] = (char) i;

    request = hg_request_create(request_class);

    ret = HG_Create(context, target_addr, hg_test_bulk_write_id_g, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Register memory */
    ret = HG_Bulk_create(
        hg_class, 2, buf_ptrs, buf_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Bulk_create() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    bulk_write_in_struct.fildes = 1;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%" PRIu64
                      ", origin_offset=%" PRIu64 ",  target_offset=%" PRIu64,
        bulk_write_in_struct.transfer_size, bulk_write_in_struct.origin_offset,
        bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG(
        "Forwarding call with op id: %" PRIu64 "...", hg_test_bulk_write_id_g);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret = HG_Forward(handle, hg_test_bulk_forward_cb, &forward_cb_args,
        &bulk_write_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    /* Free memory handle */
    cleanup_ret = HG_Bulk_free(bulk_handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Bulk_free() failed (%s)", HG_Error_to_string(cleanup_ret));

    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = {0};
    hg_size_t buf_size;
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    hg_ret = HG_Test_init(argc, argv, &hg_test_info);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "HG_Test_init() failed");
    buf_size = hg_test_info.buf_size_max;

    /* Zero size RPC bulk test */
    HG_TEST("null RPC bulk");
    hg_ret = hg_test_bulk_null(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "null RPC bulk failed");
    HG_PASSED();

    /* Zero size RPC bulk test */
    HG_TEST("zero size RPC bulk (size 0, offsets 0, 0)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, 0, hg_test_info.target_addr, buf_size, 0,
        0, 0);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "zero size RPC bulk failed");
    HG_PASSED();

    /* Simple RPC bulk test */
    HG_TEST("contiguous RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, 0, hg_test_info.target_addr, buf_size,
        buf_size, 0, 0);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "contiguous RPC bulk failed");
    HG_PASSED();

    HG_TEST("contiguous RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, 0, hg_test_info.target_addr, buf_size,
        buf_size / 4, buf_size / 2 + 1, 0);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "contiguous RPC bulk failed");
    HG_PASSED();

    HG_TEST("contiguous RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, "
            "BUFSIZE/4)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, 0, hg_test_info.target_addr, buf_size,
        buf_size / 8, buf_size / 2 + 1, buf_size / 4);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "contiguous RPC bulk failed");
    HG_PASSED();

    /* small bulk test */
    HG_TEST("small segmented RPC bulk (size 8, offsets 0, 0)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 8, 0, 0);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "small segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("small segmented RPC bulk (size 4, offsets 8, 0)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 4, 8, 0);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "small segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("small segmented RPC bulk (size 8, offsets 4, 2)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 8, 4, 2);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "small segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size, 0, 0, 16);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size / 4, buf_size / 2 + 1, 0, 16);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, "
            "BUFSIZE/4)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size / 8, buf_size / 2 + 1, buf_size / 4, 16);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "segmented RPC bulk failed");
    HG_PASSED();

#ifndef HG_HAS_XDR
    HG_TEST("over-segmented RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size, 0, 0, 1024);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "over-segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST(
        "over-segmented RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size / 4, buf_size / 2 + 1, 0, 1024);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "over-segmented RPC bulk failed");
    HG_PASSED();

    HG_TEST("over-segmented RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, "
            "BUFSIZE/4)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, buf_size,
        buf_size / 8, buf_size / 2 + 1, buf_size / 4, 1024);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "over-segmented RPC bulk failed");
    HG_PASSED();
#endif

    if (strcmp(HG_Class_get_name(hg_test_info.hg_class), "ofi") == 0 ||
        strcmp(HG_Class_get_name(hg_test_info.hg_class), "sm") == 0) {
        HG_TEST("bind contiguous RPC bulk (size BUFSIZE, offsets 0, 0)");
        hg_ret = hg_test_bulk_contig(hg_test_info.hg_class,
            hg_test_info.context, hg_test_info.request_class, 1, 0,
            hg_test_info.target_addr, buf_size, buf_size, 0, 0);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "bind contiguous RPC bulk failed");
        HG_PASSED();

        HG_TEST(
            "forward bind contiguous RPC bulk (size BUFSIZE, offsets 0, 0)");
        hg_ret = hg_test_bulk_contig(hg_test_info.hg_class,
            hg_test_info.context, hg_test_info.request_class, 1, 1,
            hg_test_info.target_addr, 3584, 3584 / 4, 0, 0);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "bind contiguous RPC bulk failed");
        HG_PASSED();
    }

done:
    if (ret != EXIT_SUCCESS)
        HG_FAILED();

    hg_ret = HG_Test_finalize(&hg_test_info);
    HG_TEST_CHECK_ERROR_DONE(hg_ret != HG_SUCCESS, "HG_Test_finalize() failed");

    return ret;
}
