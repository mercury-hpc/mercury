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

#include <stdio.h>
#include <stdlib.h>

extern hg_id_t hg_test_bulk_write_id_g;
extern hg_id_t hg_test_bulk_bind_write_id_g;

#define BUFSIZE (MERCURY_TESTING_BUFFER_SIZE * 1024 * 1024)

struct forward_cb_args {
    hg_request_t *request;
    size_t expected_bytes;
    hg_return_t ret;
};

//#define HG_TEST_DEBUG
#ifdef HG_TEST_DEBUG
#define HG_TEST_LOG_DEBUG(...)                                \
    HG_LOG_WRITE_DEBUG(HG_TEST_LOG_MODULE_NAME, __VA_ARGS__)
#else
#define HG_TEST_LOG_DEBUG(...) (void)0
#endif

/*---------------------------------------------------------------------------*/
/**
 * HG_Forward callback
 */
static hg_return_t
hg_test_bulk_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args = (struct forward_cb_args *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Return from callback info is not HG_SUCCESS");
        goto done;
    }

    /* Get output */
    ret = HG_Get_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not get output");
        goto done;
    }

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    if (bulk_write_ret != args->expected_bytes) {
        HG_TEST_LOG_ERROR("Returned: %zu bytes, was expecting %zu",
            bulk_write_ret, args->expected_bytes);
        args->ret = HG_SIZE_ERROR;
    }

    /* Free request */
    ret = HG_Free_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not free output");
        goto done;
    }

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_bind_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args = (struct forward_cb_args *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_bind_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Return from callback info is not HG_SUCCESS");
        goto done;
    }

    /* Get output */
    ret = HG_Get_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not get output");
        goto done;
    }

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    if (bulk_write_ret != args->expected_bytes) {
        HG_TEST_LOG_ERROR("Returned: %zu bytes, was expecting %zu",
            bulk_write_ret, args->expected_bytes);
        args->ret = HG_SIZE_ERROR;
    }

    /* Free request */
    ret = HG_Free_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not free output");
        goto done;
    }

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_contig(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_bool_t bind_addr,
    hg_addr_t target_addr, hg_size_t transfer_size, hg_size_t origin_offset,
    hg_size_t target_offset)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    char *bulk_buf = NULL;
    void *buf_ptrs[2];
    hg_size_t buf_sizes[2];
    hg_size_t bulk_size = BUFSIZE;
    hg_id_t rpc_id = hg_test_bulk_write_id_g;
    hg_cb_t forward_cb = hg_test_bulk_forward_cb;
    size_t i;

    if (origin_offset + transfer_size > bulk_size) {
        HG_LOG_ERROR("Exceeding bulk size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Prepare bulk_buf */
    bulk_buf = malloc(bulk_size);
    for (i = 0; i < bulk_size; i++)
        bulk_buf[i] = (char) i;
    buf_ptrs[0] = bulk_buf;
    buf_sizes[0] = bulk_size;
    buf_ptrs[1] = NULL;
    buf_sizes[1] = 0;

    request = hg_request_create(request_class);

    /* Register memory */
    ret = HG_Bulk_create(hg_class, 2, buf_ptrs, buf_sizes, HG_BULK_READ_ONLY,
        &bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create bulk handle");
        goto done;
    }

    if (bind_addr) {
        /* Bind local context to bulk, it is only necessary if this bulk handle
         * will be shared to another server by the server of this RPC, but it
         * should also work for normal case. Add here just to test the
         * functionality. */
        ret = HG_Bulk_bind(bulk_handle, context);
        if (ret != HG_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not bind context to bulk handle");
            goto done;
        }
        rpc_id = hg_test_bulk_bind_write_id_g;
        forward_cb = hg_test_bulk_bind_forward_cb;
    }

    ret = HG_Create(context, target_addr, rpc_id, &handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create handle");
        goto done;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = 0;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%zu, origin_offset=%zu, "
        "target_offset=%zu", bulk_write_in_struct.transfer_size,
        bulk_write_in_struct.origin_offset, bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding call with op id: %u...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret = HG_Forward(handle, forward_cb, &forward_cb_args,
        &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not forward call");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy bulk handle");
        goto done;
    }

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy handle");
        goto done;
    }

    hg_request_destroy(request);

    /* Free bulk data */
    free(bulk_buf);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_seg(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t target_addr,
    hg_size_t transfer_size, hg_size_t origin_offset, hg_size_t target_offset,
    hg_uint32_t origin_segment_count)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    void **buf_ptrs;
    hg_size_t *buf_sizes;
    hg_size_t bulk_size = BUFSIZE;
    size_t i;

    if (origin_offset + transfer_size > bulk_size) {
        HG_LOG_ERROR("Exceeding bulk size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Prepare bulk_buf */
    buf_ptrs = (void **) malloc(origin_segment_count * sizeof(void *));
    buf_sizes = (hg_size_t *) malloc(origin_segment_count * sizeof(hg_size_t));
    for (i = 0; i < origin_segment_count; i++) {
        hg_size_t j;

        buf_sizes[i] = bulk_size / origin_segment_count;
        buf_ptrs[i] = malloc(buf_sizes[i]);
        for (j = 0; j < buf_sizes[i]; j++) {
            ((char **) buf_ptrs)[i][j] = (char) (i * buf_sizes[i] + j);
        }
    }

    request = hg_request_create(request_class);

    ret = HG_Create(context, target_addr, hg_test_bulk_write_id_g, &handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create handle");
        goto done;
    }

    /* Register memory */
    ret = HG_Bulk_create(hg_class, origin_segment_count, buf_ptrs,
        buf_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create bulk handle");
        goto done;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = 0;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%zu, origin_offset=%zu, "
        "target_offset=%zu", bulk_write_in_struct.transfer_size,
        bulk_write_in_struct.origin_offset, bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding call with op id: %u...",
        hg_test_bulk_write_id_g);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret = HG_Forward(handle, hg_test_bulk_forward_cb, &forward_cb_args,
            &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not forward call");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy bulk handle");
        goto done;
    }

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy handle");
        goto done;
    }

    hg_request_destroy(request);

    /* Free bulk data */
    for (i = 0; i < origin_segment_count; i++)
        free(buf_ptrs[i]);
    free(buf_ptrs);
    free(buf_sizes);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_bulk_small(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t target_addr,
    hg_size_t transfer_size, hg_size_t origin_offset, hg_size_t target_offset)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    bulk_write_in_t bulk_write_in_struct;
    char data[12];
    void *buf_ptrs[2] = { data, data+8 };
    hg_size_t buf_sizes[2] = { 8, 4 };
    hg_size_t bulk_size = 12;
    size_t i;

    if (origin_offset + transfer_size > bulk_size) {
        HG_LOG_ERROR("Exceeding bulk size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* Prepare bulk buf */
    for (i = 0; i < bulk_size; i++)
        data[i] = (char) i;

    request = hg_request_create(request_class);

    ret = HG_Create(context, target_addr, hg_test_bulk_write_id_g, &handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create handle");
        goto done;
    }

    /* Register memory */
    ret = HG_Bulk_create(hg_class, 2, buf_ptrs, buf_sizes, HG_BULK_READ_ONLY,
        &bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create bulk handle");
        goto done;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = 1;
    bulk_write_in_struct.transfer_size = transfer_size;
    bulk_write_in_struct.origin_offset = origin_offset;
    bulk_write_in_struct.target_offset = target_offset;
    bulk_write_in_struct.bulk_handle = bulk_handle;
    HG_TEST_LOG_DEBUG("Requesting transfer_size=%zu, origin_offset=%zu, "
        "target_offset=%zu", bulk_write_in_struct.transfer_size,
        bulk_write_in_struct.origin_offset, bulk_write_in_struct.target_offset);

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding call with op id: %u...",
        hg_test_bulk_write_id_g);
    forward_cb_args.request = request;
    forward_cb_args.expected_bytes = transfer_size;
    forward_cb_args.ret = HG_SUCCESS;
    ret = HG_Forward(handle, hg_test_bulk_forward_cb, &forward_cb_args,
            &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not forward call");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy bulk handle");
        goto done;
    }

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy handle");
        goto done;
    }

    hg_request_destroy(request);

    /* Assign ret from CB */
    ret = forward_cb_args.ret;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = { 0 };
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    HG_Test_init(argc, argv, &hg_test_info);

    /* Simple RPC bulk test */
    HG_TEST("contiguous RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, hg_test_info.target_addr, BUFSIZE, 0, 0);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("contiguous RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, hg_test_info.target_addr, BUFSIZE/4,
        BUFSIZE/2 + 1, 0);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("contiguous RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, BUFSIZE/4)");
    hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, 0, hg_test_info.target_addr, BUFSIZE/8,
        BUFSIZE/2 + 1, BUFSIZE/4);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    /* small bulk test */
    HG_TEST("small segmented RPC bulk (size 8, offsets 0, 0)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 8, 0, 0);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("small segmented RPC bulk (size 4, offsets 8, 0)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 4, 8, 0);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("small segmented RPC bulk (size 8, offsets 4, 2)");
    hg_ret = hg_test_bulk_small(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 8, 4, 2);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE, 0, 0, 16);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE/4,
        BUFSIZE/2 + 1, 0, 16);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("segmented RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, BUFSIZE/4)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE/8,
        BUFSIZE/2 + 1, BUFSIZE/4, 16);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("over-segmented RPC bulk (size BUFSIZE, offsets 0, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE, 0, 0,
        1024);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("over-segmented RPC bulk (size BUFSIZE/4, offsets BUFSIZE/2 + 1, 0)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE/4,
        BUFSIZE/2 + 1, 0, 1024);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    HG_TEST("over-segmented RPC bulk (size BUFSIZE/8, offsets BUFSIZE/2 + 1, BUFSIZE/4)");
    hg_ret = hg_test_bulk_seg(hg_test_info.hg_class, hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, BUFSIZE/8,
        BUFSIZE/2 + 1, BUFSIZE/4, 1024);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

    if (strcmp(HG_Class_get_name(hg_test_info.hg_class), "ofi") == 0) {
        HG_TEST("bind contiguous RPC bulk (size BUFSIZE, offsets 0, 0)");
        hg_ret = hg_test_bulk_contig(hg_test_info.hg_class, hg_test_info.context,
            hg_test_info.request_class, 1, hg_test_info.target_addr, BUFSIZE, 0, 0);
        if (hg_ret != HG_SUCCESS) {
            ret = EXIT_FAILURE;
            goto done;
        }
        HG_PASSED();
    }

done:
    if (ret != EXIT_SUCCESS)
        HG_FAILED();
    HG_Test_finalize(&hg_test_info);
    return ret;
}
