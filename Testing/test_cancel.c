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

extern hg_id_t hg_test_rpc_open_id_g;
extern hg_id_t hg_test_bulk_write_id_g;

static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_CANCELED) {
        fprintf(stderr, "Error: HG_Forward() was not canceled: %d\n",
            callback_info->ret);

        /* Get output */
        ret = HG_Get_output(handle, &rpc_open_out_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not get output\n");
            goto done;
        }

        /* Get output parameters */
        rpc_open_ret = rpc_open_out_struct.ret;
        rpc_open_event_id = rpc_open_out_struct.event_id;
        printf("rpc_open returned: %d with event_id: %d\n", rpc_open_ret,
            rpc_open_event_id);

        /* Free request */
        ret = HG_Free_output(handle, &rpc_open_out_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free output\n");
            goto done;
        }
    } else {
        printf("HG_Forward() was successfully canceled\n");
    }

    hg_request_complete(request);

done:
    return ret;
}

#ifdef NA_HAS_CCI
static hg_return_t
hg_test_bulk_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_CANCELED) {
        /* Get output */
        ret = HG_Get_output(handle, &bulk_write_out_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not get output\n");
            goto done;
        }

        /* Get output parameters */
        bulk_write_ret = bulk_write_out_struct.ret;
        printf("bulk_write returned: %zu\n", bulk_write_ret);

        /* Free request */
        ret = HG_Free_output(handle, &bulk_write_out_struct);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not free output\n");
            goto done;
        }
    } else {
        printf("HG_Forward() was successfully canceled\n");
    }

    hg_request_complete(request);

done:
    return ret;
}
#endif

static hg_return_t
cancel_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;

    rpc_open_in_t rpc_open_in_struct;
    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    hg_return_t ret;

    request = hg_request_create(request_class);

    ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Fill input structure */
    rpc_open_handle.cookie = 12345;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    ret = HG_Forward(handle, hg_test_rpc_forward_cb, request,
        &rpc_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    ret = HG_Cancel(handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "HG_Cancel failed: %d\n", ret);
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        goto done;
    }

    hg_request_destroy(request);

done:
    return ret;
}

#ifdef NA_HAS_CCI
static hg_return_t
cancel_bulk_transfer(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    bulk_write_in_t bulk_write_in_struct;
    int *bulk_buf = NULL;
    void *buf_ptr[1];
    size_t count =  (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE) / sizeof(int);
    size_t bulk_size = count * sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_return_t ret;
    size_t i;

    /* Prepare bulk_buf */
    bulk_buf = (int*) malloc(bulk_size);
    for (i = 0; i < count; i++) {
        bulk_buf[i] = (int) i;
    }
    *buf_ptr = bulk_buf;

    request = hg_request_create(request_class);

    ret = HG_Create(context, addr, hg_test_bulk_write_id_g, &handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Register memory */
    ret = HG_Bulk_create(hg_class, 1, buf_ptr, (hg_size_t *) &bulk_size,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        goto done;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = -1; /* To tell target to cancel bulk transfer */
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_write_id_g);
    ret = HG_Forward(handle, hg_test_bulk_forward_cb, request,
            &bulk_write_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Free memory handle */
    ret = HG_Bulk_free(bulk_handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        goto done;
    }

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        goto done;
    }

    hg_request_destroy(request);

done:
    return ret;
}
#endif

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_addr_t addr;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
        &request_class);

    cancel_rpc(context, request_class, addr);

#ifdef NA_HAS_CCI
    if (strcmp(HG_Class_get_name(hg_class), "cci") == 0)
        cancel_bulk_transfer(hg_class, context, request_class, addr);
#endif

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
