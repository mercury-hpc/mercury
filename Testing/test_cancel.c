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

#include <stdio.h>
#include <stdlib.h>

extern hg_id_t hg_test_cancel_rpc_id_g;

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
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_CANCELED) {
        HG_TEST_LOG_DEBUG("Error: HG_Forward() was not canceled: %d",
            callback_info->ret);
    } else {
        HG_TEST_LOG_DEBUG("HG_Forward() was successfully canceled");
    }

    hg_request_complete(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_cancel_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_return_t ret = HG_SUCCESS;

    request = hg_request_create(request_class);

    /* Create RPC request */
    ret = HG_Create(context, addr, rpc_id, &handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create handle");
        goto done;
    }

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %u...", rpc_id);
    ret = HG_Forward(handle, callback, request, NULL);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not forward call");
        goto done;
    }

    /* Cancel request */
    ret = HG_Cancel(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not cancel call");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy handle");
        goto done;
    }

done:
    hg_request_destroy(request);
    return ret;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_test_info hg_test_info = { 0 };
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    HG_Test_init(argc, argv, &hg_test_info);

    /* Cancel RPC test */
    HG_TEST("cancel RPC");
    hg_ret = hg_test_cancel_rpc(hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr,
        hg_test_cancel_rpc_id_g, hg_test_rpc_forward_cb);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }
    HG_PASSED();

done:
    if (ret != EXIT_SUCCESS)
        HG_FAILED();
    HG_Test_finalize(&hg_test_info);
    return ret;
}
