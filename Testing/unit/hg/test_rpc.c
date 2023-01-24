/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_unit.h"

/****************/
/* Local Macros */
/****************/

/* Test path */
#define HG_TEST_RPC_PATH (HG_TEST_TEMP_DIRECTORY "/test.txt")

/* Wait timeout in ms */
#define HG_TEST_WAIT_TIMEOUT (HG_TEST_TIMEOUT * 1000)

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct forward_cb_args {
    hg_request_t *request;
    rpc_handle_t *rpc_handle;
    hg_return_t ret;
    bool no_entry;
};

struct forward_multi_cb_args {
    rpc_handle_t *rpc_handle;
    hg_return_t *rets;
    int32_t expected_count; /* Expected count */
    int32_t complete_count; /* Completed count */
    hg_request_t *request;  /* Request */
};

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_rpc_no_input(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request);

static hg_return_t
hg_test_rpc_input(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request);

static hg_return_t
hg_test_rpc_inv(
    hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id, hg_request_t *request);

static hg_return_t
hg_test_rpc_output_cb(const struct hg_cb_info *callback_info);

static hg_return_t
hg_test_rpc_no_output_cb(const struct hg_cb_info *callback_info);

#ifndef HG_HAS_XDR
static hg_return_t
hg_test_rpc_output_overflow_cb(const struct hg_cb_info *callback_info);
#endif

static hg_return_t
hg_test_rpc_cancel(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request);

static hg_return_t
hg_test_rpc_multi(hg_handle_t *handles, size_t handle_max, hg_addr_t addr,
    hg_uint8_t target_id, hg_id_t rpc_id, hg_cb_t callback,
    hg_request_t *request);

static hg_return_t
hg_test_rpc_multi_cb(const struct hg_cb_info *callback_info);

/*******************/
/* Local Variables */
/*******************/

extern hg_id_t hg_test_rpc_null_id_g;
extern hg_id_t hg_test_rpc_open_id_g;
extern hg_id_t hg_test_rpc_open_id_no_resp_g;
extern hg_id_t hg_test_overflow_id_g;
extern hg_id_t hg_test_cancel_rpc_id_g;

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_no_input(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request)
{
    hg_return_t ret;
    struct forward_cb_args forward_cb_args = {.request = request,
        .rpc_handle = NULL,
        .ret = HG_SUCCESS,
        .no_entry = false};
    unsigned int flag;
    int rc;

    hg_request_reset(request);

    ret = HG_Reset(handle, addr, rpc_id);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);

    ret = HG_Forward(handle, callback, &forward_cb_args, NULL);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    rc = hg_request_wait(request, HG_TEST_WAIT_TIMEOUT, &flag);
    HG_TEST_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_PROTOCOL_ERROR,
        "hg_request_wait() failed");

    HG_TEST_CHECK_ERROR(
        !flag, error, ret, HG_TIMEOUT, "hg_request_wait() timed out");
    ret = forward_cb_args.ret;
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "Error in HG callback (%s)", HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_input(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request)
{
    hg_return_t ret;
    rpc_handle_t rpc_open_handle = {.cookie = 100};
    struct forward_cb_args forward_cb_args = {.request = request,
        .rpc_handle = &rpc_open_handle,
        .ret = HG_SUCCESS,
        .no_entry = false};
    rpc_open_in_t in_struct = {
        .handle = rpc_open_handle, .path = HG_TEST_RPC_PATH};
    unsigned int flag;
    int rc;

    hg_request_reset(request);

    ret = HG_Reset(handle, addr, rpc_id);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);

    ret = HG_Forward(handle, callback, &forward_cb_args, &in_struct);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    rc = hg_request_wait(request, HG_TEST_WAIT_TIMEOUT, &flag);
    HG_TEST_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_PROTOCOL_ERROR,
        "hg_request_wait() failed");

    HG_TEST_CHECK_ERROR(
        !flag, error, ret, HG_TIMEOUT, "hg_request_wait() timed out");
    ret = forward_cb_args.ret;
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "Error in HG callback (%s)", HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_inv(
    hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id, hg_request_t *request)
{
    hg_return_t ret;
    struct forward_cb_args forward_cb_args = {.request = request,
        .rpc_handle = NULL,
        .ret = HG_SUCCESS,
        .no_entry = true};
    unsigned int flag;
    int rc;

    hg_request_reset(request);

    ret = HG_Reset(handle, addr, rpc_id);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);

    ret = HG_Forward(handle, hg_test_rpc_no_output_cb, &forward_cb_args, NULL);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    rc = hg_request_wait(request, HG_TEST_WAIT_TIMEOUT, &flag);
    HG_TEST_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_PROTOCOL_ERROR,
        "hg_request_wait() failed");

    HG_TEST_CHECK_ERROR(
        !flag, error, ret, HG_TIMEOUT, "hg_request_wait() timed out");
    ret = forward_cb_args.ret;
    HG_TEST_CHECK_ERROR_NORET(ret != HG_NOENTRY, error,
        "Error in HG callback (%s)", HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_output_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = callback_info->ret;

    if (args->no_entry && ret == HG_NOENTRY)
        goto done;

    HG_TEST_CHECK_HG_ERROR(done, ret, "Error in HG callback (%s)",
        HG_Error_to_string(callback_info->ret));

    /* Get output */
    ret = HG_Get_output(handle, &rpc_open_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

    /* Get output parameters */
    rpc_open_ret = rpc_open_out_struct.ret;
    rpc_open_event_id = rpc_open_out_struct.event_id;
    HG_TEST_LOG_DEBUG("rpc_open returned: %d with event_id: %d", rpc_open_ret,
        rpc_open_event_id);
    (void) rpc_open_ret;
    HG_TEST_CHECK_ERROR(rpc_open_event_id != (int) args->rpc_handle->cookie,
        free, ret, HG_FAULT, "Cookie did not match RPC response");

free:
    /* Free output */
    ret = HG_Free_output(handle, &rpc_open_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    args->ret = ret;

    hg_request_complete(args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_no_output_cb(const struct hg_cb_info *callback_info)
{
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;

    args->ret = callback_info->ret;

    hg_request_complete(args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
#ifndef HG_HAS_XDR
static hg_return_t
hg_test_rpc_output_overflow_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    overflow_out_t out_struct;
#    ifdef HG_HAS_DEBUG
    hg_string_t string;
    size_t string_len;
#    endif
    hg_return_t ret = callback_info->ret;

    HG_TEST_CHECK_HG_ERROR(done, ret, "Error in HG callback (%s)",
        HG_Error_to_string(callback_info->ret));

    /* Get output */
    ret = HG_Get_output(handle, &out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

    /* Get output parameters */
#    ifdef HG_HAS_DEBUG
    string = out_struct.string;
    string_len = out_struct.string_len;
#    endif
    HG_TEST_LOG_DEBUG("Returned string (length %zu): %s", string_len, string);

    /* Free output */
    ret = HG_Free_output(handle, &out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    args->ret = ret;

    hg_request_complete(args->request);

    return HG_SUCCESS;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_cancel(hg_handle_t handle, hg_addr_t addr, hg_id_t rpc_id,
    hg_cb_t callback, hg_request_t *request)
{
    hg_return_t ret;
    struct forward_cb_args forward_cb_args = {
        .request = request, .ret = HG_SUCCESS};
    unsigned int flag;
    int rc;

    hg_request_reset(request);

    ret = HG_Reset(handle, addr, rpc_id);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);

    ret = HG_Forward(handle, callback, &forward_cb_args, NULL);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    /* Cancel request before making progress, this ensures that the RPC has
     * not completed yet. */
    ret = HG_Cancel(handle);
    HG_TEST_CHECK_HG_ERROR(
        error, ret, "HG_Cancel() failed (%s)", HG_Error_to_string(ret));

    rc = hg_request_wait(request, HG_TEST_WAIT_TIMEOUT, &flag);
    HG_TEST_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_PROTOCOL_ERROR,
        "hg_request_wait() failed");

    HG_TEST_CHECK_ERROR(
        !flag, error, ret, HG_TIMEOUT, "hg_request_wait() timed out");
    ret = forward_cb_args.ret;
    HG_TEST_CHECK_ERROR_NORET(ret != HG_CANCELED, error,
        "Error in HG callback (%s)", HG_Error_to_string(ret));

    return HG_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_multi(hg_handle_t *handles, size_t handle_max, hg_addr_t addr,
    hg_uint8_t target_id, hg_id_t rpc_id, hg_cb_t callback,
    hg_request_t *request)
{
    hg_return_t ret;
    rpc_handle_t rpc_open_handle = {.cookie = 100};
    struct forward_multi_cb_args forward_multi_cb_args = {
        .rpc_handle = &rpc_open_handle,
        .request = request,
        .rets = NULL,
        .complete_count = 0,
        .expected_count = (int32_t) handle_max};
    rpc_open_in_t in_struct = {
        .handle = rpc_open_handle, .path = HG_TEST_RPC_PATH};
    size_t i;
    unsigned int flag;
    int rc;

    hg_request_reset(request);

    forward_multi_cb_args.rets =
        (hg_return_t *) calloc(handle_max, sizeof(hg_return_t));
    HG_TEST_CHECK_ERROR(forward_multi_cb_args.rets == NULL, error, ret,
        HG_NOMEM, "Could not allocate array of return values");

    /**
     * Forwarding multiple requests
     */
    HG_TEST_LOG_DEBUG("Creating %zu requests...", handle_max);
    for (i = 0; i < handle_max; i++) {
        ret = HG_Reset(handles[i], addr, rpc_id);
        HG_TEST_CHECK_HG_ERROR(
            error, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

        ret = HG_Set_target_id(handles[i], target_id);
        HG_TEST_CHECK_HG_ERROR(error, ret, "HG_Set_target_id() failed (%s)",
            HG_Error_to_string(ret));

        HG_TEST_LOG_DEBUG(
            " %zu Forwarding rpc_open, op id: %" PRIu64 "...", i, rpc_id);

        ret = HG_Forward(
            handles[i], callback, &forward_multi_cb_args, &in_struct);
        HG_TEST_CHECK_HG_ERROR(
            error, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));
    }

    rc = hg_request_wait(request, HG_TEST_WAIT_TIMEOUT, &flag);
    HG_TEST_CHECK_ERROR(rc != HG_UTIL_SUCCESS, error, ret, HG_PROTOCOL_ERROR,
        "hg_request_wait() failed");

    HG_TEST_CHECK_ERROR(
        !flag, error, ret, HG_TIMEOUT, "hg_request_wait() timed out");

    for (i = 0; i < handle_max; i++) {
        ret = forward_multi_cb_args.rets[i];
        HG_TEST_CHECK_HG_ERROR(
            error, ret, "Error in HG callback (%s)", HG_Error_to_string(ret));
    }

    HG_TEST_LOG_DEBUG("Done");

    free(forward_multi_cb_args.rets);

    return HG_SUCCESS;

error:
    free(forward_multi_cb_args.rets);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_multi_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_multi_cb_args *args =
        (struct forward_multi_cb_args *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = callback_info->ret;

    HG_TEST_CHECK_HG_ERROR(done, ret, "Error in HG callback (%s)",
        HG_Error_to_string(callback_info->ret));

    /* Get output */
    ret = HG_Get_output(handle, &rpc_open_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Get_output() failed (%s)", HG_Error_to_string(ret));

    /* Get output parameters */
    rpc_open_ret = rpc_open_out_struct.ret;
    rpc_open_event_id = rpc_open_out_struct.event_id;
    HG_TEST_LOG_DEBUG("rpc_open returned: %d with event_id: %d", rpc_open_ret,
        rpc_open_event_id);
    (void) rpc_open_ret;
    HG_TEST_CHECK_ERROR(rpc_open_event_id != (int) args->rpc_handle->cookie,
        free, ret, HG_FAULT, "Cookie did not match RPC response");

free:
    /* Free output */
    ret = HG_Free_output(handle, &rpc_open_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    args->rets[args->complete_count] = ret;
    if (++args->complete_count == args->expected_count)
        hg_request_complete(args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    struct hg_unit_info info;
    hg_return_t hg_ret;
    hg_id_t inv_id;

    /* Initialize the interface */
    hg_ret = hg_unit_init(argc, argv, false, &info);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_unit_init() failed (%s)",
        HG_Error_to_string(hg_ret));

    /* NULL RPC test */
    HG_TEST("NULL RPC");
    hg_ret = hg_test_rpc_no_input(info.handles[0], info.target_addr,
        hg_test_rpc_null_id_g, hg_test_rpc_no_output_cb, info.request);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_no_input() failed (%s)",
        HG_Error_to_string(hg_ret));
    HG_PASSED();

    /* Simple RPC test */
    HG_TEST("RPC with response");
    hg_ret = hg_test_rpc_input(info.handles[0], info.target_addr,
        hg_test_rpc_open_id_g, hg_test_rpc_output_cb, info.request);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_input() failed (%s)",
        HG_Error_to_string(hg_ret));
    HG_PASSED();

    /* RPC test with lookup/free */
    if (!info.hg_test_info.na_test_info.self_send &&
        strcmp(HG_Class_get_name(info.hg_class), "mpi")) {
        int i;

        hg_ret = HG_Addr_set_remove(info.hg_class, info.target_addr);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret,
            "HG_Addr_set_remove() failed (%s)", HG_Error_to_string(hg_ret));

        hg_ret = HG_Addr_free(info.hg_class, info.target_addr);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret, "HG_Addr_free() failed (%s)",
            HG_Error_to_string(hg_ret));
        info.target_addr = HG_ADDR_NULL;

        HG_TEST("RPC with multiple lookup/free");
        for (i = 0; i < 32; i++) {
            hg_ret = HG_Addr_lookup2(info.hg_class,
                info.hg_test_info.na_test_info.target_name, &info.target_addr);
            HG_TEST_CHECK_HG_ERROR(error, hg_ret,
                "HG_Addr_lookup2() failed (%s)", HG_Error_to_string(hg_ret));

            hg_ret = hg_test_rpc_input(info.handles[0], info.target_addr,
                hg_test_rpc_open_id_g, hg_test_rpc_output_cb, info.request);
            HG_TEST_CHECK_HG_ERROR(error, hg_ret,
                "hg_test_rpc_input() failed (%s)", HG_Error_to_string(hg_ret));

            hg_ret = HG_Addr_set_remove(info.hg_class, info.target_addr);
            HG_TEST_CHECK_HG_ERROR(error, hg_ret,
                "HG_Addr_set_remove() failed (%s)", HG_Error_to_string(hg_ret));

            hg_ret = HG_Addr_free(info.hg_class, info.target_addr);
            HG_TEST_CHECK_HG_ERROR(error, hg_ret, "HG_Addr_free() failed (%s)",
                HG_Error_to_string(hg_ret));
            info.target_addr = HG_ADDR_NULL;
        }
        HG_PASSED();

        hg_ret = HG_Addr_lookup2(info.hg_class,
            info.hg_test_info.na_test_info.target_name, &info.target_addr);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret, "HG_Addr_lookup2() failed (%s)",
            HG_Error_to_string(hg_ret));
    }

    /* RPC test with no response */
    HG_TEST("RPC without response");
    hg_ret = hg_test_rpc_input(info.handles[0], info.target_addr,
        hg_test_rpc_open_id_no_resp_g, hg_test_rpc_no_output_cb, info.request);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_input() failed (%s)",
        HG_Error_to_string(hg_ret));
    HG_PASSED();

    /* RPC test with unregistered ID */
    inv_id = MERCURY_REGISTER(info.hg_class, "unreg_id", void, void, NULL);
    HG_TEST_CHECK_ERROR_NORET(inv_id == 0, error, "HG_Register() failed");
    hg_ret = HG_Deregister(info.hg_class, inv_id);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "HG_Deregister() failed (%s)",
        HG_Error_to_string(hg_ret));

    HG_TEST("RPC with unregistered ID");
    HG_Test_log_disable(); // Expected to produce errors
    hg_ret = hg_test_rpc_input(info.handles[0], info.target_addr, inv_id,
        hg_test_rpc_output_cb, info.request);
    HG_Test_log_enable();
    HG_TEST_CHECK_ERROR_NORET(hg_ret != HG_NOENTRY, error,
        "hg_test_rpc_input() failed (%s, expected %s)",
        HG_Error_to_string(hg_ret), HG_Error_to_string(HG_NOENTRY));
    HG_PASSED();

    if (!info.hg_test_info.na_test_info.self_send) {
        /* RPC test with invalid ID (not registered on server) */
        inv_id = MERCURY_REGISTER(info.hg_class, "inv_id", void, void, NULL);
        HG_TEST_CHECK_ERROR_NORET(inv_id == 0, error, "HG_Register() failed");

        HG_TEST("RPC not registered on server");
        hg_ret = hg_test_rpc_inv(
            info.handles[0], info.target_addr, inv_id, info.request);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_inv() failed (%s)",
            HG_Error_to_string(hg_ret));
        HG_PASSED();
    }

#ifndef HG_HAS_XDR
    /* Overflow RPC test */
    HG_TEST("RPC with output overflow");
    hg_ret = hg_test_rpc_no_input(info.handles[0], info.target_addr,
        hg_test_overflow_id_g, hg_test_rpc_output_overflow_cb, info.request);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_no_input() failed (%s)",
        HG_Error_to_string(hg_ret));
    HG_PASSED();
#endif

    /* Cancel RPC test (self cancelation is not supported) */
    if (!info.hg_test_info.na_test_info.self_send) {
        HG_TEST("RPC cancelation");
        hg_ret = hg_test_rpc_cancel(info.handles[0], info.target_addr,
            hg_test_cancel_rpc_id_g, hg_test_rpc_no_output_cb, info.request);
        HG_TEST_CHECK_HG_ERROR(error, hg_ret,
            "hg_test_rpc_cancel() failed (%s)", HG_Error_to_string(hg_ret));
        HG_PASSED();
    }

    /* RPC test with multiple handle in flight */
    HG_TEST("concurrent RPCs");
    hg_ret = hg_test_rpc_multi(info.handles, info.handle_max, info.target_addr,
        0, hg_test_rpc_open_id_g, hg_test_rpc_multi_cb, info.request);
    HG_TEST_CHECK_HG_ERROR(error, hg_ret, "hg_test_rpc_multiple() failed (%s)",
        HG_Error_to_string(hg_ret));
    HG_PASSED();

    /* RPC test with multiple handle to multiple target contexts */
    if (info.hg_test_info.na_test_info.max_contexts) {
        hg_uint8_t i,
            context_count = info.hg_test_info.na_test_info.max_contexts;

        HG_TEST("multi context target RPCs");
        for (i = 0; i < context_count; i++) {
            hg_ret = hg_test_rpc_multi(info.handles, info.handle_max,
                info.target_addr, i, hg_test_rpc_open_id_g,
                hg_test_rpc_multi_cb, info.request);
            HG_TEST_CHECK_HG_ERROR(error, hg_ret,
                "hg_test_rpc_multiple() failed (%s)",
                HG_Error_to_string(hg_ret));
        }
        HG_PASSED();
    }

    hg_unit_cleanup(&info);

    return EXIT_SUCCESS;

error:
    hg_unit_cleanup(&info);

    return EXIT_FAILURE;
}
