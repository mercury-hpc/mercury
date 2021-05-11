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

/* Do not use HG_TEST_MAX_HANDLES for that and keep it fixed */
#define NINFLIGHT (16)

/************************************/
/* Local Type and Struct Definition */
/************************************/

struct forward_cb_args {
    hg_request_t *request;
    rpc_handle_t *rpc_handle;
};

struct lookup_cb_args {
    hg_request_t *request;
    hg_addr_t *addr_ptr;
};

/********************/
/* Local Prototypes */
/********************/

static hg_return_t
hg_test_rpc_null_cb(const struct hg_cb_info *callback_info);
static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info);
static hg_return_t
hg_test_rpc_forward_no_resp_cb(const struct hg_cb_info *callback_info);
static hg_return_t
hg_test_rpc_lookup_cb(const struct hg_cb_info *callback_info);
static hg_return_t
hg_test_rpc_forward_reset_cb(const struct hg_cb_info *callback_info);
#ifndef HG_HAS_XDR
static hg_return_t
hg_test_rpc_forward_overflow_cb(const struct hg_cb_info *callback_info);
#endif

static hg_return_t
hg_test_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback);
static hg_return_t
hg_test_rpc_lookup(hg_context_t *context, hg_request_class_t *request_class,
    const char *target_name, hg_id_t rpc_id, hg_cb_t callback);
static hg_return_t
hg_test_rpc_reset(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback);
static hg_return_t
hg_test_rpc_mask(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback);
static hg_return_t
hg_test_rpc_multiple(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_uint8_t target_id, hg_id_t rpc_id, hg_cb_t callback);
#ifndef HG_HAS_XDR
static hg_return_t
hg_test_overflow(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback);
#endif
static hg_return_t
hg_test_cancel_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback);

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
hg_test_rpc_null_cb(const struct hg_cb_info *callback_info)
{
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret == HG_NOENTRY)
        goto done;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

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
        done, ret, HG_FAULT, "Cookie did not match RPC response");

    /* Free request */
    ret = HG_Free_output(handle, &rpc_open_out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_forward_no_resp_cb(const struct hg_cb_info *callback_info)
{
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_lookup_cb(const struct hg_cb_info *callback_info)
{
    struct lookup_cb_args *request_args =
        (struct lookup_cb_args *) callback_info->arg;

    *request_args->addr_ptr = callback_info->info.lookup.addr;

    hg_request_complete(request_args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_forward_reset_cb(const struct hg_cb_info *callback_info)
{
    struct forward_cb_args *args =
        (struct forward_cb_args *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

    ret = HG_Reset(callback_info->info.forward.handle, HG_ADDR_NULL, 0);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

done:
    hg_request_complete(args->request);
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifndef HG_HAS_XDR
static hg_return_t
hg_test_rpc_forward_overflow_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    overflow_out_t out_struct;
#    ifdef HG_HAS_DEBUG
    hg_string_t string;
    size_t string_len;
#    endif
    hg_return_t ret = HG_SUCCESS;

    HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
        "Error in HG callback (%s)", HG_Error_to_string(callback_info->ret));

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

    /* Free request */
    ret = HG_Free_output(handle, &out_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Free_output() failed (%s)", HG_Error_to_string(ret));

done:
    hg_request_complete(request);
    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_forward_cancel_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret == HG_CANCELED)
        HG_TEST_LOG_DEBUG("HG_Forward() was successfully canceled");
    else
        HG_TEST_CHECK_ERROR_NORET(callback_info->ret != HG_SUCCESS, done,
            "Error in HG callback (%s)",
            HG_Error_to_string(callback_info->ret));

done:
    hg_request_complete(request);
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_null(
    hg_context_t *context, hg_request_class_t *request_class, hg_addr_t addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;

    request = hg_request_create(request_class);

    /* Create RPC request */
    ret = HG_Create(context, addr, hg_test_rpc_null_id_g, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG(
        "Forwarding null RPC, op id: %" PRIu64 "...", hg_test_rpc_null_id_g);
    forward_cb_args.request = request;

again:
    ret = HG_Forward(handle, hg_test_rpc_null_cb, &forward_cb_args, NULL);
    if (ret == HG_AGAIN) {
        hg_request_wait(request, 0, NULL);
        goto again;
    }
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    hg_const_string_t rpc_open_path = HG_TEST_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    rpc_open_in_t rpc_open_in_struct;

    request = hg_request_create(request_class);

    /* Create RPC request */
    ret = HG_Create(context, addr, rpc_id, &handle);
    if (ret == HG_NOENTRY)
        goto done;
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    rpc_open_handle.cookie = 100;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.rpc_handle = &rpc_open_handle;
again:
    ret = HG_Forward(handle, callback, &forward_cb_args, &rpc_open_in_struct);
    if (ret == HG_AGAIN) {
        hg_request_wait(request, 0, NULL);
        goto again;
    }
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_lookup(hg_context_t *context, hg_request_class_t *request_class,
    const char *target_name, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    hg_const_string_t rpc_open_path = HG_TEST_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    rpc_open_in_t rpc_open_in_struct;
    hg_addr_t target_addr = HG_ADDR_NULL;
    int i;

    for (i = 0; i < 32; i++) {
        struct lookup_cb_args lookup_args;
        unsigned int flag = 0;

        request = hg_request_create(request_class);

        /* Look up target addr using target name info */
        lookup_args.addr_ptr = &target_addr;
        lookup_args.request = request;

        /* Forward call to remote addr and get a new request */
        ret = HG_Addr_lookup1(context, hg_test_rpc_lookup_cb, &lookup_args,
            target_name, HG_OP_ID_IGNORE);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_lookup1() failed (%s)",
            HG_Error_to_string(ret));

        /* Wait for request to be marked completed */
        hg_request_wait(request, HG_MAX_IDLE_TIME, &flag);
        HG_TEST_CHECK_ERROR(
            flag == 0, done, ret, HG_TIMEOUT, "Operation did not complete");

        /* Reset request */
        hg_request_reset(request);

        /* Create RPC request */
        ret = HG_Create(context, target_addr, rpc_id, &handle);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

        /* Fill input structure */
        rpc_open_handle.cookie = 100;
        rpc_open_in_struct.path = rpc_open_path;
        rpc_open_in_struct.handle = rpc_open_handle;

        /* Forward call to remote addr and get a new request */
        HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
        forward_cb_args.request = request;
        forward_cb_args.rpc_handle = &rpc_open_handle;
        ret =
            HG_Forward(handle, callback, &forward_cb_args, &rpc_open_in_struct);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

        hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

        /* Complete */
        ret = HG_Destroy(handle);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

        ret = HG_Addr_set_remove(context->hg_class, target_addr);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Addr_set_remove() failed (%s)",
            HG_Error_to_string(ret));

        ret = HG_Addr_free(context->hg_class, target_addr);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Addr_free() failed (%s)", HG_Error_to_string(ret));
        target_addr = HG_ADDR_NULL;

        hg_request_destroy(request);
        request = NULL;
    }

done:
    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_reset(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    hg_const_string_t rpc_open_path = HG_TEST_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    rpc_open_in_t rpc_open_in_struct;

    request = hg_request_create(request_class);

    /* Create request with invalid RPC id */
    ret = HG_Create(context, HG_ADDR_NULL, 0, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Reset with valid addr and ID */
    ret = HG_Reset(handle, addr, rpc_id);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Reset() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    rpc_open_handle.cookie = 100;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.rpc_handle = &rpc_open_handle;
    ret = HG_Forward(handle, callback, &forward_cb_args, &rpc_open_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_mask(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;
    struct forward_cb_args forward_cb_args;
    hg_const_string_t rpc_open_path = HG_TEST_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    rpc_open_in_t rpc_open_in_struct;

    request = hg_request_create(request_class);

    /* Create request with invalid RPC id */
    ret = HG_Create(context, addr, rpc_id, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Set_target_id(handle, 0);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Set_target_id() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    rpc_open_handle.cookie = 100;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
    forward_cb_args.request = request;
    forward_cb_args.rpc_handle = &rpc_open_handle;
    ret = HG_Forward(handle, callback, &forward_cb_args, &rpc_open_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_rpc_multiple(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_uint8_t target_id, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request1 = NULL, *request2 = NULL;
    hg_handle_t handle1, handle2;
    struct forward_cb_args forward_cb_args1, forward_cb_args2;
    hg_return_t ret = HG_SUCCESS;
    rpc_open_in_t rpc_open_in_struct;
    hg_const_string_t rpc_open_path = HG_TEST_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle1, rpc_open_handle2;
    /* Used for multiple in-flight RPCs */
    hg_request_t *request_m[NINFLIGHT];
    hg_handle_t handle_m[NINFLIGHT];
    struct forward_cb_args forward_cb_args_m[NINFLIGHT];
    rpc_handle_t rpc_open_handle_m[NINFLIGHT];
    unsigned int i;

    /* Create request 1 */
    request1 = hg_request_create(request_class);

    ret = HG_Create(context, addr, rpc_id, &handle1);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Set_target_id(handle1, target_id);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Set_target_id() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    rpc_open_handle1.cookie = 1;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle1;

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
    forward_cb_args1.request = request1;
    forward_cb_args1.rpc_handle = &rpc_open_handle1;
    ret = HG_Forward(handle1, callback, &forward_cb_args1, &rpc_open_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    /* Create request 2 */
    request2 = hg_request_create(request_class);

    ret = HG_Create(context, addr, rpc_id, &handle2);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Set_target_id(handle2, target_id);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Set_target_id() failed (%s)", HG_Error_to_string(ret));

    /* Fill input structure */
    rpc_open_handle2.cookie = 2;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle2;

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding rpc_open, op id: %" PRIu64 "...", rpc_id);
    forward_cb_args2.request = request2;
    forward_cb_args2.rpc_handle = &rpc_open_handle2;
    ret = HG_Forward(handle2, callback, &forward_cb_args2, &rpc_open_in_struct);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request2, HG_MAX_IDLE_TIME, NULL);
    hg_request_wait(request1, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    ret = HG_Destroy(handle1);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    ret = HG_Destroy(handle2);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

    hg_request_destroy(request1);
    hg_request_destroy(request2);

    /**
     * Forwarding multiple requests
     */
    HG_TEST_LOG_DEBUG("Creating %u requests...", NINFLIGHT);
    for (i = 0; i < NINFLIGHT; i++) {
        request_m[i] = hg_request_create(request_class);
        ret = HG_Create(context, addr, rpc_id, handle_m + i);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

        ret = HG_Set_target_id(handle_m[i], target_id);
        HG_TEST_CHECK_HG_ERROR(done, ret, "HG_Set_target_id() failed (%s)",
            HG_Error_to_string(ret));

        rpc_open_handle_m[i].cookie = i;
        rpc_open_in_struct.path = rpc_open_path;
        rpc_open_in_struct.handle = rpc_open_handle_m[i];
        HG_TEST_LOG_DEBUG(
            " %d Forwarding rpc_open, op id: %" PRIu64 "...", i, rpc_id);
        forward_cb_args_m[i].request = request_m[i];
        forward_cb_args_m[i].rpc_handle = &rpc_open_handle_m[i];
again:
        ret = HG_Forward(
            handle_m[i], callback, &forward_cb_args_m[i], &rpc_open_in_struct);
        if (ret == HG_AGAIN) {
            hg_request_wait(request_m[i], 0, NULL);
            goto again;
        }
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));
    }

    /* Complete */
    for (i = 0; i < NINFLIGHT; i++) {
        hg_request_wait(request_m[i], HG_MAX_IDLE_TIME, NULL);

        ret = HG_Destroy(handle_m[i]);
        HG_TEST_CHECK_HG_ERROR(
            done, ret, "HG_Destroy() failed (%s)", HG_Error_to_string(ret));

        hg_request_destroy(request_m[i]);
    }
    HG_TEST_LOG_DEBUG("Done");

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
#ifndef HG_HAS_XDR
static hg_return_t
hg_test_overflow(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;

    request = hg_request_create(request_class);

    /* Create RPC request */
    ret = HG_Create(context, addr, rpc_id, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);
    ret = HG_Forward(handle, callback, request, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
    cleanup_ret = HG_Destroy(handle);
    HG_TEST_CHECK_ERROR_DONE(cleanup_ret != HG_SUCCESS,
        "HG_Destroy() failed (%s)", HG_Error_to_string(cleanup_ret));

    hg_request_destroy(request);

    return ret;
}
#endif

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_cancel_rpc(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr, hg_id_t rpc_id, hg_cb_t callback)
{
    hg_request_t *request = NULL;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t ret = HG_SUCCESS, cleanup_ret;

    request = hg_request_create(request_class);

    /* Create RPC request */
    ret = HG_Create(context, addr, rpc_id, &handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Create() failed (%s)", HG_Error_to_string(ret));

    /* Forward call to remote addr and get a new request */
    HG_TEST_LOG_DEBUG("Forwarding RPC, op id: %" PRIu64 "...", rpc_id);
    ret = HG_Forward(handle, callback, request, NULL);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Forward() failed (%s)", HG_Error_to_string(ret));

    /* Cancel request before making progress, this ensures that the RPC has not
     * completed yet. */
    ret = HG_Cancel(handle);
    HG_TEST_CHECK_HG_ERROR(
        done, ret, "HG_Cancel() failed (%s)", HG_Error_to_string(ret));

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

done:
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
    hg_return_t hg_ret;
    hg_id_t inv_id;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface */
    hg_ret = HG_Test_init(argc, argv, &hg_test_info);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "HG_Test_init() failed");

    /* NULL RPC test */
    HG_TEST("NULL RPC");
    hg_ret = hg_test_rpc_null(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "NULL RPC test failed");
    HG_PASSED();

    /* Simple RPC test */
    HG_TEST("simple RPC");
    hg_ret = hg_test_rpc(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_rpc_open_id_g,
        hg_test_rpc_forward_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "simple RPC test failed");
    HG_PASSED();

    /* RPC test with lookup/free */
    if (!hg_test_info.na_test_info.self_send &&
        strcmp(HG_Class_get_name(hg_test_info.hg_class), "mpi")) {
        hg_request_t *request = NULL;
        struct lookup_cb_args lookup_args;
        unsigned int flag = 0;

        HG_Addr_free(hg_test_info.hg_class, hg_test_info.target_addr);
        hg_test_info.target_addr = HG_ADDR_NULL;

        HG_TEST("lookup RPC");
        hg_ret = hg_test_rpc_lookup(hg_test_info.context,
            hg_test_info.request_class, hg_test_info.na_test_info.target_name,
            hg_test_rpc_open_id_g, hg_test_rpc_forward_cb);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "lookup test failed");
        HG_PASSED();

        request = hg_request_create(hg_test_info.request_class);

        /* Look up target addr using target name info */
        lookup_args.addr_ptr = &hg_test_info.target_addr;
        lookup_args.request = request;

        /* Forward call to remote addr and get a new request */
        hg_ret = HG_Addr_lookup1(hg_test_info.context, hg_test_rpc_lookup_cb,
            &lookup_args, hg_test_info.na_test_info.target_name,
            HG_OP_ID_IGNORE);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "HG_Addr_lookup1() failed (%s)", HG_Error_to_string(hg_ret));

        /* Wait for request to be marked completed */
        hg_request_wait(request, HG_MAX_IDLE_TIME, &flag);
        HG_TEST_CHECK_ERROR(
            flag == 0, done, ret, EXIT_FAILURE, "Operation did not complete");

        /* Destroy request */
        hg_request_destroy(request);
    }

    /* RPC reset test */
    HG_TEST("RPC reset");
    hg_ret = hg_test_rpc_reset(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_rpc_open_id_g,
        hg_test_rpc_forward_cb);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "reset RPC test failed");
    HG_PASSED();

    /* RPC test with tag mask */
    HG_TEST("tagged RPC");
    hg_ret = hg_test_rpc_mask(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_rpc_open_id_g,
        hg_test_rpc_forward_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "tagged RPC test failed");
    HG_PASSED();

    /* RPC test with no response */
    HG_TEST("no response RPC");
    hg_ret = hg_test_rpc(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_rpc_open_id_no_resp_g,
        hg_test_rpc_forward_no_resp_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "no response RPC test failed");
    HG_PASSED();

    /* RPC test with unregistered ID */
    inv_id =
        MERCURY_REGISTER(hg_test_info.hg_class, "unreg_id", void, void, NULL);
    HG_TEST_CHECK_ERROR(
        inv_id == 0, done, ret, EXIT_FAILURE, "HG_Register() failed");
    hg_ret = HG_Deregister(hg_test_info.hg_class, inv_id);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "HG_Deregister() failed (%s)", HG_Error_to_string(hg_ret));

    HG_TEST("unregistered RPC");
    hg_ret = hg_test_rpc(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, inv_id, hg_test_rpc_forward_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_NOENTRY, done, ret, EXIT_FAILURE,
        "unregistered RPC test failed");
    HG_PASSED();

    if (!hg_test_info.na_test_info.self_send) {
        /* RPC test with invalid ID (not registered on server) */
        inv_id =
            MERCURY_REGISTER(hg_test_info.hg_class, "inv_id", void, void, NULL);
        HG_TEST_CHECK_ERROR(
            inv_id == 0, done, ret, EXIT_FAILURE, "HG_Register() failed");

        HG_TEST("invalid RPC");
        hg_ret = hg_test_rpc(hg_test_info.context, hg_test_info.request_class,
            hg_test_info.target_addr, inv_id, hg_test_rpc_forward_cb);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "invalid RPC test failed");
        HG_PASSED();
    }

    /* RPC test with reset */
    HG_TEST("reset RPC");
    hg_ret = hg_test_rpc(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_rpc_open_id_g,
        hg_test_rpc_forward_reset_cb);
    HG_TEST_CHECK_ERROR(
        hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE, "reset RPC test failed");
    HG_PASSED();

    /* RPC test with multiple handle in flight */
    HG_TEST("concurrent RPCs");
    hg_ret = hg_test_rpc_multiple(hg_test_info.context,
        hg_test_info.request_class, hg_test_info.target_addr, 0,
        hg_test_rpc_open_id_g, hg_test_rpc_forward_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "concurrent RPC test failed");
    HG_PASSED();

    /* RPC test with multiple handle to multiple target contexts */
    if (hg_test_info.na_test_info.max_contexts) {
        hg_uint8_t i, context_count = hg_test_info.na_test_info.max_contexts;

        HG_TEST("multi context target RPCs");
        for (i = 0; i < context_count; i++) {
            hg_ret = hg_test_rpc_multiple(hg_test_info.context,
                hg_test_info.request_class, hg_test_info.target_addr, i,
                hg_test_rpc_open_id_g, hg_test_rpc_forward_cb);
            HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
                "multi context target RPC test failed");
        }
        HG_PASSED();
    }

#ifndef HG_HAS_XDR
    /* Overflow RPC test */
    HG_TEST("overflow RPC");
    hg_ret = hg_test_overflow(hg_test_info.context, hg_test_info.request_class,
        hg_test_info.target_addr, hg_test_overflow_id_g,
        hg_test_rpc_forward_overflow_cb);
    HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
        "overflow RPC test failed");
    HG_PASSED();
#endif

    /* Cancel RPC test (self cancelation is not supported) */
    if (!hg_test_info.na_test_info.self_send) {
        HG_TEST("cancel RPC");
        hg_ret = hg_test_cancel_rpc(hg_test_info.context,
            hg_test_info.request_class, hg_test_info.target_addr,
            hg_test_cancel_rpc_id_g, hg_test_rpc_forward_cancel_cb);
        HG_TEST_CHECK_ERROR(hg_ret != HG_SUCCESS, done, ret, EXIT_FAILURE,
            "cancel RPC test failed");
        HG_PASSED();
    }

done:
    if (ret != EXIT_SUCCESS)
        HG_FAILED();

    hg_ret = HG_Test_finalize(&hg_test_info);
    HG_TEST_CHECK_ERROR_DONE(hg_ret != HG_SUCCESS, "HG_Test_finalize() failed");

    return ret;
}
