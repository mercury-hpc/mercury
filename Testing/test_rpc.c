/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
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
extern hg_id_t hg_test_rpc_open_id_no_resp_g;

#define NINFLIGHT 32

struct forward_cb_args {
    hg_request_t *request;
    rpc_handle_t *rpc_handle;
};

static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->info.forward.handle;
    struct forward_cb_args *args = (struct forward_cb_args *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_SUCCESS) {
        HG_LOG_WARNING("Return from callback info is not HG_SUCCESS");
        goto done;
    }

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
    if (rpc_open_event_id != (int) args->rpc_handle->cookie) {
        fprintf(stderr, "Error: Cookie did not match RPC response\n");
        goto done;
    }

    /* Free request */
    ret = HG_Free_output(handle, &rpc_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free output\n");
        goto done;
    }

done:
    hg_request_complete(args->request);
    return ret;
}

static hg_return_t
hg_test_rpc_forward_no_resp_cb(const struct hg_cb_info *callback_info)
{
    struct forward_cb_args *args = (struct forward_cb_args *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_SUCCESS) {
        HG_LOG_WARNING("Return from callback info is not HG_SUCCESS");
        goto done;
    }

done:
    hg_request_complete(args->request);
    return ret;
}

static hg_return_t
hg_test_rpc_invalid(hg_class_t *hg_class, hg_context_t *context,
    hg_request_class_t *request_class, hg_addr_t addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_return_t hg_ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    hg_id_t inv_id;

    /* Register invalid ID */
    inv_id = MERCURY_REGISTER(hg_class, "inv_id", void, void, NULL);

    request = hg_request_create(request_class);

    /* Create request with invalid RPC id */
    hg_ret = HG_Create(context, addr, inv_id, &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Forward call to remote addr and get a new request */
    printf("Forwarding invalid handle, op id: %u...\n", inv_id);
    forward_cb_args.request = request;
    forward_cb_args.rpc_handle = NULL;
    hg_ret = HG_Forward(handle, hg_test_rpc_forward_cb, &forward_cb_args, NULL);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        goto done;
    }

    hg_request_destroy(request);

done:
    return hg_ret;
}

static hg_return_t
hg_test_rpc_no_resp(hg_class_t *hg_class, hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
    hg_return_t hg_ret = HG_SUCCESS;
    struct forward_cb_args forward_cb_args;
    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    rpc_open_in_t  rpc_open_in_struct;
    hg_id_t rpc_id = 0;

    request = hg_request_create(request_class);

    if (hg_class)
        rpc_id = MERCURY_REGISTER(hg_class, "inv_id", void, void, NULL);
    else
        rpc_id = hg_test_rpc_open_id_no_resp_g;

    /* Create request with invalid RPC id */
    hg_ret = HG_Create(context, addr, rpc_id, &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Fill input structure */
    rpc_open_handle.cookie = 100;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_no_resp_g);
    forward_cb_args.request = request;
    forward_cb_args.rpc_handle = &rpc_open_handle;
    hg_ret = HG_Forward(handle, hg_test_rpc_forward_no_resp_cb, &forward_cb_args,
        &rpc_open_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        goto done;
    }

    hg_request_destroy(request);

done:
    return hg_ret;
}

static hg_return_t
hg_test_rpc_multiple(hg_context_t *context, hg_request_class_t *request_class,
    hg_addr_t addr)
{
    hg_request_t *request1 = NULL, *request2 = NULL;
    hg_handle_t handle1, handle2;
    struct forward_cb_args forward_cb_args1, forward_cb_args2;
    hg_return_t hg_ret = HG_SUCCESS;
    rpc_open_in_t  rpc_open_in_struct;
    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle1, rpc_open_handle2;
    /* Used for multiple in-flight RPCs */
    hg_request_t *request_m[NINFLIGHT];
    hg_handle_t handle_m[NINFLIGHT];
    struct forward_cb_args forward_cb_args_m[NINFLIGHT];
    rpc_handle_t rpc_open_handle_m[NINFLIGHT];
    unsigned int i;

    /* Create request 1 */
    request1 = hg_request_create(request_class);

    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle1);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Fill input structure */
    rpc_open_handle1.cookie = 1;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle1;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    forward_cb_args1.request = request1;
    forward_cb_args1.rpc_handle = &rpc_open_handle1;
    hg_ret = HG_Forward(handle1, hg_test_rpc_forward_cb, &forward_cb_args1,
            &rpc_open_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    /* Create request 2 */
    request2 = hg_request_create(request_class);

    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle2);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        goto done;
    }

    /* Fill input structure */
    rpc_open_handle2.cookie = 2;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle2;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    forward_cb_args2.request = request2;
    forward_cb_args2.rpc_handle = &rpc_open_handle2;
    hg_ret = HG_Forward(handle2, hg_test_rpc_forward_cb, &forward_cb_args2,
            &rpc_open_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        goto done;
    }

    hg_request_wait(request2, HG_MAX_IDLE_TIME, NULL);
    hg_request_wait(request1, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    hg_ret = HG_Destroy(handle1);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        goto done;
    }
    hg_ret = HG_Destroy(handle2);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        goto done;
    }

    hg_request_destroy(request1);
    hg_request_destroy(request2);

    /**
     * Forwarding multiple requests
     */
    printf("Creating %u requests...\n", NINFLIGHT);
    for (i = 0; i < NINFLIGHT; i++) {
	    request_m[i] = hg_request_create(request_class);
	    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, handle_m + i );
	    if (hg_ret != HG_SUCCESS) {
		    fprintf(stderr, "Could not start call\n");
		    goto done;
	    }
	    rpc_open_handle_m[i].cookie = i;
	    rpc_open_in_struct.path = rpc_open_path;
	    rpc_open_in_struct.handle = rpc_open_handle_m[i];
	    printf(" %d Forwarding rpc_open, op id: %u...\n", i, hg_test_rpc_open_id_g);
	    forward_cb_args_m[i].request = request_m[i];
	    forward_cb_args_m[i].rpc_handle = &rpc_open_handle_m[i];
	    hg_ret = HG_Forward(handle_m[i], hg_test_rpc_forward_cb, &forward_cb_args_m[i],
	        &rpc_open_in_struct);
	    if (hg_ret != HG_SUCCESS) {
		    fprintf(stderr, "Could not forward call\n");
		    goto done;
	    }
    }

    /* Complete */
    for (i = 0; i < NINFLIGHT; i++) {
	    hg_request_wait(request_m[i], HG_MAX_IDLE_TIME, NULL);

	    hg_ret = HG_Destroy(handle_m[i]);
	    if (hg_ret != HG_SUCCESS) {
		    fprintf(stderr, "Could not destroy\n");
		    goto done;
	    }
	    hg_request_destroy(request_m[i]);
    }
    printf("Done\n");

done:
    return hg_ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_addr_t addr;
    hg_return_t hg_ret;
    int ret = EXIT_SUCCESS;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);

    hg_ret = hg_test_rpc_no_resp(NULL, context, request_class, addr);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_ret = hg_test_rpc_no_resp(hg_class, context, request_class, addr);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_ret = hg_test_rpc_invalid(hg_class, context, request_class, addr);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }

    hg_ret = hg_test_rpc_multiple(context, request_class, addr);
    if (hg_ret != HG_SUCCESS) {
        ret = EXIT_FAILURE;
        goto done;
    }

done:
    HG_Test_finalize(hg_class);
    return ret;
}
