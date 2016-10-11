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

    hg_request_complete(args->request);

done:
    return ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_request_t *request1 = NULL, *request2 = NULL;
    hg_handle_t handle1, handle2;
    struct forward_cb_args forward_cb_args1, forward_cb_args2;
    hg_addr_t addr;
    rpc_open_in_t  rpc_open_in_struct;

    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle1, rpc_open_handle2;
    hg_return_t hg_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);

    /* Create request 1 */
    request1 = hg_request_create(request_class);

    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle1);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
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
        return EXIT_FAILURE;
    }

    /* Create request 2 */
    request2 = hg_request_create(request_class);

    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle2);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
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
        return EXIT_FAILURE;
    }

    hg_request_wait(request2, HG_MAX_IDLE_TIME, NULL);
    hg_request_wait(request1, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    hg_ret = HG_Destroy(handle1);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        return EXIT_FAILURE;
    }
    hg_ret = HG_Destroy(handle2);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not destroy\n");
        return EXIT_FAILURE;
    }

    hg_request_destroy(request1);
    hg_request_destroy(request2);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
