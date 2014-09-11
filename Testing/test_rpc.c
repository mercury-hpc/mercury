/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
static int test_done_g = 0;

static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->handle;
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

    /* Do something */
    test_done_g = 1;

    /* Free request */
    ret = HG_Free_output(handle, &rpc_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free output\n");
        goto done;
    }

done:
    return ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_handle_t handle;
    na_addr_t addr;
    rpc_open_in_t  rpc_open_in_struct;
//    rpc_open_out_t rpc_open_out_struct;

    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    hg_return_t hg_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL);
    context = HG_Context_create(hg_class);

    hg_ret = HG_Create(hg_class, context, addr, hg_test_rpc_open_id_g, &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    rpc_open_handle.cookie = 12345;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    hg_ret = HG_Forward(handle, hg_test_rpc_forward_cb, NULL,
            &rpc_open_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    while(!test_done_g) {
        hg_return_t trigger_ret;
        unsigned int actual_count = 0;

        do {
            trigger_ret = HG_Trigger(hg_class, context, 0, 1, &actual_count);
        } while ((trigger_ret == HG_SUCCESS) && actual_count);

        if (test_done_g) break;

        HG_Progress(hg_class, context, NA_MAX_IDLE_TIME);
    }

    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        return EXIT_FAILURE;
    }

    HG_Context_destroy(context);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
