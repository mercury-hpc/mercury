/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

extern hg_id_t hg_test_overflow_id_g;

static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->handle;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    overflow_out_t out_struct;
    hg_return_t ret = HG_SUCCESS;

    hg_string_t string;
    size_t string_len;

    if (callback_info->ret != HG_SUCCESS) {
        HG_LOG_WARNING("Return from callback info is not HG_SUCCESS");
        goto done;
    }

    /* Get output */
    ret = HG_Get_output(handle, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get output\n");
        goto done;
    }

    /* Get output parameters */
    string = out_struct.string;
    string_len = out_struct.string_len;
    printf("Returned string (length %zu): %s\n", string_len, string);

    /* Free request */
    ret = HG_Free_output(handle, &out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free output\n");
        goto done;
    }

done:
    hg_request_complete(request);
    return ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_request_t *request = NULL;
    hg_handle_t handle;
    na_addr_t addr;
    hg_return_t hg_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);

    request = hg_request_create(request_class);

    hg_ret = HG_Create(hg_class, context, addr, hg_test_overflow_id_g, &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
    }

    /* Forward call to remote addr and get a new request */
    printf("Forwarding call, op id: %u...\n", hg_test_overflow_id_g);
    hg_ret = HG_Forward(handle, hg_test_rpc_forward_cb, request, NULL);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        return EXIT_FAILURE;
    }

    hg_request_destroy(request);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
