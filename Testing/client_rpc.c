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

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *port_name;
    na_addr_t addr;
    na_class_t *network_class = NULL;

    rpc_open_in_t  rpc_open_in_struct;
    rpc_open_out_t rpc_open_out_struct;
    hg_request_t rpc_open_request;

    hg_const_string_t rpc_open_path = "/scratch/hdf/test.h5";
    rpc_handle_t rpc_open_handle;
    int rpc_open_ret = 0;
    int rpc_open_event_id = 0;

    hg_status_t rpc_open_status;
    int hg_ret, na_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = HG_Test_client_init(argc, argv, &port_name, NULL);

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury\n");
        return EXIT_FAILURE;
    }

    if (strcmp(port_name, "self") == 0) {
        /* Self addr */
        na_ret = NA_Addr_self(network_class, &addr);
    } else {
        /* Look up addr using port name info */
        na_ret = NA_Addr_lookup_wait(network_class, port_name, &addr);
    }
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", port_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    HG_Test_register();

    /* Fill input structure */
    rpc_open_handle.cookie = 12345;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    hg_ret = HG_Forward(addr, hg_test_rpc_open_id_g, &rpc_open_in_struct,
            &rpc_open_out_struct, &rpc_open_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(rpc_open_request, HG_MAX_IDLE_TIME, &rpc_open_status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    if (!rpc_open_status) {
        fprintf(stderr, "Operation did not complete\n");
        return EXIT_FAILURE;
    } else {
        printf("Call completed\n");
    }

    /* Get output parameters */
    rpc_open_ret = rpc_open_out_struct.ret;
    rpc_open_event_id = rpc_open_out_struct.event_id;
    printf("rpc_open returned: %d with event_id: %d\n", rpc_open_ret,
            rpc_open_event_id);

    /* Free request */
    hg_ret = HG_Request_free(rpc_open_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
        return EXIT_FAILURE;
    }

    /* Free addr id */
    na_ret = NA_Addr_free(network_class, addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    /* Finalize interface */
    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury\n");
        return EXIT_FAILURE;
    }

    HG_Test_finalize(network_class);

    return EXIT_SUCCESS;
}
