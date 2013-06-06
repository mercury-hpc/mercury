/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_rpc.h"
#include "mercury_test.h"
#include "mercury.h"

#include <stdio.h>
#include <stdlib.h>

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_class_t *network_class = NULL;

    hg_id_t bla_open_id;
    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;
    hg_request_t bla_open_request;

    const char *bla_open_path = "/scratch/hdf/test.h5";
    bla_handle_t bla_open_handle;
    int bla_open_ret = 0;
    int bla_open_event_id = 0;

    hg_status_t bla_open_status;
    int hg_ret, na_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = HG_Test_client_init(argc, argv, NULL);
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
        return EXIT_FAILURE;
    }

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    na_ret = NA_Addr_lookup(network_class, ion_name, &addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    bla_open_id = MERCURY_REGISTER("bla_open", bla_open_in_t, bla_open_out_t);

    /* Fill input structure */
    bla_open_handle.cookie = 12345;
    bla_open_in_struct.path = bla_open_path;
    bla_open_in_struct.handle = bla_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bla_open, op id: %u...\n", bla_open_id);
    hg_ret = HG_Forward(addr, bla_open_id, &bla_open_in_struct,
            &bla_open_out_struct, &bla_open_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(bla_open_request, HG_MAX_IDLE_TIME, &bla_open_status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    if (!bla_open_status) {
        fprintf(stderr, "Operation did not complete\n");
        return EXIT_FAILURE;
    } else {
        printf("Call completed\n");
    }

    /* Get output parameters */
    bla_open_ret = bla_open_out_struct.ret;
    bla_open_event_id = bla_open_out_struct.event_id;
    printf("bla_open returned: %d with event_id: %d\n", bla_open_ret, bla_open_event_id);

    /* Free addr id */
    na_ret = NA_Addr_free(network_class, addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    /* Finalize interface */
    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
