/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_fs.h"
#include "shipper_test.h"
#include "function_shipper.h"

#include <stdio.h>
#include <stdlib.h>

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_network_class_t *network_class = NULL;

    fs_id_t bla_open_id;
    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;
    fs_request_t bla_open_request;

    const char *bla_open_path = "/scratch/hdf/test.h5";
    bla_handle_t bla_open_handle;
    int bla_open_ret = 0;
    int bla_open_event_id = 0;
    bla_open_handle.cookie = 12345;

    fs_status_t bla_open_status;
    int fs_ret;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = shipper_test_client_init(argc, argv, NULL);
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
        return EXIT_FAILURE;
    }

    fs_ret = fs_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    fs_ret = na_addr_lookup(network_class, ion_name, &addr);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    bla_open_id = IOFSL_SHIPPER_REGISTER("bla_open", bla_open_in_t, bla_open_out_t);

    /* Fill input structure */
    bla_open_in_struct.path = bla_open_path;
    bla_open_in_struct.handle = bla_open_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bla_open, op id: %u...\n", bla_open_id);
    fs_ret = fs_forward(addr, bla_open_id, &bla_open_in_struct,
            &bla_open_out_struct, &bla_open_request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(bla_open_request, FS_MAX_IDLE_TIME, &bla_open_status);
    if (fs_ret != S_SUCCESS) {
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
    fs_ret = na_addr_free(network_class, addr);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        return EXIT_FAILURE;
    }

    /* Finalize interface */
    fs_ret = fs_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
