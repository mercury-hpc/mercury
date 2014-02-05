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
#include "mercury_handler.h"

#include <stdio.h>
#include <stdlib.h>

/* Actual definition of the function that needs to be executed */
int bla_open(const char *path, bla_handle_t handle, int *event_id)
{
    printf("Called bla_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return HG_SUCCESS;
}

/******************************************************************************/
static hg_return_t
fs_bla_open(hg_handle_t handle)
{
    hg_return_t ret = HG_SUCCESS;

    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;

    hg_const_string_t bla_open_path;
    bla_handle_t bla_open_handle;
    int bla_open_event_id;
    int bla_open_ret;

    /* Get input buffer */
    ret = HG_Handler_get_input(handle, &bla_open_in_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get input\n");
        return ret;
    }

    /* Get parameters */
    bla_open_path = bla_open_in_struct.path;
    bla_open_handle = bla_open_in_struct.handle;

    /* Call bla_open */
    bla_open_ret = bla_open(bla_open_path, bla_open_handle, &bla_open_event_id);

    /* Fill output structure */
    bla_open_out_struct.event_id = bla_open_event_id;
    bla_open_out_struct.ret = bla_open_ret;

    /* Free handle and send response back */
    ret = HG_Handler_start_output(handle, &bla_open_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    na_class_t *network_class = NULL;
    unsigned int number_of_peers;
    unsigned int i;
    int hg_ret;

    /* Initialize the interface */
    network_class = HG_Test_server_init(argc, argv, NULL, NULL, &number_of_peers);

    hg_ret = HG_Handler_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize Mercury handler\n");
        return EXIT_FAILURE;
    }

    /* Register routine */
    MERCURY_HANDLER_REGISTER("bla_open", fs_bla_open, bla_open_in_t, bla_open_out_t);

    for (i = 0; i < number_of_peers; i++) {
        hg_status_t status = 0;
        /* Receive new function calls */
        while (!status) {
            printf("Processing...\n");
        hg_ret = HG_Handler_process(1000, &status);
        if (hg_ret != HG_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
        }
        }
        printf("Processed\n");
    }

    printf("Finalizing...\n");

    hg_ret = HG_Handler_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize Mercury handler\n");
        return EXIT_FAILURE;
    }

    HG_Test_finalize(network_class);

    return EXIT_SUCCESS;
}
