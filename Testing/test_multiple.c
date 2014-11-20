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

extern hg_id_t hg_test_rpc_open_id_g;
extern hg_id_t hg_test_bulk_write_id_g;

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_addr_t addr;

    rpc_open_in_t  rpc_open_in_struct;
    rpc_open_out_t rpc_open_out_struct;
    hg_request_t rpc_open_request;

    bulk_write_in_t bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;
    hg_request_t bulk_write_request;

    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    int rpc_open_ret = 0;
    int rpc_open_event_id = 0;

    int fildes = 12345;
    int *bulk_buf = NULL;
    size_t bulk_size = 1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE / sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t bulk_write_ret = 0;

    hg_status_t rpc_open_status;
    hg_status_t bulk_write_status;
    hg_return_t hg_ret;
    size_t i;

    /* Prepare bulk_buf */
    bulk_buf = (int*) malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    HG_Test_client_init(argc, argv, &addr, NULL);

    /* Register memory */
    hg_ret = HG_Bulk_handle_create(bulk_buf, sizeof(int) * bulk_size, HG_BULK_READ_ONLY,
            &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    rpc_open_handle.cookie = 12345;
    rpc_open_in_struct.path = rpc_open_path;
    rpc_open_in_struct.handle = rpc_open_handle;
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding rpc_open, op id: %u...\n", hg_test_rpc_open_id_g);
    hg_ret = HG_Forward(addr, hg_test_rpc_open_id_g, &rpc_open_in_struct,
            &rpc_open_out_struct, &rpc_open_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }
    printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_write_id_g);
    hg_ret = HG_Forward(addr, hg_test_bulk_write_id_g,
            &bulk_write_in_struct, &bulk_write_out_struct, &bulk_write_request);
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
    hg_ret = HG_Wait(bulk_write_request, HG_MAX_IDLE_TIME, &bulk_write_status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    if (!bulk_write_status) {
        fprintf(stderr, "Operation did not complete\n");
        return EXIT_FAILURE;
    } else {
        printf("Call completed\n");
    }

    /* Get output parameters */
    rpc_open_ret = rpc_open_out_struct.ret;
    rpc_open_event_id = rpc_open_out_struct.event_id;
    printf("rpc_open returned: %d with event_id: %d\n", rpc_open_ret, rpc_open_event_id);
    bulk_write_ret = bulk_write_out_struct.ret;
    printf("bulk_write returned: %lu\n", bulk_write_ret);

    /* Free request */
    hg_ret = HG_Request_free(rpc_open_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
        return EXIT_FAILURE;
    }
    hg_ret = HG_Request_free(bulk_write_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free request\n");
        return EXIT_FAILURE;
    }

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Free bulk data */
    free(bulk_buf);

    HG_Test_finalize();

    return EXIT_SUCCESS;
}
