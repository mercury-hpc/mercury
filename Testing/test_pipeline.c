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

extern hg_id_t hg_test_pipeline_write_id_g;

/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_addr_t addr;

    bulk_write_in_t bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;
    hg_request_t bulk_write_request;

    int fildes = 12345;
    int *bulk_buf;
    void *buf_ptr[1];
    size_t count = (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE) / sizeof(int);
    size_t bulk_size = count * sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    size_t bulk_write_ret = 0;

    hg_status_t bla_open_status;
    hg_return_t hg_ret;
    size_t i;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    HG_Test_client_init(argc, argv, &addr, NULL);

    /* Prepare bulk_buf */
    bulk_buf = (int*) malloc(bulk_size);
    for (i = 0; i < count; i++) {
        bulk_buf[i] = (int) i;
    }
    *buf_ptr = bulk_buf;

    /* Register memory */
    hg_ret = HG_Bulk_handle_create(1, buf_ptr, &bulk_size,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    /* printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_write_id_g); */
    hg_ret = HG_Forward(addr, hg_test_pipeline_write_id_g,
            &bulk_write_in_struct, &bulk_write_out_struct, &bulk_write_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(bulk_write_request, HG_MAX_IDLE_TIME, &bla_open_status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        return EXIT_FAILURE;
    }
    if (!bla_open_status) {
        fprintf(stderr, "Operation did not complete\n");
        return EXIT_FAILURE;
    } else {
        /* printf("Call completed\n"); */
    }

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    if (bulk_write_ret != bulk_size) {
        fprintf(stderr, "Data not correctly processed\n");
    }

    /* Free request */
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

    /* Free bulk_buf */
    free(bulk_buf);
    bulk_buf = NULL;

    HG_Test_finalize();

    return EXIT_SUCCESS;
}
