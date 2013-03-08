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

#include "test_bds.h"
#include "shipper_test.h"
#include "function_shipper.h"
#include "bulk_data_shipper.h"

#include <stdio.h>
#include <stdlib.h>

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_network_class_t *network_class = NULL;

    fs_id_t bla_write_id;
    bla_write_in_t bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;
    fs_request_t bla_write_request;

    int fildes = 12345;
    int *bulk_buf = NULL;
    int bulk_size = 1024*1024;
    bds_handle_t bla_bulk_handle = NULL;
    int bla_write_ret = 0;

    fs_status_t bla_open_status;
    int fs_ret;
    int i;

    /* Prepare bulk_buf */
    bulk_buf = malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = shipper_test_client_init(argc, argv);
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

    fs_ret = bds_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    fs_ret = na_addr_lookup(network_class, ion_name, &addr);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    bla_write_id = IOFSL_SHIPPER_REGISTER(bla_write, bla_write_in_t, bla_write_out_t);

    /* Register memory */
    fs_ret = bds_handle_create(bulk_buf, sizeof(int) * bulk_size, BDS_READ_ONLY,
            &bla_bulk_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    bla_write_in_struct.fildes = fildes;
    bla_write_in_struct.bds_handle = bla_bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bla_write, op id: %u...\n", bla_write_id);
    fs_ret = fs_forward(addr, bla_write_id, &bla_write_in_struct, &bla_write_out_struct, &bla_write_request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(bla_write_request, FS_MAX_IDLE_TIME, &bla_open_status);
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
    bla_write_ret = bla_write_out_struct.ret;
    printf("bla_write returned: %d\n", bla_write_ret);

    /* Free memory handle */
    fs_ret = bds_handle_free(bla_bulk_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Free bulk data */
    free(bulk_buf);

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

    fs_ret = bds_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
