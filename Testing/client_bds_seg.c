/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_bds_seg.h"
#include "mercury_test.h"
#include "mercury.h"
#include "mercury_bulk.h"

#include <stdio.h>
#include <stdlib.h>

/*****************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_class_t *network_class = NULL;

    hg_id_t bla_write_id;
    bla_write_in_t bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;
    hg_request_t bla_write_request;

    int fildes = 12345;
    int bulk_buf[1024][1024];
    int bulk_size_x = 1024;
    int bulk_size_y = 1024;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_bulk_segment_t *bulk_segments = NULL;
    int bla_write_ret = 0;

    hg_status_t bla_open_status;
    int hg_ret, na_ret;
    int i, j;

    /* Prepare bulk_buf */
    for (i = 0; i < bulk_size_x; i++) {
        for (j = 0; j < bulk_size_y; j++) {
            bulk_buf[i][j] = i * bulk_size_y + j;
        }
    }

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

    hg_ret = HG_Bulk_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Look up addr id */
    na_ret = NA_Addr_lookup(network_class, ion_name, &addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        return EXIT_FAILURE;
    }

    /* Register function and encoding/decoding functions */
    bla_write_id = MERCURY_REGISTER("bla_write", bla_write_in_t, bla_write_out_t);

    /* Register memory */
    bulk_segments = malloc(bulk_size_x * sizeof(hg_bulk_segment_t));
    for (i = 0; i < bulk_size_x ; i++) {
        bulk_segments[i].address = bulk_buf[i];
        bulk_segments[i].size = bulk_size_y*sizeof(int);
    }

    hg_ret = HG_Bulk_handle_create_segments(bulk_segments, bulk_size_x,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    free(bulk_segments);

    /* Fill input structure */
    bla_write_in_struct.fildes = fildes;
    bla_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bla_write, op id: %u...\n", bla_write_id);
    hg_ret = HG_Forward(addr, bla_write_id,
            &bla_write_in_struct, &bla_write_out_struct, &bla_write_request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(bla_write_request, HG_MAX_IDLE_TIME, &bla_open_status);
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
    bla_write_ret = bla_write_out_struct.ret;
    printf("bla_write returned: %d\n", bla_write_ret);

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
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
        fprintf(stderr, "Could not finalize function shipper\n");
        return EXIT_FAILURE;
    }

    hg_ret = HG_Bulk_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
