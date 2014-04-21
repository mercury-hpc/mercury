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
#include <string.h>

extern hg_id_t hg_test_bulk_seg_write_id_g;

/*****************************************************************************/
int main(int argc, char *argv[])
{
    na_addr_t addr;

    bulk_write_in_t bulk_write_in_struct;
    bulk_write_out_t bulk_write_out_struct;
    hg_request_t bulk_write_request;

    int fildes = 12345;
    int **bulk_buf;
    size_t bulk_size = 1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE / sizeof(int);
    size_t bulk_size_x = 16;
    size_t bulk_size_y = 0;
    size_t *bulk_size_y_var = NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;
    hg_bulk_segment_t *bulk_segments = NULL;
    size_t bulk_write_ret = 0;

    hg_status_t bla_open_status;
    hg_return_t hg_ret;
    size_t i, j;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    HG_Test_client_init(argc, argv, &addr, NULL);

    /* This will create a list of variable size segments */
    if (argc > 2 && strcmp(argv[2], "variable") == 0) {
        printf("Using variable size segments!\n");
        /* bulk_size_x >= 2 */
        /* 524288 + 262144 + 131072 + 65536 + 32768 + 16384 + 8192 + 8192 */
        bulk_size_x = 8;
        bulk_size_y_var = (size_t*) malloc(bulk_size_x * sizeof(size_t));
        bulk_size_y_var[0] = bulk_size / 2;
        for (i = 1; i < bulk_size_x - 1; i++) {
            bulk_size_y_var[i] = bulk_size_y_var[i-1] / 2;
        }
        bulk_size_y_var[bulk_size_x - 1] = bulk_size_y_var[bulk_size_x - 2];
    }
    /* This will use an extra encoding buffer */
    else if (argc > 2 && strcmp(argv[2], "extra") == 0) {
        printf("Using large number of segments!\n");
        bulk_size_x = 1024;
        bulk_size_y = bulk_size / bulk_size_x;
    }
    else {
        /* This will create a list of fixed size segments */
        bulk_size_y = bulk_size / bulk_size_x;
    }

    /* Prepare bulk_buf */
    bulk_buf = (int**) malloc(bulk_size_x * sizeof(int*));
    if (bulk_size_y_var) {
        int val = 0;
        for (i = 0; i < bulk_size_x; i++) {
            bulk_buf[i] = (int*) malloc(bulk_size_y_var[i] * sizeof(int));
            for (j = 0; j < bulk_size_y_var[i]; j++) {
                bulk_buf[i][j] = val;
                val++;
            }
        }
    } else {
        for (i = 0; i < bulk_size_x; i++) {
            bulk_buf[i] = (int*) malloc(bulk_size_y * sizeof(int));
            for (j = 0; j < bulk_size_y; j++) {
                bulk_buf[i][j] = i * bulk_size_y + j;
            }
        }
    }

    /* Register memory */
    bulk_segments = (hg_bulk_segment_t*) malloc(bulk_size_x * sizeof(hg_bulk_segment_t));
    if (bulk_size_y_var) {
        for (i = 0; i < bulk_size_x ; i++) {
            bulk_segments[i].address = (hg_ptr_t) bulk_buf[i];
            bulk_segments[i].size = bulk_size_y_var[i] * sizeof(int);
        }
    } else {
        for (i = 0; i < bulk_size_x ; i++) {
            bulk_segments[i].address = (hg_ptr_t) bulk_buf[i];
            bulk_segments[i].size = bulk_size_y * sizeof(int);
        }
    }

    hg_ret = HG_Bulk_handle_create_segments(bulk_segments, bulk_size_x,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    free(bulk_segments);
    bulk_segments = NULL;
    if (bulk_size_y_var) free(bulk_size_y_var);
    bulk_size_y_var = NULL;

    /* Fill input structure */
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_seg_write_id_g);
    hg_ret = HG_Forward(addr, hg_test_bulk_seg_write_id_g,
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
        printf("Call completed\n");
    }

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    printf("bulk_write returned: %lu\n", bulk_write_ret);

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
    for (i = 0; i < bulk_size_x; i++) {
        free(bulk_buf[i]);
        bulk_buf[i] = NULL;
    }
    free(bulk_buf);
    bulk_buf = NULL;

    HG_Test_finalize();

    return EXIT_SUCCESS;
}
