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
#include <string.h>

extern hg_id_t hg_test_bulk_seg_write_id_g;
extern na_bool_t na_test_use_variable_g;
extern na_bool_t na_test_use_extra_g;

static hg_return_t
hg_test_bulk_seg_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->handle;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    size_t bulk_write_ret = 0;
    bulk_write_out_t bulk_write_out_struct;
    hg_return_t ret = HG_SUCCESS;

    /* Get output */
    ret = HG_Get_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not get output\n");
        goto done;
    }

    /* Get output parameters */
    bulk_write_ret = bulk_write_out_struct.ret;
    printf("bulk_write returned: %zu\n", bulk_write_ret);

    /* Free request */
    ret = HG_Free_output(handle, &bulk_write_out_struct);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free output\n");
        goto done;
    }

    hg_request_complete(request);

done:
    return ret;
}

/*****************************************************************************/
int main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_request_t *request = NULL;
    hg_handle_t handle;
    na_addr_t addr;
    struct hg_info *hg_info = NULL;

    bulk_write_in_t bulk_write_in_struct;

    int fildes = 12345;
    void **bulk_buf;
    size_t *bulk_sizes;
    size_t bulk_size = 1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE / sizeof(int);
    size_t bulk_size_x = 16;
    size_t bulk_size_y = 0;
    size_t *bulk_size_y_var = NULL;
    hg_bulk_t bulk_handle = HG_BULK_NULL;

    hg_return_t hg_ret;
    size_t i, j;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);

    request = hg_request_create(request_class);

    hg_ret = HG_Create(hg_class, context, addr, hg_test_bulk_seg_write_id_g,
            &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
    }

    /* Must get info to retrieve bulk class if not provided by user */
    hg_info = HG_Get_info(handle);

    /* This will create a list of variable size segments */
    if (na_test_use_variable_g) {
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
    else if (na_test_use_extra_g) {
        printf("Using large number of segments!\n");
        bulk_size_x = 1024;
        bulk_size_y = bulk_size / bulk_size_x;
    }
    else {
        /* This will create a list of fixed size segments */
        bulk_size_y = bulk_size / bulk_size_x;
    }

    /* Prepare bulk_buf */
    bulk_buf = (void **) malloc(bulk_size_x * sizeof(void *));
    bulk_sizes = (size_t *) malloc(bulk_size_x * sizeof(size_t));
    if (bulk_size_y_var) {
        int val = 0;
        for (i = 0; i < bulk_size_x; i++) {
            bulk_sizes[i] = bulk_size_y_var[i] * sizeof(int);
            bulk_buf[i] = malloc(bulk_sizes[i]);
            for (j = 0; j < bulk_size_y_var[i]; j++) {
                ((int **) (bulk_buf))[i][j] = val;
                val++;
            }
        }
    } else {
        for (i = 0; i < bulk_size_x; i++) {
            bulk_sizes[i] = bulk_size_y * sizeof(int);
            bulk_buf[i] = malloc(bulk_sizes[i]);
            for (j = 0; j < bulk_size_y; j++) {
                ((int **) (bulk_buf))[i][j] = i * bulk_size_y + j;
            }
        }
    }

    /* Register memory */
    hg_ret = HG_Bulk_create(hg_info->hg_bulk_class, bulk_size_x, bulk_buf,
            bulk_sizes, HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    free(bulk_sizes);
    bulk_sizes = NULL;
    if (bulk_size_y_var) free(bulk_size_y_var);
    bulk_size_y_var = NULL;

    /* Fill input structure */
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_seg_write_id_g);
    hg_ret = HG_Forward(handle, hg_test_bulk_seg_forward_cb, request,
            &bulk_write_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }

    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Free memory handle */
    hg_ret = HG_Bulk_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        return EXIT_FAILURE;
    }

    hg_request_destroy(request);

    HG_Test_finalize(hg_class);

    /* Free bulk_buf */
    for (i = 0; i < bulk_size_x; i++) {
        free(bulk_buf[i]);
        bulk_buf[i] = NULL;
    }
    free(bulk_buf);
    bulk_buf = NULL;

    return EXIT_SUCCESS;
}
