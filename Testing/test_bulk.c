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

extern hg_id_t hg_test_bulk_write_id_g;

static hg_return_t
hg_test_bulk_forward_cb(const struct hg_cb_info *callback_info)
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

/******************************************************************************/
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
    int *bulk_buf = NULL;
    void *buf_ptr[1];
    size_t count =  (1024 * 1024 * MERCURY_TESTING_BUFFER_SIZE) / sizeof(int);
    size_t bulk_size = count * sizeof(int);
    hg_bulk_t bulk_handle = HG_BULK_NULL;

    hg_return_t hg_ret;
    size_t i;

    /* Prepare bulk_buf */
    bulk_buf = (int*) malloc(bulk_size);
    for (i = 0; i < count; i++) {
        bulk_buf[i] = i;
    }
    *buf_ptr = bulk_buf;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);

    request = hg_request_create(request_class);

    hg_ret = HG_Create(hg_class, context, addr, hg_test_bulk_write_id_g,
            &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
    }

    /* Must get info to retrieve bulk class if not provided by user */
    hg_info = HG_Get_info(handle);

    /* Register memory */
    hg_ret = HG_Bulk_create(hg_info->hg_bulk_class, 1, buf_ptr, &bulk_size,
            HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure */
    bulk_write_in_struct.fildes = fildes;
    bulk_write_in_struct.bulk_handle = bulk_handle;

    /* Forward call to remote addr and get a new request */
    printf("Forwarding bulk_write, op id: %u...\n", hg_test_bulk_write_id_g);
    hg_ret = HG_Forward(handle, hg_test_bulk_forward_cb, request,
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

    /* Free bulk data */
    free(bulk_buf);

    return EXIT_SUCCESS;
}
