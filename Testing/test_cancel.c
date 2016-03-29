/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                         UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test.h"

#include <stdio.h>
#include <stdlib.h>

/*
  The following extern variable is defined in mercury_test.c with initial 
  value of 0.  The RPC rpc_open() is defined in mercury_rpc_cb.c. 
*/
extern hg_id_t hg_test_rpc_open_id_g; 

#define COMPLETION_MAGIC 123456
/* 
   This call back function will never be called if CANCEL succeeds.
   However, it may be useful in the future to check for NA plugins 
   that do not support cancel (e.g., CCI). 
 */
static hg_return_t
hg_test_rpc_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_handle_t handle = callback_info->handle;
    int *ptr = callback_info->arg;
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    int rpc_open_ret;
    int rpc_open_event_id;
    rpc_open_out_t rpc_open_out_struct;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_CANCELLED) 
    {
        fprintf(stderr, "Callback was not cancelled: %d\n",
                callback_info->ret);
    }
    else /* Cancelled. */
    {                           
        fprintf(stderr, "Callback was cancelled: %d\n",
                callback_info->ret);        
    }
    hg_request_complete(request);
    
done:
    return ret;
}

/******************************************************************************/
int
main(int argc, char *argv[])
{
    hg_class_t *hg_class = NULL;
    hg_context_t *context = NULL;
    hg_request_class_t *request_class = NULL;
    hg_request_t *request = NULL;
    hg_handle_t handle;
    na_addr_t addr;
    rpc_open_in_t  rpc_open_in_struct;
    void *data[2];
    unsigned int flag;
    hg_const_string_t rpc_open_path = MERCURY_TESTING_TEMP_DIRECTORY "/test.h5";
    rpc_handle_t rpc_open_handle;
    hg_return_t hg_ret;
    unsigned int timeout = HG_MAX_IDLE_TIME;
    
    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    hg_class = HG_Test_client_init(argc, argv, &addr, NULL, &context,
            &request_class);
    
    /* This sets request completed to FALSE. */
    request = hg_request_create(request_class);

    hg_ret = HG_Create(context, addr, hg_test_rpc_open_id_g, &handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not start call\n");
        return EXIT_FAILURE;
    }

    /* Fill input structure for rpc_open(). */
    rpc_open_handle.cookie = 12345; 
    rpc_open_in_struct.path = rpc_open_path; 
    rpc_open_in_struct.handle = rpc_open_handle;

    /* Forward call to remote addr and get a new request */
    fprintf(stderr, "Forwarding rpc_open, op id: %u...\n",
            hg_test_rpc_open_id_g);
    hg_ret = HG_Forward(handle, 
                        hg_test_rpc_forward_cb,
                        request,
                        &rpc_open_in_struct);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        return EXIT_FAILURE;
    }


    fprintf(stderr, "Cancelling...\n");
    /*  
        HG_Cancel() is for origin (client) operation.
        It doesn't send anything special to server.
        It simply calls NA_Cancel() that calls a plugin's cancel operation.
    */
    hg_ret = HG_Cancel(handle);
    if (hg_ret != HG_SUCCESS)
    {
        fprintf(stderr, "HG_Cancel failed: %d\n", hg_ret);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Waiting...\n");
    hg_request_wait(request, timeout, NULL);    
    
    /* Complete */
    hg_ret = HG_Destroy(handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not complete\n");
        return EXIT_FAILURE;
    }

    hg_request_destroy(request);

    HG_Test_finalize(hg_class);

    return EXIT_SUCCESS;
}
