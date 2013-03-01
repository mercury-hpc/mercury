/*
 * server_fs.c
 */

#include "function_shipper_handler.h"
#include "shipper_test.h"
#include "test_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dummy function that needs to be shipped */
int bla_open(const char *path, bla_handle_t handle, int *event_id)
{
    printf("Called bla_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return S_SUCCESS;
}

/******************************************************************************/
int fs_bla_open(fs_handle_t handle)
{
    int ret = S_SUCCESS;

    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;

    const char *bla_open_path;
    bla_handle_t bla_open_handle;
    int bla_open_event_id;
    int bla_open_ret;

    /* Get input parameters and data */
    fs_handler_get_input(handle, &bla_open_in_struct);
    bla_open_path = bla_open_in_struct.path;
    bla_open_handle = bla_open_in_struct.handle;

    /* Call bla_open */
    bla_open_ret = bla_open(bla_open_path, bla_open_handle, &bla_open_event_id);

    /* Fill output structure */
    bla_open_out_struct.event_id = bla_open_event_id;
    bla_open_out_struct.ret = bla_open_ret;

    /* Free handle and send response back */
    fs_handler_complete(handle, &bla_open_out_struct);

    /* Free string */
    fs_free_fs_string_t(bla_open_in_struct.path);

    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;
    unsigned int number_of_peers;
    unsigned int i;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_handler_init(network_class);

    /* Register routine */
    IOFSL_SHIPPER_HANDLER_REGISTER(bla_open, fs_bla_open, bla_open_in_t, bla_open_out_t);

    for (i = 0; i < number_of_peers; i++) {
        /* Receive new function calls */
        fs_handler_receive();
    }

    printf("Finalizing...\n");

    fs_handler_finalize();
    return EXIT_SUCCESS;
}
