/*
 * client_fs.c
 */

#include "function_shipper.h"
#include "generic_macros.h"
#include "shipper_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dummy function that needs to be shipped:
 * int bla_open(const char *path, bla_handle_t handle, int *event_id);
 */

/*****************************************************************************/
/* 1. Generate processor for additional struct type
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_PROC( bla_handle_t, ((uint64_t)(cookie)) )

/*****************************************************************************/
/* 2. Generate processor for input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_PROC( bla_open_in_t, ((fs_string_t)(path)) ((bla_handle_t)(handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_open_out_t, ((int32_t)(ret)) ((int32_t)(event_id)) )

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_network_class_t *network_class = NULL;

    fs_id_t bla_open_id;
    bla_open_in_t  bla_open_in_struct;
    bla_open_out_t bla_open_out_struct;
    fs_request_t bla_open_request;

    const char *bla_open_path = "/scratch/hdf/test.h5";
    bla_handle_t bla_open_handle;
    int bla_open_ret = 0;
    int bla_open_event_id = 0;
    bla_open_handle.cookie = 12345;

    /* Initialize the interface */
    network_class = shipper_test_client_init(argc, argv);
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
    }
    fs_init(network_class);

    /* Look up addr id */
    na_addr_lookup(network_class, ion_name, &addr);

    /* Register function and encoding/decoding functions */
    bla_open_id = fs_register("bla_open", &fs_proc_bla_open_in_t, &fs_proc_bla_open_out_t);

    /* Fill input structure */
    bla_open_in_struct.path = bla_open_path;
    bla_open_in_struct.handle = bla_open_handle;

    /* Forward call to addr */
    printf("Fowarding bla_open, op id: %u...\n", bla_open_id);
    fs_forward(addr, bla_open_id, &bla_open_in_struct,
            &bla_open_out_struct, &bla_open_request);

    /* Wait for call to be executed and return value to be sent back */
    fs_wait(bla_open_request, FS_MAX_IDLE_TIME, FS_STATUS_IGNORE);

    /* Get output parameter */
    bla_open_ret = bla_open_out_struct.ret;
    bla_open_event_id = bla_open_out_struct.event_id;
    printf("bla_open returned: %d with event_id: %d\n", bla_open_ret, bla_open_event_id);

    /* Free addr id */
    na_addr_free(network_class, addr);

    /* Finalize interface */
    fs_finalize();
    return EXIT_SUCCESS;
}
