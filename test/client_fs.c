/*
 * client_fs.c
 */

#include "function_shipper.h"
#include "shipper_error.h"
#include "shipper_test.h"
#include "generic_macros.h"
#include "generic_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 1. Dummy function that needs to be shipped:
 * int bla_open(const char *path, bla_handle_t handle, int *event_id)
 */

/* 2. Additional struct type used by remote function */
typedef struct {
    uint64_t    cookie;
} bla_handle_t;

/*****************************************************************************/
/* 3. Generate processor for bla_handle_t struct
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_ENC_PROC( bla_handle_t, ((uint64_t)(cookie)) )

/*****************************************************************************/
/* 4. Generate input / output structure and encoding / decoding functions
 *    for bla_open call
 * IOFSL_SHIPPER_GEN( return type, function name, input parameters, output parameters )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_CLIENT(
        int32_t,
        bla_open,
        ((fs_string_t)(path)) ((bla_handle_t)(handle)),
        ((int32_t)(event_id))
)

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    fs_peer_t peer;
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

    /* Look up peer id */
    fs_peer_lookup(ion_name, &peer);

    /* Register function and encoding/decoding functions */
    bla_open_id = fs_register("bla_open", &bla_open_enc, &bla_open_dec);

    /* Fill input structure */
    bla_open_in_struct.path.length = strlen(bla_open_path) + 1;
    strcpy(bla_open_in_struct.path.buffer, bla_open_path);
    bla_open_in_struct.handle = bla_open_handle;

    /* Forward call to peer */
    printf("Fowarding bla_open, op id: %u...\n", bla_open_id);
    fs_forward(peer, bla_open_id, &bla_open_in_struct,
            &bla_open_out_struct, &bla_open_request);

    /* Wait for call to be executed and return value to be sent back */
    fs_wait(bla_open_request, FS_MAX_IDLE_TIME, FS_STATUS_IGNORE);

    /* Get output parameter */
    bla_open_ret = bla_open_out_struct.bla_open_ret;
    bla_open_event_id = bla_open_out_struct.event_id;
    printf("bla_open returned: %d with event_id: %d\n", bla_open_ret, bla_open_event_id);

    /* Free peer id */
    fs_peer_free(peer);

    /* Finalize interface */
    fs_finalize();
    return EXIT_SUCCESS;
}
