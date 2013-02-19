/*
 * server_fs.c
 */

#include "function_shipper.h"
#include "shipper_error.h"
#include "shipper_test.h"
#include "generic_macros.h"
#include "generic_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t    cookie;
} bla_handle_t;

/* Dummy function that needs to be shipped */
int bla_open(const char *path, bla_handle_t handle, int *event_id)
{
    printf("Called bla_open of %s with cookie %lu\n", path, handle.cookie);
    *event_id = 232;
    return S_SUCCESS;
}

/*****************************************************************************/
/* 3. Generate processor for bla_handle_t struct
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_DEC_PROC( bla_handle_t, ((uint64_t)(cookie)) )

/*****************************************************************************/
/* 4. Generate input / output structure and encoding / decoding functions
 *    for bla_open call
 * IOFSL_SHIPPER_GEN( return type, function name, input parameters, output parameters )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_SERVER(
        int32_t,
        bla_open,
        ((fs_string_t)(path)) ((bla_handle_t)(handle)),
        ((int32_t)(event_id))
)

/******************************************************************************/
int bla_open_exe(const void *in_struct, void *out_struct, fs_info_t info)
{
    int ret = S_SUCCESS;
    bla_open_in_t *bla_open_in_struct = (bla_open_in_t*) in_struct;
    bla_open_out_t *bla_open_out_struct = (bla_open_out_t*) out_struct;
    int bla_open_ret = 0;

    bla_open_ret = bla_open(bla_open_in_struct->path.buffer,
            bla_open_in_struct->handle,
            &bla_open_out_struct->event_id);

    bla_open_out_struct->bla_open_ret = bla_open_ret;

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

    fs_init(network_class);

    /* Register routine */
    fs_server_register("bla_open", sizeof(bla_open_in_t), sizeof(bla_open_out_t),
            bla_open_dec, bla_open_exe, bla_open_enc);

    for (i = 0; i < number_of_peers; i++) {
        void     *func_in_struct;
        void     *func_out_struct;
        fs_id_t   func_id;
        fs_info_t func_info;

        /* Receive a new function call */
        fs_server_receive(&func_id, &func_info, &func_in_struct);

        /* TODO Get dependency here ? */
        /* Execute the call */
        fs_server_execute(func_id, func_info, func_in_struct, &func_out_struct);

        /* Respond back */
        fs_server_respond(func_id, func_info, func_out_struct);

        /* Free memory and addresses */
        free(func_in_struct);
        func_in_struct = NULL;

        free(func_out_struct);
        func_out_struct = NULL;
    }

    printf("Finalizing...\n");

    fs_finalize();
    return EXIT_SUCCESS;
}
