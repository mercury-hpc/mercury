/*
 * server_fs.c
 */

#include "function_shipper.h"
#include "shipper_error.h"
#include "shipper_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dummy function that needs to be shipped */
int bla_initialize(int comm)
{
    const char message[] = "Hi, I'm bla_initialize";
    printf("%s (%d)\n", message, (int) strlen(message));
    return strlen(message);
}

/******************************************************************************/
/* Can be automatically generated using macros */
typedef struct bla_initialize_in {
    int comm;
} bla_initialize_in_t;

typedef struct bla_initialize_out {
    int bla_initialize_ret;
} bla_initialize_out_t;

int bla_initialize_dec(void **in_struct, void *buf, int buf_len)
{
    int ret = S_SUCCESS;
    bla_initialize_in_t *bla_initialize_in_struct;

    if (buf_len < sizeof(bla_initialize_in_t)) {
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = S_FAIL;
    } else {
        bla_initialize_in_struct = malloc(sizeof(bla_initialize_in_t));
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(bla_initialize_in_struct, buf, sizeof(bla_initialize_in_t));
        *in_struct = bla_initialize_in_struct;
    }
    return ret;
}

int bla_initialize_enc(void *buf, int buf_len, void *out_struct)
{
    int ret = S_SUCCESS;
    bla_initialize_out_t *bla_initialize_out_struct = (bla_initialize_out_t*) out_struct;

    if (buf_len < sizeof(bla_initialize_out_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bla_initialize_out_struct, sizeof(bla_initialize_out_t));
    }
    return ret;
}

int bla_initialize_exe(void *in_struct, void **out_struct)
{
    int ret = S_SUCCESS;
    bla_initialize_in_t *bla_initialize_in_struct = (bla_initialize_in_t*) in_struct;
    bla_initialize_out_t *bla_initialize_out_struct;
    int comm;
    int bla_initialize_ret;

    comm = bla_initialize_in_struct->comm;
    bla_initialize_ret = bla_initialize(comm);

    bla_initialize_out_struct = malloc(sizeof(bla_initialize_out_t));
    bla_initialize_out_struct->bla_initialize_ret = bla_initialize_ret;
    *out_struct = bla_initialize_out_struct;
    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    void *func_in_struct;
    void *func_out_struct;
    fs_id_t func_id;
    fs_tag_t func_tag;
    fs_peer_t func_peer;

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv);

    fs_init(network_class);

    /* Register routine */
    fs_server_register("bla_initialize", bla_initialize_dec, bla_initialize_exe, bla_initialize_enc);

    /* Receive a new function call */
    fs_server_receive(&func_peer, &func_id, &func_tag, &func_in_struct);

    /* Execute the call */
    fs_server_execute(func_id, func_in_struct, &func_out_struct);

    /* Respond back */
    fs_server_respond(func_peer, func_id, func_tag, func_out_struct);

    printf("Finalizing...\n");

    /* Free memory and addresses */
    fs_peer_free(func_peer);
    func_peer = NULL;

    free(func_in_struct);
    func_in_struct = NULL;

    free(func_out_struct);
    func_out_struct = NULL;

    fs_finalize();
    return EXIT_SUCCESS;
}
