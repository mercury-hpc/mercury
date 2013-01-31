/*
 * server_fs.c
 */

#include "network_bmi.h"
#include "network_mpi.h"
#include "iofsl_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fs_func_info {
    int (*dec_routine)(void **in_struct, void *buf, int buf_len);
    int (*enc_routine)(void *buf, int buf_len, void *out_struct);
    int (*exe_routine)(void *in_struct, void **out_struct);
} fs_func_info_t;

/* Dummy function that needs to be shipped */
int bla_initialize(MPI_Comm comm)
{
    const char message[] = "Hi, I'm bla_initialize";
    printf("%s (%d)\n", message, (int) strlen(message));
    return strlen(message);
}

/******************************************************************************/
/* Can be automatically generated using macros */
typedef struct bla_initialize_in {
    MPI_Comm comm;
} bla_initialize_in_t;

typedef struct bla_initialize_out {
    int bla_initialize_ret;
} bla_initialize_out_t;

int bla_initialize_dec(void **in_struct, void *buf, int buf_len)
{
    int ret = NA_SUCCESS;
    bla_initialize_in_t *bla_initialize_in_struct;

    if (buf_len < sizeof(bla_initialize_in_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for deserializing parameter");
        ret = NA_FAIL;
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
    int ret = NA_SUCCESS;
    bla_initialize_out_t *bla_initialize_out_struct = (bla_initialize_out_t*) out_struct;

    if (buf_len < sizeof(bla_initialize_out_t)) {
        NA_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = NA_FAIL;
    } else {
        /* Here safe to do a simple memcpy */
        /* TODO may also want to add a checksum or something */
        memcpy(buf, bla_initialize_out_struct, sizeof(bla_initialize_out_t));
    }
    return ret;
}

int bla_initialize_exe(void *in_struct, void **out_struct)
{
    int ret = NA_SUCCESS;
    bla_initialize_in_t *bla_initialize_in_struct = (bla_initialize_in_t*) in_struct;
    bla_initialize_out_t *bla_initialize_out_struct;
    MPI_Comm comm;
    int bla_initialize_ret;

    bla_initialize_out_struct = malloc(sizeof(bla_initialize_out_t));
    comm = bla_initialize_in_struct->comm;
    bla_initialize_ret = bla_initialize(comm);
    bla_initialize_out_struct->bla_initialize_ret = bla_initialize_ret;
    *out_struct = bla_initialize_out_struct;
    return ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;

    fs_func_info_t func_info;
    void *func_in_struct;
    void *func_out_struct;

    char *recv_buf = NULL;
    char *send_buf = NULL;

    na_size_t recv_buf_len = 0;

    na_tag_t recv_tag = 0;
    na_tag_t send_tag = 0;

    na_addr_t recv_addr = NULL;

    na_request_t send_request = NULL;

    unsigned int bla_initialize_id; // fs_id_t ?

    /* Initialize the interface */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        network_class = na_mpi_init(NULL, MPI_INIT_SERVER);
    } else {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return EXIT_FAILURE;
        }
        network_class = na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }
    na_register(network_class);

    /* Register routine */
    //fs_register ?
    func_info.dec_routine = bla_initialize_dec;
    func_info.exe_routine = bla_initialize_exe;
    func_info.enc_routine = bla_initialize_enc;

    /* Allocate send and recv bufs */
    send_buf = malloc(na_get_unexpected_size());
    recv_buf = malloc(na_get_unexpected_size());

    /* Recv a message from a client (blocking for now) */
    na_recv_unexpected(recv_buf, &recv_buf_len, &recv_addr, &recv_tag, NULL, NULL);

    /* Decode IOFSL id (used for compat) */
    iofsl_compat_xdr_process_id(recv_buf, recv_buf_len, DECODE);

    /* Get generic op id */
    memcpy(&bla_initialize_id, recv_buf + iofsl_compat_xdr_get_size_id(), sizeof(unsigned int));

    /* Retrieve decoding function from function map */
//    func_info = func_map_lookup(func_map, &id);
//    if (!func_info) {
//        FS_ERROR_DEFAULT("func_map_lookup failed");
//        return FS_FAIL;
//    }
    printf("Got function ID: %u...\n", bla_initialize_id);

    /* Decode input parameters */
    func_info.dec_routine(&func_in_struct, recv_buf + iofsl_compat_xdr_get_size_id() + sizeof(unsigned int),
            recv_buf_len - iofsl_compat_xdr_get_size_id() - sizeof(unsigned int));

    /* Execute function and fill output parameters */
    func_info.exe_routine(func_in_struct, &func_out_struct);

    /* Simulate IOFSL behavior and add op status */
    iofsl_compat_xdr_process_status(send_buf, na_get_unexpected_size(), ENCODE);

    /* Encode output parameters */
    func_info.enc_routine(send_buf + iofsl_compat_xdr_get_size_status(),
            na_get_unexpected_size() - iofsl_compat_xdr_get_size_status(), func_out_struct);

    /* Respond back */
    send_tag = recv_tag;
    na_send(send_buf, na_get_unexpected_size(), recv_addr, send_tag, &send_request, NULL);

    na_wait(send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

    printf("Finalizing...\n");

    /* TODO Free in and out struct */

    /* Free memory and addresses */
    na_addr_free(recv_addr);
    recv_addr = NULL;

    free(recv_buf);
    recv_buf = NULL;

    free(send_buf);
    send_buf = NULL;

    na_finalize();
    return EXIT_SUCCESS;
}
