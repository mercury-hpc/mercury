/*
 * server.c
 *
 *  Created on: Nov 15, 2012
 *      Author: soumagne
 */

#include "network_bmi.h"
#include "network_mpi.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <stdbool.h>

#define ION_ENV "ZOIDFS_ION_NAME"

/******************************************************************************/
/* TODO Only used for encoding / decoding and this should be cleaned up       */
/******************************************************************************/
enum {
    PROTO_GENERIC = 16
};

typedef struct {
    XDR  xdr;
    bool xdr_init;
} generic_xdr_t;

typedef uint32_t generic_op_id_t;
typedef int32_t generic_op_status_t;

typedef enum {
    OP_ID_T = 0,
    OP_STATUS_T
} generic_msg_data_t;

#ifdef __APPLE__
#define XDR_UINT32 xdr_u_int32_t

#ifdef __LP64__
unsigned int
#else
unsigned long
#endif
xdr_sizeof(xdrproc_t func, void *data);

#else
#define XDR_UINT32 xdr_uint32_t
#endif

static inline bool_t xdr_generic_op_id_t(XDR *xdrs, generic_op_id_t *op_id) {
    return(XDR_UINT32(xdrs, op_id));
}

static inline bool_t xdr_generic_op_status_t(XDR *xdrs, generic_op_status_t *op_status) {
    return(xdr_int32_t(xdrs, op_status));
}

static int generic_xdr_processor(generic_msg_data_t data_t, void *data, generic_xdr_t *xdr)
{
    switch(data_t) {
        case OP_ID_T:
            if (!xdr_generic_op_id_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_id_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        case OP_STATUS_T:
            if (!xdr_generic_op_status_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_status_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        default:
            fprintf(stderr, "%s(): processing error, unknown zoidfs data type, %s:%i.\n", __func__, __FILE__, __LINE__);
            break;
    }
    return 0;
}

static void xdr_decode(void *buf, na_size_t actual_size, void *out)
{
    generic_xdr_t recv_xdr;
    generic_op_id_t zoidfs_op_id = PROTO_GENERIC; /* TODO keep that for now */
    generic_op_id_t *out_op_id = (generic_op_id_t *) out;

    xdrmem_create(&recv_xdr.xdr, buf, (unsigned int) actual_size, XDR_DECODE);
    recv_xdr.xdr_init = 1;
    generic_xdr_processor(OP_ID_T, &zoidfs_op_id, &recv_xdr);
    generic_xdr_processor(OP_ID_T, out_op_id, &recv_xdr);
}

static void xdr_encode(void *buf, na_size_t actual_size, void *in)
{
    generic_xdr_t send_xdr;
    generic_op_status_t zoidfs_op_status = 0;
    generic_op_status_t *in_op_status = (generic_op_status_t *) in;

    xdrmem_create(&send_xdr.xdr, buf, (unsigned int) actual_size, XDR_ENCODE);
    send_xdr.xdr_init = 1;
    generic_xdr_processor(OP_STATUS_T, &zoidfs_op_status, &send_xdr);
    generic_xdr_processor(OP_STATUS_T, in_op_status, &send_xdr);
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/


int main(int argc, char *argv[])
{
    int i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        na_mpi_init(NULL, MPI_INIT_SERVER);
    } else {
        char *listen_addr = getenv(ION_ENV);
        if (!listen_addr) {
            fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
            return EXIT_FAILURE;
        }
        na_bmi_init("bmi_tcp", listen_addr, BMI_INIT_SERVER);
    }

    for (i = 0; i < 16; i++) {
        void *recv_buf = NULL;
        na_size_t recv_buf_len = 0;
        na_addr_t source;
        na_tag_t tag;
        na_request_t req;
        generic_op_id_t recv_id;
        generic_op_status_t op_status;

        recv_buf = malloc(na_get_unexpected_size());
        na_recv_unexpected(recv_buf, &recv_buf_len, &source, &tag, NULL, NULL);
        xdr_decode(recv_buf, recv_buf_len, &recv_id);
        printf("Unexpectedly received id: %d (%lu bytes, tag=%d)\n",
                (int) recv_id, (long unsigned int) recv_buf_len, tag);
        op_status = recv_id;
        xdr_encode(recv_buf, recv_buf_len, &op_status);
        na_send(recv_buf, recv_buf_len, source, tag, &req, NULL);
        na_wait(req, NULL, NA_BMI_MAX_IDLE_TIME, NA_STATUS_IGNORE);
        na_addr_free(source);
        source = NULL;
        free(recv_buf);
        recv_buf = NULL;
    }

    na_finalize();
    return EXIT_SUCCESS;
}
