/*
 * iofsl_compat.c
 *
 */

#include "iofsl_compat.h"

#include <stdint.h>
#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

/* TODO (keep that for now) Define the ZOIDFS operations */
enum {
    PROTO_GENERIC = 16, /* TODO map to zoidfs proto */

    /* First invalid operation id */
    PROTO_MAX
};

typedef struct iofsl_compat_xdr {
    XDR  xdr;
    int  xdr_init;
} iofsl_compat_xdr_t;

/* Op id describes the various generic operations (setattr, getattr etc.) */
typedef uint32_t iofsl_compat_op_id_t;

/*
 * generic_op_status_t is used by the server to inform the client of the status
 * of the operation.
 */
typedef int32_t iofsl_compat_op_status_t;

/*
 * zoidfs message data types
 * Used by the zoidfs xdr processor to encode / decode data
 */
typedef enum {
    OP_ID_T = 0,
    OP_STATUS_T
} iofsl_compat_data_t;

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

/*
 * xdr_generic_op_id_t
 * Encode/decode generic_op_id_t using XDR.
 */
static inline bool_t iofsl_compat_xdr_op_id_t(XDR *xdrs, iofsl_compat_op_id_t *op_id) {
    return(XDR_UINT32(xdrs, op_id));
}

/*
 * xdr_generic_op_status_t
 * Encode/decode generic_op_status_t using XDR.
 */
static inline bool_t iofsl_compat_xdr_op_status_t(XDR *xdrs, iofsl_compat_op_status_t *op_status) {
    return(xdr_int32_t(xdrs, op_status));
}

static unsigned int iofsl_compat_xdr_size_processor(iofsl_compat_data_t data_t, void *data)
{
    unsigned int size = 0;
    if(data) {
        switch(data_t) {
            case OP_ID_T:
                size = xdr_sizeof((xdrproc_t)iofsl_compat_xdr_op_id_t, data);
                break;
            case OP_STATUS_T:
                size = xdr_sizeof((xdrproc_t)iofsl_compat_xdr_op_status_t, data);
                break;
            default:
                fprintf(stderr, "%s(): processing error, unknown zoidfs data type, %s:%i.\n", __func__, __FILE__, __LINE__);
                size = 0;
                break;
        }
    }
    return size;
}

/*
 * xdr processing for generic messages
 */
static int iofsl_compat_xdr_processor(iofsl_compat_data_t data_t, void *data, iofsl_compat_xdr_t *xdr)
{
    switch(data_t) {
        case OP_ID_T:
            if (!iofsl_compat_xdr_op_id_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_id_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        case OP_STATUS_T:
            if (!iofsl_compat_xdr_op_status_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_status_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        default:
            fprintf(stderr, "%s(): processing error, unknown zoidfs data type, %s:%i.\n", __func__, __FILE__, __LINE__);
            break;
    }
    return 0;
}

void iofsl_compat_xdr_process_id(void *buf, unsigned int actual_size, iofsl_compat_op_t op)
{
    iofsl_compat_xdr_t compat_xdr;
    iofsl_compat_op_id_t op_id = PROTO_GENERIC; /* TODO keep that for now */

    switch (op) {
        case ENCODE:
            xdrmem_create(&compat_xdr.xdr, buf, actual_size, XDR_ENCODE);
            break;
        case DECODE:
            xdrmem_create(&compat_xdr.xdr, buf, actual_size, XDR_DECODE);
            break;
        default:
            fprintf(stderr, "%s(): processing error, unknown op type, %s:%i.\n", __func__, __FILE__, __LINE__);
            return;
    }
    compat_xdr.xdr_init = 1;
    iofsl_compat_xdr_processor(OP_ID_T, &op_id, &compat_xdr);
    if (op == DECODE) printf("IOFSL compat op id: %d\n", op_id);
}

void iofsl_compat_xdr_process_status(void *buf, unsigned int actual_size, iofsl_compat_op_t op)
{
    iofsl_compat_xdr_t compat_xdr;
    iofsl_compat_op_status_t op_status = 0;

    switch (op) {
        case ENCODE:
            xdrmem_create(&compat_xdr.xdr, buf, actual_size, XDR_ENCODE);
            break;
        case DECODE:
            xdrmem_create(&compat_xdr.xdr, buf, actual_size, XDR_DECODE);
            break;
        default:
            fprintf(stderr, "%s(): processing error, unknown op type, %s:%i.\n", __func__, __FILE__, __LINE__);
            return;
    }
    compat_xdr.xdr_init = 1;
    iofsl_compat_xdr_processor(OP_STATUS_T, &op_status, &compat_xdr);
    if (op == DECODE) printf("IOFSL compat op status: %d\n", op_status);
}

size_t iofsl_compat_xdr_get_size_id()
{
    iofsl_compat_op_id_t op_id;
    return iofsl_compat_xdr_size_processor(OP_ID_T, &op_id);
}

size_t iofsl_compat_xdr_get_size_status()
{
    iofsl_compat_op_status_t op_status;
    return iofsl_compat_xdr_size_processor(OP_STATUS_T, &op_status);
}
