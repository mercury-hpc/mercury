/*
 * iofsl_compat.h
 */

#ifndef IOFSL_COMPAT_H
#define IOFSL_COMPAT_H

#include <rpc/types.h>
#include <rpc/xdr.h>

#define ION_ENV "ZOIDFS_ION_NAME"

/* TODO (keep that for now) Define the ZOIDFS operations */
enum {
    PROTO_GENERIC = 16, /* TODO map to zoidfs proto */

    /* First invalid operation id */
    PROTO_MAX
};

typedef struct {
    XDR  xdr;
    int  xdr_init;
} generic_xdr_t;


#endif /* IOFSL_COMPAT_H */
