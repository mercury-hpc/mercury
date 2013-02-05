/*
 * iofsl_compat.h
 */

#ifndef IOFSL_COMPAT_H
#define IOFSL_COMPAT_H

#include <stddef.h>

typedef enum {
    ENCODE,
    DECODE
} iofsl_compat_op_t;

#define ION_ENV "ZOIDFS_ION_NAME"

#ifdef __cplusplus
extern "C" {
#endif

void iofsl_compat_xdr_process_id(void *buf, unsigned int actual_size, iofsl_compat_op_t op);

void iofsl_compat_xdr_process_status(void *buf, unsigned int actual_size, iofsl_compat_op_t op);

size_t iofsl_compat_xdr_get_size_id(void);

size_t iofsl_compat_xdr_get_size_status(void);

#ifdef __cplusplus
}
#endif

#endif /* IOFSL_COMPAT_H */
