/*
 * iofsl_compat.h
 */

#ifndef IOFSL_COMPAT_H
#define IOFSL_COMPAT_H

#include <stddef.h>

#include "generic_proc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Encode/decode IOFSL ID */
void iofsl_compat_proc_enc_id(void *buf, size_t buf_len);
void iofsl_compat_proc_dec_id(const void *buf, size_t buf_len);

/* Encode/decode IOFSL return status */
void iofsl_compat_proc_enc_status(void *buf, size_t buf_len);
void iofsl_compat_proc_dec_status(const void *buf, size_t buf_len);

/* Get required size for encoding ID */
size_t iofsl_compat_get_size_id(void);

/* Get required size for encoding return status */
size_t iofsl_compat_get_size_status(void);

#ifdef __cplusplus
}
#endif

#endif /* IOFSL_COMPAT_H */
