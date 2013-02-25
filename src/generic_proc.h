/*
 * generic_proc.h
 */

#ifndef GENERIC_PROC_H
#define GENERIC_PROC_H

#include "shipper_error.h"
#include "shipper_config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef FS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define FS_INLINE extern inline
# else
#  define FS_INLINE inline
# endif
#endif

/* TODO using ifdef IOFSL_SHIPPER_HAS_XDR is dangerous for inline functions */

#ifdef IOFSL_SHIPPER_HAS_XDR
#include <rpc/types.h>
#include <rpc/xdr.h>
#endif

typedef void * fs_proc_t;

typedef enum {
    FS_ENCODE,
    FS_DECODE
} fs_proc_op_t;

typedef struct fs_priv_proc {
    fs_proc_op_t op;
#ifdef IOFSL_SHIPPER_HAS_XDR
    XDR      xdr;
#else
    void    *buf;
    size_t   buf_len;
    void    *buf_ptr;
    size_t   buf_size_left;
    bool     buf_is_mine;
#endif
} fs_priv_proc_t;

typedef const char * fs_string_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new encoding/decoding processor */
int fs_proc_create(void *buf, size_t buf_len, fs_proc_op_t op, fs_proc_t *proc);

/* Free the processor */
int fs_proc_free(fs_proc_t proc);

/* Get number of bytes available for processing */
size_t fs_proc_get_size(fs_proc_t proc);

/*---------------------------------------------------------------------------
 * Function:    fs_proc_string_hash
 *
 * Purpose:     Hash function name for unique ID to register
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_string_hash(const char *string)
{
    /* This is the djb2 string hash function */

    unsigned int result = 5381;
    unsigned char *p;

    p = (unsigned char *) string;

    while (*p != '\0') {
        result = (result << 5) + result + *p;
        ++p;
    }
    return result;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_memcpy
 *
 * Purpose:     Generic processing routines using memcpy
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
#ifndef IOFSL_SHIPPER_HAS_XDR
FS_INLINE int fs_proc_memcpy(fs_proc_t proc, void *data, size_t data_size)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
    const void *src;
    void *dest;

    if (priv_proc->buf_size_left > data_size) {
        src = (priv_proc->op == FS_ENCODE) ? (const void *) data : (const void *) priv_proc->buf_ptr ;
        dest = (priv_proc->op == FS_ENCODE) ? priv_proc->buf_ptr : data;
        memcpy(dest, src, data_size);
        priv_proc->buf_ptr += data_size;
        priv_proc->buf_size_left -= data_size;
        ret = S_SUCCESS;
    }
    return ret;
}
#endif

/*---------------------------------------------------------------------------
 * Function:    fs_proc_int8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_int8_t  (fs_proc_t proc, int8_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int8_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(int8_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_uint8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_uint8_t  (fs_proc_t proc, uint8_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint8_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(uint8_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_int16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_int16_t  (fs_proc_t proc, int16_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int16_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(int16_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_uint16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_uint16_t  (fs_proc_t proc, uint16_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint16_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(uint16_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_int32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_int32_t  (fs_proc_t proc, int32_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int32_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(int32_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_uint32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_uint32_t  (fs_proc_t proc, uint32_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint32_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(uint32_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_int64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_int64_t  (fs_proc_t proc, int64_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int64_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(int64_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_uint64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_uint64_t  (fs_proc_t proc, uint64_t *data)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint64_t(&priv_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    ret = fs_proc_memcpy(priv_proc, data, sizeof(uint64_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_raw
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_raw  (fs_proc_t proc, void *buf, size_t buf_len)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    uint8_t *buf_ptr;
    int ret = S_FAIL;

    for (buf_ptr = buf; buf_ptr < (uint8_t*)buf + buf_len; buf_ptr++) {
        ret = fs_proc_uint8_t(priv_proc, buf_ptr);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("Proc error");
            break;
        }
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_fs_string_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_fs_string_t(fs_proc_t proc, fs_string_t *string)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    uint32_t string_len;
    char *string_buf = NULL;
    int ret = S_FAIL;

    if (priv_proc->op == FS_ENCODE) {
        string_len = strlen(*string) + 1;
        string_buf = malloc(string_len);
        strcpy(string_buf, *string);
    }
    ret = fs_proc_uint32_t(priv_proc, &string_len);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    if (priv_proc->op == FS_DECODE) {
        string_buf = malloc(string_len);
    }

    ret = fs_proc_raw(priv_proc, string_buf, string_len);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("Proc error");
        ret = S_FAIL;
        return ret;
    }

    if (priv_proc->op == FS_DECODE) {
        *string = string_buf;
    } else {
        if (string_buf) free(string_buf);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_free_fs_string_t
 *
 * Purpose:     Free allocated fs_string_t
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_free_fs_string_t(fs_string_t string)
{
    char *string_buf = (char*) string;
    int ret = S_SUCCESS;

    if (!string_buf) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }
    free(string_buf);

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* GENERIC_PROC_H */
