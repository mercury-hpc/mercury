/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROC_H
#define MERCURY_PROC_H

#include "mercury_config.h"
#include "mercury_error.h"
#include "mercury_bulk.h"
#include "iofsl_compat.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef HG_PROC_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define HG_PROC_INLINE extern inline
# else
#  define HG_PROC_INLINE inline
# endif
#endif

/* TODO may want a better solution than ifdef MERCURY_HAS_XDR */
#ifdef MERCURY_HAS_XDR
#include <rpc/types.h>
#include <rpc/xdr.h>
#endif

typedef void * hg_proc_t;

#define HG_PROC_NULL ((hg_proc_t)0)

/*
 * Proc operations.  HG_ENCODE causes the type to be encoded into the
 * stream.  HG_DECODE causes the type to be extracted from the stream.
 * HG_FREE can be used to release the space allocated by an HG_DECODE
 * request.
 */
typedef enum {
    HG_ENCODE,
    HG_DECODE,
    HG_FREE
} hg_proc_op_t;

/*
 * 0      HG_PROC_HEADER_SIZE              size
 * |______________|__________________________|
 * |    Header    |        Encoded Data      |
 * |______________|__________________________|
 */

typedef struct hg_proc_buf {
    void    *buf;       /* Pointer to allocated buffer */
    void    *buf_ptr;   /* Pointer to current position */
    size_t   size;      /* Total buffer size */
    size_t   size_left; /* Available size for user */
    bool     is_mine;
#ifdef MERCURY_HAS_XDR
    XDR      xdr;
#endif
} hg_proc_buf_t;

typedef struct hg_priv_proc {
    hg_proc_op_t   op;
    hg_proc_buf_t *current_buf;
    hg_proc_buf_t  proc_buf;
    hg_proc_buf_t  extra_buf;
} hg_priv_proc_t;

typedef const char * hg_string_t;

#define HG_BULK_MAX_HANDLE_SIZE 32 /* TODO Arbitrary value */

#ifdef __cplusplus
extern "C" {
#endif

/* Can be used to allocate a buffer that will be used by the generic proc
 * (use free to free it)
 */
int hg_proc_buf_alloc(void **mem_ptr, size_t size);

/* Create/Free a new encoding/decoding processor from a given buffer */
int hg_proc_create(void *buf, size_t buf_size, hg_proc_op_t op, hg_proc_t *proc);
int hg_proc_free(hg_proc_t proc);

/* Get current operation mode used for processor (Only valid if proc is created) */
hg_proc_op_t hg_proc_get_op(hg_proc_t proc);

/* Get/Request buffer size for processing */
size_t hg_proc_get_size(hg_proc_t proc);
int hg_proc_set_size(hg_proc_t proc, size_t buf_size);

/* Get size left for processing (info) */
size_t hg_proc_get_size_left(hg_proc_t proc);

/* Get/Set current buffer position */
void * hg_proc_get_buf_ptr(hg_proc_t proc);
int hg_proc_set_buf_ptr(hg_proc_t proc, void *buf_ptr);

/* Get required space for storing header data */
size_t hg_proc_get_header_size(void);

/* Get extra buffer */
void * hg_proc_get_extra_buf(hg_proc_t proc);

/* Get extra buffer size */
size_t hg_proc_get_extra_size(hg_proc_t proc);

/* Set extra buffer to mine (if other calls mine, buffer is no longer freed
 * after hg_proc_free)
 */
int hg_proc_set_extra_buf_is_mine(hg_proc_t proc, bool mine);

/*---------------------------------------------------------------------------
 * Function:    hg_proc_string_hash
 *
 * Purpose:     Hash function name for unique ID to register
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE unsigned int hg_proc_string_hash(const char *string)
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
 * Function:    hg_proc_memcpy
 *
 * Purpose:     Generic processing routines using memcpy
 *              NB. Only uses memcpy / use hg_proc_raw for more generic proc
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_memcpy(hg_proc_t proc, void *data, size_t data_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    const void *src;
    void *dest;
    int ret = HG_SUCCESS;

    if (priv_proc->op == HG_FREE) return ret;

    /* If not enough space allocate extra space if encoding or just get extra buffer if decoding */
    if (priv_proc->current_buf->size_left < data_size) {
        hg_proc_set_size(proc, priv_proc->proc_buf.size + priv_proc->extra_buf.size + data_size);
    }

    /* Process data */
    src = (priv_proc->op == HG_ENCODE) ? (const void *) data : (const void *) priv_proc->current_buf->buf_ptr;
    dest = (priv_proc->op == HG_ENCODE) ? priv_proc->current_buf->buf_ptr : data;
    memcpy(dest, src, data_size);
    priv_proc->current_buf->buf_ptr = (char*) priv_proc->current_buf->buf_ptr + data_size;
    priv_proc->current_buf->size_left -= data_size;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_int8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_int8_t  (hg_proc_t proc, int8_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int8_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(int8_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_uint8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_uint8_t  (hg_proc_t proc, uint8_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint8_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(uint8_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_int16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_int16_t  (hg_proc_t proc, int16_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int16_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(int16_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_uint16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_uint16_t  (hg_proc_t proc, uint16_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint16_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(uint16_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_int32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_int32_t  (hg_proc_t proc, int32_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int32_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(int32_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_uint32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_uint32_t  (hg_proc_t proc, uint32_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint32_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(uint32_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_int64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_int64_t  (hg_proc_t proc, int64_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int64_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(int64_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_uint64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_uint64_t  (hg_proc_t proc, uint64_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint64_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(uint64_t));
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_raw
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_raw  (hg_proc_t proc, void *buf, size_t buf_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    uint8_t *buf_ptr;
    uint8_t *buf_ptr_lim = (uint8_t*) buf + buf_size;
    int ret = HG_FAIL;

    for (buf_ptr = (uint8_t*) buf; buf_ptr < buf_ptr_lim; buf_ptr++) {
        ret = hg_proc_uint8_t(priv_proc, buf_ptr);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Proc error");
            break;
        }
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_hg_string_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_hg_string_t(hg_proc_t proc, hg_string_t *string)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    uint32_t string_len = 0;
    char *string_buf = NULL;
    int ret = HG_FAIL;

    switch (priv_proc->op) {
        case HG_ENCODE:
            string_len = strlen(*string) + 1;
            string_buf = (char*) *string;
            ret = hg_proc_uint32_t(priv_proc, &string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            ret = hg_proc_raw(priv_proc, string_buf, string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            break;
        case HG_DECODE:
            ret = hg_proc_uint32_t(priv_proc, &string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            string_buf = (char*) malloc(string_len);
            ret = hg_proc_raw(priv_proc, string_buf, string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            *string = string_buf;
            break;
        case HG_FREE:
            string_buf = (char*) *string;
            if (!string_buf) {
                HG_ERROR_DEFAULT("Already freed");
                ret = HG_FAIL;
                return ret;
            }
            free(string_buf);
            *string = NULL;
            ret = HG_SUCCESS;
            break;
        default:
            break;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_hg_bulk_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_hg_bulk_t(hg_proc_t proc, hg_bulk_t *handle)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
    char buf[HG_BULK_MAX_HANDLE_SIZE];

    switch (priv_proc->op) {
        case HG_ENCODE:
            ret = HG_Bulk_handle_serialize(buf, HG_BULK_MAX_HANDLE_SIZE, *handle);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not serialize bulk handle");
                ret = HG_FAIL;
                break;
            }
            ret = hg_proc_raw(proc, buf, HG_BULK_MAX_HANDLE_SIZE);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
            }
            break;
        case HG_DECODE:
            ret = hg_proc_raw(proc, buf, HG_BULK_MAX_HANDLE_SIZE);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
            }
            ret = HG_Bulk_handle_deserialize(handle, buf, HG_BULK_MAX_HANDLE_SIZE);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not deserialize bulk handle");
                ret = HG_FAIL;
            }
            break;
        case HG_FREE:
            ret = HG_Bulk_handle_free(*handle);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not free bulk handle");
                ret = HG_FAIL;
            }
            *handle = NULL;
            break;
        default:
            break;
    }
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_header_function
 *
 * Purpose:     Private information for function shipping
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_header_request (hg_proc_t proc, uint32_t *op_id,
        uint8_t *extra_buf_used)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_buf_t  *current_buf;
    void *current_buf_ptr;
    uint32_t iofsl_op_id = PROTO_GENERIC;
    int ret = HG_FAIL;

    current_buf = priv_proc->current_buf;
    current_buf_ptr = hg_proc_get_buf_ptr(proc);
    priv_proc->current_buf = &priv_proc->proc_buf;
    hg_proc_set_buf_ptr(proc, priv_proc->proc_buf.buf);

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    ret = hg_proc_uint32_t(proc, &iofsl_op_id);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        return ret;
    }

    /* Add generic op id now */
    ret = hg_proc_uint32_t(proc, op_id);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        return ret;
    }

    /* Has an extra buffer */
    ret = hg_proc_uint8_t(proc, extra_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        return ret;
    }

    priv_proc->current_buf = current_buf;
    hg_proc_set_buf_ptr(proc, current_buf_ptr);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_header_response
 *
 * Purpose:     Private information for response
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
HG_PROC_INLINE int hg_proc_header_response (hg_proc_t proc, uint8_t *extra_buf_used)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_buf_t  *current_buf;
    void *current_buf_ptr;
    int32_t iofsl_op_status = 0;
    int ret = HG_FAIL;

    current_buf = priv_proc->current_buf;
    current_buf_ptr = hg_proc_get_buf_ptr(proc);
    priv_proc->current_buf = &priv_proc->proc_buf;
    hg_proc_set_buf_ptr(proc, priv_proc->proc_buf.buf);

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    ret = hg_proc_int32_t(proc, &iofsl_op_status);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        return ret;
    }

    /* Has an extra buffer */
    hg_proc_uint8_t(proc, extra_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        return ret;
    }

    priv_proc->current_buf = current_buf;
    hg_proc_set_buf_ptr(proc, current_buf_ptr);

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_PROC_H */
