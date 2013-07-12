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

#include "mercury_types.h"
#include "mercury_error.h"
#include "mercury_bulk.h"
#include "iofsl_compat.h"

#include <stdlib.h>
#include <string.h>
#ifdef MERCURY_HAS_XDR
#include <rpc/types.h>
#include <rpc/xdr.h>
#endif

#ifndef HG_PROC_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define HG_PROC_INLINE extern inline
# else
#  define HG_PROC_INLINE inline
# endif
#endif

/*
 * 0      HG_PROC_HEADER_SIZE              size
 * |______________|__________________________|
 * |    Header    |        Encoded Data      |
 * |______________|__________________________|
 */
#define HG_PROC_MAX_HEADER_SIZE 64

typedef struct hg_proc_buf {
    void *    buf;       /* Pointer to allocated buffer */
    void *    buf_ptr;   /* Pointer to current position */
    size_t    size;      /* Total buffer size */
    size_t    size_left; /* Available size for user */
    hg_bool_t is_mine;
#ifdef MERCURY_HAS_XDR
    XDR      xdr;
#endif
} hg_proc_buf_t;

typedef struct hg_priv_proc {
    hg_proc_op_t    op;
    hg_proc_buf_t * current_buf;
    hg_proc_buf_t   proc_buf;
    hg_proc_buf_t   extra_buf;
} hg_priv_proc_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Can be used to allocate a buffer that will be used by the generic processor.
 * Buffer can be freed using "free".
 *
 * \param mem_ptr [IN]          pointer to memory address
 * \param size [IN]             request buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_buf_alloc(void **mem_ptr, size_t size);

/**
 * Create a new encoding/decoding processor.
 *
 * \param buf [IN]              pointer to buffer that will be used for
 *                              serialization/deserialization
 * \param buf_size [IN]         buffer size
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE / HG_FREE
 * \param proc [OUT]            pointer to abstract processor object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_create(void *buf, size_t buf_size, hg_proc_op_t op, hg_proc_t *proc);

/**
 * Free the processor.
 *
 * \param proc [IN/OUT]         abstract processor object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_free(hg_proc_t proc);

/**
 * Get the operation type associated to the processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Operation type
 */
HG_EXPORT hg_proc_op_t
hg_proc_get_op(hg_proc_t proc);

/**
 * Get buffer size available for processing.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Non-negative size value
 */
HG_EXPORT size_t
hg_proc_get_size(hg_proc_t proc);

/**
 * Request a new buffer size. This will modify the size of the buffer attached
 * to the processor or create an extra processing buffer.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param buf_size [IN]         buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_set_size(hg_proc_t proc, size_t buf_size);

/**
 * Get size left for processing.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Non-negative size value
 */
HG_EXPORT size_t
hg_proc_get_size_left(hg_proc_t proc);

/**
 * Get pointer to current buffer (for manual encoding).
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Buffer pointer
 */
HG_EXPORT void *
hg_proc_get_buf_ptr(hg_proc_t proc);

/**
 * Set new buffer pointer (for manual encoding).
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param buf_ptr [IN]          pointer to buffer used by the processor
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_set_buf_ptr(hg_proc_t proc, void *buf_ptr);

/**
 * Get eventual extra buffer used by processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Pointer to buffer or NULL if no extra buffer has been used
 */
HG_EXPORT void *
hg_proc_get_extra_buf(hg_proc_t proc);

/**
 * Get eventual size of the extra buffer used by processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Size of buffer or 0 if no extra buffer has been used
 */
HG_EXPORT size_t
hg_proc_get_extra_size(hg_proc_t proc);

/**
 * Set extra buffer to mine (if other calls mine, buffer is no longer freed
 * after hg_proc_free)
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
hg_proc_set_extra_buf_is_mine(hg_proc_t proc, hg_bool_t mine);

/**
 * Inline prototypes (do not remove)
 */
HG_PROC_INLINE unsigned int hg_proc_string_hash(const char *string);
HG_PROC_INLINE int hg_proc_memcpy(hg_proc_t proc, void *data, size_t data_size);
HG_PROC_INLINE int hg_proc_int8_t(hg_proc_t proc, hg_int8_t *data);
HG_PROC_INLINE int hg_proc_uint8_t(hg_proc_t proc, hg_uint8_t *data);
HG_PROC_INLINE int hg_proc_int16_t(hg_proc_t proc, hg_int16_t *data);
HG_PROC_INLINE int hg_proc_uint16_t(hg_proc_t proc, hg_uint16_t *data);
HG_PROC_INLINE int hg_proc_int32_t(hg_proc_t proc, hg_int32_t *data);
HG_PROC_INLINE int hg_proc_uint32_t(hg_proc_t proc, hg_uint32_t *data);
HG_PROC_INLINE int hg_proc_int64_t(hg_proc_t proc, hg_int64_t *data);
HG_PROC_INLINE int hg_proc_uint64_t(hg_proc_t proc, hg_uint64_t *data);
HG_PROC_INLINE int hg_proc_raw(hg_proc_t proc, void *buf, size_t buf_size);
HG_PROC_INLINE int hg_proc_hg_string_t(hg_proc_t proc, hg_string_t *string);
HG_PROC_INLINE int hg_proc_hg_bulk_t(hg_proc_t proc, hg_bulk_t *handle);
HG_PROC_INLINE size_t hg_proc_get_header_size(void);
HG_PROC_INLINE int hg_proc_header_request(hg_proc_t proc, hg_uint32_t *op_id,
        uint8_t *extra_buf_used, hg_bulk_t *extra_handle);
HG_PROC_INLINE int hg_proc_header_response(hg_proc_t proc, hg_uint8_t *extra_buf_used);

/**
 * Hash function name for unique ID to register.
 *
 * \param string [IN]           string name
 *
 * \return Non-negative ID that corresponds to string name
 */
HG_PROC_INLINE unsigned int
hg_proc_string_hash(const char *string)
{
    /* This is the djb2 string hash function */

    unsigned int result = 5381;
    const unsigned char *p;

    p = (const unsigned char *) string;

    while (*p != '\0') {
        result = (result << 5) + result + *p;
        ++p;
    }
    return result;
}

/**
 * Generic processing routine using memcpy.
 * NB. Only uses memcpy / use hg_proc_raw for more generic proc.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 * \param data_size [IN]        data size
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_memcpy(hg_proc_t proc, void *data, size_t data_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    const void *src;
    void *dest;
    int ret = HG_SUCCESS;

    if (priv_proc->op == HG_FREE) return ret;

    /* If not enough space allocate extra space if encoding or
     * just get extra buffer if decoding */
    if (priv_proc->current_buf->size_left < data_size) {
        hg_proc_set_size(proc, priv_proc->proc_buf.size +
                priv_proc->extra_buf.size + data_size);
    }

    /* Process data */
    src = (priv_proc->op == HG_ENCODE) ? (const void *) data :
            (const void *) priv_proc->current_buf->buf_ptr;
    dest = (priv_proc->op == HG_ENCODE) ? priv_proc->current_buf->buf_ptr :
            data;
    memcpy(dest, src, data_size);
    priv_proc->current_buf->buf_ptr = (char*) priv_proc->current_buf->buf_ptr
            + data_size;
    priv_proc->current_buf->size_left -= data_size;

    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_int8_t(hg_proc_t proc, hg_int8_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int8_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_int8_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_uint8_t(hg_proc_t proc, hg_uint8_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint8_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_uint8_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_int16_t(hg_proc_t proc, hg_int16_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int16_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_int16_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_uint16_t(hg_proc_t proc, hg_uint16_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint16_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_uint16_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_int32_t(hg_proc_t proc, hg_int32_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int32_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_int32_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_uint32_t(hg_proc_t proc, hg_uint32_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint32_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_uint32_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_int64_t(hg_proc_t proc, hg_int64_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_int64_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_int64_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_uint64_t(hg_proc_t proc, hg_uint64_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
#ifdef MERCURY_HAS_XDR
    ret = xdr_uint64_t(&priv_proc->current_buf->xdr, data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(priv_proc, data, sizeof(hg_uint64_t));
#endif
    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param buf [IN/OUT]          pointer to buffer
 * \param buf_size [IN]         buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_raw(hg_proc_t proc, void *buf, size_t buf_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_uint8_t *buf_ptr;
    hg_uint8_t *buf_ptr_lim = (hg_uint8_t*) buf + buf_size;
    int ret = HG_FAIL;

    for (buf_ptr = (hg_uint8_t*) buf; buf_ptr < buf_ptr_lim; buf_ptr++) {
        ret = hg_proc_uint8_t(priv_proc, buf_ptr);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Proc error");
            break;
        }
    }

    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param string [IN/OUT]       pointer to string
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_hg_string_t(hg_proc_t proc, hg_string_t *string)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_uint64_t string_len = 0;
    char *string_buf = NULL;
    int ret = HG_FAIL;

    switch (priv_proc->op) {
        case HG_ENCODE:
            string_len = strlen(*string) + 1;
            string_buf = (char*) *string;
            ret = hg_proc_uint64_t(priv_proc, &string_len);
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
            ret = hg_proc_uint64_t(priv_proc, &string_len);
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

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param handle [IN/OUT]       pointer to bulk handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_hg_bulk_t(hg_proc_t proc, hg_bulk_t *handle)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;
    void *buf;
    hg_uint64_t buf_size = 0;

    switch (priv_proc->op) {
        case HG_ENCODE:
            buf_size = HG_Bulk_handle_get_serialize_size(*handle);
            buf = malloc(buf_size);
            ret = HG_Bulk_handle_serialize(buf, buf_size, *handle);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not serialize bulk handle");
                ret = HG_FAIL;
                return ret;
            }
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            ret = hg_proc_raw(proc, buf, buf_size);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            free(buf);
            buf = NULL;
            break;
        case HG_DECODE:
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            buf = malloc(buf_size);
            ret = hg_proc_raw(proc, buf, buf_size);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            ret = HG_Bulk_handle_deserialize(handle, buf, buf_size);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not deserialize bulk handle");
                ret = HG_FAIL;
                return ret;
            }
            free(buf);
            buf = NULL;
            break;
        case HG_FREE:
            ret = HG_Bulk_handle_free(*handle);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Could not free bulk handle");
                ret = HG_FAIL;
                return ret;
            }
            *handle = NULL;
            break;
        default:
            break;
    }
    return ret;
}

/**
 * Get size reserved for header (separates user data from metadata used for
 * encoding / decoding).
 *
 * \return Non-negative size value
 */
HG_PROC_INLINE size_t
hg_proc_get_header_size(void)
{
    /* TODO this may need to more accurately defined in the future */
    return HG_PROC_MAX_HEADER_SIZE;
}

/**
 * Process private information for sending/receiving RPC request.
 *
 * \param proc [IN/OUT]            abstract processor object
 * \param op_id [IN/OUT]           pointer to operation ID
 * \param extra_buf_used [IN/OUT]  pointer to boolean
 * \param extra_handle [IN/OUT]    pointer to eventual bulk handle that
 *                                 describes an extra buffer if it has been
 *                                 used for encoding
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_header_request(hg_proc_t proc, hg_uint32_t *op_id,
        hg_uint8_t *extra_buf_used, hg_bulk_t *extra_handle)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_buf_t  *current_buf;
    void *current_buf_ptr;
    hg_uint32_t iofsl_op_id = PROTO_GENERIC;
    int ret = HG_FAIL;

    /* If we have switched buffers we need to go back to the buffer that
     * contains the header */
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

    if (*extra_buf_used) {
        ret = hg_proc_hg_bulk_t(proc, extra_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Proc error");
            ret = HG_FAIL;
            return ret;
        }
    }

    priv_proc->current_buf = current_buf;
    hg_proc_set_buf_ptr(proc, current_buf_ptr);

    return ret;
}

/**
 * Process private information for sending/receiving RPC response.
 *
 * \param proc [IN/OUT]            abstract processor object
 * \param extra_buf_used [IN/OUT]  pointer to boolean
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_header_response(hg_proc_t proc, hg_uint8_t *extra_buf_used)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_buf_t  *current_buf;
    void *current_buf_ptr;
    hg_int32_t iofsl_op_status = 0;
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
