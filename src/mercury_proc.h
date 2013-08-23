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
#ifdef HG_HAS_XDR
#include <rpc/types.h>
#include <rpc/xdr.h>
#    ifdef __APPLE__
#        define xdr_int8_t   xdr_char
#        define xdr_uint8_t  xdr_u_char
#        define xdr_uint16_t xdr_u_int16_t
#        define xdr_uint32_t xdr_u_int32_t
#        define xdr_uint64_t xdr_u_int64_t
#    endif
#endif

typedef char * hg_string_t;

#ifndef HG_PROC_INLINE
  #if defined(__GNUC__) && !defined(__GNUC_STDC_INLINE__)
    #define HG_PROC_INLINE extern HG_INLINE
  #else
    #define HG_PROC_INLINE HG_INLINE
  #endif
#endif

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

#ifdef HG_HAS_XDR
/**
 * Get pointer to current XDR stream (for manual encoding).
 *
 * \param proc [IN]             abstract processor object
 *
 * \return XDR stream pointer
 */
HG_EXPORT XDR *
hg_proc_get_xdr_ptr(hg_proc_t proc);
#endif

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
 * Base proc routine using memcpy.
 * NB. Only uses memcpy / use hg_proc_raw for encoding independent proc routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 * \param data_size [IN]        data size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT
int hg_proc_memcpy(hg_proc_t proc, void *data, size_t data_size);

/**
 * Inline prototypes (do not remove)
 */
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_int8_t(hg_proc_t proc, hg_int8_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_uint8_t(hg_proc_t proc, hg_uint8_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_int16_t(hg_proc_t proc, hg_int16_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_uint16_t(hg_proc_t proc, hg_uint16_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_int32_t(hg_proc_t proc, hg_int32_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_uint32_t(hg_proc_t proc, hg_uint32_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_int64_t(hg_proc_t proc, hg_int64_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_uint64_t(hg_proc_t proc, hg_uint64_t *data);
HG_EXPORT HG_PROC_INLINE int hg_proc_raw(hg_proc_t proc, void *buf, size_t buf_size);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_string_t(hg_proc_t proc, hg_string_t *string);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_bulk_t(hg_proc_t proc, hg_bulk_t *handle);

/**
 * For convenience map stdint types to hg types
 */
#define hg_proc_int8_t   hg_proc_hg_int8_t
#define hg_proc_uint8_t  hg_proc_hg_uint8_t
#define hg_proc_int16_t  hg_proc_hg_int16_t
#define hg_proc_uint16_t hg_proc_hg_uint16_t
#define hg_proc_int32_t  hg_proc_hg_int32_t
#define hg_proc_uint32_t hg_proc_hg_uint32_t
#define hg_proc_int64_t  hg_proc_hg_int64_t
#define hg_proc_uint64_t hg_proc_hg_uint64_t

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return Non-negative on success or negative on failure
 */
HG_PROC_INLINE int
hg_proc_hg_int8_t(hg_proc_t proc, hg_int8_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_int8_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_int8_t));
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
hg_proc_hg_uint8_t(hg_proc_t proc, hg_uint8_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_uint8_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_uint8_t));
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
hg_proc_hg_int16_t(hg_proc_t proc, hg_int16_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_int16_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_int16_t));
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
hg_proc_hg_uint16_t(hg_proc_t proc, hg_uint16_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_uint16_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_uint16_t));
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
hg_proc_hg_int32_t(hg_proc_t proc, hg_int32_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_int32_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_int32_t));
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
hg_proc_hg_uint32_t(hg_proc_t proc, hg_uint32_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_uint32_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_uint32_t));
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
hg_proc_hg_int64_t(hg_proc_t proc, hg_int64_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_int64_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_int64_t));
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
hg_proc_hg_uint64_t(hg_proc_t proc, hg_uint64_t *data)
{
    int ret = HG_FAIL;
#ifdef HG_HAS_XDR
    ret = xdr_uint64_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_FAIL;
#else
    ret = hg_proc_memcpy(proc, data, sizeof(hg_uint64_t));
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
    hg_uint8_t *buf_ptr;
    hg_uint8_t *buf_ptr_lim = (hg_uint8_t*) buf + buf_size;
    int ret = HG_FAIL;

    for (buf_ptr = (hg_uint8_t*) buf; buf_ptr < buf_ptr_lim; buf_ptr++) {
        ret = hg_proc_uint8_t(proc, buf_ptr);
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
    hg_uint64_t string_len = 0;
    hg_string_t string_buf = NULL;
    int ret = HG_FAIL;

    switch (hg_proc_get_op(proc)) {
        case HG_ENCODE:
            string_len = strlen(*string) + 1;
            string_buf = *string;
            ret = hg_proc_uint64_t(proc, &string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            ret = hg_proc_raw(proc, string_buf, string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            break;
        case HG_DECODE:
            ret = hg_proc_uint64_t(proc, &string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            string_buf = (hg_string_t) malloc(string_len);
            ret = hg_proc_raw(proc, string_buf, string_len);
            if (ret != HG_SUCCESS) {
                HG_ERROR_DEFAULT("Proc error");
                ret = HG_FAIL;
                return ret;
            }
            *string = string_buf;
            break;
        case HG_FREE:
            string_buf = *string;
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
    int ret = HG_FAIL;
    void *buf;
    hg_uint64_t buf_size = 0;

    switch (hg_proc_get_op(proc)) {
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

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_PROC_H */
