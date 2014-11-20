/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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
 * Buffer should be freed using "hg_proc_buf_free".
 *
 * \param size [IN]             request buffer size
 *
 * \return Pointer to memory address or NULL if allocation failed
 */
HG_EXPORT void *
hg_proc_buf_alloc(
        hg_size_t size
        );

/**
 * Free memory which has been previously allocated using hg_proc_buf_alloc.
 *
 * \param mem_ptr [IN]          pointer to memory address
 */
HG_EXPORT void
hg_proc_buf_free(
        void *mem_ptr
        );

/**
 * Create a new encoding/decoding processor.
 *
 * \param buf [IN]              pointer to buffer that will be used for
 *                              serialization/deserialization
 * \param buf_size [IN]         buffer size
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE / HG_FREE
 * \param hash [IN]             hash method used for computing checksum
 *                              (if NULL, checksum is not computed)
 *                              hash method: HG_CRC16, HG_CRC64, HG_NOHASH
 * \param hg_bulk_class [IN]    (optional) HG Bulk class
 * \param proc [OUT]            pointer to abstract processor object
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_create(
        void *buf,
        hg_size_t buf_size,
        hg_proc_op_t op,
        hg_proc_hash_t hash,
        hg_bulk_class_t *hg_bulk_class,
        hg_proc_t *proc
        );

/**
 * Free the processor.
 *
 * \param proc [IN/OUT]         abstract processor object
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_free(
        hg_proc_t proc
        );

/**
 * Get the HG bulk class associated to the processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return HG Bulk class
 */
HG_EXPORT hg_bulk_class_t *
hg_proc_get_bulk_class(
        hg_proc_t proc
        );

/**
 * Get the operation type associated to the processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Operation type
 */
HG_EXPORT hg_proc_op_t
hg_proc_get_op(
        hg_proc_t proc
        );

/**
 * Get buffer size available for processing.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Non-negative size value
 */
HG_EXPORT hg_size_t
hg_proc_get_size(
        hg_proc_t proc
        );

/**
 * Request a new buffer size. This will modify the size of the buffer attached
 * to the processor or create an extra processing buffer.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param buf_size [IN]         buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_set_size(
        hg_proc_t proc,
        hg_size_t buf_size
        );

/**
 * Get size left for processing.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Non-negative size value
 */
HG_EXPORT hg_size_t
hg_proc_get_size_left(
        hg_proc_t proc
        );

/**
 * Get pointer to current buffer (for manual encoding).
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Buffer pointer
 */
HG_EXPORT void *
hg_proc_get_buf_ptr(
        hg_proc_t proc
        );

#ifdef HG_HAS_XDR
/**
 * Get pointer to current XDR stream (for manual encoding).
 *
 * \param proc [IN]             abstract processor object
 *
 * \return XDR stream pointer
 */
HG_EXPORT XDR *
hg_proc_get_xdr_ptr(
        hg_proc_t proc
        );
#endif

/**
 * Set new buffer pointer (for manual encoding).
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param buf_ptr [IN]          pointer to buffer used by the processor
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_set_buf_ptr(
        hg_proc_t proc,
        void *buf_ptr
        );

/**
 * Get eventual extra buffer used by processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Pointer to buffer or NULL if no extra buffer has been used
 */
HG_EXPORT void *
hg_proc_get_extra_buf(
        hg_proc_t proc
        );

/**
 * Get eventual size of the extra buffer used by processor.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return Size of buffer or 0 if no extra buffer has been used
 */
HG_EXPORT hg_size_t
hg_proc_get_extra_size(
        hg_proc_t proc
        );

/**
 * Set extra buffer to mine (if other calls mine, buffer is no longer freed
 * after hg_proc_free)
 *
 * \param proc [IN]             abstract processor object
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_set_extra_buf_is_mine(
        hg_proc_t proc,
        hg_bool_t mine
        );

/**
 * Flush the proc after data has been encoded or decoded and verify data using
 * base checksum if available.
 *
 * \param proc [IN]             abstract processor object
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_flush(
        hg_proc_t proc
        );

/**
 * Base proc routine using memcpy.
 * NB. Only uses memcpy / use hg_proc_raw for encoding independent proc routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 * \param data_size [IN]        data size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_memcpy(
        hg_proc_t proc,
        void *data,
        hg_size_t data_size
        );

/**
 * Copy data to buf if HG_ENCODE or buf to data if HG_DECODE and return
 * incremented pointer to buf.
 *
 * \param buf [IN/OUT]          abstract processor object
 * \param data [IN/OUT]         pointer to data
 * \param data_size [IN]        data size
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 *
 * \return incremented pointer to buf
 */
static HG_INLINE void *
hg_proc_buf_memcpy(void *buf, void *data, hg_size_t data_size, hg_proc_op_t op)
{
    const void *src = NULL;
    void *dest = NULL;

    if ((op != HG_ENCODE) && (op != HG_DECODE)) return NULL;
    src = (op == HG_ENCODE) ? (const void *) data : (const void *) buf;
    dest = (op == HG_ENCODE) ? buf : data;
    memcpy(dest, src, data_size);

    return ((char *) buf + data_size);
}

/**
 * Inline prototypes (do not remove)
 */
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_int8_t(hg_proc_t proc,
        hg_int8_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_uint8_t(hg_proc_t proc,
        hg_uint8_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_int16_t(hg_proc_t proc,
        hg_int16_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_uint16_t(hg_proc_t proc,
        hg_uint16_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_int32_t(hg_proc_t proc,
        hg_int32_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_uint32_t(hg_proc_t proc,
        hg_uint32_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_int64_t(hg_proc_t proc,
        hg_int64_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_uint64_t(hg_proc_t proc,
        hg_uint64_t *data);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_raw(hg_proc_t proc, void *buf,
        hg_size_t buf_size);
HG_EXPORT HG_PROC_INLINE hg_return_t hg_proc_hg_bulk_t(hg_proc_t proc,
        hg_bulk_t *handle);


/* Note: float types are not supported but can be built on top of the existing
 * proc routines; encoding floats using XDR could modify checksum */

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

/* Map mercury common types */
#define hg_proc_hg_bool_t     hg_proc_hg_uint8_t
#define hg_proc_hg_ptr_t      hg_proc_hg_uint64_t
#define hg_proc_hg_size_t     hg_proc_hg_uint64_t
#define hg_proc_hg_id_t       hg_proc_hg_uint32_t

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param data [IN/OUT]         pointer to data
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_int8_t(hg_proc_t proc, hg_int8_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_int8_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_uint8_t(hg_proc_t proc, hg_uint8_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_uint8_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_int16_t(hg_proc_t proc, hg_int16_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_int16_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_uint16_t(hg_proc_t proc, hg_uint16_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_uint16_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_int32_t(hg_proc_t proc, hg_int32_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_int32_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_uint32_t(hg_proc_t proc, hg_uint32_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_uint32_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_int64_t(hg_proc_t proc, hg_int64_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_int64_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_uint64_t(hg_proc_t proc, hg_uint64_t *data)
{
    hg_return_t ret;
#ifdef HG_HAS_XDR
    ret = xdr_uint64_t(hg_proc_get_xdr_ptr(proc), data) ? HG_SUCCESS : HG_PROTOCOL_ERROR;
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
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_raw(hg_proc_t proc, void *buf, hg_size_t buf_size)
{
    hg_uint8_t *buf_ptr;
    hg_uint8_t *buf_ptr_lim = (hg_uint8_t*) buf + buf_size;
    hg_return_t ret = HG_SUCCESS;

    for (buf_ptr = (hg_uint8_t*) buf; buf_ptr < buf_ptr_lim; buf_ptr++) {
        ret = hg_proc_uint8_t(proc, buf_ptr);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Proc error");
            break;
        }
    }

    return ret;
}

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param handle [IN/OUT]       pointer to bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_PROC_INLINE hg_return_t
hg_proc_hg_bulk_t(hg_proc_t proc, hg_bulk_t *handle)
{
    hg_return_t ret = HG_SUCCESS;
    void *buf = NULL;
    hg_uint64_t buf_size = 0;

    switch (hg_proc_get_op(proc)) {
        case HG_ENCODE:
            if (*handle != HG_BULK_NULL) {
                buf_size = HG_Bulk_get_serialize_size(*handle);
                buf = malloc(buf_size);
                ret = HG_Bulk_serialize(buf, buf_size, *handle);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not serialize bulk handle");
                    return ret;
                }
            } else {
                /* If HG_BULK_NULL set 0 to buf_size */
                buf_size = 0;
            }
            /* Encode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Proc error");
                return ret;
            }
            if (buf_size) {
                /* Encode serialized buffer */
                ret = hg_proc_raw(proc, buf, buf_size);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Proc error");
                    return ret;
                }
                free(buf);
                buf = NULL;
            }
            break;
        case HG_DECODE:
            /* Decode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS) {
                HG_LOG_ERROR("Proc error");
                return ret;
            }
            if (buf_size) {
                hg_bulk_class_t *hg_bulk_class = hg_proc_get_bulk_class(proc);

                buf = malloc(buf_size);
                /* Decode serialized buffer */
                ret = hg_proc_raw(proc, buf, buf_size);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Proc error");
                    return ret;
                }
                ret = HG_Bulk_deserialize(hg_bulk_class, handle, buf, buf_size);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not deserialize bulk handle");
                    return ret;
                }
                free(buf);
                buf = NULL;
            } else {
                /* If buf_size is 0, define handle to HG_BULK_NULL */
                *handle = HG_BULK_NULL;
            }
            break;
        case HG_FREE:
            if (*handle != HG_BULK_NULL) {
                ret = HG_Bulk_free(*handle);
                if (ret != HG_SUCCESS) {
                    HG_LOG_ERROR("Could not free bulk handle");
                    return ret;
                }
                *handle = HG_BULK_NULL;
            } else {
                /* If *handle is HG_BULK_NULL, just return success */
                ret = HG_SUCCESS;
            }
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
