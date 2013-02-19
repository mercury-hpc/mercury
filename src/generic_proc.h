/*
 * generic_proc.h
 */

#ifndef GENERIC_PROC_H
#define GENERIC_PROC_H

#include "shipper_error.h"
#include "shipper_config.h"

#include <stddef.h>
#include <stdint.h>

/* TODO using ifdef IOFSL_SHIPPER_HAS_XDR is dangerous for inline functions */

#ifdef IOFSL_SHIPPER_HAS_XDR
#include <rpc/types.h>
#include <rpc/xdr.h>
#else
#include <string.h>
#endif

typedef void * fs_proc_t;

typedef struct fs_enc_proc {
#ifdef IOFSL_SHIPPER_HAS_XDR
    XDR      xdr;
#else
    void    *buf;
    size_t   buf_len;
    void    *buf_ptr;
    size_t   buf_size_left;
#endif
} fs_enc_proc_t;

typedef struct fs_dec_proc {
#ifdef IOFSL_SHIPPER_HAS_XDR
    XDR      xdr;
#else
    const void *buf;
    size_t      buf_len;
    const void *buf_ptr;
    size_t      buf_size_left;
#endif
} fs_dec_proc_t;

#ifndef FS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define FS_INLINE extern inline
# else
#  define FS_INLINE inline
# endif
#endif

#define FS_MAX_STRING_LEN 256

typedef struct fs_string {
    uint32_t length;
    char     buffer[FS_MAX_STRING_LEN];
} fs_string_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new encoding processor */
int fs_proc_enc_create(fs_proc_t *proc, void *buf, size_t buf_len);

/* Create a new decoding processor */
int fs_proc_dec_create(fs_proc_t *proc, const void *buf, size_t buf_len);

/* Free the processor */
int fs_proc_enc_free(fs_proc_t proc);

/* Free the processor */
int fs_proc_dec_free(fs_proc_t proc);

/* Get number of bytes available for processing */
//size_t fs_proc_enc_get_avail(fs_proc_t proc);

/* Get number of bytes required for processing */
//size_t fs_proc_get_req(fs_proc_t proc);

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_int8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_int8_t  (fs_proc_t proc, const int8_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int8_t(&enc_proc->xdr, (int8_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int8_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_int8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_int8_t  (fs_proc_t proc, int8_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int8_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int8_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_uint8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_uint8_t  (fs_proc_t proc, const uint8_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint8_t(&enc_proc->xdr, (uint8_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint8_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_uint8_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_uint8_t  (fs_proc_t proc, uint8_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint8_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint8_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_int16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_int16_t  (fs_proc_t proc, const int16_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int16_t(&enc_proc->xdr, (int16_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int16_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_int16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_int16_t  (fs_proc_t proc, int16_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int16_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int16_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_uint16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_uint16_t  (fs_proc_t proc, const uint16_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint16_t(&enc_proc->xdr, (uint16_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint16_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_uint16_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_uint16_t  (fs_proc_t proc, uint16_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint16_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint16_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_int32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_int32_t  (fs_proc_t proc, const int32_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int32_t(&enc_proc->xdr, (int32_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int32_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_int32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_int32_t  (fs_proc_t proc, int32_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int32_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int32_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_uint32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_uint32_t  (fs_proc_t proc, const uint32_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint32_t(&enc_proc->xdr, (uint32_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint32_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_uint32_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_uint32_t  (fs_proc_t proc, uint32_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint32_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint32_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_int64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_int64_t  (fs_proc_t proc, const int64_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int64_t(&enc_proc->xdr, (int64_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int64_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_int64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_int64_t  (fs_proc_t proc, int64_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_int64_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(int64_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_uint64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_uint64_t  (fs_proc_t proc, const uint64_t *data)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint64_t(&enc_proc->xdr, (uint64_t*)data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint64_t);
    if (enc_proc->buf_size_left > proc_size) {
        memcpy(enc_proc->buf_ptr, data, proc_size);
        enc_proc->buf_ptr += proc_size;
        enc_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_uint64_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_uint64_t  (fs_proc_t proc, uint64_t *data)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;
#ifdef IOFSL_SHIPPER_HAS_XDR
    ret = xdr_uint64_t(&dec_proc->xdr, data) ? S_SUCCESS : S_FAIL;
#else
    size_t proc_size = sizeof(uint64_t);
    if (dec_proc->buf_size_left > proc_size) {
        memcpy(data, dec_proc->buf_ptr, proc_size);
        dec_proc->buf_ptr += proc_size;
        dec_proc->buf_size_left -= proc_size;
        ret = S_SUCCESS;
    }
#endif
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_raw
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_raw  (fs_proc_t proc, const void *buf, size_t buf_len)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    const uint8_t *buf_ptr;
    int ret = S_FAIL;

    for (buf_ptr = buf; buf_ptr < ((const uint8_t*)buf + buf_len); buf_ptr++) {
        fs_proc_enc_uint8_t(enc_proc, buf_ptr);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_raw
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_raw  (fs_proc_t proc, void *buf, size_t buf_len)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    uint8_t *buf_ptr = buf;
    int ret = S_FAIL;

    for (buf_ptr = buf; buf_ptr < (uint8_t*)buf + buf_len; buf_ptr++) {
        fs_proc_dec_uint8_t(dec_proc, buf_ptr);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_fs_string_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_enc_fs_string_t(fs_proc_t proc, const fs_string_t *string)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_FAIL;

    fs_proc_enc_uint32_t(enc_proc, &string->length);
    fs_proc_enc_raw(enc_proc, string->buffer, string->length);
    printf("%s\n", string->buffer);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_fs_string_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
FS_INLINE int fs_proc_dec_fs_string_t(fs_proc_t proc, fs_string_t *string)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_FAIL;

    fs_proc_dec_uint32_t(dec_proc, &string->length);
    if (string->length >= FS_MAX_STRING_LEN) {
        S_ERROR_DEFAULT("Exceeded FS_MAX_STRING_LEN");
        ret = S_FAIL;
        return ret;
    }
    fs_proc_dec_raw(dec_proc, string->buffer, string->length);

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* GENERIC_PROC_H */
