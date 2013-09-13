/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROC_PRIVATE_H
#define MERCURY_PROC_PRIVATE_H

#include "mercury_proc.h"
#include "mercury_checksum.h"
#include "mercury_util_error.h"

typedef struct hg_proc_buf {
    void *    buf;       /* Pointer to allocated buffer */
    void *    buf_ptr;   /* Pointer to current position */
    size_t    size;      /* Total buffer size */
    size_t    size_left; /* Available size for user */
    hg_bool_t is_mine;
#ifdef HG_HAS_XDR
    XDR      xdr;
#endif
    hg_checksum_t checksum;         /* Checksum */
    void *        base_checksum;    /* Base checksum */
    size_t        checksum_size;    /* Checksum size */
    hg_bool_t     update_checksum;  /* Update checksum on proc operation */
} hg_proc_buf_t;

typedef struct hg_priv_proc {
    hg_proc_op_t    op;
    hg_proc_buf_t * current_buf;
    hg_proc_buf_t   proc_buf;
    hg_proc_buf_t   extra_buf;
} hg_priv_proc_t;

typedef struct hg_priv_header {
    hg_id_t       id;               /* Operation ID */
    hg_bulk_t     extra_buf_handle; /* Extra handle (large data) */
} hg_priv_header_t;

/*
 * 0      HG_PROC_HEADER_SIZE              size
 * |______________|__________________________|
 * |    Header    |        Encoded Data      |
 * |______________|__________________________|
 */
#define HG_PROC_MAX_HEADER_SIZE 64

HG_EXPORT HG_PROC_INLINE unsigned int hg_proc_string_hash(const char *string);

HG_EXPORT HG_PROC_INLINE size_t hg_proc_get_header_size(void);
HG_EXPORT HG_PROC_INLINE int hg_proc_hg_priv_header_t(hg_proc_t proc, hg_priv_header_t *data);

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
hg_proc_hg_priv_header_t(hg_proc_t proc, hg_priv_header_t *data)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_buf_t  *current_buf;
    hg_bool_t extra_buf_used;
    hg_bool_t current_update_checksum;
    void *current_buf_ptr;
    int ret = HG_FAIL;

    /* Disable checksum update here if it was enabled */
    current_update_checksum = priv_proc->current_buf->update_checksum;
    if (current_update_checksum) {
        priv_proc->current_buf->update_checksum = 0;
    }

    if (hg_proc_get_op(proc) == HG_ENCODE) {
        extra_buf_used = (data->extra_buf_handle != HG_BULK_NULL) ? 1 : 0;
    }

    /* If we have switched buffers we need to go back to the buffer that
     * contains the header */
    current_buf = priv_proc->current_buf;
    current_buf_ptr = hg_proc_get_buf_ptr(proc);
    priv_proc->current_buf = &priv_proc->proc_buf;
    hg_proc_set_buf_ptr(proc, priv_proc->proc_buf.buf);

    /* Process generic op id now */
    ret = hg_proc_hg_id_t(proc, &data->id);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* Process extra buffer info */
    ret = hg_proc_hg_bool_t(proc, &extra_buf_used);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    if (extra_buf_used) {
        ret = hg_proc_hg_bulk_t(proc, &data->extra_buf_handle);
        if (ret != HG_SUCCESS) {
            HG_ERROR_DEFAULT("Proc error");
            ret = HG_FAIL;
            goto done;
        }
    } else {
        if (hg_proc_get_op(proc) == HG_DECODE) {
            data->extra_buf_handle = HG_BULK_NULL;
        }
    }

    /* Process checksum */
    ret = hg_proc_raw(proc, priv_proc->current_buf->base_checksum,
            priv_proc->current_buf->checksum_size);
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

done:
    priv_proc->current_buf->update_checksum = current_update_checksum;
    priv_proc->current_buf = current_buf;
    hg_proc_set_buf_ptr(proc, current_buf_ptr);

    return ret;
}

#endif /* MERCURY_PROC_PRIVATE_H */
