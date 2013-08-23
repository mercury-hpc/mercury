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

typedef struct hg_proc_buf {
    void *    buf;       /* Pointer to allocated buffer */
    void *    buf_ptr;   /* Pointer to current position */
    size_t    size;      /* Total buffer size */
    size_t    size_left; /* Available size for user */
    hg_bool_t is_mine;
#ifdef HG_HAS_XDR
    XDR      xdr;
#endif
} hg_proc_buf_t;

typedef struct hg_priv_proc {
    hg_proc_op_t    op;
    hg_proc_buf_t * current_buf;
    hg_proc_buf_t   proc_buf;
    hg_proc_buf_t   extra_buf;
} hg_priv_proc_t;

/*
 * 0      HG_PROC_HEADER_SIZE              size
 * |______________|__________________________|
 * |    Header    |        Encoded Data      |
 * |______________|__________________________|
 */
#define HG_PROC_MAX_HEADER_SIZE 64

HG_EXPORT HG_PROC_INLINE size_t hg_proc_get_header_size(void);
HG_EXPORT HG_PROC_INLINE unsigned int hg_proc_string_hash(const char *string);
HG_EXPORT HG_PROC_INLINE int hg_proc_header_request(hg_proc_t proc, hg_uint32_t *op_id,
        hg_uint8_t *extra_buf_used, hg_bulk_t *extra_handle);
HG_EXPORT HG_PROC_INLINE int hg_proc_header_response(hg_proc_t proc, hg_uint8_t *extra_buf_used);

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

#endif /* MERCURY_PROC_PRIVATE_H */
