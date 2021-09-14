/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_proc.h"
#include "mercury_error.h"
#include "mercury_mem.h"

#ifdef HG_HAS_CHECKSUMS
#    include <mchecksum.h>
#endif

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_create(hg_class_t *hg_class, hg_proc_hash_t hash, hg_proc_t *proc)
{
    struct hg_proc *hg_proc = NULL;
    const char *hash_method;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        hg_class == NULL, error, ret, HG_INVALID_ARG, "NULL HG class");

    hg_proc = (struct hg_proc *) malloc(sizeof(struct hg_proc));
    HG_CHECK_ERROR(
        hg_proc == NULL, error, ret, HG_NOMEM, "Could not allocate proc");

    memset(hg_proc, 0, sizeof(struct hg_proc));
    hg_proc->hg_class = hg_class;

    /* Map enum to string */
    switch (hash) {
        case HG_CRC16:
            hash_method = "crc16";
            break;
        case HG_CRC32:
            hash_method = "crc32c";
            break;
        case HG_CRC64:
            hash_method = "crc64";
            break;
        default:
            hash_method = NULL;
            break;
    }

    if (hash_method) {
#ifdef HG_HAS_CHECKSUMS
        int rc = mchecksum_init(hash_method, &hg_proc->checksum);
        HG_CHECK_ERROR(rc < 0, error, ret, HG_CHECKSUM_ERROR,
            "Could not initialize checksum");

        hg_proc->checksum_size = mchecksum_get_size(hg_proc->checksum);
        hg_proc->checksum_hash = (char *) malloc(hg_proc->checksum_size);
        HG_CHECK_ERROR(hg_proc->checksum_hash == NULL, error, ret, HG_NOMEM,
            "Could not allocate space for checksum hash");
#endif
    }

    /* Default to proc_buf */
    hg_proc->current_buf = &hg_proc->proc_buf;

    *proc = (struct hg_proc *) hg_proc;

    return ret;

error:
    if (hg_proc) {
#ifdef HG_HAS_CHECKSUMS
        if (hg_proc->checksum != MCHECKSUM_OBJECT_NULL)
            mchecksum_destroy(hg_proc->checksum);
        free(hg_proc->checksum_hash);
#endif
        free(hg_proc);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_create_set(hg_class_t *hg_class, void *buf, hg_size_t buf_size,
    hg_proc_op_t op, hg_proc_hash_t hash, hg_proc_t *proc)
{
    hg_proc_t hg_proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    ret = hg_proc_create(hg_class, hash, &hg_proc);
    HG_CHECK_HG_ERROR(error, ret, "Could not create proc");

    ret = hg_proc_reset(hg_proc, buf, buf_size, op);
    HG_CHECK_HG_ERROR(error, ret, "Could not reset proc");

    *proc = hg_proc;

    return ret;

error:
    if (hg_proc != HG_PROC_NULL)
        hg_proc_free(hg_proc);

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_free(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc)
        goto done;

#ifdef HG_HAS_CHECKSUMS
    if (hg_proc->checksum != MCHECKSUM_OBJECT_NULL) {
        int rc = mchecksum_destroy(hg_proc->checksum);
        HG_CHECK_ERROR(
            rc < 0, done, ret, HG_CHECKSUM_ERROR, "Could not destroy checksum");
    }
    free(hg_proc->checksum_hash);
#endif

    /* Free extra proc buffer if needed */
    if (hg_proc->extra_buf.buf && hg_proc->extra_buf.is_mine)
        hg_mem_aligned_free(hg_proc->extra_buf.buf);

    /* Free proc */
    free(hg_proc);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_reset(hg_proc_t proc, void *buf, hg_size_t buf_size, hg_proc_op_t op)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(
        proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG, "NULL HG proc");
    HG_CHECK_ERROR(
        !buf && op != HG_FREE, done, ret, HG_INVALID_ARG, "NULL buffer");

    hg_proc->op = op;
#ifdef HG_HAS_XDR
    switch (op) {
        case HG_ENCODE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf,
                (hg_uint32_t) buf_size, XDR_ENCODE);
            break;
        case HG_DECODE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf,
                (hg_uint32_t) buf_size, XDR_DECODE);
            break;
        case HG_FREE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf,
                (hg_uint32_t) buf_size, XDR_FREE);
            break;
        default:
            HG_GOTO_ERROR(
                done, ret, HG_INVALID_PARAM, "Unknown proc operation");
    }
#endif

    /* Reset flags */
    hg_proc->flags = 0;

    /* Reset proc buf */
    hg_proc->proc_buf.buf = buf;
    hg_proc->proc_buf.size = buf_size;
    hg_proc->proc_buf.buf_ptr = hg_proc->proc_buf.buf;
    hg_proc->proc_buf.size_left = hg_proc->proc_buf.size;

    /* Free extra proc buffer if needed */
    if (hg_proc->extra_buf.buf && hg_proc->extra_buf.is_mine)
        hg_mem_aligned_free(hg_proc->extra_buf.buf);
    hg_proc->extra_buf.buf = NULL;
    hg_proc->extra_buf.size = 0;
    hg_proc->extra_buf.buf_ptr = hg_proc->extra_buf.buf;
    hg_proc->extra_buf.size_left = hg_proc->extra_buf.size;

    /* Default to proc_buf */
    hg_proc->current_buf = &hg_proc->proc_buf;

#ifdef HG_HAS_CHECKSUMS
    /* Reset checksum */
    if (hg_proc->checksum != MCHECKSUM_OBJECT_NULL) {
        int rc = mchecksum_reset(hg_proc->checksum);
        HG_CHECK_ERROR(
            rc < 0, done, ret, HG_CHECKSUM_ERROR, "Could not reset checksum");
        memset(hg_proc->checksum_hash, 0, hg_proc->checksum_size);
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_set_size(hg_proc_t proc, hg_size_t req_buf_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_size_t new_buf_size;
    hg_size_t page_size = (hg_size_t) hg_mem_get_page_size();
    void *new_buf = NULL;
    ptrdiff_t current_pos;
    hg_bool_t allocated = HG_FALSE;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, error, ret, HG_INVALID_ARG,
        "Proc is not initialized");

    /* Save current position */
    current_pos = (char *) hg_proc->current_buf->buf_ptr -
                  (char *) hg_proc->current_buf->buf;

    /* Get one more page size buf */
    new_buf_size = ((hg_size_t) (req_buf_size / page_size) + 1) * page_size;
    HG_CHECK_ERROR(new_buf_size <= hg_proc_get_size(proc), error, ret,
        HG_INVALID_ARG, "Buffer is already of the size requested");

    /* If was not using extra buffer init extra buffer */
    if (!hg_proc->extra_buf.buf) {
        /* Allocate buffer */
        new_buf = hg_mem_aligned_alloc(page_size, new_buf_size);
        allocated = HG_TRUE;
    } else
        new_buf = realloc(hg_proc->extra_buf.buf, new_buf_size);
    HG_CHECK_ERROR(new_buf == NULL, error, ret, HG_NOMEM,
        "Could not allocate buffer of size %" PRIu64, new_buf_size);

    if (!hg_proc->extra_buf.buf) {
        /* Copy proc_buf (should be small) */
        memcpy(new_buf, hg_proc->proc_buf.buf, (size_t) current_pos);

        /* Switch buffer */
        hg_proc->current_buf = &hg_proc->extra_buf;
    }

    hg_proc->extra_buf.buf = new_buf;
    hg_proc->extra_buf.size = new_buf_size;
    hg_proc->extra_buf.buf_ptr = (char *) hg_proc->extra_buf.buf + current_pos;
    hg_proc->extra_buf.size_left =
        hg_proc->extra_buf.size - (hg_size_t) current_pos;
    hg_proc->extra_buf.is_mine = HG_TRUE;

    return ret;

error:
    if (new_buf && allocated)
        hg_mem_aligned_free(new_buf);
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
hg_proc_save_ptr(hg_proc_t proc, hg_size_t data_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    void *ptr = NULL;
#ifdef HG_HAS_XDR
    unsigned int cur_pos;
#endif

    HG_CHECK_ERROR_NORET(proc == HG_PROC_NULL, done, "Proc is not initialized");

    /* If not enough space allocate extra space if encoding or
     * just get extra buffer if decoding */
    if (data_size && hg_proc->current_buf->size_left < data_size)
        hg_proc_set_size(
            proc, hg_proc->proc_buf.size + hg_proc->extra_buf.size + data_size);

    ptr = hg_proc->current_buf->buf_ptr;
    hg_proc->current_buf->buf_ptr =
        (char *) hg_proc->current_buf->buf_ptr + data_size;
    hg_proc->current_buf->size_left -= data_size;
#ifdef HG_HAS_XDR
    cur_pos = xdr_getpos(&hg_proc->current_buf->xdr);
    xdr_setpos(&hg_proc->current_buf->xdr, (hg_uint32_t) (cur_pos + data_size));
#endif

done:
    return ptr;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_restore_ptr(hg_proc_t proc, void *data, hg_size_t data_size)
{
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG,
        "Proc is not initialized");

#ifdef HG_HAS_CHECKSUMS
    hg_proc_checksum_update(proc, data, data_size);
#else
    /* Silent warning */
    (void) data;
    (void) data_size;
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_set_extra_buf_is_mine(hg_proc_t proc, hg_bool_t theirs)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG,
        "Proc is not initialized");
    HG_CHECK_ERROR(hg_proc->extra_buf.buf == NULL, done, ret, HG_INVALID_ARG,
        "Extra buf is not set");

    hg_proc->extra_buf.is_mine = (hg_bool_t) (!theirs);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_flush(hg_proc_t proc)
{
#ifdef HG_HAS_CHECKSUMS
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    int rc;
#endif
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG,
        "Proc is not initialized");

#ifdef HG_HAS_CHECKSUMS
    rc = mchecksum_get(hg_proc->checksum, hg_proc->checksum_hash,
        hg_proc->checksum_size, MCHECKSUM_FINALIZE);
    HG_CHECK_ERROR(
        rc < 0, done, ret, HG_CHECKSUM_ERROR, "Could not get checksum");
#endif

done:
    return ret;
}

#ifdef HG_HAS_CHECKSUMS
/*---------------------------------------------------------------------------*/
void
hg_proc_checksum_update(hg_proc_t proc, void *data, hg_size_t data_size)
{
    int rc;

    /* Update checksum */
    rc = mchecksum_update(((struct hg_proc *) proc)->checksum, data, data_size);
    HG_CHECK_ERROR_NORET(rc < 0, done, "Could not update checksum");

done:
    return;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_checksum_get(hg_proc_t proc, void *hash, hg_size_t hash_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG,
        "Proc is not initialized");
    HG_CHECK_ERROR(
        hash == NULL, done, ret, HG_INVALID_ARG, "NULL hash pointer");
    HG_CHECK_ERROR(hash_size < hg_proc->checksum_size, done, ret,
        HG_INVALID_ARG, "Hash size passed is too small");

    memcpy(hash, hg_proc->checksum_hash, hg_proc->checksum_size);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_checksum_verify(hg_proc_t proc, const void *hash, hg_size_t hash_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    HG_CHECK_ERROR(proc == HG_PROC_NULL, done, ret, HG_INVALID_ARG,
        "Proc is not initialized");
    HG_CHECK_ERROR(hash_size < hg_proc->checksum_size, done, ret,
        HG_INVALID_ARG, "Hash size passed is too small");

    /* Verify checksums */
    if (memcmp(hash, hg_proc->checksum_hash, hg_proc->checksum_size) != 0) {
        if (hg_proc->checksum_size == sizeof(hg_uint16_t))
            HG_LOG_ERROR("checksum 0x%04X does not match (expected 0x%04X!)",
                *(hg_uint16_t *) hg_proc->checksum_hash,
                *(const hg_uint16_t *) hash);
        else if (hg_proc->checksum_size == sizeof(hg_uint32_t))
            HG_LOG_ERROR("checksum 0x%08X does not match (expected 0x%08X!)",
                *(hg_uint32_t *) hg_proc->checksum_hash,
                *(const hg_uint32_t *) hash);
        else if (hg_proc->checksum_size == sizeof(hg_uint64_t))
            HG_LOG_ERROR("checksum 0x%016" PRIx64
                         " does not match (expected 0x%016" PRIx64 "!)",
                *(hg_uint64_t *) hg_proc->checksum_hash,
                *(const hg_uint64_t *) hash);
        else
            HG_LOG_ERROR("Checksums do not match (unknown size?)");
        ret = HG_CHECKSUM_ERROR;
        goto done;
    }

done:
    return ret;
}
#endif
