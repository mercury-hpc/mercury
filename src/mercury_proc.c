/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#define HG_PROC_INLINE /* Needed for inline functions */
#include "mercury_proc.h"

#include <stdlib.h>
#include <unistd.h>

/*---------------------------------------------------------------------------
 * Function:    hg_proc_buf_alloc
 *
 * Purpose:     Can be used to allocate a buffer that will be used by the
 *              generic proc (use free to free it)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_buf_alloc(void **mem_ptr, size_t size)
{
    int ret = HG_SUCCESS;
    size_t alignment;

    alignment = getpagesize();

    posix_memalign(mem_ptr, alignment, size);
    memset(*mem_ptr, 0, size);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_create
 *
 * Purpose:     Create a new encoding/decoding processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_create(void *buf, size_t buf_size, hg_proc_op_t op, hg_proc_t *proc)
{
    hg_priv_proc_t *priv_proc = NULL;
    int ret = HG_SUCCESS;

    if (!buf && op != HG_FREE) {
        HG_ERROR_DEFAULT("NULL buffer");
        ret = HG_FAIL;
        return ret;
    }

    priv_proc = malloc(sizeof(hg_priv_proc_t));
    priv_proc->op = op;

    priv_proc->proc_buf.buf = buf;
    priv_proc->proc_buf.size = buf_size;
    priv_proc->proc_buf.buf_ptr = buf;
    priv_proc->proc_buf.size_left = buf_size;
    priv_proc->proc_buf.is_mine = 0;
#ifdef MERCURY_HAS_XDR
    switch (op) {
        case HG_ENCODE:
            xdrmem_create(&priv_proc->proc_buf.xdr, buf, buf_size, XDR_ENCODE);
            break;
        case HG_DECODE:
            xdrmem_create(&priv_proc->proc_buf.xdr, buf, buf_size, XDR_DECODE);
            break;
        case HG_FREE:
            xdrmem_create(&priv_proc->proc_buf.xdr, buf, buf_size, XDR_FREE);
            break;
        default:
            HG_ERROR_DEFAULT("Unknown proc operation");
            ret = HG_FAIL;
            return ret;
    }
#endif

    /* Do not allocate extra buffer yet */
    priv_proc->extra_buf.buf = NULL;
    priv_proc->extra_buf.size = 0;
    priv_proc->extra_buf.buf_ptr = NULL;
    priv_proc->extra_buf.size_left = 0;
    priv_proc->extra_buf.is_mine = 0;

    /* Default to proc_buf */
    priv_proc->current_buf = &priv_proc->proc_buf;

    *proc = (hg_priv_proc_t*) priv_proc;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_free
 *
 * Purpose:     Free the processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_free(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_SUCCESS;

    if (!priv_proc) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    /* Free extra proc buffer if needed */
    if (priv_proc->extra_buf.buf && priv_proc->extra_buf.is_mine) {
        free (priv_proc->extra_buf.buf);
        priv_proc->extra_buf.buf = NULL;
    }

    /* Free proc */
    free(priv_proc);
    priv_proc = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_op
 *
 * Purpose:     Get current operation mode used for processor
 *              (Only valid if proc is created)
 *
 * Returns:     HG_ENCODE/HG_DECODE/HG_FREE
 *
 *---------------------------------------------------------------------------
 */
hg_proc_op_t hg_proc_get_op(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_op_t proc_op = 0;

    if (priv_proc) proc_op = priv_proc->op;

    return proc_op;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_size
 *
 * Purpose:     Get buffer size available for processing
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
size_t hg_proc_get_size(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->proc_buf.size + priv_proc->extra_buf.size;

    return size;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_set_size
 *
 * Purpose:     Request a new buffer size
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_set_size(hg_proc_t proc, size_t req_buf_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t new_buf_size;
    size_t page_size;
    ptrdiff_t current_pos;
    int ret = HG_SUCCESS;

    page_size = getpagesize();
    new_buf_size = ((size_t)(req_buf_size / page_size) + 1) * page_size;

    if (new_buf_size <= hg_proc_get_size(proc)) {
        HG_ERROR_DEFAULT("Buffer is already of the size requested");
        ret = HG_FAIL;
        return ret;
    }

    /* If was not using extra buffer init extra buffer */
    if (!priv_proc->extra_buf.buf) {
        /* Save current position */
        current_pos = (char*) priv_proc->proc_buf.buf_ptr - (char*) priv_proc->proc_buf.buf;

        /* Allocate buffer */
        priv_proc->extra_buf.buf = malloc(new_buf_size);
        if (!priv_proc->extra_buf.buf) {
            HG_ERROR_DEFAULT("Could not allocate buffer");
            ret = HG_FAIL;
            return ret;
        }

        /* Copy proc_buf (should be small) */
        memcpy(priv_proc->extra_buf.buf, priv_proc->proc_buf.buf, current_pos);
        priv_proc->extra_buf.size = new_buf_size;
        priv_proc->extra_buf.buf_ptr = (char*) priv_proc->extra_buf.buf + current_pos;
        priv_proc->extra_buf.size_left = priv_proc->extra_buf.size - current_pos;
        priv_proc->extra_buf.is_mine = 1;

        /* Switch buffer */
        priv_proc->current_buf = &priv_proc->extra_buf;
    } else {
        /* Save current position */
        current_pos = (char*) priv_proc->extra_buf.buf_ptr - (char*) priv_proc->extra_buf.buf;

        /* Reallocate buffer */
        priv_proc->extra_buf.buf = realloc(priv_proc->extra_buf.buf, new_buf_size);
        if (!priv_proc->extra_buf.buf) {
            HG_ERROR_DEFAULT("Could not reallocate buffer");
            ret = HG_FAIL;
            return ret;
        }

        priv_proc->extra_buf.size = new_buf_size;
        priv_proc->extra_buf.buf_ptr = (char*) priv_proc->extra_buf.buf + current_pos;
        priv_proc->extra_buf.size_left = priv_proc->extra_buf.size - current_pos;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_size_left
 *
 * Purpose:     Get buffer size available for processing
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
size_t hg_proc_get_size_left(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->current_buf->size_left;

    return size;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_buf_ptr
 *
 * Purpose:     Get pointer to current buffer (for manual encoding)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void * hg_proc_get_buf_ptr(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    void *ptr = NULL;

    if (priv_proc) {
        ptr = priv_proc->current_buf->buf_ptr;
    }

    return ptr;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_set_buf_ptr
 *
 * Purpose:     Set new buffer pointer (for manual encoding)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_set_buf_ptr(hg_proc_t proc, void *buf_ptr)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;

    if (priv_proc) {
        ptrdiff_t new_pos, lim_pos;

        /* Work out new position */
        new_pos = (char*) buf_ptr - (char*) priv_proc->current_buf->buf;
        lim_pos = (ptrdiff_t) priv_proc->current_buf->size;
        if (new_pos > lim_pos) {
            HG_ERROR_DEFAULT("Out of memory");
            ret = HG_FAIL;
            return ret;
        }

        priv_proc->current_buf->buf_ptr   = buf_ptr;
        priv_proc->current_buf->size_left = priv_proc->current_buf->size - (size_t)new_pos;
#ifdef MERCURY_HAS_XDR
        xdr_setpos(&priv_proc->current_buf->xdr, new_pos);
#endif
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_header_size
 *
 * Purpose:     Get extra buffer
 *
 * Returns:     Pointer to buffer or NULL
 *
 *---------------------------------------------------------------------------
 */
void * hg_proc_get_extra_buf(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    void *extra_buf = NULL;

    if (priv_proc->extra_buf.buf) {
        extra_buf = priv_proc->extra_buf.buf;
    }

    return extra_buf;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_get_extra_size
 *
 * Purpose:     Get size of extra buffer
 *
 * Returns:     Size of extra buffer or 0
 *
 *---------------------------------------------------------------------------
 */
size_t hg_proc_get_extra_size(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t extra_size = 0;

    if (priv_proc->extra_buf.buf) {
        extra_size = priv_proc->extra_buf.size;
    }

    return extra_size;
}

/*---------------------------------------------------------------------------
 * Function:    hg_proc_set_extra_buf_is_mine
 *
 * Purpose:     Set extra buffer to mine (if other calls mine, buffer is no
 *              longer freed after hg_proc_free)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int hg_proc_set_extra_buf_is_mine(hg_proc_t proc, bool theirs)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;

    if (priv_proc->extra_buf.buf) {
        priv_proc->extra_buf.is_mine = !theirs;
        ret = HG_SUCCESS;
    }

    return ret;
}
