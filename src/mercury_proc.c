/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef _WIN32
  #define HG_PROC_INLINE
#endif
#include "mercury_proc.h"
#include "mercury_proc_private.h"

#ifdef _WIN32
  #include <windows.h>
#else
  #include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------------*/
void *
hg_proc_buf_alloc(size_t size)
{
    size_t alignment;
    void *mem_ptr = NULL;

#ifdef _WIN32
    SYSTEM_INFO system_info;
    GetSystemInfo (&system_info);
    alignment = system_info.dwPageSize;
    mem_ptr = _aligned_malloc(size, alignment);
#else
    alignment = sysconf(_SC_PAGE_SIZE);
    posix_memalign(&mem_ptr, alignment, size);
#endif
    if (mem_ptr) {
        memset(mem_ptr, 0, size);
    }

    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_buf_free(void *mem_ptr)
{
    int ret = HG_SUCCESS;

#ifdef _WIN32
    _aligned_free(mem_ptr);
#else
    free(mem_ptr);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_create(void *buf, size_t buf_size, hg_proc_op_t op, hg_proc_t *proc)
{
    hg_priv_proc_t *priv_proc = NULL;
    int ret = HG_SUCCESS;

    if (!buf && op != HG_FREE) {
        HG_ERROR_DEFAULT("NULL buffer");
        ret = HG_FAIL;
        return ret;
    }

    priv_proc = (hg_priv_proc_t*) malloc(sizeof(hg_priv_proc_t));
    if (!priv_proc) {
        HG_ERROR_DEFAULT("Could not allocate proc");
        ret = HG_FAIL;
        return ret;
    }

    priv_proc->op = op;
    priv_proc->proc_buf.buf = buf;
    priv_proc->proc_buf.size = buf_size;
    priv_proc->proc_buf.buf_ptr = buf;
    priv_proc->proc_buf.size_left = buf_size;
    priv_proc->proc_buf.is_mine = 0;
#ifdef HG_HAS_XDR
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

/*---------------------------------------------------------------------------*/
int
hg_proc_free(hg_proc_t proc)
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

/*---------------------------------------------------------------------------*/
hg_proc_op_t
hg_proc_get_op(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    hg_proc_op_t proc_op = HG_INVALID;

    if (priv_proc) proc_op = priv_proc->op;

    return proc_op;
}

/*---------------------------------------------------------------------------*/
size_t
hg_proc_get_size(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->proc_buf.size + priv_proc->extra_buf.size;

    return size;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_set_size(hg_proc_t proc, size_t req_buf_size)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t new_buf_size;
    size_t page_size;
    ptrdiff_t current_pos;
    int ret = HG_SUCCESS;

#ifdef _WIN32
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    page_size = system_info.dwPageSize;
#else
    page_size = sysconf(_SC_PAGE_SIZE);
#endif
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

/*---------------------------------------------------------------------------*/
size_t
hg_proc_get_size_left(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->current_buf->size_left;

    return size;
}

/*---------------------------------------------------------------------------*/
void *
hg_proc_get_buf_ptr(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    void *ptr = NULL;

    if (priv_proc) {
        ptr = priv_proc->current_buf->buf_ptr;
    }

    return ptr;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_XDR
XDR *
hg_proc_get_xdr_ptr(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    XDR *ptr = NULL;

    if (priv_proc) {
        ptr = &priv_proc->current_buf->xdr;
    }

    return ptr;
}
#endif

/*---------------------------------------------------------------------------*/
int
hg_proc_set_buf_ptr(hg_proc_t proc, void *buf_ptr)
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
#ifdef HG_HAS_XDR
        xdr_setpos(&priv_proc->current_buf->xdr, new_pos);
#endif
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
void *
hg_proc_get_extra_buf(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    void *extra_buf = NULL;

    if (priv_proc->extra_buf.buf) {
        extra_buf = priv_proc->extra_buf.buf;
    }

    return extra_buf;
}

/*---------------------------------------------------------------------------*/
size_t
hg_proc_get_extra_size(hg_proc_t proc)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    size_t extra_size = 0;

    if (priv_proc->extra_buf.buf) {
        extra_size = priv_proc->extra_buf.size;
    }

    return extra_size;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_set_extra_buf_is_mine(hg_proc_t proc, hg_bool_t theirs)
{
    hg_priv_proc_t *priv_proc = (hg_priv_proc_t*) proc;
    int ret = HG_FAIL;

    if (priv_proc->extra_buf.buf) {
        priv_proc->extra_buf.is_mine = !theirs;
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
int
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
