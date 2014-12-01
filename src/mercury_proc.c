/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

#ifdef HG_HAS_CHECKSUMS
  #include <mchecksum.h>
  #include <mchecksum_error.h>
#endif

#ifdef _WIN32
  #include <windows.h>
#else
  #include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

struct hg_proc_buf {
    void *    buf;       /* Pointer to allocated buffer */
    void *    buf_ptr;   /* Pointer to current position */
    hg_size_t size;      /* Total buffer size */
    hg_size_t size_left; /* Available size for user */
    hg_bool_t is_mine;
#ifdef HG_HAS_XDR
    XDR      xdr;
#endif
#ifdef HG_HAS_CHECKSUMS
    mchecksum_object_t checksum;    /* Checksum */
    hg_bool_t     update_checksum;  /* Update checksum on proc operation */
#endif
};

struct hg_proc {
    hg_proc_op_t op;
    struct hg_proc_buf *current_buf;
    struct hg_proc_buf proc_buf;
    struct hg_proc_buf extra_buf;
    hg_bulk_class_t *hg_bulk_class;
};

/*---------------------------------------------------------------------------*/
void *
hg_proc_buf_alloc(hg_size_t size)
{
    hg_size_t alignment;
    void *mem_ptr = NULL;

#ifdef _WIN32
    SYSTEM_INFO system_info;
    GetSystemInfo (&system_info);
    alignment = system_info.dwPageSize;
    mem_ptr = _aligned_malloc(size, alignment);
#else
    alignment = sysconf(_SC_PAGE_SIZE);

    if (posix_memalign(&mem_ptr, alignment, size) != 0) {
        HG_LOG_ERROR("posix_memalign failed");
        return NULL;
    }
#endif
    if (mem_ptr) {
        memset(mem_ptr, 0, size);
    }

    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
void
hg_proc_buf_free(void *mem_ptr)
{
#ifdef _WIN32
    _aligned_free(mem_ptr);
#else
    free(mem_ptr);
#endif
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_create(void *buf, hg_size_t buf_size, hg_proc_op_t op, hg_proc_hash_t hash,
        hg_bulk_class_t *hg_bulk_class, hg_proc_t *proc)
{
    struct hg_proc *hg_proc = NULL;
    const char *hash_method;
    hg_return_t ret = HG_SUCCESS;

    if (!buf && op != HG_FREE) {
        HG_LOG_ERROR("NULL buffer");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_proc = (struct hg_proc *) malloc(sizeof(struct hg_proc));
    if (!hg_proc) {
        HG_LOG_ERROR("Could not allocate proc");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    hg_proc->op = op;
    hg_proc->proc_buf.buf = buf;
    hg_proc->proc_buf.size = buf_size;
    hg_proc->proc_buf.buf_ptr = buf;
    hg_proc->proc_buf.size_left = buf_size;
    hg_proc->proc_buf.is_mine = 0;
#ifdef HG_HAS_CHECKSUMS
    hg_proc->proc_buf.checksum = MCHECKSUM_OBJECT_NULL;
    hg_proc->proc_buf.update_checksum = 0;
#endif
#ifdef HG_HAS_XDR
    switch (op) {
        case HG_ENCODE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf, buf_size, XDR_ENCODE);
            break;
        case HG_DECODE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf, buf_size, XDR_DECODE);
            break;
        case HG_FREE:
            xdrmem_create(&hg_proc->proc_buf.xdr, (char *) buf, buf_size, XDR_FREE);
            break;
        default:
            HG_LOG_ERROR("Unknown proc operation");
            ret = HG_INVALID_PARAM;
            goto done;
    }
#endif

    /* Map enum to string */
    switch (hash) {
        case HG_CRC16:
            hash_method = "crc16";
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
        int checksum_ret;

        checksum_ret = mchecksum_init(hash_method,
                &hg_proc->proc_buf.checksum);
        if (checksum_ret != MCHECKSUM_SUCCESS) {
            HG_LOG_ERROR("Could not initialize checksum");
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
        hg_proc->proc_buf.update_checksum = 1;
#endif
    }

    /* Do not allocate extra buffer yet */
    hg_proc->extra_buf.buf = NULL;
    hg_proc->extra_buf.size = 0;
    hg_proc->extra_buf.buf_ptr = NULL;
    hg_proc->extra_buf.size_left = 0;
    hg_proc->extra_buf.is_mine = 0;
#ifdef HG_HAS_CHECKSUMS
    hg_proc->extra_buf.checksum = hg_proc->proc_buf.checksum;
    hg_proc->extra_buf.update_checksum = hg_proc->proc_buf.update_checksum;
#endif

    /* Default to proc_buf */
    hg_proc->current_buf = &hg_proc->proc_buf;

    /* Set bulk class for later use */
    hg_proc->hg_bulk_class = hg_bulk_class;

    *proc = (struct hg_proc *) hg_proc;

done:
    if (ret != HG_SUCCESS) {
        free(hg_proc);
    }
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_free(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc) goto done;

#ifdef HG_HAS_CHECKSUMS
    if (hg_proc->proc_buf.checksum != MCHECKSUM_OBJECT_NULL) {
        int checksum_ret;

        checksum_ret = mchecksum_destroy(hg_proc->proc_buf.checksum);
        if (checksum_ret != MCHECKSUM_SUCCESS) {
            HG_LOG_ERROR("Could not destroy checksum");
            ret = HG_CHECKSUM_ERROR;
        }
    }
#endif

    /* Free extra proc buffer if needed */
    if (hg_proc->extra_buf.buf && hg_proc->extra_buf.is_mine) {
        free (hg_proc->extra_buf.buf);
        hg_proc->extra_buf.buf = NULL;
    }

    /* Free proc */
    free(hg_proc);
    hg_proc = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_bulk_class_t *
hg_proc_get_bulk_class(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_bulk_class_t *hg_bulk_class = NULL;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        goto done;
    }

    hg_bulk_class = hg_proc->hg_bulk_class;

done:
    return hg_bulk_class;
}

/*---------------------------------------------------------------------------*/
hg_proc_op_t
hg_proc_get_op(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_proc_op_t proc_op = HG_ENCODE;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        goto done;
    }

    proc_op = hg_proc->op;

done:
    return proc_op;
}

/*---------------------------------------------------------------------------*/
hg_size_t
hg_proc_get_size(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_size_t size = 0;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        goto done;
    }

    size = hg_proc->proc_buf.size + hg_proc->extra_buf.size;

done:
    return size;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_set_size(hg_proc_t proc, hg_size_t req_buf_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_size_t new_buf_size;
    hg_size_t page_size;
    ptrdiff_t current_pos;
    hg_return_t ret = HG_SUCCESS;

#ifdef _WIN32
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    page_size = system_info.dwPageSize;
#else
    page_size = sysconf(_SC_PAGE_SIZE);
#endif
    new_buf_size = ((hg_size_t)(req_buf_size / page_size) + 1) * page_size;

    if (new_buf_size <= hg_proc_get_size(proc)) {
        HG_LOG_ERROR("Buffer is already of the size requested");
        ret = HG_SIZE_ERROR;
        goto done;
    }

    /* If was not using extra buffer init extra buffer */
    if (!hg_proc->extra_buf.buf) {
        /* Save current position */
        current_pos = (char *) hg_proc->proc_buf.buf_ptr -
                (char *) hg_proc->proc_buf.buf;

        /* Allocate buffer */
        hg_proc->extra_buf.buf = malloc(new_buf_size);
        if (!hg_proc->extra_buf.buf) {
            HG_LOG_ERROR("Could not allocate buffer");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        /* Copy proc_buf (should be small) */
        memcpy(hg_proc->extra_buf.buf, hg_proc->proc_buf.buf, current_pos);
        hg_proc->extra_buf.size = new_buf_size;
        hg_proc->extra_buf.buf_ptr = (char *) hg_proc->extra_buf.buf + current_pos;
        hg_proc->extra_buf.size_left = hg_proc->extra_buf.size - current_pos;
        hg_proc->extra_buf.is_mine = 1;

        /* Switch buffer */
        hg_proc->current_buf = &hg_proc->extra_buf;
    } else {
        void *new_buf = NULL;

        /* Save current position */
        current_pos = (char *) hg_proc->extra_buf.buf_ptr - (char *) hg_proc->extra_buf.buf;

        /* Reallocate buffer */
        new_buf = realloc(hg_proc->extra_buf.buf, new_buf_size);
        if (!new_buf) {
            HG_LOG_ERROR("Could not reallocate buffer");
            ret = HG_NOMEM_ERROR;
            goto done;
        }
        hg_proc->extra_buf.buf = new_buf;
        hg_proc->extra_buf.size = new_buf_size;
        hg_proc->extra_buf.buf_ptr = (char *) hg_proc->extra_buf.buf + current_pos;
        hg_proc->extra_buf.size_left = hg_proc->extra_buf.size - current_pos;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_size_t
hg_proc_get_size_left(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_size_t size = 0;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        goto done;
    }

    size = hg_proc->current_buf->size_left;

done:
    return size;
}

/*---------------------------------------------------------------------------*/
void *
hg_proc_get_buf_ptr(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    void *ptr = NULL;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        goto done;
    }

    ptr = hg_proc->current_buf->buf_ptr;

done:
    return ptr;
}

/*---------------------------------------------------------------------------*/
#ifdef HG_HAS_XDR
XDR *
hg_proc_get_xdr_ptr(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    XDR *ptr = NULL;

    if (hg_proc) {
        ptr = &hg_proc->current_buf->xdr;
    }

    return ptr;
}
#endif

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_set_buf_ptr(hg_proc_t proc, void *buf_ptr)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    ptrdiff_t new_pos, lim_pos;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    /* Work out new position */
    new_pos = (char *) buf_ptr - (char *) hg_proc->current_buf->buf;
    lim_pos = (ptrdiff_t) hg_proc->current_buf->size;
    if (new_pos > lim_pos) {
        HG_LOG_ERROR("Out of memory");
        ret = HG_SIZE_ERROR;
        return ret;
    }

    hg_proc->current_buf->buf_ptr   = buf_ptr;
    hg_proc->current_buf->size_left = hg_proc->current_buf->size -
            (hg_size_t) new_pos;
#ifdef HG_HAS_XDR
    xdr_setpos(&hg_proc->current_buf->xdr, new_pos);
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void *
hg_proc_get_extra_buf(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    void *extra_buf = NULL;

    if (hg_proc->extra_buf.buf) {
        extra_buf = hg_proc->extra_buf.buf;
    }

    return extra_buf;
}

/*---------------------------------------------------------------------------*/
hg_size_t
hg_proc_get_extra_size(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_size_t extra_size = 0;

    if (hg_proc->extra_buf.buf) {
        extra_size = hg_proc->extra_buf.size;
    }

    return extra_size;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_set_extra_buf_is_mine(hg_proc_t proc, hg_bool_t theirs)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc->extra_buf.buf) {
        ret = HG_INVALID_PARAM;
        goto done;
    }

    hg_proc->extra_buf.is_mine = (hg_bool_t) (!theirs);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_flush(hg_proc_t proc)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
#ifdef HG_HAS_CHECKSUMS
    hg_bool_t current_update_checksum;
    hg_size_t checksum_size;
    char *base_checksum = NULL;
    char *new_checksum = NULL;
    int checksum_ret, cmp_ret;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    current_update_checksum = hg_proc->current_buf->update_checksum;
    if (!current_update_checksum) {
        /* Checksum was not enabled so do nothing here */
        goto done;
    }

    /* Disable checksum update now */
    hg_proc->current_buf->update_checksum = 0;

    checksum_size = mchecksum_get_size(hg_proc->current_buf->checksum);
    base_checksum = (char *) malloc(checksum_size);
    if (!base_checksum) {
        HG_LOG_ERROR("Could not allocate space for base checksum");
        ret = HG_NOMEM_ERROR;
        goto done;
    }

    if (hg_proc_get_op(proc) == HG_ENCODE) {
        checksum_ret = mchecksum_get(hg_proc->current_buf->checksum,
                base_checksum, checksum_size, 1);
        if (checksum_ret != MCHECKSUM_SUCCESS) {
            HG_LOG_ERROR("Could not get checksum");
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }

    /* Process checksum (TODO should that depend on the encoding method) */
    ret = hg_proc_raw(proc, base_checksum, checksum_size);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Proc error");
        goto done;
    }

    if (hg_proc_get_op(proc) == HG_DECODE) {
        new_checksum = (char *) malloc(checksum_size);
        if (!new_checksum) {
            HG_LOG_ERROR("Could not allocate checksum");
            ret = HG_NOMEM_ERROR;
            goto done;
        }

        checksum_ret = mchecksum_get(hg_proc->current_buf->checksum,
                new_checksum, checksum_size, 1);
        if (checksum_ret != MCHECKSUM_SUCCESS) {
            HG_LOG_ERROR("Could not get checksum");
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }

        /* Verify checksums */
        cmp_ret = strncmp(base_checksum, new_checksum, checksum_size);
        if (cmp_ret != 0) {
            HG_LOG_ERROR("Checksums do not match");
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }
#endif

done:
#ifdef HG_HAS_CHECKSUMS
    free(base_checksum);
    free(new_checksum);
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_memcpy(hg_proc_t proc, void *data, hg_size_t data_size)
{
    struct hg_proc *hg_proc = (struct hg_proc *) proc;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_proc) {
        HG_LOG_ERROR("Proc is not initialized");
        ret = HG_INVALID_PARAM;
        goto done;
    }

    if (hg_proc->op == HG_FREE) goto done;

    /* If not enough space allocate extra space if encoding or
     * just get extra buffer if decoding */
    if (hg_proc->current_buf->size_left < data_size) {
        hg_proc_set_size(proc, hg_proc->proc_buf.size +
                hg_proc->extra_buf.size + data_size);
    }

    /* Process data */
    hg_proc->current_buf->buf_ptr =
            hg_proc_buf_memcpy(hg_proc->current_buf->buf_ptr, data, data_size,
                    hg_proc->op);
    hg_proc->current_buf->size_left -= data_size;

#ifdef HG_HAS_CHECKSUMS
    /* Update checksum */
    if (hg_proc->current_buf->update_checksum) {
        int checksum_ret;

        checksum_ret = mchecksum_update(hg_proc->current_buf->checksum, data,
                data_size);
        if (checksum_ret != MCHECKSUM_SUCCESS) {
            HG_LOG_ERROR("Could not update checksum");
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }
#endif

done:
    return ret;
}
