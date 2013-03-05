/*
 * generic_proc.c
 */

#define FS_INLINE /* Needed for inline functions */
#include "generic_proc.h"

#include <stdlib.h>
#include <unistd.h>

/* Initialize a new proc buffer */
static inline int fs_proc_buf_init(fs_proc_buf_t *proc_buf, void *buf, size_t alignment, size_t buf_len)
{
    int ret = S_SUCCESS;

    if (!buf && buf_len) {
        if (proc_buf->buf) {
            S_ERROR_DEFAULT("Proc buffer was already initialized");
            ret = S_FAIL;
            return ret;
        }

        /* Allocate a new buffer */
        posix_memalign(&proc_buf->buf, alignment, buf_len);
        memset(proc_buf->buf, 0, buf_len);
        proc_buf->is_mine = 1;
    } else {
        proc_buf->buf = buf;
        proc_buf->is_mine = 0;
    }

    proc_buf->size = buf_len;
    proc_buf->buf_ptr = proc_buf->buf;
    proc_buf->size_left = proc_buf->size;
    proc_buf->is_used = 0;

    return ret;
}

/* Reallocate a proc buffer */
static inline int fs_proc_buf_realloc(fs_proc_buf_t *proc_buf, size_t buf_len)
{
    int ret = S_SUCCESS;
    ptrdiff_t current_pos;

    if (!proc_buf->buf) {
        S_ERROR_DEFAULT("Cannot reallocate non-allocated proc buffer");
        ret = S_FAIL;
        return ret;
    }

    /* Save current position */
    current_pos = proc_buf->buf_ptr - proc_buf->buf;

    /* Reallocate buffer */
    proc_buf->buf = realloc(proc_buf->buf, buf_len);

    proc_buf->size = buf_len;
    proc_buf->buf_ptr = proc_buf->buf + current_pos;
    proc_buf->size_left = proc_buf->size - current_pos;

    return ret;
}

/* Free a proc buffer */
static inline int fs_proc_buf_free(fs_proc_buf_t *proc_buf)
{
    int ret = S_SUCCESS;

    if (!proc_buf) {
        S_ERROR_DEFAULT("NULL proc buffer");
        ret = S_FAIL;
        return ret;
    }

    if (proc_buf->is_mine) {
        if (!proc_buf->buf) {
            S_ERROR_DEFAULT("Already freed");
            ret = S_FAIL;
            return ret;
        }
        free (proc_buf->buf);
        proc_buf->buf = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_create
 *
 * Purpose:     Create a new encoding/decoding processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_create(void *buf, size_t buf_len, fs_proc_op_t op, fs_proc_t *proc)
{
    fs_priv_proc_t *priv_proc = NULL;
    size_t page_size;
    int ret = S_SUCCESS;

    priv_proc = malloc(sizeof(fs_priv_proc_t));
    priv_proc->op = op;
#ifdef IOFSL_SHIPPER_HAS_XDR
    switch (op) {
        case FS_ENCODE:
            xdrmem_create(&priv_proc->xdr, buf, buf_len, XDR_ENCODE);
            break;
        case FS_DECODE:
            xdrmem_create(&priv_proc->xdr, buf, buf_len, FS_DECODE);
            break;
        default:
            S_ERROR_DEFAULT("Unknown proc operation");
            ret = S_FAIL;
            return ret;
    }
#endif
    priv_proc->proc_buf.buf = NULL;
    priv_proc->extra_buf.buf = NULL;
    priv_proc->current_buf = &priv_proc->proc_buf;

    page_size = getpagesize();
    fs_proc_buf_init(&priv_proc->proc_buf, buf, page_size, buf_len);
    priv_proc->proc_buf.is_used = 1;

    /* Do not allocate extra buffer yet */
    fs_proc_buf_init(&priv_proc->extra_buf, NULL, 0, 0);

    *proc = (fs_priv_proc_t*) priv_proc;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_free
 *
 * Purpose:     Free the processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_free(fs_proc_t proc)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_SUCCESS;

    if (!priv_proc) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    /* Free proc buffers if needed */
    fs_proc_buf_free(&priv_proc->proc_buf);
    fs_proc_buf_free(&priv_proc->extra_buf);

    /* Free proc */
    free(priv_proc);
    priv_proc = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_get_size
 *
 * Purpose:     Get total buffer size available for processing
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
size_t fs_proc_get_size(fs_proc_t proc)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->proc_buf.size + priv_proc->extra_buf.size;

    return size;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_set_size
 *
 * Purpose:     Request a new buffer size
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_set_size(fs_proc_t proc, size_t req_buf_len)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    size_t new_buf_len;
    size_t page_size;
    int ret = S_FAIL;

    page_size = getpagesize();
    new_buf_len = ((size_t)(req_buf_len / page_size) + 1) * page_size;

    if (new_buf_len > fs_proc_get_size(proc)) {

        /* If was not using extra buffer switch buffer and init extra buffer */
        if (!priv_proc->extra_buf.is_used) {
            ret = fs_proc_buf_init(&priv_proc->extra_buf, NULL, page_size, new_buf_len);
            priv_proc->current_buf = &priv_proc->extra_buf;
            priv_proc->extra_buf.is_used = 1;
        } else {
            /* Resize extra buffer */
            ret = fs_proc_buf_realloc(&priv_proc->extra_buf, new_buf_len);
        }

    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_get_size_left
 *
 * Purpose:     Get total buffer size available for processing
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
size_t fs_proc_get_size_left(fs_proc_t proc)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    size_t size = 0;

    if (priv_proc) size = priv_proc->proc_buf.size_left + priv_proc->extra_buf.size_left;

    return size;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_get_buf_ptr
 *
 * Purpose:     Get pointer to current buffer (for manual encoding)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void * fs_proc_get_buf_ptr(fs_proc_t proc)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    void *ptr = NULL;

    if (priv_proc) {
        ptr = priv_proc->current_buf->buf_ptr;
    }

    return ptr;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_set_buf_ptr
 *
 * Purpose:     Set new buffer pointer (for manual encoding)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_set_buf_ptr(fs_proc_t proc, void *buf_ptr)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    int ret = S_FAIL;

    if (priv_proc) {
        ptrdiff_t new_pos, lim_pos;

        /* Work out new position */
        new_pos = buf_ptr - priv_proc->current_buf->buf_ptr;
        lim_pos = (ptrdiff_t)priv_proc->current_buf->buf - priv_proc->current_buf->size;
        if (new_pos > lim_pos) {
            S_ERROR_DEFAULT("Out of memory");
            ret = S_FAIL;
            return ret;
        }

        priv_proc->current_buf->buf_ptr += new_pos;
        priv_proc->current_buf->size_left -= new_pos;

        ret = S_SUCCESS;
    }

    return ret;

}
