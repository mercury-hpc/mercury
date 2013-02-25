/*
 * generic_proc.c
 */

#define FS_INLINE /* Needed for inline functions */
#include "generic_proc.h"

#include <stdlib.h>

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
#else
    priv_proc->buf = buf;
    priv_proc->buf_len = buf_len;
    priv_proc->buf_ptr = buf;
    priv_proc->buf_size_left = buf_len;
    priv_proc->buf_is_mine = 0;
#endif
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

    free(priv_proc);
    priv_proc = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_get_size
 *
 * Purpose:     Get number of bytes available for processing
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
size_t fs_proc_get_size(fs_proc_t proc)
{
//    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
//    return priv_proc->buf_len;
    return 0;
}
