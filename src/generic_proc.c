/*
 * generic_proc.c
 */

#define FS_INLINE /* Needed for inline functions */
#include "generic_proc.h"

#include <stdlib.h>

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_create
 *
 * Purpose:     Create a new encoding processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_enc_create(fs_proc_t *proc, void *buf, size_t buf_len)
{
    fs_enc_proc_t *enc_proc = NULL;
    int ret = S_SUCCESS;

    enc_proc = malloc(sizeof(fs_enc_proc_t));
#ifdef IOFSL_SHIPPER_HAS_XDR
    xdrmem_create(&enc_proc->xdr, buf, buf_len, XDR_ENCODE);
#else
    enc_proc->buf = buf;
    enc_proc->buf_len = buf_len;
    enc_proc->buf_ptr = buf;
    enc_proc->buf_size_left = buf_len;
#endif
    *proc = (fs_enc_proc_t*) enc_proc;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_create
 *
 * Purpose:     Create a new decoding processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_dec_create(fs_proc_t *proc, const void *buf, size_t buf_len)
{
    fs_dec_proc_t *dec_proc = NULL;
    int ret = S_SUCCESS;

    dec_proc = malloc(sizeof(fs_dec_proc_t));
#ifdef IOFSL_SHIPPER_HAS_XDR
    xdrmem_create(&dec_proc->xdr, (void*)buf, buf_len, XDR_DECODE);
#else
    dec_proc->buf = buf;
    dec_proc->buf_len = buf_len;
    dec_proc->buf_ptr = buf;
    dec_proc->buf_size_left = buf_len;
#endif
    *proc = (fs_dec_proc_t*) dec_proc;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_enc_free
 *
 * Purpose:     Free the processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_enc_free(fs_proc_t proc)
{
    fs_enc_proc_t *enc_proc = (fs_enc_proc_t*) proc;
    int ret = S_SUCCESS;

    if (!enc_proc) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    free(enc_proc);
    enc_proc = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_proc_dec_free
 *
 * Purpose:     Free the processor
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_proc_dec_free(fs_proc_t proc)
{
    fs_dec_proc_t *dec_proc = (fs_dec_proc_t*) proc;
    int ret = S_SUCCESS;

    if (!dec_proc) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    free(dec_proc);
    dec_proc = NULL;

    return ret;
}
