/*
 * bulk_data_proc.h
 */

#ifndef BULK_DATA_PROC_H
#define BULK_DATA_PROC_H

#include "generic_proc.h"
#include "bulk_data_shipper.h"

#ifndef BDS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define BDS_INLINE extern inline
# else
#  define BDS_INLINE inline
# endif
#endif

#define BDS_MAX_HANDLE_SIZE 32 /* TODO Arbitrary value / may need to be increased depending on implementations */

/*---------------------------------------------------------------------------
 * Function:    fs_proc_bds_handle_t
 *
 * Purpose:     Generic processing routines
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
BDS_INLINE int fs_proc_bds_handle_t(fs_proc_t proc, bds_handle_t *handle)
{
    fs_priv_proc_t *priv_proc = (fs_priv_proc_t*) proc;
    char bds_handle_buf[BDS_MAX_HANDLE_SIZE];
    int ret = S_FAIL;

    if (priv_proc->op == FS_ENCODE) {
        bds_handle_serialize(bds_handle_buf, BDS_MAX_HANDLE_SIZE, *handle);
        ret = fs_proc_raw(priv_proc, bds_handle_buf, BDS_MAX_HANDLE_SIZE);
    } else {
        ret = fs_proc_raw(priv_proc, bds_handle_buf, BDS_MAX_HANDLE_SIZE);
        bds_handle_deserialize(handle, bds_handle_buf, BDS_MAX_HANDLE_SIZE);
    }

    return ret;
}

#endif /* BULK_DATA_PROC_H */
