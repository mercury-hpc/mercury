/*
 * iofsl_compat.h
 */

#ifndef IOFSL_COMPAT_H
#define IOFSL_COMPAT_H

#include "generic_proc.h"

#ifndef COMPAT_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#   define COMPAT_INLINE extern inline
# else
#  define COMPAT_INLINE inline
# endif
#endif

/* TODO (keep that for now) Define the ZOIDFS operations */
enum {
    PROTO_GENERIC = 16, /* TODO map to zoidfs proto */

    /* First invalid operation id */
    PROTO_MAX
};

/* Op id describes the various generic operations (setattr, getattr etc.) */
typedef uint32_t iofsl_compat_op_id_t;

/*
 * generic_op_status_t is used by the server to inform the client of the status
 * of the operation.
 */
typedef int32_t iofsl_compat_op_status_t;

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------
 * Function:    iofsl_compat_proc_id
 *
 * Purpose:     Process IOFSL ID
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
COMPAT_INLINE int iofsl_compat_proc_id(fs_proc_t proc)
{
    iofsl_compat_op_id_t op_id = PROTO_GENERIC;
    int ret = S_FAIL;

    ret = fs_proc_uint32_t(proc, &op_id);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    iofsl_compat_proc_status
 *
 * Purpose:     Process IOFSL return status
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
COMPAT_INLINE int iofsl_compat_proc_status(fs_proc_t proc)
{
    iofsl_compat_op_status_t op_status = 0;
    int ret = S_FAIL;

    ret = fs_proc_int32_t(proc, &op_status);

    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* IOFSL_COMPAT_H */
