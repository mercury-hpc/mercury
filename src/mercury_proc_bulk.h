/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROC_BULK_H
#define MERCURY_PROC_BULK_H

#include "mercury_bulk.h"
#include "mercury_proc.h"

/**
 * Generic processing routine.
 *
 * \param proc [IN/OUT]         abstract processor object
 * \param handle [IN/OUT]       pointer to bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
static HG_INLINE hg_return_t
hg_proc_hg_bulk_t(hg_proc_t proc, void *data)
{
    hg_return_t ret = HG_SUCCESS;
    void *buf = NULL;
    hg_bulk_t *bulk_ptr = (hg_bulk_t *) data;
    hg_uint64_t buf_size = 0;

    switch (hg_proc_get_op(proc)) {
        case HG_ENCODE: {
            hg_bool_t request_eager = HG_FALSE;
            void *cached_ptr = NULL;

            /* If HG_BULK_NULL set 0 to buf_size */
            if (*bulk_ptr == HG_BULK_NULL)
                buf_size = 0;
            else if ((cached_ptr = HG_Bulk_get_serialize_cached_ptr(*bulk_ptr))
                != NULL)
                buf_size = HG_Bulk_get_serialize_cached_size(*bulk_ptr);
            else {
#ifdef HG_HAS_EAGER_BULK
                hg_size_t serialize_size = HG_Bulk_get_serialize_size(*bulk_ptr,
                    HG_TRUE);
                request_eager =
                    (hg_proc_get_size_left(proc) > serialize_size) ? HG_TRUE :
                        HG_FALSE;
                if (request_eager)
                    buf_size = serialize_size;
                else
#endif
                    buf_size = HG_Bulk_get_serialize_size(*bulk_ptr, HG_FALSE);
            }
            /* Encode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS)
                return ret;
            if (!buf_size)
                break;
            if (cached_ptr)
                hg_proc_raw(proc, cached_ptr, buf_size);
            else {
                buf = hg_proc_save_ptr(proc, buf_size);
                ret = HG_Bulk_serialize(buf, buf_size, request_eager,
                    *bulk_ptr);
                if (ret != HG_SUCCESS)
                    return ret;
                hg_proc_restore_ptr(proc, buf, buf_size);
            }
            break;
        }
        case HG_DECODE: {
            hg_class_t *hg_class = hg_proc_get_class(proc);

            /* Decode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            if (ret != HG_SUCCESS)
                return ret;
            if (!buf_size) {
                /* If buf_size is 0, define handle to HG_BULK_NULL */
                *bulk_ptr = HG_BULK_NULL;
                break;
            }

            buf = hg_proc_save_ptr(proc, buf_size);
            ret = HG_Bulk_deserialize(hg_class, bulk_ptr, buf, buf_size);
            if (ret != HG_SUCCESS)
                return ret;
            /* Cache serialize ptr to buf */
            ret = HG_Bulk_set_serialize_cached_ptr(*bulk_ptr, buf, buf_size);
            if (ret != HG_SUCCESS)
                return ret;
            hg_proc_restore_ptr(proc, buf, buf_size);
            break;
        }
        case HG_FREE:
            if (*bulk_ptr == HG_BULK_NULL) {
                /* If *bulk is HG_BULK_NULL, just return success */
                ret = HG_SUCCESS;
                break;
            }
            /* Set serialize ptr to NULL */
            ret = HG_Bulk_set_serialize_cached_ptr(*bulk_ptr, NULL, 0);
            if (ret != HG_SUCCESS)
                return ret;

            /* Decrement refcount on bulk handle */
            ret = HG_Bulk_free(*bulk_ptr);
            if (ret != HG_SUCCESS)
                return ret;
            *bulk_ptr = HG_BULK_NULL;
            break;
        default:
            break;
    }
    return ret;
}

#endif /* MERCURY_PROC_BULK_H */
