/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_proc_bulk.h"
#include "mercury_bulk_proc.h"
#include "mercury_error.h"

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
hg_proc_hg_bulk_t(hg_proc_t proc, void *data)
{
    hg_return_t ret = HG_SUCCESS;
    void *buf = NULL;
    hg_bulk_t *bulk_ptr = (hg_bulk_t *) data;
    hg_uint64_t buf_size = 0;

    switch (hg_proc_get_op(proc)) {
        case HG_ENCODE: {
            hg_uint8_t flags = 0;

            /* If HG_BULK_NULL set 0 to buf_size */
            if (*bulk_ptr == HG_BULK_NULL) {
                /* Encode zero size */
                ret = hg_proc_uint64_t(proc, &buf_size);
                HG_CHECK_HG_ERROR(done, ret, "Could not encode serialize size");
                break;
            }

#ifdef HG_HAS_SM_ROUTING
            /* Are we using SM routing */
            if (hg_proc_get_flags(proc) & HG_PROC_SM)
                flags |= HG_BULK_SM;
#endif

#ifdef HG_HAS_EAGER_BULK
            /* Try to make everything fit in an eager buffer */
            HG_LOG_DEBUG(
                "Proc size left is %zu bytes", hg_proc_get_size_left(proc));
            buf_size =
                HG_Bulk_get_serialize_size(*bulk_ptr, HG_BULK_EAGER | flags);
            if (hg_proc_get_size_left(proc) >= (buf_size + sizeof(hg_uint64_t)))
                flags |= HG_BULK_EAGER;
            else
#endif
                buf_size = HG_Bulk_get_serialize_size(*bulk_ptr, flags);

            /* Encode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not encode serialize size");

            if (buf_size == hg_bulk_get_serialize_cached_size(*bulk_ptr)) {
                void *cached_ptr = hg_bulk_get_serialize_cached_ptr(*bulk_ptr);
                hg_proc_bytes(proc, cached_ptr, buf_size);
            } else {
                buf = hg_proc_save_ptr(proc, buf_size);
                ret = HG_Bulk_serialize(buf, buf_size, flags, *bulk_ptr);
                HG_CHECK_HG_ERROR(done, ret, "Could not serialize handle");
                hg_proc_restore_ptr(proc, buf, buf_size);
            }
            break;
        }
        case HG_DECODE: {
            hg_class_t *hg_class = hg_proc_get_class(proc);

            /* Decode size */
            ret = hg_proc_uint64_t(proc, &buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not decode serialize size");

            /* If buf_size is 0, define handle to HG_BULK_NULL */
            if (buf_size == 0) {
                *bulk_ptr = HG_BULK_NULL;
                break;
            }

            buf = hg_proc_save_ptr(proc, buf_size);
            ret = HG_Bulk_deserialize(hg_class, bulk_ptr, buf, buf_size);
            HG_CHECK_HG_ERROR(done, ret, "Could not deserialize handle");

            /* Cache serialize ptr to buf */
            hg_bulk_set_serialize_cached_ptr(*bulk_ptr, buf, buf_size);
            hg_proc_restore_ptr(proc, buf, buf_size);
            break;
        }
        case HG_FREE:
            /* If bulk handle is HG_BULK_NULL, just return success */
            if (*bulk_ptr == HG_BULK_NULL)
                break;

            /* Set serialize ptr to NULL */
            hg_bulk_set_serialize_cached_ptr(*bulk_ptr, NULL, 0);

            /* Decrement refcount on bulk handle */
            ret = HG_Bulk_free(*bulk_ptr);
            HG_CHECK_HG_ERROR(done, ret, "Could not free handle");
            *bulk_ptr = HG_BULK_NULL;
            break;
        default:
            break;
    }

done:
    return ret;
}
