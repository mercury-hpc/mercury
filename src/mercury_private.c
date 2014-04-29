/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_private.h"
#include "mercury_proc.h"

#include "mercury_error.h"

#include <stdlib.h>

/* Pointer to NA class */
extern na_class_t *hg_na_class_g;

/*---------------------------------------------------------------------------*/
struct hg_handle *
hg_handle_new(void)
{
    struct hg_handle *hg_handle = NULL;

    hg_handle = (struct hg_handle *) malloc(sizeof(struct hg_handle));
    if (!hg_handle) {
        HG_ERROR_DEFAULT("Could not allocate handle");
        goto done;
    }

    hg_handle->id = 0;
    hg_handle->cookie = 0;
    hg_handle->addr = NA_ADDR_NULL;
    hg_handle->tag = 0;

    hg_handle->in_buf = NULL;
    hg_handle->in_buf_size = 0;
    hg_handle->extra_in_buf = NULL;
    hg_handle->extra_in_buf_size = 0;
    hg_handle->extra_in_handle = HG_BULK_NULL;
    hg_handle->in_request = NULL;

    hg_handle->out_buf = NULL;
    hg_handle->out_buf_size = 0;
    hg_handle->extra_out_buf = NULL;
    hg_handle->extra_out_buf_size = 0;
    hg_handle->out_request = NULL;

    hg_handle->out_struct_ptr = NULL;

    hg_handle->processing_entry = NULL;

    hg_atomic_set32(&hg_handle->ref_count, 1);

    hg_handle->local = HG_FALSE;
    hg_handle->processed = HG_FALSE;
    hg_thread_mutex_init(&hg_handle->processed_mutex);
    hg_thread_cond_init(&hg_handle->processed_cond);
done:
    return hg_handle;
}

/*---------------------------------------------------------------------------*/
void
hg_handle_free(struct hg_handle *hg_handle)
{
    if (!hg_handle) goto done;

    if (hg_atomic_decr32(&hg_handle->ref_count)) {
        goto done;
    }

    if (hg_handle->addr != NA_ADDR_NULL && !hg_handle->local)
        NA_Addr_free(hg_na_class_g, hg_handle->addr);

    hg_proc_buf_free(hg_handle->in_buf);
    free(hg_handle->extra_in_buf);
    HG_Bulk_handle_free(hg_handle->extra_in_handle);

    hg_proc_buf_free(hg_handle->out_buf);
    free(hg_handle->extra_out_buf);

    hg_thread_mutex_destroy(&hg_handle->processed_mutex);
    hg_thread_cond_destroy(&hg_handle->processed_cond);

    free(hg_handle);

done:
    return;
}
