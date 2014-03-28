/*
 * mercury_private.c
 *
 *  Created on: Mar 27, 2014
 *      Author: jsoumagne
 */

#include "mercury_private.h"

#include "mercury_error.h"

#include <stdlib.h>

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

    hg_handle->send_buf = NULL;
    hg_handle->send_buf_size = 0;
    hg_handle->extra_send_buf = NULL;
    hg_handle->extra_send_buf_size = 0;
    hg_handle->extra_send_buf_handle = HG_BULK_NULL;
    hg_handle->send_request = NULL;

    hg_handle->recv_buf = NULL;
    hg_handle->recv_buf_size = 0;
    hg_handle->extra_recv_buf = NULL;
    hg_handle->extra_recv_buf_size = 0;
    hg_handle->recv_request = NULL;

    hg_handle->in_struct = NULL;
    hg_handle->out_struct = NULL;

    hg_handle->processing_entry = NULL;

    hg_handle->local = HG_FALSE;
    hg_handle->processed = HG_FALSE;
    hg_thread_mutex_init(&hg_handle->processed_mutex);
    hg_thread_cond_init(&hg_handle->processed_cond);
done:
    return hg_handle;
}
