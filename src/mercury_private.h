/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PRIVATE_H
#define MERCURY_PRIVATE_H

#include "mercury_types.h"

/* TODO temp includes */
#include "mercury_request.h"
#include "mercury_list.h"

struct hg_handle {
    hg_id_t       id;                  /* Request ID */
    hg_uint32_t   cookie;              /* Cookie unique to every RPC call */
    na_addr_t     addr;                /* Address of the RPC source/dest */
    na_tag_t      tag;                 /* Tag used for request and response */

    void         *send_buf;            /* Send buffer for response */
    na_size_t     send_buf_size;       /* Send buffer size */
    void         *extra_send_buf;      /* Extra send buffer */
    na_size_t     extra_send_buf_size; /* Extra send buffer size */
    hg_bulk_t     extra_send_buf_handle;
    hg_request_object_t *send_request;

    void         *recv_buf;            /* Recv buffer for request */
    na_size_t     recv_buf_size;       /* Recv buffer size */
    void         *extra_recv_buf;      /* Extra recv buffer */
    na_size_t     extra_recv_buf_size; /* Extra recv buffer size */
    hg_request_object_t *recv_request;

    void         *in_struct;           /* Input structure */
    void         *out_struct;          /* Output structure */

    hg_list_entry_t *processing_entry; /* Entry in processing list */
};

struct hg_info {
    hg_proc_cb_t input_proc_cb;  /* Input serial/deserial callback */
    hg_proc_cb_t output_proc_cb; /* Output serial/deserial callback */
    hg_rpc_cb_t  rpc_cb;         /* RPC callback */
};


#endif /* MERCURY_PRIVATE_H */
