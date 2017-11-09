/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_header.h"
#include "mercury_proc_buf.h"
#include "mercury_error.h"

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_HEADER_PROC(hg_header, buf_ptr, data, op) \
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &data, sizeof(data), op);

#define HG_HEADER_PROC32(hg_header, buf_ptr, data, op, tmp) do { \
    hg_uint32_t tmp;                                             \
    if (op == HG_ENCODE)                                         \
        tmp = htonl(data);                                       \
    HG_HEADER_PROC(hg_header, buf_ptr, tmp, op);                 \
    if (op == HG_DECODE)                                         \
        data = ntohl(tmp);                                       \
} while (0)

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
void
hg_header_init(struct hg_header *hg_header, hg_op_t op)
{
    hg_header_reset(hg_header, op);
}

/*---------------------------------------------------------------------------*/
void
hg_header_finalize(struct hg_header *hg_header)
{
    (void) hg_header;
}

/*---------------------------------------------------------------------------*/
void
hg_header_reset(struct hg_header *hg_header, hg_op_t op)
{
    switch (op) {
        case HG_INPUT:
            memset(&hg_header->msg.input, 0, sizeof(struct hg_header_input));
            break;
        case HG_OUTPUT:
            memset(&hg_header->msg.output, 0, sizeof(struct hg_header_output));
            break;
        default:
            break;
    }
    hg_header->op = op;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_header_proc(hg_proc_op_t op, void *buf, size_t buf_size,
    struct hg_header *hg_header)
{
    void *buf_ptr = buf;
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash *header_hash = NULL;
#endif
    hg_return_t ret = HG_SUCCESS;

    switch (hg_header->op) {
        case HG_INPUT:
            if (buf_size < sizeof(struct hg_header_input)) {
                HG_LOG_ERROR("Invalid buffer size");
                ret = HG_INVALID_PARAM;
                goto done;
            }
#ifdef HG_HAS_CHECKSUMS
            header_hash = &hg_header->msg.input.hash;
#endif
            break;
        case HG_OUTPUT:
            if (buf_size < sizeof(struct hg_header_output)) {
                HG_LOG_ERROR("Invalid buffer size");
                ret = HG_SIZE_ERROR;
                goto done;
            }
#ifdef HG_HAS_CHECKSUMS
            header_hash = &hg_header->msg.output.hash;
#endif
            break;
        default:
            break;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Checksum of user payload */
    HG_HEADER_PROC32(hg_header, buf_ptr, header_hash->payload, op, tmp);
#else
    (void) hg_header;
    (void) buf_ptr;
    (void) op;
#endif

done:
    return ret;
}
