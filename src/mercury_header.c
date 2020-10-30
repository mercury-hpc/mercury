/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_header.h"
#include "mercury_error.h"

#ifdef _WIN32
#    include <winsock2.h>
#else
#    include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/* Convert values between host and network byte order */
#define hg_header_proc_hg_uint32_t_enc(x) htonl(x & 0xffffffff)
#define hg_header_proc_hg_uint32_t_dec(x) ntohl(x & 0xffffffff)

/* Proc type */
#define HG_HEADER_PROC_TYPE(buf_ptr, data, type, op)                           \
    do {                                                                       \
        type __tmp;                                                            \
        if (op == HG_ENCODE) {                                                 \
            __tmp = hg_header_proc_##type##_enc(data);                         \
            memcpy(buf_ptr, &__tmp, sizeof(type));                             \
        } else {                                                               \
            memcpy(&__tmp, buf_ptr, sizeof(type));                             \
            data = hg_header_proc_##type##_dec(__tmp);                         \
        }                                                                      \
        buf_ptr = (char *) buf_ptr + sizeof(type);                             \
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
hg_header_proc(
    hg_proc_op_t op, void *buf, size_t buf_size, struct hg_header *hg_header)
{
    void *buf_ptr = buf;
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash *header_hash = NULL;
#endif
    hg_return_t ret = HG_SUCCESS;

    switch (hg_header->op) {
        case HG_INPUT:
            HG_CHECK_ERROR(buf_size < sizeof(struct hg_header_input), done, ret,
                HG_INVALID_ARG, "Invalid buffer size");
#ifdef HG_HAS_CHECKSUMS
            header_hash = &hg_header->msg.input.hash;
#endif
            break;
        case HG_OUTPUT:
            HG_CHECK_ERROR(buf_size < sizeof(struct hg_header_output), done,
                ret, HG_INVALID_ARG, "Invalid buffer size");
#ifdef HG_HAS_CHECKSUMS
            header_hash = &hg_header->msg.output.hash;
#endif
            break;
        default:
            HG_GOTO_ERROR(done, ret, HG_INVALID_ARG, "Invalid header op");
    }

#ifdef HG_HAS_CHECKSUMS
    /* Checksum of user payload */
    HG_HEADER_PROC_TYPE(buf_ptr, header_hash->payload, hg_uint32_t, op);
#else
    (void) hg_header;
    (void) buf_ptr;
    (void) op;
#endif

done:
    return ret;
}
