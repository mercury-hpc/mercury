/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_core_header.h"
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

#define HG_CORE_HEADER_CHECKSUM "crc16"

/* Helper macros for encoding header */
#ifdef HG_HAS_CHECKSUMS
# define HG_CORE_HEADER_PROC(hg_header, buf_ptr, data, op)          \
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &data, sizeof(data), op); \
    mchecksum_update(hg_header->checksum, &data, sizeof(data));
#else
# define HG_CORE_HEADER_PROC(hg_header, buf_ptr, data, op)          \
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &data, sizeof(data), op);
#endif

#define HG_CORE_HEADER_PROC16(hg_header, buf_ptr, data, op, tmp) do {   \
    hg_uint16_t tmp;                                                    \
    if (op == HG_ENCODE)                                                \
        tmp = htons(data);                                              \
    HG_CORE_HEADER_PROC(hg_header, buf_ptr, tmp, op);                   \
    if (op == HG_DECODE)                                                \
        data = ntohs(tmp);                                              \
} while (0)

#define HG_CORE_HEADER_PROC32(hg_header, buf_ptr, data, op, tmp) do {   \
    hg_uint32_t tmp;                                                    \
    if (op == HG_ENCODE)                                                \
        tmp = htonl(data);                                              \
    HG_CORE_HEADER_PROC(hg_header, buf_ptr, tmp, op);                   \
    if (op == HG_DECODE)                                                \
        data = ntohl(tmp);                                              \
} while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/
extern const char *
HG_Error_to_string(
        hg_return_t errnum
        );

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
void
hg_core_header_request_init(struct hg_core_header *hg_core_header)
{
#ifdef HG_HAS_CHECKSUMS
    /* Create a new checksum (CRC16) */
    mchecksum_init(HG_CORE_HEADER_CHECKSUM, &hg_core_header->checksum);
#endif
    hg_core_header_request_reset(hg_core_header);
}

/*---------------------------------------------------------------------------*/
void
hg_core_header_response_init(struct hg_core_header *hg_core_header)
{
#ifdef HG_HAS_CHECKSUMS
    /* Create a new checksum (CRC16) */
    mchecksum_init(HG_CORE_HEADER_CHECKSUM, &hg_core_header->checksum);
#endif
    hg_core_header_response_reset(hg_core_header);
}

/*---------------------------------------------------------------------------*/
void
hg_core_header_request_finalize(struct hg_core_header *hg_core_header)
{
#ifdef HG_HAS_CHECKSUMS
    mchecksum_destroy(hg_core_header->checksum);
    hg_core_header->checksum = MCHECKSUM_OBJECT_NULL;
#else
    (void) hg_core_header;
#endif
}

/*---------------------------------------------------------------------------*/
void
hg_core_header_response_finalize(struct hg_core_header *hg_core_header)
{
#ifdef HG_HAS_CHECKSUMS
    mchecksum_destroy(hg_core_header->checksum);
    hg_core_header->checksum = MCHECKSUM_OBJECT_NULL;
#else
    (void) hg_core_header;
#endif
}

/*---------------------------------------------------------------------------*/
void
hg_core_header_request_reset(struct hg_core_header *hg_core_header)
{
    memset(&hg_core_header->msg.request, 0,
        sizeof(struct hg_core_header_request));
    hg_core_header->msg.request.hg = HG_CORE_IDENTIFIER;
    hg_core_header->msg.request.protocol = HG_CORE_PROTOCOL_VERSION;
#ifdef HG_HAS_CHECKSUMS
    mchecksum_reset(hg_core_header->checksum);
#endif
}

/*---------------------------------------------------------------------------*/
void
hg_core_header_response_reset(struct hg_core_header *hg_core_header)
{
    memset(&hg_core_header->msg.response, 0,
        sizeof(struct hg_core_header_response));
#ifdef HG_HAS_CHECKSUMS
    mchecksum_reset(hg_core_header->checksum);
#endif
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_header_request_proc(hg_proc_op_t op, void *buf, size_t buf_size,
    struct hg_core_header *hg_core_header)
{
    void *buf_ptr = buf;
    struct hg_core_header_request *header = &hg_core_header->msg.request;
#ifdef HG_HAS_CHECKSUMS
    hg_uint16_t n_hash_header;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (buf_size < sizeof(struct hg_core_header_request)) {
        HG_LOG_ERROR("Invalid buffer size");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Reset header checksum first */
    mchecksum_reset(hg_core_header->checksum);
#endif

    /* HG byte */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->hg, op);

    /* Protocol */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->protocol, op);

    /* Convert ID to network byte order */
    HG_CORE_HEADER_PROC32(hg_core_header, buf_ptr, header->id, op, tmp);

    /* Flags */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->flags, op);

    /* Cookie */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->cookie, op);

#ifdef HG_HAS_CHECKSUMS
    /* Checksum of header */
    mchecksum_get(hg_core_header->checksum, &header->hash.header,
        sizeof(header->hash.header), MCHECKSUM_FINALIZE);
    if (op == HG_ENCODE)
        n_hash_header = (hg_uint16_t) htons(header->hash.header);
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_hash_header, sizeof(n_hash_header),
        op);
    if (op == HG_DECODE) {
        hg_uint16_t h_hash_header = ntohs(n_hash_header);
        if (header->hash.header != h_hash_header) {
            HG_LOG_ERROR("checksum 0x%04X does not match (expected 0x%04X!)",
                header->hash.header, h_hash_header);
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_header_response_proc(hg_proc_op_t op, void *buf, size_t buf_size,
    struct hg_core_header *hg_core_header)
{
    void *buf_ptr = buf;
    struct hg_core_header_response *header = &hg_core_header->msg.response;
#ifdef HG_HAS_CHECKSUMS
    hg_uint16_t n_hash_header;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (buf_size < sizeof(struct hg_core_header_response)) {
        HG_LOG_ERROR("Invalid buffer size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Reset header checksum first */
    mchecksum_reset(hg_core_header->checksum);
#endif

    /* Flags */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->flags, op);

    /* Return code */
    HG_CORE_HEADER_PROC(hg_core_header, buf_ptr, header->ret_code, op);

    /* Convert cookie to network byte order */
    HG_CORE_HEADER_PROC16(hg_core_header, buf_ptr, header->cookie, op, tmp);

#ifdef HG_HAS_CHECKSUMS
    /* Checksum of header */
    mchecksum_get(hg_core_header->checksum, &header->hash.header,
        sizeof(header->hash.header), MCHECKSUM_FINALIZE);
    if (op == HG_ENCODE)
        n_hash_header = (hg_uint16_t) htons(header->hash.header);
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_hash_header, sizeof(n_hash_header),
        op);
    if (op == HG_DECODE) {
        hg_uint16_t h_hash_header = ntohs(n_hash_header);
        if (header->hash.header != h_hash_header) {
            HG_LOG_ERROR("checksum 0x%04X does not match (expected 0x%04X!)",
                header->hash.header, h_hash_header);
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_header_request_verify(const struct hg_core_header *hg_core_header)
{
    const struct hg_core_header_request *header = &hg_core_header->msg.request;
    hg_return_t ret = HG_SUCCESS;

    /* Must match HG */
    if ((((header->hg >> 1)  & 'H') != 'H') ||
        (((header->hg)       & 'G') != 'G')) {
        HG_LOG_ERROR("Invalid HG byte");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (header->protocol != HG_CORE_PROTOCOL_VERSION) {
        HG_LOG_ERROR("Invalid protocol version");
        ret = HG_NO_MATCH;
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_core_header_response_verify(const struct hg_core_header *hg_core_header)
{
    const struct hg_core_header_response *header = &hg_core_header->msg.response;
    hg_return_t ret = HG_SUCCESS;

    if (header->ret_code)
        HG_LOG_WARNING("Response return code: %s",
            HG_Error_to_string((hg_return_t) header->ret_code));

    return ret;
}
