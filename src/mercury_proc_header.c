/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef _WIN32
  #define HG_PROC_HEADER_INLINE
#endif
#include "mercury_proc_header.h"
#include "mercury_proc.h"
#include "mercury_core.h"

#ifdef HG_HAS_CHECKSUMS
  #include <mchecksum.h>
  #include <mchecksum_error.h>
#endif

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif
#include <stdlib.h>

/*---------------------------------------------------------------------------*/
void
hg_proc_header_request_init(hg_id_t id, hg_bulk_t extra_in_handle,
        struct hg_header_request *header)
{
    header->hg = HG_IDENTIFIER;
    header->protocol = HG_PROTOCOL_VERSION;
    header->id = id;
    header->flags = (hg_uint8_t) (extra_in_handle != HG_BULK_NULL);
    header->cookie = (hg_uint32_t) rand();
    header->crc16 = 0;
    header->extra_in_handle = extra_in_handle;
}

/*---------------------------------------------------------------------------*/
void
hg_proc_header_response_init(struct hg_header_response *header)
{
    header->flags = 0;
    header->ret_code = 0;
    header->cookie = 0;
    header->crc16 = 0;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_header_request(void *buf, size_t buf_size,
        struct hg_header_request *header, hg_proc_op_t op,
        hg_bulk_class_t *bulk_class)
{
    hg_uint32_t n_protocol, n_id, n_cookie;
    hg_uint16_t n_crc16;
    void *buf_ptr = buf;
#ifdef HG_HAS_CHECKSUMS
    mchecksum_object_t checksum = MCHECKSUM_OBJECT_NULL;
#endif
    hg_proc_t proc = HG_PROC_NULL;
    hg_return_t ret = HG_SUCCESS;

    if (buf_size < sizeof(struct hg_header_request)) {
        HG_LOG_ERROR("Invalid buffer size");
        ret = HG_INVALID_PARAM;
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Create a new CRC16 checksum */
    mchecksum_init("crc16", &checksum);
#endif

    /* Mercury header */
    if (op == HG_ENCODE) {
        n_protocol = htonl(header->protocol);
        n_id = htonl((hg_uint32_t) header->id);
        n_cookie = htonl(header->cookie);
    }

    /* hg */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &header->hg, sizeof(hg_uint8_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &header->hg, sizeof(hg_uint8_t));
#endif

    /* protocol */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_protocol, sizeof(hg_uint32_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &n_protocol, sizeof(hg_uint32_t));
#endif

    /* id */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_id, sizeof(hg_uint32_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &n_id, sizeof(hg_uint32_t));
#endif

    /* flags */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &header->flags, sizeof(hg_uint8_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &header->flags, sizeof(hg_uint8_t));
#endif

    /* cookie */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_cookie, sizeof(hg_uint32_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &n_cookie, sizeof(hg_uint32_t));
#endif

    /* crc16 */
#ifdef HG_HAS_CHECKSUMS
    mchecksum_get(checksum, &header->crc16, sizeof(hg_uint16_t),
            MCHECKSUM_FINALIZE);
#endif
    if (op == HG_ENCODE) {
        n_crc16 = htons(header->crc16);
    }
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_crc16, sizeof(hg_uint16_t), op);
    if (op == HG_DECODE) {
        hg_uint16_t decoded_crc16 = ntohs(n_crc16);
        if (header->crc16 != decoded_crc16) {
            HG_LOG_ERROR("Invalid request checksum (%04X != %04X)",
                    header->crc16, decoded_crc16);
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }

    if (op == HG_DECODE) {
        header->protocol = ntohl(n_protocol);
        header->id = (hg_id_t) ntohl(n_id);
        header->cookie = ntohl(n_cookie);
    }

    /* Encode/decode extra_bulk_handle if flags have been set, we can do that
     * safely here because the user payload is copied in this case so we don't
     * have to worry about the extra space taken by the header */
    if (header->flags) {
        ret = hg_proc_create(buf_ptr, buf_size, op, HG_CRC64, bulk_class, &proc);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not create proc");
            goto done;
        }

        ret = hg_proc_hg_bulk_t(proc, &header->extra_in_handle);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Could not process extra bulk handle");
            goto done;
        }

        ret = hg_proc_flush(proc);
        if (ret != HG_SUCCESS) {
            HG_LOG_ERROR("Error in proc flush");
            goto done;
        }
    }

done:
#ifdef HG_HAS_CHECKSUMS
    if (checksum != MCHECKSUM_OBJECT_NULL) mchecksum_destroy(checksum);
#endif
    if (proc != HG_PROC_NULL) hg_proc_free(proc);
    proc = HG_PROC_NULL;
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_header_response(void *buf, size_t buf_size,
        struct hg_header_response *header, hg_proc_op_t op)
{
    hg_uint32_t n_ret_code, n_cookie;
    hg_uint16_t n_crc16;
    void *buf_ptr = buf;
#ifdef HG_HAS_CHECKSUMS
    mchecksum_object_t checksum = MCHECKSUM_OBJECT_NULL;
#endif
    hg_return_t ret = HG_SUCCESS;

    if (buf_size < sizeof(struct hg_header_response)) {
        HG_LOG_ERROR("Invalid buffer size");
        ret = HG_SIZE_ERROR;
        goto done;
    }

#ifdef HG_HAS_CHECKSUMS
    /* Create a new CRC16 checksum */
    mchecksum_init("crc16", &checksum);
#endif

    /* Mercury header */
    if (op == HG_ENCODE) {
        n_ret_code = htonl((hg_uint32_t) header->ret_code);
        n_cookie = htonl(header->cookie);
    }

    /* flags */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &header->flags, sizeof(hg_uint8_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &header->flags, sizeof(hg_uint8_t));
#endif

    /* error */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_ret_code, sizeof(hg_uint32_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &n_ret_code, sizeof(hg_uint32_t));
#endif

    /* cookie */
    buf_ptr = hg_proc_buf_memcpy(buf_ptr, &n_cookie, sizeof(hg_uint32_t), op);
#ifdef HG_HAS_CHECKSUMS
    mchecksum_update(checksum, &n_cookie, sizeof(hg_uint32_t));
#endif

    /* crc16 */
#ifdef HG_HAS_CHECKSUMS
    mchecksum_get(checksum, &header->crc16, sizeof(hg_uint16_t),
            MCHECKSUM_FINALIZE);
#endif
    if (op == HG_ENCODE) {
        n_crc16 = htons(header->crc16);
    }
    hg_proc_buf_memcpy(buf_ptr, &n_crc16, sizeof(hg_uint16_t), op);
    if (op == HG_DECODE) {
        hg_uint16_t decoded_crc16 = ntohs(n_crc16);
        if (header->crc16 != decoded_crc16) {
            HG_LOG_ERROR("Invalid response checksum (%04X != %04X)",
                    header->crc16, decoded_crc16);
            ret = HG_CHECKSUM_ERROR;
            goto done;
        }
    }

    if (op == HG_DECODE) {
        header->ret_code = (hg_return_t) ntohl(n_ret_code);
        header->cookie = ntohl(n_cookie);
    }

done:
#ifdef HG_HAS_CHECKSUMS
    if (checksum != MCHECKSUM_OBJECT_NULL) mchecksum_destroy(checksum);
#endif
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_header_request_verify(const struct hg_header_request *header)
{
    hg_return_t ret = HG_SUCCESS;

    /* Must match HG */
    if ( (((header->hg >> 1)  & 'H') != 'H') ||
            (((header->hg)  & 'G') != 'G') ) {
        HG_LOG_ERROR("Invalid HG byte");
        ret = HG_NO_MATCH;
        goto done;
    }

    if (header->protocol != HG_PROTOCOL_VERSION) {
        HG_LOG_ERROR("Invalid HG_PROTOCOL_VERSION");
        ret = HG_NO_MATCH;
        goto done;
    }

    /* Debug
    printf("HG: 0x%02X\n", header.hg);
    printf("PROTOCOL: 0x%08X\n", header.protocol);
    printf("ID: %d\n", header.id);
    printf("FLAGS: 0x%02X\n", header.flags);
    printf("COOKIE: 0x%08X\n", header.cookie);
    printf("CRC16: 0x%04hX\n", header.crc16);
     */

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_proc_header_response_verify(const struct hg_header_response *header)
{
    hg_return_t ret = HG_SUCCESS;

    if (header->ret_code) {
        HG_LOG_WARNING("Response return code: %s",
                HG_Error_to_string((hg_return_t) header->ret_code));
    }

    return ret;
}
