/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
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

#include "mercury_checksum.h"

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif
#include <stdlib.h>

/*---------------------------------------------------------------------------*/
void
hg_proc_header_request_init(hg_id_t id, hg_bulk_t extra_buf_handle,
        hg_header_request_t *header)
{
    header->hg = HG_IDENTIFIER;
    header->protocol = HG_VERSION;
    header->id = id;
    header->flags = (extra_buf_handle != HG_BULK_NULL) ? 1 : 0;
    header->cookie = (hg_uint32_t) rand();
    header->crc16 = 0;
    header->extra_buf_handle = extra_buf_handle;
}

/*---------------------------------------------------------------------------*/
void
hg_proc_header_response_init(hg_header_response_t *header)
{
    header->flags = 0;
    header->error = 0;
    header->cookie = 0;
    header->crc16 = 0;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_header_request(hg_proc_t proc, hg_header_request_t *header)
{
    hg_uint32_t n_protocol, n_id, n_cookie;
    hg_uint16_t n_crc16;
    int ret = HG_FAIL;

    /* Mercury header */
    if (hg_proc_get_op(proc) == HG_ENCODE) {
        n_protocol = htonl(header->protocol);
        n_id = htonl((hg_uint32_t) header->id);
        n_cookie = htonl(header->cookie);
        n_crc16 = htons(header->crc16);
    }

    /* hg */
    ret = hg_proc_memcpy(proc, &header->hg, sizeof(hg_uint8_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* protocol */
    ret = hg_proc_memcpy(proc, &n_protocol, sizeof(hg_uint32_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* id */
    ret = hg_proc_memcpy(proc, &n_id, sizeof(hg_uint32_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* flags */
    ret = hg_proc_memcpy(proc, &header->flags, sizeof(hg_uint8_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* cookie */
    ret = hg_proc_memcpy(proc, &n_cookie, sizeof(hg_uint32_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* crc16 */
    ret = hg_proc_memcpy(proc, &n_crc16, sizeof(hg_uint16_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* extra_bulk_handle */
    if (header->flags && (header->extra_buf_handle != HG_BULK_NULL)) {
        hg_proc_hg_bulk_t(proc, &header->extra_buf_handle);
    } else if (hg_proc_get_op(proc) == HG_DECODE) {
        header->extra_buf_handle = HG_BULK_NULL;
    }

    if (hg_proc_get_op(proc) == HG_DECODE) {
        header->protocol = ntohl(n_protocol);
        header->id = (hg_id_t) ntohl(n_id);
        header->cookie = ntohl(n_cookie);
        header->crc16 = ntohs(n_crc16);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_header_response(hg_proc_t proc, hg_header_response_t *header)
{
    hg_uint32_t n_error;
    hg_uint32_t n_cookie;
    hg_uint16_t n_crc16;
    int ret = HG_FAIL;

    /* Mercury header */
    if (hg_proc_get_op(proc) == HG_ENCODE) {
        n_error = htonl((hg_uint32_t) header->error);
        n_cookie = htonl(header->cookie);
        n_crc16 = htons(header->crc16);
    }

    /* flags */
    ret = hg_proc_memcpy(proc, &header->flags, sizeof(hg_uint8_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* error */
    ret = hg_proc_memcpy(proc, &n_error, sizeof(hg_uint32_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* cookie */
    ret = hg_proc_memcpy(proc, &n_cookie, sizeof(hg_uint32_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    /* crc16 */
    ret = hg_proc_memcpy(proc, &n_crc16, sizeof(hg_uint16_t));
    if (ret != HG_SUCCESS) {
        HG_ERROR_DEFAULT("Proc error");
        ret = HG_FAIL;
        goto done;
    }

    if (hg_proc_get_op(proc) == HG_DECODE) {
        header->error = (hg_error_t) ntohl(n_error);
        header->cookie = ntohl(n_cookie);
        header->crc16 = ntohs(n_crc16);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_header_request_verify(hg_header_request_t header)
{
    int ret = HG_SUCCESS;

    /* Must match HG */
    if ( (((header.hg >> 1)  & 'H') != 'H') ||
            (((header.hg)  & 'G') != 'G') ) {
        HG_ERROR_DEFAULT("HG byte does not match");
        ret = HG_FAIL;
        goto done;
    }

    /* Protocol version must be at least major and minor version */
    if ( (HG_VERSION_MAJOR && (HG_GET_MAJOR(header.protocol) < HG_VERSION_MAJOR)) ||
            (HG_VERSION_MINOR && (HG_GET_MINOR(header.protocol) < HG_VERSION_MINOR)) ) {
        HG_ERROR_DEFAULT("Protocol does not match");
        ret = HG_FAIL;
        goto done;
    }

//    printf("ID: %d\n", header.id);
//    printf("FLAGS: %02X\n", header.flags);
//    printf("COOKIE: %08X\n", header.cookie);
//    printf("CRC16: %04hX\n", header.crc16);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_proc_header_response_verify(hg_header_response_t header)
{
    int ret = HG_SUCCESS;

    if (header.error) {
        HG_ERROR_DEFAULT("Error detected");
        ret = HG_FAIL;
    }

    return ret;
}
