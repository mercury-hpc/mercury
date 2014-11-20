/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROC_HEADER_H
#define MERCURY_PROC_HEADER_H

#include "mercury_types.h"

struct hg_header_request {
     hg_uint8_t  hg;               /* Mercury identifier */
     hg_uint32_t protocol;         /* Version number */
     hg_id_t     id;               /* RPC request identifier */
     hg_uint8_t  flags;            /* Flags (extra buffer) */
     hg_uint32_t cookie;           /* Random cookie */
     hg_uint16_t crc16;            /* CRC16 checksum */
     /* Should be 128 bits here */
     hg_bulk_t   extra_in_handle;  /* Extra handle (large data) */
};

struct hg_header_response {
    hg_uint8_t  flags;      /* Flags */
    hg_int32_t  ret_code;   /* Return code */
    hg_uint32_t cookie;     /* Cookie */
    hg_uint16_t crc16;      /* CRC16 checksum */
    hg_uint8_t  padding;
    /* Should be 96 bits here */
};

/*
 * 0      HG_PROC_HEADER_SIZE              size
 * |______________|__________________________|
 * |    Header    |        Encoded Data      |
 * |______________|__________________________|
 *
 *
 * Request:
 * mercury byte / protocol version number / rpc id / flags (e.g. for extra buf) /
 * random cookie / crc16 / (bulk handle, there is space since payload is copied)
 *
 * Response:
 * flags / error / cookie / crc16 / payload
 */

/* Mercury identifier for packets sent */
#define HG_IDENTIFIER (('H' << 1) | ('G')) /* 0xD7 */

/* Mercury protocol version number */
#define HG_PROTOCOL_VERSION 0x00000002

/* Encode/decode version number into uint32 */
#define HG_GET_MAJOR(value) ((value >> 24) & 0xFF)
#define HG_GET_MINOR(value) ((value >> 16) & 0xFF)
#define HG_GET_PATCH(value) (value & 0xFFFF)
#define HG_VERSION ((HG_VERSION_MAJOR << 24) | (HG_VERSION_MINOR << 16) \
        | HG_VERSION_PATCH)

#ifndef HG_PROC_HEADER_INLINE
  #if defined(__GNUC__) && !defined(__GNUC_STDC_INLINE__)
    #define HG_PROC_HEADER_INLINE extern HG_INLINE
  #else
    #define HG_PROC_HEADER_INLINE HG_INLINE
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

HG_EXPORT HG_PROC_HEADER_INLINE size_t hg_proc_header_request_get_size(void);
HG_EXPORT HG_PROC_HEADER_INLINE size_t hg_proc_header_response_get_size(void);

/**
 * Get size reserved for request header (separate user data stored in payload).
 *
 * \return Non-negative size value
 */
HG_PROC_HEADER_INLINE size_t
hg_proc_header_request_get_size(void)
{
    /* hg_bulk_t is optional and is not really part of the header */
    return (sizeof(struct hg_header_request) - sizeof(hg_bulk_t));
}

/**
 * Get size reserved for response header (separate user data stored in payload).
 *
 * \return Non-negative size value
 */
HG_PROC_HEADER_INLINE size_t
hg_proc_header_response_get_size(void)
{
    return sizeof(struct hg_header_response);
}

/**
 * Initialize RPC request header.
 *
 * \param id [IN]               registered function ID
 * \param extra_buf_handle [IN] extra bulk handle
 * \param header [IN/OUT]       pointer to request header structure
 *
 */
HG_EXPORT void
hg_proc_header_request_init(hg_id_t id, hg_bulk_t extra_buf_handle,
        struct hg_header_request *header);

/**
 * Initialize RPC response header.
 *
 * \param header [IN/OUT]       pointer to response header structure
 *
 */
HG_EXPORT void
hg_proc_header_response_init(struct hg_header_response *header);


/**
 * Process private information for sending/receiving RPC request.
 *
 * \param buf [IN/OUT]          buffer
 * \param buf_size [IN]         buffer size
 * \param header [IN/OUT]       pointer to header structure
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 * \param bulk_class [IN]       HG bulk class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_header_request(void *buf, size_t buf_size,
        struct hg_header_request *header, hg_proc_op_t op,
        hg_bulk_class_t *bulk_class);

/**
 * Process private information for sending/receiving response.
 *
 * \param buf [IN/OUT]          buffer
 * \param buf_size [IN]         buffer size
 * \param header [IN/OUT]       pointer to header structure
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_header_response(void *buf, size_t buf_size,
        struct hg_header_response *header, hg_proc_op_t op);

/**
 * Verify private information from request header.
 *
 * \param header [IN]           pointer to request header structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_header_request_verify(const struct hg_header_request *header);

/**
 * Verify private information from response header.
 *
 * \param header [IN]           pointer to response header structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_proc_header_response_verify(const struct hg_header_response *header);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_PROC_HEADER_H */
