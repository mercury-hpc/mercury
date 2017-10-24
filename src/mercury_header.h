/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HEADER_H
#define MERCURY_HEADER_H

#include "mercury_types.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

#if defined(__GNUC__) || defined(_WIN32)
# pragma pack(push,1)
#else
# warning "Proc header struct padding may not be consistent across platforms."
#endif
#ifdef HG_HAS_CHECKSUMS
struct hg_header_hash {
    hg_uint32_t payload;        /* Payload checksum (32-bits checksum) */
};
#endif

struct hg_header_input {
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash hash; /* Hash */
#else
    hg_uint64_t pad;
#endif
    /* 128 bits here */
};

struct hg_header_output {
#ifdef HG_HAS_CHECKSUMS
    struct hg_header_hash hash; /* Hash */
#endif
    hg_uint32_t pad;
    /* 128/64 bits here */
};
#if defined(__GNUC__) || defined(_WIN32)
# pragma pack(pop)
#endif

/* Common header struct input/output */
struct hg_header {
    union {
        struct hg_header_input input;
        struct hg_header_output output;
    } msg;
};

/*****************/
/* Public Macros */
/*****************/


/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

static HG_INLINE size_t hg_header_input_get_size(void);
static HG_INLINE size_t hg_header_output_get_size(void);

/**
 * Get size reserved for input header (separate user data stored in payload).
 *
 * \return Non-negative size value
 */
static HG_INLINE size_t
hg_header_input_get_size(void)
{
    return sizeof(struct hg_header_input);
}

/**
 * Get size reserved for output header (separate user data stored in payload).
 *
 * \return Non-negative size value
 */
static HG_INLINE size_t
hg_header_output_get_size(void)
{
    return sizeof(struct hg_header_output);
}

/**
 * Initialize RPC input header.
 *
 * \param hg_header [IN/OUT]    pointer to input header structure
 *
 */
HG_EXPORT void
hg_header_input_init(
        struct hg_header *hg_header
        );

/**
 * Initialize RPC output header.
 *
 * \param hg_header [IN/OUT]    pointer to output header structure
 *
 */
HG_EXPORT void
hg_header_output_init(
        struct hg_header *hg_header
        );

/**
 * Finalize RPC input header.
 *
 * \param hg_header [IN/OUT]    pointer to input header structure
 *
 */
HG_EXPORT void
hg_header_input_finalize(
        struct hg_header *hg_header
        );

/**
 * Finalize RPC output header.
 *
 * \param hg_header [IN/OUT]    pointer to output header structure
 *
 */
HG_EXPORT void
hg_header_output_finalize(
        struct hg_header *hg_header
        );

/**
 * Reset RPC input header.
 *
 * \param hg_header [IN/OUT]    pointer to input header structure
 *
 */
HG_EXPORT void
hg_header_input_reset(
        struct hg_header *hg_header
        );

/**
 * Reset RPC output header.
 *
 * \param hg_header [IN/OUT]    pointer to output header structure
 *
 */
HG_EXPORT void
hg_header_output_reset(
        struct hg_header *hg_header
        );

/**
 * Process private information for sending/receiving RPC input.
 *
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 * \param buf [IN/OUT]          buffer
 * \param buf_size [IN]         buffer size
 * \param hg_header [IN/OUT]    pointer to header structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_header_input_proc(
        hg_proc_op_t op,
        void *buf,
        size_t buf_size,
        struct hg_header *hg_header
        );

/**
 * Process private information for sending/receiving output.
 *
 * \param op [IN]               operation type: HG_ENCODE / HG_DECODE
 * \param buf [IN/OUT]          buffer
 * \param buf_size [IN]         buffer size
 * \param hg_header [IN/OUT]    pointer to header structure
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
hg_header_output_proc(
        hg_proc_op_t op,
        void *buf,
        size_t buf_size,
        struct hg_header *hg_header
        );

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HEADER_H */
