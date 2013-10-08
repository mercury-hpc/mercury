/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CHECKSUM_H
#define MERCURY_CHECKSUM_H

#include "mercury_util_config.h"

typedef void *hg_checksum_t;

#define HG_CHECKSUM_NULL ((hg_checksum_t)0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the checksum with the specified hash method.
 *
 * \param hash_method [IN]      hash method string
 * \param checksum [OUT]        pointer to abstract checksum
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_init(const char *hash_method, hg_checksum_t *checksum);

/**
 * Destroy the checksum.
 *
 * \param checksum [IN/OUT]     abstract checksum
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_destroy(hg_checksum_t checksum);

/**
 * Reset the checksum.
 *
 * \param checksum [IN/OUT]     abstract checksum
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_reset(hg_checksum_t checksum);

/**
 * Get size of checksum.
 *
 * \param checksum [IN]         abstract checksum
 *
 * \return Non-negative value
 */
HG_UTIL_EXPORT size_t
hg_checksum_get_size(hg_checksum_t checksum);

/**
 * Get checksum and copy it into buf.
 *
 * \param checksum [IN/OUT]     abstract checksum
 * \param buf [IN]              pointer to buffer
 * \param size [IN]             size of buffer
 * \param finalize [IN]         boolean
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_get(hg_checksum_t checksum, void *buf, size_t size, int finalize);

/**
 * Accumulates a partial checksum of the input data.
 *
 * \param checksum [IN/OUT]     abstract checksum
 * \param data [IN]             pointer to buffer
 * \param size [IN]             size of buffer
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_update(hg_checksum_t checksum, const void *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_CHECKSUM_H */
