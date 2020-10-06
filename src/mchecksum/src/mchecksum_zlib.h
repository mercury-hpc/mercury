/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MCHECKSUM_ZLIB_H
#define MCHECKSUM_ZLIB_H

#include "mchecksum_plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \param checksum_class [IN/OUT]  pointer to checksum class
 *
 * \return Non-negative on success or negative on failure
 */
MCHECKSUM_EXPORT int
mchecksum_crc32_init(struct mchecksum_class *checksum_class);

MCHECKSUM_EXPORT int
mchecksum_adler32_init(struct mchecksum_class *checksum_class);

#ifdef __cplusplus
}
#endif

#endif
