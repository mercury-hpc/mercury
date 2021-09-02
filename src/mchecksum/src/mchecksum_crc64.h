/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MCHECKSUM_CRC64_H
#define MCHECKSUM_CRC64_H

#include "mchecksum_plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the checksum with the CRC64 ECMA hash method.
 *
 * \param checksum_class [IN/OUT]  pointer to checksum class
 *
 * \return Non-negative on success or negative on failure
 */
MCHECKSUM_EXPORT int
mchecksum_crc64_init(struct mchecksum_class *checksum_class);

#ifdef __cplusplus
}
#endif

#endif /* MCHECKSUM_CRC64_H */
