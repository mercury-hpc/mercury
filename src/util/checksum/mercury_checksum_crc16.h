/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CHECKSUM_CRC16_H
#define MERCURY_CHECKSUM_CRC16_H

#include "mercury_checksum_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the checksum with the CRC16 hash method.
 *
 * \param checksum_class [IN/OUT]  pointer to checksum class
 *
 * \return Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_checksum_crc16_init(hg_checksum_class_t *checksum_class);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_CHECKSUM_CRC16_H */
