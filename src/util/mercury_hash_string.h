/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_HASH_STRING_H
#define MERCURY_HASH_STRING_H

#include "mercury_util_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Hash function name for unique ID to register.
 *
 * \param string [IN]           string name
 *
 * \return Non-negative ID that corresponds to string name
 */
HG_UTIL_EXPORT unsigned int
hg_hash_string(const char *string);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_HASH_STRING_H */
