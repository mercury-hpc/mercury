/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_hash_string.h"

/*---------------------------------------------------------------------------*/
unsigned int
hg_hash_string(const char *string)
{
    /* This is the djb2 string hash function */

    unsigned int result = 5381;
    const unsigned char *p;

    p = (const unsigned char *) string;

    while (*p != '\0') {
        result = (result << 5) + result + *p;
        ++p;
    }
    return result;
}
