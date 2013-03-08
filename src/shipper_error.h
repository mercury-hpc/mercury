/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef SHIPPER_ERROR_H
#define SHIPPER_ERROR_H

#include <stdio.h>

/* Error return codes */
#define S_SUCCESS  1
#define S_FAIL    -1
#define S_TRUE     1
#define S_FALSE    0

/* Default error macro */
#define S_ERROR_DEFAULT(x) {              \
  fprintf(stderr, "Error "                \
        "in %s:%d (%s): "                 \
        "%s.\n",                          \
        __FILE__, __LINE__, __func__, x); \
}

#endif /* SHIPPER_ERROR_H */
