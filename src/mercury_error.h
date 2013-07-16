/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_ERROR_H
#define MERCURY_ERROR_H

#include <stdio.h>

/* TODO Error return codes should be moved */
#ifndef HG_SUCCESS
  #define HG_SUCCESS  1
  #define HG_FAIL    -1
  #define HG_TRUE     1
  #define HG_FALSE    0
#endif

/* For compatibility */
#if __STDC_VERSION__ < 199901L
  #if __GNUC__ >= 2
    #define __func__ __FUNCTION__
  #else
    #define __func__ "<unknown>"
  #endif
#elif _WIN32
  #define __func__ __FUNCTION__
#endif

/* Default error macro */
#define HG_ERROR_DEFAULT(x) {             \
  fprintf(stderr, "Error "                \
        "in %s:%d (%s): "                 \
        "%s.\n",                          \
        __FILE__, __LINE__, __func__, x); \
}

#endif /* MERCURY_ERROR_H */
