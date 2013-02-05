/*
 * shipper_error.h
 *
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
