/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_CHECKSUM_PRIVATE_H
#define MERCURY_CHECKSUM_PRIVATE_H

#include "mercury_checksum.h"

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
    #define HG_UTIL_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
    #define HG_UTIL_UNUSED __attribute__((unused))
#else
    #define HG_UTIL_UNUSED
#endif

/* Checksum class definition */
typedef struct hg_checksum_class hg_checksum_class_t;

struct hg_checksum_class {
    /* Private data */
    void *data;
    /* Callbacks */
    int (*destroy)(hg_checksum_class_t *checksum_class);
    int (*reset)(hg_checksum_class_t *checksum_class);
    size_t (*get_size)(hg_checksum_class_t *checksum_class);
    int (*get)(hg_checksum_class_t *checksum_class,
            void *buf, size_t size, int finalize);
    int (*update)(hg_checksum_class_t *checksum_class,
            const void *data, size_t size);
};

#endif /* MERCURY_CHECKSUM_PRIVATE_H */
