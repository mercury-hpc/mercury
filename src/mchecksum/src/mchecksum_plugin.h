/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MCHECKSUM_PRIVATE_H
#define MCHECKSUM_PRIVATE_H

#include "mchecksum.h"

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/* Checksum class definition */
struct mchecksum_class {
    /* Private data */
    void *data;
    /* Callbacks */
    int (*destroy)(struct mchecksum_class *checksum_class);
    int (*reset)(struct mchecksum_class *checksum_class);
    size_t (*get_size)(struct mchecksum_class *checksum_class);
    int (*get)(struct mchecksum_class *checksum_class,
            void *buf, size_t size, int finalize);
    int (*update)(struct mchecksum_class *checksum_class,
            const void *data, size_t size);
};

/*****************/
/* Public Macros */
/*****************/

/* Remove warnings when plugin does not use callback arguments */
#if defined(__cplusplus)
# define MCHECKSUM_UNUSED
#elif defined(__GNUC__) && (__GNUC__ >= 4)
# define MCHECKSUM_UNUSED __attribute__((unused))
#else
# define MCHECKSUM_UNUSED
#endif

#endif /* MCHECKSUM_PRIVATE_H */
