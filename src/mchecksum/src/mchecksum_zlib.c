/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mchecksum_zlib.h"
#include "mchecksum_error.h"

#include <zlib.h>
#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static int mchecksum_crc32_destroy(struct mchecksum_class *checksum_class);
static int mchecksum_crc32_reset(struct mchecksum_class *checksum_class);
static size_t mchecksum_crc32_get_size(struct mchecksum_class *checksum_class);
static int mchecksum_crc32_get(struct mchecksum_class *checksum_class,
        void *buf, size_t size, int finalize);
static int mchecksum_crc32_update(struct mchecksum_class *checksum_class,
        const void *data, size_t size);

static int mchecksum_adler32_destroy(struct mchecksum_class *checksum_class);
static int mchecksum_adler32_reset(struct mchecksum_class *checksum_class);
static size_t mchecksum_adler32_get_size(struct mchecksum_class *checksum_class);
static int mchecksum_adler32_get(struct mchecksum_class *checksum_class,
        void *buf, size_t size, int finalize);
static int mchecksum_adler32_update(struct mchecksum_class *checksum_class,
        const void *data, size_t size);

/*******************/
/* Local Variables */
/*******************/

static const struct mchecksum_class mchecksum_crc32_g = {
    NULL,
    mchecksum_crc32_destroy,
    mchecksum_crc32_reset,
    mchecksum_crc32_get_size,
    mchecksum_crc32_get,
    mchecksum_crc32_update
};

static const struct mchecksum_class mchecksum_adler32_g = {
    NULL,
    mchecksum_adler32_destroy,
    mchecksum_adler32_reset,
    mchecksum_adler32_get_size,
    mchecksum_adler32_get,
    mchecksum_adler32_update
};

/*---------------------------------------------------------------------------*/
int
mchecksum_crc32_init(struct mchecksum_class *checksum_class)
{
    int ret = MCHECKSUM_SUCCESS;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("NULL checksum class");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *checksum_class = mchecksum_crc32_g;

    checksum_class->data = malloc(sizeof(mchecksum_uint32_t));
    if (!checksum_class->data) {
        MCHECKSUM_ERROR_DEFAULT("Could not allocate private data");
        ret = MCHECKSUM_FAIL;
        goto done;
    }


    mchecksum_crc32_reset (checksum_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc32_destroy(struct mchecksum_class *checksum_class)
{
    free(checksum_class->data);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc32_reset(struct mchecksum_class *checksum_class)
{
    *(mchecksum_uint32_t*) checksum_class->data =
        (mchecksum_uint32_t) crc32(0L, Z_NULL, 0);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
mchecksum_crc32_get_size(struct mchecksum_class MCHECKSUM_UNUSED *checksum_class)
{
    return sizeof(mchecksum_uint32_t);
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc32_get(struct mchecksum_class *checksum_class,
        void *buf, size_t size, int MCHECKSUM_UNUSED finalize)
{
    int ret = MCHECKSUM_SUCCESS;

    if (size < sizeof(mchecksum_uint32_t)) {
        MCHECKSUM_ERROR_DEFAULT("Buffer is too small to store checksum");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *(mchecksum_uint32_t*) buf = *(mchecksum_uint32_t*) checksum_class->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc32_update(struct mchecksum_class *checksum_class,
        const void *data, size_t size)
{
    mchecksum_uint32_t *state = (mchecksum_uint32_t*) checksum_class->data;

    *state = (mchecksum_uint32_t) crc32(*state, data, (unsigned int) size);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
mchecksum_adler32_init(struct mchecksum_class *checksum_class)
{
    int ret = MCHECKSUM_SUCCESS;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("NULL checksum class");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *checksum_class = mchecksum_adler32_g;

    checksum_class->data = malloc(sizeof(mchecksum_uint32_t));
    if (!checksum_class->data) {
        MCHECKSUM_ERROR_DEFAULT("Could not allocate private data");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    mchecksum_adler32_reset (checksum_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_adler32_destroy(struct mchecksum_class *checksum_class)
{
    free(checksum_class->data);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_adler32_reset(struct mchecksum_class *checksum_class)
{
    *(mchecksum_uint32_t*) checksum_class->data =
        (mchecksum_uint32_t) adler32(0L, Z_NULL, 0);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
mchecksum_adler32_get_size(struct mchecksum_class MCHECKSUM_UNUSED *checksum_class)
{
    return sizeof(mchecksum_uint32_t);
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_adler32_get(struct mchecksum_class *checksum_class,
        void *buf, size_t size, int MCHECKSUM_UNUSED finalize)
{
    int ret = MCHECKSUM_SUCCESS;

    if (size < sizeof(mchecksum_uint32_t)) {
        MCHECKSUM_ERROR_DEFAULT("Buffer is too small to store checksum");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *(mchecksum_uint32_t*) buf = *(mchecksum_uint32_t*) checksum_class->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_adler32_update(struct mchecksum_class *checksum_class,
        const void *data, size_t size)
{
    mchecksum_uint32_t *state = (mchecksum_uint32_t*) checksum_class->data;

    *state = (mchecksum_uint32_t) adler32(*state, data, (unsigned int) size);

    return MCHECKSUM_SUCCESS;
}
