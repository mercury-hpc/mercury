/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_checksum_crc64.h"
#include "mercury_thread_mutex.h"

#include "mercury_util_error.h"

#include <stdlib.h>

static int hg_checksum_crc64_destroy(hg_checksum_class_t *checksum_class);
static int hg_checksum_crc64_reset(hg_checksum_class_t *checksum_class);
static size_t hg_checksum_crc64_get_size(hg_checksum_class_t *checksum_class);
static int hg_checksum_crc64_get(hg_checksum_class_t *checksum_class,
        void *buf, size_t size, int finalize);
static int hg_checksum_crc64_update(hg_checksum_class_t *checksum_class,
        const void *data, size_t size);

static hg_checksum_class_t hg_checksum_crc64_g = {
        NULL,
        hg_checksum_crc64_destroy,
        hg_checksum_crc64_reset,
        hg_checksum_crc64_get_size,
        hg_checksum_crc64_get,
        hg_checksum_crc64_update
};

#define POLY64REV     0x95AC9329AC4BC9B5ULL
#define INITIALCRC    0xFFFFFFFFFFFFFFFFULL

static hg_util_uint64_t table_[256];
static hg_util_bool_t   table_initialized = 0;

/**
 * Initialize the CRC table.
 */
static void
init_table(void)
{
    unsigned int i, j;
    for (i = 0; i < 256; i++) {
        hg_util_uint64_t part = i;

        for (j = 0; j < 8; j++) {
            if (part & 1)
                part = (part >> 1) ^ POLY64REV;
            else
                part >>= 1;
        }
        table_[i] = part;
    }
}

/*---------------------------------------------------------------------------*/
int
hg_checksum_crc64_init(hg_checksum_class_t *checksum_class)
{
    if (!table_initialized) init_table();
    table_initialized = 1;
    int ret = HG_UTIL_SUCCESS;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("NULL checksum class");
        ret = HG_UTIL_FAIL;
    }

    *checksum_class = hg_checksum_crc64_g;

    checksum_class->data = malloc(sizeof(hg_util_uint64_t));
    if (!checksum_class->data) {
        HG_UTIL_ERROR_DEFAULT("Could not allocate private data");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    *(hg_util_uint64_t*) checksum_class->data = INITIALCRC;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc64_destroy(hg_checksum_class_t *checksum_class)
{
    free(checksum_class->data);

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc64_reset(hg_checksum_class_t *checksum_class)
{
    *(hg_util_uint64_t*) checksum_class->data = INITIALCRC;

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
hg_checksum_crc64_get_size(hg_checksum_class_t HG_UTIL_UNUSED *checksum_class)
{
    return sizeof(hg_util_uint64_t);
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc64_get(hg_checksum_class_t *checksum_class,
        void *buf, size_t size, int HG_UTIL_UNUSED finalize)
{
    int ret = HG_UTIL_SUCCESS;

    if (size < sizeof(hg_util_uint64_t)) {
        HG_UTIL_ERROR_DEFAULT("Buffer is too small to store checksum");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    *(hg_util_uint64_t*) buf = *(hg_util_uint64_t*) checksum_class->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc64_update(hg_checksum_class_t *checksum_class,
        const void *data, size_t size)
{
    const unsigned char *cur = (const unsigned char *) data;
    const unsigned char *end = cur + size;
    hg_util_uint64_t *state = (hg_util_uint64_t*) checksum_class->data;

    while (cur < end) {
        *state = table_[(*state ^ *cur++) & 0xff] ^ (*state >> 8);
    }

    return HG_UTIL_SUCCESS;
}
