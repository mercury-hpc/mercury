/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_checksum_crc16.h"
#include "mercury_util_error.h"

#include <stdlib.h>

static int hg_checksum_crc16_destroy(hg_checksum_class_t *checksum_class);
static int hg_checksum_crc16_reset(hg_checksum_class_t *checksum_class);
static size_t hg_checksum_crc16_get_size(hg_checksum_class_t *checksum_class);
static int hg_checksum_crc16_get(hg_checksum_class_t *checksum_class,
        void *buf, size_t size, int finalize);
static int hg_checksum_crc16_update(hg_checksum_class_t *checksum_class,
        const void *data, size_t size);

static hg_checksum_class_t hg_checksum_crc16_g = {
        NULL,
        hg_checksum_crc16_destroy,
        hg_checksum_crc16_reset,
        hg_checksum_crc16_get_size,
        hg_checksum_crc16_get,
        hg_checksum_crc16_update
};

static const hg_util_uint16_t table_[256] = {
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

/* CRC-16 Poly is 0x8005 (x^16 + x^15 + x^2 + 1) -> Rev Poly is 0xA001 */
#define POLYREV    0xA001
#define INITIALCRC 0
/**
 * Initialize the CRC table.
 */
/*
static void
gen_table(void)
{
    unsigned int i, j;
    unsigned int col = 0;

    for (i = 0; i < 256; i++) {
        hg_util_uint16_t part = i;

        for (j = 0; j < 8; j++) {
            if (part & 1)
                part = (part >> 1) ^ POLYREV;
            else
                part >>= 1;
        }
        col++;
        printf("0x%04X, ", part);
        if (col == 8) {
            printf("\n");
            col = 0;
        }
    }
    printf("\n");
}
*/

/*---------------------------------------------------------------------------*/
int
hg_checksum_crc16_init(hg_checksum_class_t *checksum_class)
{
    int ret = HG_UTIL_SUCCESS;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("NULL checksum class");
        ret = HG_UTIL_FAIL;
    }

    *checksum_class = hg_checksum_crc16_g;

    checksum_class->data = malloc(sizeof(hg_util_uint16_t));
    if (!checksum_class->data) {
        HG_UTIL_ERROR_DEFAULT("Could not allocate private data");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    *(hg_util_uint16_t*) checksum_class->data = INITIALCRC;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc16_destroy(hg_checksum_class_t *checksum_class)
{
    free(checksum_class->data);

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc16_reset(hg_checksum_class_t *checksum_class)
{
    *(hg_util_uint16_t*) checksum_class->data = INITIALCRC;

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
hg_checksum_crc16_get_size(hg_checksum_class_t HG_UTIL_UNUSED *checksum_class)
{
    return sizeof(hg_util_uint16_t);
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc16_get(hg_checksum_class_t *checksum_class,
        void *buf, size_t size, int HG_UTIL_UNUSED finalize)
{
    int ret = HG_UTIL_SUCCESS;

    if (size < sizeof(hg_util_uint16_t)) {
        HG_UTIL_ERROR_DEFAULT("Buffer is too small to store checksum");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    *(hg_util_uint16_t*) buf = *(hg_util_uint16_t*) checksum_class->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_checksum_crc16_update(hg_checksum_class_t *checksum_class,
        const void *data, size_t size)
{
    const unsigned char *cur = (const unsigned char *) data;
    const unsigned char *end = cur + size;
    hg_util_uint16_t *state = (hg_util_uint16_t*) checksum_class->data;

    while (cur < end) {
        *state = (*state >> 8) ^ table_[(*state ^ *cur++) & 0xff];
    }

    return HG_UTIL_SUCCESS;
}
