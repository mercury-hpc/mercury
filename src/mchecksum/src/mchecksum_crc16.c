/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mchecksum_crc16.h"
#include "mchecksum_error.h"

#include <stdlib.h>
#ifdef MCHECKSUM_HAS_ISAL
# include <isa-l.h>
#endif

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static int mchecksum_crc16_destroy(struct mchecksum_class *checksum_class);
static int mchecksum_crc16_reset(struct mchecksum_class *checksum_class);
static size_t mchecksum_crc16_get_size(struct mchecksum_class *checksum_class);
static int mchecksum_crc16_get(struct mchecksum_class *checksum_class,
    void *buf, size_t size, int finalize);
static int mchecksum_crc16_update(struct mchecksum_class *checksum_class,
    const void *data, size_t size);

/*******************/
/* Local Variables */
/*******************/

static const struct mchecksum_class mchecksum_crc16_g = {
    NULL,
    mchecksum_crc16_destroy,
    mchecksum_crc16_reset,
    mchecksum_crc16_get_size,
    mchecksum_crc16_get,
    mchecksum_crc16_update
};

#ifndef MCHECKSUM_HAS_ISAL
static const mchecksum_uint16_t table_[256] = {
    0x0000, 0x8BB7, 0x9CD9, 0x176E, 0xB205, 0x39B2, 0x2EDC, 0xA56B,
    0xEFBD, 0x640A, 0x7364, 0xF8D3, 0x5DB8, 0xD60F, 0xC161, 0x4AD6,
    0x54CD, 0xDF7A, 0xC814, 0x43A3, 0xE6C8, 0x6D7F, 0x7A11, 0xF1A6,
    0xBB70, 0x30C7, 0x27A9, 0xAC1E, 0x0975, 0x82C2, 0x95AC, 0x1E1B,
    0xA99A, 0x222D, 0x3543, 0xBEF4, 0x1B9F, 0x9028, 0x8746, 0x0CF1,
    0x4627, 0xCD90, 0xDAFE, 0x5149, 0xF422, 0x7F95, 0x68FB, 0xE34C,
    0xFD57, 0x76E0, 0x618E, 0xEA39, 0x4F52, 0xC4E5, 0xD38B, 0x583C,
    0x12EA, 0x995D, 0x8E33, 0x0584, 0xA0EF, 0x2B58, 0x3C36, 0xB781,
    0xD883, 0x5334, 0x445A, 0xCFED, 0x6A86, 0xE131, 0xF65F, 0x7DE8,
    0x373E, 0xBC89, 0xABE7, 0x2050, 0x853B, 0x0E8C, 0x19E2, 0x9255,
    0x8C4E, 0x07F9, 0x1097, 0x9B20, 0x3E4B, 0xB5FC, 0xA292, 0x2925,
    0x63F3, 0xE844, 0xFF2A, 0x749D, 0xD1F6, 0x5A41, 0x4D2F, 0xC698,
    0x7119, 0xFAAE, 0xEDC0, 0x6677, 0xC31C, 0x48AB, 0x5FC5, 0xD472,
    0x9EA4, 0x1513, 0x027D, 0x89CA, 0x2CA1, 0xA716, 0xB078, 0x3BCF,
    0x25D4, 0xAE63, 0xB90D, 0x32BA, 0x97D1, 0x1C66, 0x0B08, 0x80BF,
    0xCA69, 0x41DE, 0x56B0, 0xDD07, 0x786C, 0xF3DB, 0xE4B5, 0x6F02,
    0x3AB1, 0xB106, 0xA668, 0x2DDF, 0x88B4, 0x0303, 0x146D, 0x9FDA,
    0xD50C, 0x5EBB, 0x49D5, 0xC262, 0x6709, 0xECBE, 0xFBD0, 0x7067,
    0x6E7C, 0xE5CB, 0xF2A5, 0x7912, 0xDC79, 0x57CE, 0x40A0, 0xCB17,
    0x81C1, 0x0A76, 0x1D18, 0x96AF, 0x33C4, 0xB873, 0xAF1D, 0x24AA,
    0x932B, 0x189C, 0x0FF2, 0x8445, 0x212E, 0xAA99, 0xBDF7, 0x3640,
    0x7C96, 0xF721, 0xE04F, 0x6BF8, 0xCE93, 0x4524, 0x524A, 0xD9FD,
    0xC7E6, 0x4C51, 0x5B3F, 0xD088, 0x75E3, 0xFE54, 0xE93A, 0x628D,
    0x285B, 0xA3EC, 0xB482, 0x3F35, 0x9A5E, 0x11E9, 0x0687, 0x8D30,
    0xE232, 0x6985, 0x7EEB, 0xF55C, 0x5037, 0xDB80, 0xCCEE, 0x4759,
    0x0D8F, 0x8638, 0x9156, 0x1AE1, 0xBF8A, 0x343D, 0x2353, 0xA8E4,
    0xB6FF, 0x3D48, 0x2A26, 0xA191, 0x04FA, 0x8F4D, 0x9823, 0x1394,
    0x5942, 0xD2F5, 0xC59B, 0x4E2C, 0xEB47, 0x60F0, 0x779E, 0xFC29,
    0x4BA8, 0xC01F, 0xD771, 0x5CC6, 0xF9AD, 0x721A, 0x6574, 0xEEC3,
    0xA415, 0x2FA2, 0x38CC, 0xB37B, 0x1610, 0x9DA7, 0x8AC9, 0x017E,
    0x1F65, 0x94D2, 0x83BC, 0x080B, 0xAD60, 0x26D7, 0x31B9, 0xBA0E,
    0xF0D8, 0x7B6F, 0x6C01, 0xE7B6, 0x42DD, 0xC96A, 0xDE04, 0x55B3
};
#endif

/*---------------------------------------------------------------------------*/
int
mchecksum_crc16_init(struct mchecksum_class *checksum_class)
{
    int ret = MCHECKSUM_SUCCESS;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("NULL checksum class");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *checksum_class = mchecksum_crc16_g;

    checksum_class->data = malloc(sizeof(mchecksum_uint16_t));
    if (!checksum_class->data) {
        MCHECKSUM_ERROR_DEFAULT("Could not allocate private data");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    mchecksum_crc16_reset(checksum_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc16_destroy(struct mchecksum_class *checksum_class)
{
    free(checksum_class->data);

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc16_reset(struct mchecksum_class *checksum_class)
{
    *(mchecksum_uint16_t *) checksum_class->data = (mchecksum_uint16_t)0;

    return MCHECKSUM_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static size_t
mchecksum_crc16_get_size(struct mchecksum_class MCHECKSUM_UNUSED *checksum_class)
{
    return sizeof(mchecksum_uint16_t);
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc16_get(struct mchecksum_class *checksum_class,
        void *buf, size_t size, int MCHECKSUM_UNUSED finalize)
{
    int ret = MCHECKSUM_SUCCESS;

    if (size < sizeof(mchecksum_uint16_t)) {
        MCHECKSUM_ERROR_DEFAULT("Buffer is too small to store checksum");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *(mchecksum_uint16_t *) buf = *(mchecksum_uint16_t *) checksum_class->data;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static int
mchecksum_crc16_update(struct mchecksum_class *checksum_class,
        const void *data, size_t size)
{
    mchecksum_uint16_t *state = (mchecksum_uint16_t *) checksum_class->data;
#ifdef MCHECKSUM_HAS_ISAL
    *state = crc16_t10dif(*state, (const unsigned char *) data, size);
#else
    const unsigned char *cur = (const unsigned char *) data;
    const unsigned char *end = cur + size;

    while (cur < end) {
        *state = ((mchecksum_uint16_t) (*state << 8))
            ^ table_[((*state >> 8) ^ *cur++) & 0xff];
    }
#endif

    return MCHECKSUM_SUCCESS;
}