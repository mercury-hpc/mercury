/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mchecksum_crc64.h"
#include "mchecksum_crc16.h"
#include "mchecksum_crc32c.h"
#ifdef MCHECKSUM_HAS_ZLIB
#include "mchecksum_zlib.h"
#endif

#include "mchecksum_error.h"

#include <string.h>
#include <stdlib.h>

/*---------------------------------------------------------------------------*/
int
mchecksum_init(const char *hash_method, mchecksum_object_t *checksum)
{
    struct mchecksum_class *checksum_class = NULL;
    int ret = MCHECKSUM_SUCCESS;

    checksum_class = (struct mchecksum_class *) malloc(sizeof(struct mchecksum_class));
    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Could not allocate checksum class");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    if (strcmp(hash_method, "crc64") == 0) {
        if (mchecksum_crc64_init(checksum_class) != MCHECKSUM_SUCCESS) {
            MCHECKSUM_ERROR_DEFAULT("Could not initialize crc64 checksum");
            ret = MCHECKSUM_FAIL;
            goto done;
        }
    } else if (strcmp(hash_method, "crc16") == 0) {
        if (mchecksum_crc16_init(checksum_class) != MCHECKSUM_SUCCESS) {
            MCHECKSUM_ERROR_DEFAULT("Could not initialize crc16 checksum");
            ret = MCHECKSUM_FAIL;
            goto done;
        }
    } else if (strcmp(hash_method, "crc32c") == 0) {
        if (mchecksum_crc32c_init(checksum_class) != MCHECKSUM_SUCCESS) {
            MCHECKSUM_ERROR_DEFAULT("Could not initialize crc32c checksum");
            ret = MCHECKSUM_FAIL;
            goto done;
        }
#ifdef MCHECKSUM_HAS_ZLIB
    } else if (strcmp(hash_method, "crc32") == 0) {
        if (mchecksum_crc32_init(checksum_class) != MCHECKSUM_SUCCESS) {
            MCHECKSUM_ERROR_DEFAULT("Could not initialize crc32 checksum");
            ret = MCHECKSUM_FAIL;
            goto done;
        }
    } else if (strcmp(hash_method, "adler32") == 0) {
        if (mchecksum_adler32_init(checksum_class) != MCHECKSUM_SUCCESS) {
            MCHECKSUM_ERROR_DEFAULT("Could not initialize adler32 checksum");
            ret = MCHECKSUM_FAIL;
            goto done;
        }
#endif
     } else {
        MCHECKSUM_ERROR_DEFAULT("Unknown hash method");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    *checksum = (mchecksum_object_t) checksum_class;

done:
    if (ret != MCHECKSUM_SUCCESS) {
        free(checksum_class);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
int
mchecksum_destroy(mchecksum_object_t checksum)
{
    struct mchecksum_class *checksum_class = (struct mchecksum_class *) checksum;
    int ret = MCHECKSUM_SUCCESS;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Checksum not initialized");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    if (checksum_class->destroy(checksum_class) != MCHECKSUM_SUCCESS) {
        MCHECKSUM_ERROR_DEFAULT("Could not destroy checksum");
        ret = MCHECKSUM_FAIL;
        goto done;
    }

    free(checksum_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
mchecksum_reset(mchecksum_object_t checksum)
{
    struct mchecksum_class *checksum_class = (struct mchecksum_class *) checksum;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Checksum not initialized");
        return MCHECKSUM_FAIL;
    }

    return checksum_class->reset(checksum_class);
}

/*---------------------------------------------------------------------------*/
size_t
mchecksum_get_size(mchecksum_object_t checksum)
{
    struct mchecksum_class *checksum_class = (struct mchecksum_class *) checksum;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Checksum not initialized");
        return 0;
    }

    return checksum_class->get_size(checksum_class);
}

/*---------------------------------------------------------------------------*/
int
mchecksum_get(mchecksum_object_t checksum, void *buf, size_t size, int finalize)
{
    struct mchecksum_class *checksum_class = (struct mchecksum_class *) checksum;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Checksum not initialized");
        return MCHECKSUM_FAIL;
    }

    return checksum_class->get(checksum_class, buf, size, finalize);
}

/*---------------------------------------------------------------------------*/
int
mchecksum_update(mchecksum_object_t checksum, const void *data, size_t size)
{
    struct mchecksum_class *checksum_class = (struct mchecksum_class *) checksum;

    if (!checksum_class) {
        MCHECKSUM_ERROR_DEFAULT("Checksum not initialized");
        return MCHECKSUM_FAIL;
    }

    return checksum_class->update(checksum_class, data, size);
}
