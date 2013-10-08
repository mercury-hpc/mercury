/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_checksum_private.h"
#include "mercury_checksum_crc64.h"
#include "mercury_checksum_crc16.h"

#include "mercury_util_error.h"

#include <string.h>
#include <stdlib.h>

/*---------------------------------------------------------------------------*/
int
hg_checksum_init(const char *hash_method, hg_checksum_t *checksum)
{
    hg_checksum_class_t *checksum_class;
    int ret = HG_UTIL_SUCCESS;

    checksum_class = (hg_checksum_class_t *) malloc(sizeof(hg_checksum_class_t));

    if (strcmp(hash_method, "crc64") == 0) {
        if (hg_checksum_crc64_init(checksum_class) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Could not initialize crc64 checksum");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    } else if (strcmp(hash_method, "crc16") == 0) {
        if (hg_checksum_crc16_init(checksum_class) != HG_UTIL_SUCCESS) {
            HG_UTIL_ERROR_DEFAULT("Could not initialize crc16 checksum");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    } else {
        HG_UTIL_ERROR_DEFAULT("Unknown hash method");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    *checksum = (hg_checksum_t) checksum_class;

done:
    if (ret != HG_UTIL_SUCCESS) {
        free(checksum_class);
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_checksum_destroy(hg_checksum_t checksum)
{
    hg_checksum_class_t *checksum_class = (hg_checksum_class_t *) checksum;
    int ret = HG_UTIL_SUCCESS;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("Checksum not initialized");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (checksum_class->destroy(checksum_class) != HG_UTIL_SUCCESS) {
        HG_UTIL_ERROR_DEFAULT("Could not destroy checksum");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    free(checksum_class);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
int
hg_checksum_reset(hg_checksum_t checksum)
{
    hg_checksum_class_t *checksum_class = (hg_checksum_class_t *) checksum;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("Checksum not initialized");
        return HG_UTIL_FAIL;
    }

    return checksum_class->reset(checksum_class);
}

/*---------------------------------------------------------------------------*/
size_t
hg_checksum_get_size(hg_checksum_t checksum)
{
    hg_checksum_class_t *checksum_class = (hg_checksum_class_t *) checksum;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("Checksum not initialized");
        return 0;
    }

    return checksum_class->get_size(checksum_class);
}

/*---------------------------------------------------------------------------*/
int
hg_checksum_get(hg_checksum_t checksum, void *buf, size_t size, int finalize)
{
    hg_checksum_class_t *checksum_class = (hg_checksum_class_t *) checksum;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("Checksum not initialized");
        return HG_UTIL_FAIL;
    }

    return checksum_class->get(checksum_class, buf, size, finalize);
}

/*---------------------------------------------------------------------------*/
int
hg_checksum_update(hg_checksum_t checksum, const void *data, size_t size)
{
    hg_checksum_class_t *checksum_class = (hg_checksum_class_t *) checksum;

    if (!checksum_class) {
        HG_UTIL_ERROR_DEFAULT("Checksum not initialized");
        return HG_UTIL_FAIL;
    }

    return checksum_class->update(checksum_class, data, size);
}
