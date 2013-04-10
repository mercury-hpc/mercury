/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_bulk.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct hg_bulk_priv {
    na_size_t       size;
    na_mem_handle_t mem_handle;
    bool            registered;
} hg_bulk_priv_t;

typedef struct hg_bulk_priv_block {
    void *          data;
    na_size_t       size;
    na_mem_handle_t mem_handle;
    na_request_t    bulk_request;
} hg_bulk_priv_block_t;

static na_class_t *bulk_na_class = NULL;

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_init
 *
 * Purpose:     Initialize the bulk data shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_init(na_class_t *network_class)
{
    int ret = HG_SUCCESS;

    if (bulk_na_class) {
        HG_ERROR_DEFAULT("Already initialized");
        ret = HG_FAIL;
        return ret;
    }

    bulk_na_class = network_class;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_finalize
 *
 * Purpose:     Finalize
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_finalize(void)
{
    int ret = HG_SUCCESS;

    if (!bulk_na_class) {
        HG_ERROR_DEFAULT("Already finalized");
        ret = HG_FAIL;
        return ret;
    }

    bulk_na_class = NULL;

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle)
{
    int ret, na_ret;
    hg_bulk_priv_t *priv_handle;
    unsigned long na_flags;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_FAIL;
            return ret;
    }

    priv_handle = malloc(sizeof(hg_bulk_priv_t));
    priv_handle->size = buf_size;

    na_ret = NA_Mem_register(bulk_na_class, buf, buf_size, na_flags,
            &priv_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("na_mem_register failed");
        free(priv_handle);
        priv_handle = NULL;
        ret = HG_FAIL;
    } else {
        priv_handle->registered = 1;
        *handle = (hg_bulk_t) priv_handle;
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_free
 *
 * Purpose:     Free bulk data handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_free(hg_bulk_t handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_t *priv_handle = (hg_bulk_priv_t*) handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_handle->registered) {
        na_ret = NA_Mem_deregister(bulk_na_class, priv_handle->mem_handle);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_deregister failed");
            ret = HG_FAIL;
        }
    } else {
        na_ret = NA_Mem_handle_free(bulk_na_class, priv_handle->mem_handle);
        if (na_ret != NA_SUCCESS) {
            HG_ERROR_DEFAULT("na_mem_handle_free failed");
            ret = HG_FAIL;
        }
    }
    free(priv_handle);
    priv_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_get_size
 *
 * Purpose:     Get data size from handle
 *
 *---------------------------------------------------------------------------
 */
size_t HG_Bulk_handle_get_size(hg_bulk_t handle)
{
    size_t ret = 0;
    hg_bulk_priv_t *priv_handle = (hg_bulk_priv_t*) handle;

    if (priv_handle) {
        ret = priv_handle->size;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_serialize
 *
 * Purpose:     Serialize bulk data handle into buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_serialize(void *buf, na_size_t buf_len, hg_bulk_t handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_t *priv_handle = (hg_bulk_priv_t*) handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    if (buf_len < sizeof(hg_bulk_priv_t)) {
        HG_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = HG_FAIL;
        return ret;
    }

    /* Here add the size of the data */
    memcpy(buf, &priv_handle->size, sizeof(na_size_t));
    na_ret = NA_Mem_handle_serialize(bulk_na_class, buf + sizeof(na_size_t),
            buf_len - sizeof(na_size_t), priv_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not serialize memory handle");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_handle_deserialize
 *
 * Purpose:     Deserialize bulk data handle from buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, na_size_t buf_len)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_t *priv_handle = NULL;

    if (!handle) {
        HG_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    if (buf_len < sizeof(hg_bulk_priv_t)) {
        HG_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = HG_FAIL;
        return ret;
    }

    priv_handle = malloc(sizeof(hg_bulk_priv_t));
    memcpy(&priv_handle->size, buf, sizeof(na_size_t));
    na_ret = NA_Mem_handle_deserialize(bulk_na_class, &priv_handle->mem_handle,
            buf + sizeof(na_size_t), buf_len - sizeof(na_size_t));
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not deserialize memory handle");
        ret = HG_FAIL;
    } else {
        /* The handle is not registered, only deserialized */
        priv_handle->registered = 0;
        *handle = priv_handle;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_write
 *
 * Purpose:     Write data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_write(hg_bulk_t handle, na_addr_t addr, hg_bulk_block_t block_handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_t *priv_handle = (hg_bulk_priv_t*) handle;
    hg_bulk_priv_block_t *priv_block_handle = (hg_bulk_priv_block_t*) block_handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_block_handle->bulk_request != NULL) {
        HG_ERROR_DEFAULT("Block handle is being used for another operation");
        ret = HG_FAIL;
        return ret;
    }

    /* Offsets are not used for now */
    na_ret = NA_Put(bulk_na_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, addr, &priv_block_handle->bulk_request);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not put data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_read
 *
 * Purpose:     Read data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_read(hg_bulk_t handle, na_addr_t addr, hg_bulk_block_t block_handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_t *priv_handle = (hg_bulk_priv_t*) handle;
    hg_bulk_priv_block_t *priv_block_handle = (hg_bulk_priv_block_t*) block_handle;

    if (!priv_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    if (priv_block_handle->bulk_request != NULL) {
        HG_ERROR_DEFAULT("Block handle is being used for another operation");
        ret = HG_FAIL;
        return ret;
    }

    /* Offsets are not used for now */
    na_ret = NA_Get(bulk_na_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, addr, &priv_block_handle->bulk_request);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not get data");
        ret = HG_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_wait
 *
 * Purpose:     Wait for bulk data operation to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_wait(hg_bulk_block_t block_handle, unsigned int timeout)
{
    int ret = HG_SUCCESS, na_ret;
    na_status_t block_status;
    hg_bulk_priv_block_t *priv_block_handle = (hg_bulk_priv_block_t*) block_handle;

    if (!priv_block_handle) {
        HG_ERROR_DEFAULT("NULL memory handle passed");
        ret = HG_FAIL;
        return ret;
    }

    na_ret = NA_Wait(bulk_na_class, priv_block_handle->bulk_request, timeout, &block_status);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Error during wait");
        ret = HG_FAIL;
    } else {
        /* Request has been freed in NA_Wait */
        priv_block_handle->bulk_request = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        hg_bulk_block_t *block_handle)
{
    int ret, na_ret;
    hg_bulk_priv_block_t *priv_block_handle;
    unsigned long na_flags;

    switch (flags) {
        case HG_BULK_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case HG_BULK_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            HG_ERROR_DEFAULT("Unrecognized handle flag");
            ret = HG_FAIL;
            return ret;
    }

    priv_block_handle = malloc(sizeof(hg_bulk_priv_block_t));
    priv_block_handle->data = buf;
    priv_block_handle->size = block_size;
    priv_block_handle->bulk_request = NULL;

    na_ret = NA_Mem_register(bulk_na_class, buf, block_size, na_flags,
            &priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not register block");
        free(priv_block_handle);
        priv_block_handle = NULL;
        ret = HG_FAIL;
    } else {
        *block_handle = (hg_bulk_block_t) priv_block_handle;
        ret = HG_SUCCESS;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_free
 *
 * Purpose:     Free block handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int HG_Bulk_block_handle_free(hg_bulk_block_t block_handle)
{
    int ret = HG_SUCCESS, na_ret;
    hg_bulk_priv_block_t *priv_block_handle = (hg_bulk_priv_block_t*) block_handle;

    if (!priv_block_handle) {
        HG_ERROR_DEFAULT("Already freed");
        ret = HG_FAIL;
    }

    na_ret = NA_Mem_deregister(bulk_na_class, priv_block_handle->mem_handle);
    if (na_ret != NA_SUCCESS) {
        HG_ERROR_DEFAULT("Could not deregister block");
        ret = HG_FAIL;
        return ret;
    }
    free(priv_block_handle);
    priv_block_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    HG_Bulk_block_handle_get_size
 *
 * Purpose:     Get data size from block handle
 *
 *---------------------------------------------------------------------------
 */
size_t HG_Bulk_block_handle_get_size(hg_bulk_block_t block_handle)
{
    size_t ret = 0;
    hg_bulk_priv_block_t *priv_block_handle = (hg_bulk_priv_block_t*) block_handle;

    if (priv_block_handle) {
        ret = priv_block_handle->size;
    }

    return ret;
}

