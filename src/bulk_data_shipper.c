/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "bulk_data_shipper.h"
#include "shipper_error.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct bds_priv_handle {
    na_size_t       size;
    na_mem_handle_t mem_handle;
    bool            registered;
} bds_priv_handle_t;

typedef struct bds_priv_block_handle {
    void *          data;
    na_size_t       size;
    na_mem_handle_t mem_handle;
    na_request_t    bulk_request;
} bds_priv_block_handle_t;

static na_network_class_t *bds_network_class = NULL;

/*---------------------------------------------------------------------------
 * Function:    bds_init
 *
 * Purpose:     Initialize the bulk data shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_init(na_network_class_t *network_class)
{
    int ret = S_SUCCESS;

    if (bds_network_class) {
        S_ERROR_DEFAULT("Already initialized");
        ret = S_FAIL;
        return ret;
    }

    bds_network_class = network_class;

    return S_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    bds_finalize
 *
 * Purpose:     Finalize
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_finalize(void)
{
    int ret = S_SUCCESS;

    if (!bds_network_class) {
        S_ERROR_DEFAULT("Already finalized");
        ret = S_FAIL;
        return ret;
    }

    bds_network_class = NULL;

    return S_SUCCESS;
}

/*---------------------------------------------------------------------------
 * Function:    bds_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_handle_create(void *buf, size_t buf_size, unsigned long flags,
        bds_handle_t *handle)
{
    int ret;
    bds_priv_handle_t *priv_handle;
    unsigned long na_flags;

    switch (flags) {
        case BDS_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case BDS_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            S_ERROR_DEFAULT("Unrecognized handle flag");
            ret = S_FAIL;
            return ret;
    }

    priv_handle = malloc(sizeof(bds_priv_handle_t));
    priv_handle->size = buf_size;

    ret = na_mem_register(bds_network_class, buf, buf_size, na_flags,
            &priv_handle->mem_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("na_mem_register failed");
        free(priv_handle);
        priv_handle = NULL;
    } else {
        priv_handle->registered = 1;
        *handle = (bds_handle_t) priv_handle;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_handle_free
 *
 * Purpose:     Free bulk data handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_handle_free(bds_handle_t handle)
{
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;

    if (!priv_handle) {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
        return ret;
    }

    if (priv_handle->registered) {
        ret = na_mem_deregister(bds_network_class, priv_handle->mem_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("na_mem_deregister failed");
        }
    } else {
        ret = na_mem_handle_free(bds_network_class, priv_handle->mem_handle);
        if (ret != S_SUCCESS) {
            S_ERROR_DEFAULT("na_mem_handle_free failed");
        }
    }
    free(priv_handle);
    priv_handle = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_handle_get_size
 *
 * Purpose:     Get data size from handle
 *
 *---------------------------------------------------------------------------
 */
size_t bds_handle_get_size(bds_handle_t handle)
{
    size_t ret = 0;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;

    if (priv_handle) {
        ret = priv_handle->size;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_handle_serialize
 *
 * Purpose:     Serialize bulk data handle into buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_handle_serialize(void *buf, na_size_t buf_len, bds_handle_t handle)
{
    int ret = S_SUCCESS;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL memory handle passed");
        ret = S_FAIL;
        return ret;
    }

    if (buf_len < sizeof(bds_priv_handle_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        /* Here add the size of the data */
        memcpy(buf, &priv_handle->size, sizeof(na_size_t));
        ret = na_mem_handle_serialize(bds_network_class, buf + sizeof(na_size_t),
                buf_len - sizeof(na_size_t), priv_handle->mem_handle);
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_handle_deserialize
 *
 * Purpose:     Deserialize bulk data handle from buf
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_handle_deserialize(bds_handle_t *handle, const void *buf, na_size_t buf_len)
{
    int ret = S_SUCCESS;
    bds_priv_handle_t *priv_handle = NULL;

    if (!handle) {
        S_ERROR_DEFAULT("NULL pointer to memory handle passed");
        ret = S_FAIL;
        return ret;
    }

    if (buf_len < sizeof(bds_priv_handle_t)) {
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter");
        ret = S_FAIL;
    } else {
        priv_handle = malloc(sizeof(bds_priv_handle_t));
        memcpy(&priv_handle->size, buf, sizeof(na_size_t));
        ret = na_mem_handle_deserialize(bds_network_class, &priv_handle->mem_handle,
                buf + sizeof(na_size_t), buf_len - sizeof(na_size_t));
        priv_handle->registered = 0;
    }

    if (ret == S_SUCCESS) {
        *handle = priv_handle;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_write
 *
 * Purpose:     Write data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_write(bds_handle_t handle, na_addr_t addr, bds_block_handle_t block_handle)
{
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL memory handle passed");
        ret = S_FAIL;
        return ret;
    }

    if (priv_block_handle->bulk_request != NULL) {
        S_ERROR_DEFAULT("Block handle is being used for another operation");
        ret = S_FAIL;
        return ret;
    }

    /* Offsets are not used for now */
    ret = na_put(bds_network_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, addr, &priv_block_handle->bulk_request);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_read
 *
 * Purpose:     Read data
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_read(bds_handle_t handle, na_addr_t addr, bds_block_handle_t block_handle)
{
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (!priv_handle) {
        S_ERROR_DEFAULT("NULL memory handle passed");
        ret = S_FAIL;
        return ret;
    }

    if (priv_block_handle->bulk_request != NULL) {
        S_ERROR_DEFAULT("Block handle is being used for another operation");
        ret = S_FAIL;
        return ret;
    }

    /* Offsets are not used for now */
    ret = na_get(bds_network_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, addr, &priv_block_handle->bulk_request);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_wait
 *
 * Purpose:     Wait for bulk data operation to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_wait(bds_block_handle_t block_handle, unsigned int timeout)
{
    int ret;
    na_status_t block_status;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (!priv_block_handle) {
        S_ERROR_DEFAULT("NULL memory handle passed");
        ret = S_FAIL;
        return ret;
    }

    ret = na_wait(bds_network_class, priv_block_handle->bulk_request, timeout, &block_status);

    if (ret == S_SUCCESS) {
        priv_block_handle->bulk_request = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_create
 *
 * Purpose:     Create bulk data handle from buffer (register memory, etc)
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_block_handle_create(void *buf, size_t block_size, unsigned long flags,
        bds_block_handle_t *block_handle)
{
    int ret;
    bds_priv_block_handle_t *priv_block_handle;
    unsigned long na_flags;

    switch (flags) {
        case BDS_READWRITE:
            na_flags = NA_MEM_READWRITE;
            break;
        case BDS_READ_ONLY:
            na_flags = NA_MEM_READ_ONLY;
            break;
        default:
            S_ERROR_DEFAULT("Unrecognized handle flag");
            ret = S_FAIL;
            return ret;
    }

    priv_block_handle = malloc(sizeof(bds_priv_block_handle_t));
    priv_block_handle->data = buf;
    priv_block_handle->size = block_size;
    priv_block_handle->bulk_request = NULL;

    ret = na_mem_register(bds_network_class, buf, block_size, na_flags,
            &priv_block_handle->mem_handle);
    if (ret != S_SUCCESS) {
        S_ERROR_DEFAULT("na_mem_register failed");
        free(priv_block_handle);
        priv_block_handle = NULL;
    } else {
        *block_handle = (bds_block_handle_t) priv_block_handle;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_free
 *
 * Purpose:     Free block handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_block_handle_free(bds_block_handle_t block_handle)
{
    int ret = S_SUCCESS;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        ret = na_mem_deregister(bds_network_class, priv_block_handle->mem_handle);
        /* No longer free the data block here */
        //if (priv_block_handle->data) free(priv_block_handle->data);
        //priv_block_handle->data = NULL;
        free(priv_block_handle);
        priv_block_handle = NULL;
    } else {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_get_size
 *
 * Purpose:     Get data size from block handle
 *
 *---------------------------------------------------------------------------
 */
size_t bds_block_handle_get_size(bds_block_handle_t block_handle)
{
    size_t ret = 0;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        ret = priv_block_handle->size;
    }

    return ret;
}

