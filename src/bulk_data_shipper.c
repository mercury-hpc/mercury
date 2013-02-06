/*
 * bulk_data_shipper.c
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
static na_addr_t bds_remote_addr;

/*---------------------------------------------------------------------------
 * Function:    bds_init
 *
 * Purpose:     Initialize the bulk data shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int bds_init(na_network_class_t *network_class, na_addr_t remote_addr)
{
    int ret = S_SUCCESS;

    if (bds_network_class) {
        S_ERROR_DEFAULT("Already initialized");
        ret = S_FAIL;
        return ret;
    }

    bds_network_class = network_class;
    bds_remote_addr = remote_addr;

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
    bds_remote_addr = NULL;

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
int bds_handle_create(void *buf, size_t buf_size, bds_handle_t *handle)
{
    int ret;
    bds_priv_handle_t *priv_handle;

    priv_handle = malloc(sizeof(bds_priv_handle_t));
    priv_handle->size = buf_size;

    ret = na_mem_register(bds_network_class, buf, buf_size, NA_MEM_READWRITE, &priv_handle->mem_handle);
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
int bds_handle_free(bds_handle_t *handle)
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
int bds_write(bds_handle_t handle, bds_block_handle_t *block_handle)
{
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;
    bds_priv_block_handle_t *priv_block_handle = NULL;

    /* Create and register a new block handle that will be used to receive data */
    priv_block_handle = malloc(sizeof(bds_priv_block_handle_t));
    priv_block_handle->size = priv_handle->size; /* Take the whole size for now */
    priv_block_handle->data = malloc(priv_block_handle->size);
    priv_block_handle->bulk_request = NULL;

    na_mem_register(bds_network_class, priv_block_handle->data,
            priv_block_handle->size, NA_MEM_READWRITE, &priv_block_handle->mem_handle);

    /* Offsets are not used for now */
    ret = na_put(bds_network_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, bds_remote_addr, &priv_block_handle->bulk_request);

    if (ret == S_SUCCESS) {
        *block_handle = priv_block_handle;
    }

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
int bds_read(bds_handle_t handle, bds_block_handle_t *block_handle)
{
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;
    bds_priv_block_handle_t *priv_block_handle = NULL;

    /* Create and register a new block handle that will be used to receive data */
    priv_block_handle = malloc(sizeof(bds_priv_block_handle_t));
    priv_block_handle->size = priv_handle->size; /* Take the whole size for now */
    priv_block_handle->data = malloc(priv_block_handle->size);
    priv_block_handle->bulk_request = NULL;

    na_mem_register(bds_network_class, priv_block_handle->data,
            priv_block_handle->size, NA_MEM_READWRITE, &priv_block_handle->mem_handle);

    /* Offsets are not used for now */
    ret = na_get(bds_network_class,
            priv_block_handle->mem_handle, 0,
            priv_handle->mem_handle, 0,
            priv_block_handle->size, bds_remote_addr, &priv_block_handle->bulk_request);

    if (ret == S_SUCCESS) {
        *block_handle = priv_block_handle;
    }

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

    ret = na_wait(bds_network_class, priv_block_handle->bulk_request, timeout, &block_status);

    if (ret == S_SUCCESS) {
        priv_block_handle->bulk_request = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_get_data
 *
 * Purpose:     Get data pointer from handle
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
void* bds_block_handle_get_data(bds_block_handle_t block_handle)
{
    void *ret = NULL;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        ret = priv_block_handle->data;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_get_size
 *
 * Purpose:     Get data size from block handle
 *
 * Returns:
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

/*---------------------------------------------------------------------------
 * Function:    bds_block_handle_set_size
 *
 * Purpose:     Set data size to block handle
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
void bds_block_handle_set_size(bds_block_handle_t block_handle, size_t size)
{
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        priv_block_handle->size = size;
    }
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
int bds_block_handle_free(bds_block_handle_t *block_handle)
{
    int ret = S_SUCCESS;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        ret = na_mem_deregister(bds_network_class, priv_block_handle->mem_handle);
        if (priv_block_handle->data) free(priv_block_handle->data);
        priv_block_handle->data = NULL;
        free(priv_block_handle);
        priv_block_handle = NULL;
    } else {
        S_ERROR_DEFAULT("Already freed");
        ret = S_FAIL;
    }

    return ret;
}
