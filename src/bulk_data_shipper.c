/*
 * bulk_data_shipper.c
 */

#include "bulk_data_shipper.h"

#include <stdlib.h>
#include <stdio.h>

typedef struct bds_priv_handle {
    void *          data;
    na_size_t       size;
    na_addr_t       remote_addr;
    na_mem_handle_t local_mem_handle;
    na_mem_handle_t remote_mem_handle;
} bds_priv_handle_t;

typedef struct bds_priv_block_handle {
    void *       data;
    na_size_t    size;
    na_request_t bulk_request;
} bds_priv_block_handle_t;

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

    return 0;
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
    return 0;
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
    priv_handle->data = buf;
    priv_handle->size = buf_size;
    priv_handle->remote_addr = NULL;
    priv_handle->remote_mem_handle = NULL;

    ret = na_mem_register(buf, buf_size, NA_MEM_TARGET_GET, &priv_handle->local_mem_handle);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("na_mem_register failed");
        free(priv_handle);
        priv_handle = NULL;
    } else {
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

    ret = na_mem_deregister(priv_handle->local_mem_handle);
    if (ret != NA_SUCCESS) {
        NA_ERROR_DEFAULT("na_mem_deregister failed");
    } else {
        free(priv_handle);
        priv_handle = NULL;
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
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;

    /* Serialize mem handle */
    ret = na_mem_handle_serialize(buf, buf_len, priv_handle->local_mem_handle);
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
    int ret;
    bds_priv_handle_t *priv_handle = (bds_priv_handle_t*) handle;

    ret = na_mem_handle_deserialize(&priv_handle->remote_mem_handle, buf, buf_len);
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
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    /* Offsets are not used for now */
    ret = na_put(priv_handle->local_mem_handle, 0, priv_handle->remote_mem_handle, 0,
            priv_handle->size, priv_handle->remote_addr, &priv_block_handle->bulk_request);

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
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    /* Offsets are not used for now */
    ret = na_get(priv_handle->local_mem_handle, 0, priv_handle->remote_mem_handle, 0,
            priv_handle->size, priv_handle->remote_addr, &priv_block_handle->bulk_request);

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

    ret = na_wait(priv_block_handle->bulk_request, timeout, &block_status);

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
    int ret = NA_SUCCESS;
    bds_priv_block_handle_t *priv_block_handle = (bds_priv_block_handle_t*) block_handle;

    if (priv_block_handle) {
        free(priv_block_handle);
        priv_block_handle = NULL;
    } else {
        NA_ERROR_DEFAULT("Already freed");
        ret = NA_FAIL;
    }
    return ret;
}
