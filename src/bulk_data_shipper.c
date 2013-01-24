/*
 * bulk_data_shipper.c
 */

#include "bulk_data_shipper.h"

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
    return 0;
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
void bds_handle_free(bds_handle_t bulk_handle)
{
    return;
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
    return 0;
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
    return 0;
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
    return 0;
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
    return 0;
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
    return 0;
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
    return NULL;
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
    return 0;
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
void bds_block_handle_set_size(bds_block_handle_t block_handle)
{
    return;
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
    return 0;
}
