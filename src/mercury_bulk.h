/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_BULK_H
#define MERCURY_BULK_H

#include "mercury_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the Mercury bulk layer.
 *
 * \param network_class [IN]    pointer to network class
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_init(na_class_t *network_class);

/**
 * Finalize the Mercury bulk layer.
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_finalize(void);

/**
 * Indicate whether HG_Bulk_init has been called
 * and return associated network class.
 *
 * \param flag [OUT]            pointer to boolean
 * \param na_class_t [OUT]      pointer to returned network class pointer
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_initialized(hg_bool_t *flag, na_class_t **network_class);

/**
 * Create abstract bulk handle from buffer (register memory, etc).
 *
 * \param buf [IN]              pointer to buffer
 * \param buf_size [IN]         buffer size
 * \param flags [IN]            permission flag:
 *                                - HG_BULK_READWRITE
 *                                - HG_BULK_READ_ONLY
 * \param handle [OUT]          pointer to returned abstract bulk handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_t *handle);

/**
 * Create bulk handle from arbitrary memory regions.
 *
 * \param bulk_segments [IN]    pointer to array of segments
 * \param segment_count [IN]    number of segments
 * \param flags [IN]            permission flag:
 *                                - HG_BULK_READWRITE
 *                                - HG_BULK_READ_ONLY
 * \param handle [OUT]          pointer to returned abstract bulk handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_handle_create_segments(hg_bulk_segment_t *bulk_segments,
        size_t segment_count, unsigned long flags, hg_bulk_t *handle);

/**
 * Free bulk handle.
 *
 * \param handle [IN/OUT]       abstract bulk handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_handle_free(hg_bulk_t handle);

/**
 * Get total size of data associated to abstract bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative value
 */
HG_EXPORT size_t
HG_Bulk_handle_get_size(hg_bulk_t handle);

/**
 * Get size required to serialize abstract bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative value
 */
HG_EXPORT size_t
HG_Bulk_handle_get_serialize_size(hg_bulk_t handle);

/**
 * Serialize bulk handle into a buffer.
 *
 * \param buf [IN/OUT]          pointer to buffer
 * \param buf_size [IN]         buffer size
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_handle_serialize(void *buf, size_t buf_size, hg_bulk_t handle);

/**
 * Deserialize bulk handle from a buffer.
 *
 * \param handle [OUT]          abstract bulk handle
 * \param buf [IN]              pointer to buffer
 * \param buf_size [IN]         buffer size
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_handle_deserialize(hg_bulk_t *handle, const void *buf, size_t buf_size);

/**
 * Create abstract bulk block handle from buffer (register memory, etc).
 *
 * \param buf [IN]              pointer to buffer
 * \param buf_size [IN]         buffer size
 * \param flags [IN]            permission flag:
 *                                - HG_BULK_READWRITE
 *                                - HG_BULK_READ_ONLY
 * \param handle [OUT]          pointer to returned abstract bulk block handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_block_handle_create(void *buf, size_t buf_size, unsigned long flags,
        hg_bulk_block_t *handle);

/**
 * Free bulk block handle.
 *
 * \param handle [IN/OUT]       abstract bulk block handle
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_block_handle_free(hg_bulk_block_t block_handle);

/**
 * Get size of data associated to abstract bulk block handle.
 *
 * \param handle [IN]           abstract bulk block handle
 *
 * \return Non-negative value
 */
HG_EXPORT size_t
HG_Bulk_block_handle_get_size(hg_bulk_block_t handle);

/**
 * Write data to remote address using abstract bulk and bulk block handles.
 *
 * \param addr [IN]             abstract network address of destination
 * \param bulk_handle [IN]      abstract bulk handle
 * \param bulk_offset [IN]      bulk offset
 * \param block_handle [IN]     abstract bulk block handle
 * \param block_offset [IN]     bulk block offset
 * \param block_size [IN]       size of data to be transferred
 * \param bulk_request [OUT]    pointer to returned bulk request
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_write(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_block_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request);

/**
 * Write data to remote address using abstract bulk and bulk block handles.
 * All the data described by the bulk handle will be transferred.
 *
 * \param addr [IN]             abstract network address of destination
 * \param bulk_handle [IN]      abstract bulk handle
 * \param block_handle [IN]     abstract bulk block handle
 * \param bulk_request [OUT]    pointer to returned bulk request
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_write_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request);

/**
 * Read data from remote address using abstract bulk and bulk block handles.
 *
 * \param addr [IN]             abstract network address of destination
 * \param bulk_handle [IN]      abstract bulk handle
 * \param bulk_offset [IN]      bulk offset
 * \param block_handle [IN]     abstract bulk block handle
 * \param block_offset [IN]     bulk block offset
 * \param block_size [IN]       size of data to be transferred
 * \param bulk_request [OUT]    pointer to returned bulk request
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_read(na_addr_t addr, hg_bulk_t bulk_handle, size_t bulk_offset,
        hg_bulk_block_t block_handle, size_t block_offset, size_t block_size,
        hg_bulk_request_t *bulk_request);

/**
 * Read data from remote address using abstract bulk and bulk block handles.
 * All the data described by the bulk handle will be transferred.
 *
 * \param addr [IN]             abstract network address of destination
 * \param bulk_handle [IN]      abstract bulk handle
 * \param block_handle [IN]     abstract bulk block handle
 * \param bulk_request [OUT]    pointer to returned bulk request
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_read_all(na_addr_t addr, hg_bulk_t bulk_handle,
        hg_bulk_block_t block_handle, hg_bulk_request_t *bulk_request);

/**
 * Wait for a bulk operation request to complete.
 *
 * \param bulk_request [IN]     bulk request
 * \param timeout [IN]          timeout (in milliseconds)
 * \param status [OUT]          pointer to returned status
 *
 * \return Non-negative on success or negative on failure
 */
HG_EXPORT int
HG_Bulk_wait(hg_bulk_request_t bulk_request, unsigned int timeout,
        hg_status_t *status);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_BULK_H */
