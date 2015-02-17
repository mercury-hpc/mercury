/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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
 * The NA class can be different from the one used for the RPC interface.
 *
 * \param na_class [IN]         pointer to NA class
 * \param na_context [IN]       pointer to NA context
 *
 * \return Pointer to HG bulk class or NULL in case of failure
 */
HG_EXPORT hg_bulk_class_t *
HG_Bulk_init(
        na_class_t *na_class,
        na_context_t *na_context
        );

/**
 * Finalize the Mercury bulk layer.
 *
 * \param hg_bulk_class [IN]    pointer to HG bulk class
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_finalize(
        hg_bulk_class_t *hg_bulk_class
        );

/**
 * Create a new context.
 *
 * \param hg_bulk_class [IN]    pointer to HG bulk class
 *
 * \return Pointer to HG bulk context or NULL in case of failure
 */
HG_EXPORT hg_bulk_context_t *
HG_Bulk_context_create(
        hg_bulk_class_t *hg_bulk_class
        );

/**
 * Destroy a context created by HG_Bulk_context_create().
 *
 * \param context [IN]          pointer to HG bulk context
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_context_destroy(
        hg_bulk_context_t *context
        );

/**
 * Create abstract bulk handle from specified memory segments.
 * Note.
 * If NULL is passed to buf_ptrs, i.e.,
 *   HG_Bulk_handle_create(count, NULL, buf_sizes, flags, &handle)
 * memory for the missing buf_ptrs array will be internally allocated.
 * Memory allocated is then freed when HG_Bulk_handle_free is called.
 *
 * \param hg_bulk_class [IN]    pointer to HG bulk class
 * \param count [IN]            number of segments
 * \param buf_ptrs [IN]         array of pointers
 * \param buf_sizes [IN]        array of sizes
 * \param flags [IN]            permission flag:
 *                                - HG_BULK_READWRITE
 *                                - HG_BULK_READ_ONLY
 *                                - HG_BULK_WRITE_ONLY
 * \param handle [OUT]          pointer to returned abstract bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_create(
        hg_bulk_class_t *hg_bulk_class,
        hg_uint32_t count,
        void **buf_ptrs,
        const hg_size_t *buf_sizes,
        hg_uint8_t flags,
        hg_bulk_t *handle
        );

/**
 * Free bulk handle.
 *
 * \param handle [IN/OUT]       abstract bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_free(
        hg_bulk_t handle
        );

/**
 * Access bulk handle to retrieve memory segments abstracted by handle.
 * When using mercury in coresident mode (i.e., when addr passed is self addr),
 * it is possible to avoid copy of bulk data by accessing pointers
 * from an existing bulk handle directly.
 *
 * \param handle [IN]            abstract bulk handle
 * \param offset [IN]            bulk offset
 * \param size [IN]              bulk size
 * \param flags [IN]             permission flag:
 *                                 - HG_BULK_READWRITE
 *                                 - HG_BULK_READ_ONLY
 * \param max_count [IN]         maximum number of segments to be returned
 * \param buf_ptrs [IN/OUT]      array of buffer pointers
 * \param buf_sizes [IN/OUT]     array of buffer sizes
 * \param actual_count [OUT]     actual number of segments returned
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_access(
        hg_bulk_t handle,
        hg_size_t offset,
        hg_size_t size,
        hg_uint8_t flags,
        hg_uint32_t max_count,
        void **buf_ptrs,
        hg_size_t *buf_sizes,
        hg_uint32_t *actual_count
        );

/**
 * Get total size of data abstracted by bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative value
 */
HG_EXPORT hg_uint64_t
HG_Bulk_get_size(
        hg_bulk_t handle
        );

/**
 * Get total number of segments abstracted by bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative value
 */
HG_EXPORT hg_uint32_t
HG_Bulk_get_segment_count(
        hg_bulk_t handle
        );

/**
 * Get size required to serialize bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return Non-negative value
 */
HG_EXPORT hg_size_t
HG_Bulk_get_serialize_size(
        hg_bulk_t handle
        );

/**
 * Serialize bulk handle into a buffer.
 *
 * \param buf [IN/OUT]          pointer to buffer
 * \param buf_size [IN]         buffer size
 * \param handle [IN]           abstract bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_serialize(
        void *buf,
        hg_size_t buf_size,
        hg_bulk_t handle
        );

/**
 * Deserialize bulk handle from a buffer.
 *
 * \param hg_bulk_class [IN]    pointer to HG bulk class
 * \param handle [OUT]          abstract bulk handle
 * \param buf [IN]              pointer to buffer
 * \param buf_size [IN]         buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_deserialize(
        hg_bulk_class_t *hg_bulk_class,
        hg_bulk_t *handle,
        const void *buf,
        hg_size_t buf_size
        );

/**
 * Transfer data to/from origin using abstract bulk handles.
 *
 * \param context [IN]          pointer to HG bulk context
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param op [IN]               transfer operation:
 *                                  - HG_BULK_PUSH
 *                                  - HG_BULK_PULL
 * \param origin_addr [IN]      abstract NA address of origin
 * \param origin_handle [IN]    abstract bulk handle
 * \param origin_offset [IN]    offset
 * \param local_handle [IN]     abstract bulk handle
 * \param local_offset [IN]     offset
 * \param size [IN]             size of data to be transferred
 * \param op_id [OUT]           pointer to returned operation ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_transfer(
        hg_bulk_context_t *context,
        hg_bulk_cb_t callback,
        void *arg,
        hg_bulk_op_t op,
        na_addr_t origin_addr,
        hg_bulk_t origin_handle,
        hg_size_t origin_offset,
        hg_bulk_t local_handle,
        hg_size_t local_offset,
        hg_size_t size,
        hg_op_id_t *op_id
        );

/**
 * Try to progress communication for at most timeout until timeout reached or
 * any completion has occurred.
 * Progress should not be considered as wait, in the sense that it cannot be
 * assumed that completion of a specific operation will occur only when
 * progress is called.
 * Calling HG_Bulk_progress is only necessary if a context has been separately
 * created as HG_Progress will call NA_Progress/NA_Trigger on the associated NA
 * context.
 *
 * \param bulk_class [IN]       pointer to HG bulk class
 * \param context [IN]          pointer to HG bulk context
 * \param timeout [IN]          timeout (in milliseconds)
 *
 * \return HG_SUCCESS if any completion has occurred / HG error code otherwise
 */
HG_EXPORT hg_return_t
HG_Bulk_progress(
        hg_bulk_class_t *bulk_class,
        hg_bulk_context_t *context,
        unsigned int timeout
        );

/**
 * Execute at most max_count callbacks. If timeout is non-zero, wait up to
 * timeout before returning. Function can return when at least one or more
 * callbacks are triggered (at most max_count).
 * Calling HG_Trigger is only necessary if a context has been separately
 * created as HG_Progress will call HG_Bulk_trigger on the same NA
 * context.
 *
 * \param bulk_class [IN]       pointer to HG bulk class
 * \param context [IN]          pointer to HG bulk context
 * \param timeout [IN]          timeout (in milliseconds)
 * \param max_count [IN]        maximum number of callbacks triggered
 * \param actual_count [IN]     actual number of callbacks triggered
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_trigger(
        hg_bulk_class_t *bulk_class,
        hg_bulk_context_t *context,
        unsigned int timeout,
        unsigned int max_count,
        unsigned int *actual_count
        );

/**
 * Cancel an ongoing operation.
 *
 * \param op_id [IN]            operation ID
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_cancel(
        hg_op_id_t op_id
        );

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_BULK_H */
