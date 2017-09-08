/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_BULK_H
#define MERCURY_BULK_H

#include "mercury_types.h"

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create an abstract bulk handle from specified memory segments.
 * Memory allocated is then freed when HG_Bulk_free() is called.
 * \remark If NULL is passed to buf_ptrs, i.e.,
 * \verbatim HG_Bulk_create(count, NULL, buf_sizes, flags, &handle) \endverbatim
 * memory for the missing buf_ptrs array will be internally allocated.
 *
 * \param hg_class [IN]         pointer to HG class
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
        hg_class_t *hg_class,
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
 * Increment ref count on bulk handle.
 *
 * \param handle [IN]           abstract bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_ref_incr(
        hg_bulk_t handle
        );

/**
 * Access bulk handle to retrieve memory segments abstracted by handle.
 * \remark When using mercury in co-resident mode (i.e., when addr passed is
 * self addr), this function allows to avoid copy of bulk data by directly
 * accessing pointers from an existing HG bulk handle.
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
HG_EXPORT hg_size_t
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
 * \param request_eager [IN]    boolean (passing HG_TRUE adds size of encoding
 *                              actual data along the handle if handle meets
 *                              HG_BULK_READ_ONLY flag condition)
 *
 * \return Non-negative value
 */
HG_EXPORT hg_size_t
HG_Bulk_get_serialize_size(
        hg_bulk_t handle,
        hg_bool_t request_eager
        );

/**
 * Serialize bulk handle into a buffer.
 *
 * \param buf [IN/OUT]          pointer to buffer
 * \param buf_size [IN]         buffer size
 * \param request_eager [IN]    boolean (passing HG_TRUE encodes actual data
 *                              along the handle, which is more efficient for
 *                              small data, this is only valid if bulk handle
 *                              has HG_BULK_READ_ONLY permission)
 * \param handle [IN]           abstract bulk handle
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_serialize(
        void *buf,
        hg_size_t buf_size,
        hg_bool_t request_eager,
        hg_bulk_t handle
        );

/**
 * Deserialize bulk handle from an existing buffer.
 *
 * \param hg_class [IN]         pointer to HG class
 * \param handle [OUT]          abstract bulk handle
 * \param buf [IN]              pointer to buffer
 * \param buf_size [IN]         buffer size
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
HG_EXPORT hg_return_t
HG_Bulk_deserialize(
        hg_class_t *hg_class,
        hg_bulk_t *handle,
        const void *buf,
        hg_size_t buf_size
        );

/**
 * Transfer data to/from origin using abstract bulk handles. After completion,
 * user callback is placed into a completion queue and can be triggered using
 * HG_Trigger().
 *
 * \param context [IN]          pointer to HG context
 * \param callback [IN]         pointer to function callback
 * \param arg [IN]              pointer to data passed to callback
 * \param op [IN]               transfer operation:
 *                                  - HG_BULK_PUSH
 *                                  - HG_BULK_PULL
 * \param origin_addr [IN]      abstract address of origin
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
        hg_context_t *context,
        hg_cb_t callback,
        void *arg,
        hg_bulk_op_t op,
        hg_addr_t origin_addr,
        hg_bulk_t origin_handle,
        hg_size_t origin_offset,
        hg_bulk_t local_handle,
        hg_size_t local_offset,
        hg_size_t size,
        hg_op_id_t *op_id
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
